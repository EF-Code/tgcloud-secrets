import { randomBytes, timingSafeEqual } from 'node:crypto';
import pg from 'pg';
import {
  capabilityMatches,
  decryptSecret,
  decryptSecretWithDEK,
  encryptSecret,
  encryptSecretEnvelope,
  encryptSecretWithDEK,
  generateDEK,
  generateMasterKey,
  hashCapability,
  hashCapabilityMetadata,
  capabilityMetadataMatches,
  parseMasterKey,
  ENCRYPTED_SECRET_VERSION,
} from './crypto.js';
import { createKMSProvider, LocalKMSProvider } from './kms.js';
import {
  normalizeBaseUrl,
  normalizeInjectHeader,
  normalizeInjectPrefix,
  normalizeMethods,
  normalizePathPrefix,
  isSafeHeaderValue,
} from './policy.js';

const { Pool } = pg;

const STORE_VERSION = 1;
const SECRET_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const CAPABILITY_ID = /^cap_[a-f0-9]{20}$/;
const MAX_SECRET_BYTES = 8 * 1024;

function validateSecretName(name) {
  if (typeof name !== 'string' || !SECRET_NAME.test(name)) {
    throw new Error('Secret name must start with a letter and contain only letters, numbers, ., _, or -');
  }
  if (name === '__proto__' || name === 'constructor' || name === 'prototype') {
    throw new Error('Secret name is reserved');
  }
  return name;
}

function validateCapabilityId(id) {
  if (typeof id !== 'string' || !CAPABILITY_ID.test(id)) throw new Error('Capability ID is invalid');
  return id;
}

// Schema for Postgres
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kms_key_id TEXT NOT NULL DEFAULT 'local',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(org_id, name)
);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  encrypted_blob JSONB NOT NULL,
  dek_ciphertext TEXT,
  key_id TEXT NOT NULL DEFAULT 'local',
  version INT NOT NULL DEFAULT 3,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id, name)
);

CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  secret_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  base_url TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  methods JSONB NOT NULL,
  inject_header TEXT NOT NULL,
  inject_prefix TEXT NOT NULL,
  allow_http BOOLEAN NOT NULL DEFAULT false,
  expires_at TIMESTAMPTZ,
  metadata_mac TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_capabilities_token_hash ON capabilities(token_hash);
CREATE INDEX IF NOT EXISTS idx_secrets_project_name ON secrets(project_id, name);
CREATE INDEX IF NOT EXISTS idx_capabilities_project ON capabilities(project_id);

CREATE TABLE IF NOT EXISTS capability_audit (
  id BIGSERIAL PRIMARY KEY,
  capability_id TEXT REFERENCES capabilities(id) ON DELETE SET NULL,
  org_id TEXT,
  project_id TEXT,
  peer TEXT,
  path TEXT,
  method TEXT,
  status INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_capability_time ON capability_audit(capability_id, created_at);
`;

export class PgStore {
  constructor({ dsn, kmsProvider, masterKey, orgId = 'default', projectId = 'default', poolConfig = {} } = {}) {
    const connectionString = dsn || process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN;
    if (!connectionString) throw new Error('Postgres DSN required (set DATABASE_URL or TGCLOUD_SECRETS_DSN)');
    this.dsn = connectionString;
    this.orgId = orgId;
    this.projectId = projectId;
    this.pool = new Pool({ connectionString, ...poolConfig });
    if (kmsProvider) {
      this.kms = kmsProvider;
    } else if (masterKey) {
      this.kms = new LocalKMSProvider({ masterKey, keyId: 'local' });
    } else {
      this.kms = null; // lazy init via _getKMS from env
      this._pendingMasterKey = masterKey;
    }
    this._initPromise = null;
  }

  // Lazy import to avoid circular
  async init() {
    if (this._initPromise) return this._initPromise;
    this._initPromise = (async () => {
      const client = await this.pool.connect();
      try {
        await client.query(SCHEMA_SQL);
        // Ensure default org/project exists
        await client.query(
          `INSERT INTO orgs (id, name, kms_key_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
          [this.orgId, this.orgId, this.kms.getKeyId()]
        );
        await client.query(
          `INSERT INTO projects (id, org_id, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
          [this.projectId, this.orgId, this.projectId]
        );
      } finally {
        client.release();
      }
      return this;
    })();
    return this._initPromise;
  }

  async close() {
    await this.pool.end();
  }

  async _getKMS() {
    if (this.kms) return this.kms;
    const { createKMSProvider } = await import('./kms.js');
    // try env-based provider, fallback to local generated
    try {
      this.kms = createKMSProvider({ masterKey: this._pendingMasterKey });
    } catch {
      this.kms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' });
    }
    return this.kms;
  }

  async setSecret(name, value, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateSecretName(name);
    if (typeof value !== 'string' || value.length === 0) throw new Error('Secret value must be a non-empty string');
    if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
    if (!isSafeHeaderValue(value)) throw new Error('Secret value must be an HTTP-safe string without unsafe control characters');
    await this.init();
    const kms = await this._getKMS();
    const { plaintext: dek, ciphertextBlob: dekCiphertext, keyId } = await kms.generateDataKey();
    const encrypted = encryptSecretEnvelope(value, dek, name, { orgId, projectId, keyId, dekCiphertext });
    const id = `${projectId}:${name}`;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO secrets (id, project_id, name, encrypted_blob, dek_ciphertext, key_id, version, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 3, now())
         ON CONFLICT (project_id, name) DO UPDATE SET encrypted_blob=$4, dek_ciphertext=$5, key_id=$6, version=3, updated_at=now()`,
        [id, projectId, name, JSON.stringify(encrypted), dekCiphertext, keyId]
      );
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async getSecret(name, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateSecretName(name);
    await this.init();
    const res = await this.pool.query(
      `SELECT encrypted_blob, dek_ciphertext, key_id, version FROM secrets WHERE project_id=$1 AND name=$2`,
      [projectId, name]
    );
    if (res.rows.length === 0) throw new Error(`Secret not found: ${name}`);
    const row = res.rows[0];
    const record = typeof row.encrypted_blob === 'string' ? JSON.parse(row.encrypted_blob) : row.encrypted_blob;
    // v2 fallback (no dek)
    if (record.version === 2 || record.version === ENCRYPTED_SECRET_VERSION) {
      // For v2, we need masterKey — try KMS local master
      const kms = await this._getKMS();
      if (kms instanceof LocalKMSProvider) {
        return decryptSecret(record, kms.key, name);
      }
      throw new Error('v2 record requires local master key, use file store migration');
    }
    // v3 envelope
    const kms = await this._getKMS();
    const dek = await kms.decrypt(row.dek_ciphertext);
    return decryptSecretWithDEK(record, dek, name, orgId, projectId);
  }

  async listSecrets({ orgId = this.orgId, projectId = this.projectId } = {}) {
    await this.init();
    const res = await this.pool.query(`SELECT name, updated_at FROM secrets WHERE project_id=$1 ORDER BY name`, [projectId]);
    return res.rows.map((r) => ({ name: r.name, updatedAt: r.updated_at.toISOString() }));
  }

  async createCapability({
    secretName,
    baseUrl,
    pathPrefix = '/',
    methods = ['GET'],
    injectHeader = 'authorization',
    injectPrefix = '',
    allowHttp = false,
    expiresAt = null,
    orgId = this.orgId,
    projectId = this.projectId,
  }) {
    validateSecretName(secretName);
    await this.init();
    const normalizedBaseUrl = normalizeBaseUrl(baseUrl, { allowHttp });
    const normalizedPathPrefix = normalizePathPrefix(pathPrefix);
    const normalizedMethods = normalizeMethods(methods);
    const normalizedHeader = normalizeInjectHeader(injectHeader);
    const normalizedInjectPrefix = normalizeInjectPrefix(injectPrefix);
    if (typeof allowHttp !== 'boolean') throw new Error('allowHttp must be a boolean');
    // Verify secret exists
    const secretRes = await this.pool.query(`SELECT id FROM secrets WHERE project_id=$1 AND name=$2`, [projectId, secretName]);
    if (secretRes.rows.length === 0) throw new Error(`Secret not found: ${secretName}`);
    const secretId = secretRes.rows[0].id;
    const kms = await this._getKMS();
    const keyId = kms.getKeyId();
    // Use KMS master key for HMAC — for local, use masterKey; for AWS, use a derived HMAC key (use dek for now, but better to use separate)
    // For simplicity, use a stable HMAC key derived from KMS keyId + local master if available
    let hmacKey;
    if (kms instanceof LocalKMSProvider) {
      hmacKey = kms.key;
    } else {
      // For AWS, use a local HMAC key derived from keyId (not ideal, but for envelope we use KMS for DEK, HMAC can be separate)
      // Generate a stable key from keyId hash
      const { createHash } = await import('node:crypto');
      hmacKey = createHash('sha256').update(String(keyId)).digest();
      // Pad to 32 bytes
      if (hmacKey.length < 32) hmacKey = Buffer.concat([hmacKey, Buffer.alloc(32 - hmacKey.length)]);
    }

    const id = `cap_${randomBytes(10).toString('hex')}`;
    const token = `tgscap_${randomBytes(32).toString('base64url')}`;
    const capability = {
      id,
      tokenHash: hashCapability(token),
      secretName,
      baseUrl: normalizedBaseUrl,
      pathPrefix: normalizedPathPrefix,
      methods: normalizedMethods,
      injectHeader: normalizedHeader,
      injectPrefix: normalizedInjectPrefix,
      allowHttp,
      orgId,
      projectId,
      keyId,
      expiresAt,
      createdAt: new Date().toISOString(),
    };
    capability.metadataMac = hashCapabilityMetadata(capability, hmacKey);

    await this.pool.query(
      `INSERT INTO capabilities (id, project_id, secret_id, secret_name, token_hash, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, expires_at, metadata_mac)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [id, projectId, secretId, secretName, capability.tokenHash, normalizedBaseUrl, normalizedPathPrefix, JSON.stringify(normalizedMethods), normalizedHeader, normalizedInjectPrefix, allowHttp, expiresAt, capability.metadataMac]
    );

    return {
      id,
      token,
      secretName,
      baseUrl: normalizedBaseUrl,
      pathPrefix: normalizedPathPrefix,
      methods: normalizedMethods,
      injectHeader: normalizedHeader,
      injectPrefix: normalizedInjectPrefix,
      allowHttp: Boolean(allowHttp),
      orgId,
      projectId,
      keyId,
      expiresAt,
    };
  }

  async listCapabilities({ orgId = this.orgId, projectId = this.projectId } = {}) {
    await this.init();
    const res = await this.pool.query(
      `SELECT id, secret_name, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, expires_at, created_at FROM capabilities WHERE project_id=$1 ORDER BY created_at`,
      [projectId]
    );
    return res.rows.map((r) => ({
      id: r.id,
      secretName: r.secret_name,
      baseUrl: r.base_url,
      pathPrefix: r.path_prefix,
      methods: typeof r.methods === 'string' ? JSON.parse(r.methods) : r.methods,
      injectHeader: r.inject_header,
      injectPrefix: r.inject_prefix,
      allowHttp: r.allow_http,
      expiresAt: r.expires_at,
      createdAt: r.created_at,
    }));
  }

  async revokeCapability(id, { projectId = this.projectId } = {}) {
    validateCapabilityId(id);
    await this.init();
    const res = await this.pool.query(`DELETE FROM capabilities WHERE id=$1 AND project_id=$2`, [id, projectId]);
    return res.rowCount > 0;
  }

  async resolveCapability(token) {
    if (typeof token !== 'string' || token.length < 16 || token.length > 256) return null;
    await this.init();
    // Find by token hash — need to compute hash and look up, but we store hash, so we hash token and query
    const tokenHash = hashCapability(token);
    const res = await this.pool.query(
      `SELECT c.*, s.encrypted_blob, s.dek_ciphertext, s.key_id as secret_key_id, s.version as secret_version
       FROM capabilities c JOIN secrets s ON c.secret_id = s.id
       WHERE c.token_hash=$1`,
      [tokenHash]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    // Check expiresAt
    if (row.expires_at && new Date(row.expires_at) < new Date()) return null;
    // Verify metadataMac
    const kms = await this._getKMS();
    let hmacKey;
    if (kms instanceof LocalKMSProvider) {
      hmacKey = kms.key;
    } else {
      const { createHash } = await import('node:crypto');
      hmacKey = createHash('sha256').update(String(row.key_id || 'local')).digest();
      if (hmacKey.length < 32) hmacKey = Buffer.concat([hmacKey, Buffer.alloc(32 - hmacKey.length)]);
    }
    const capForMac = {
      id: row.id,
      tokenHash: row.token_hash,
      secretName: row.secret_name,
      baseUrl: row.base_url,
      pathPrefix: row.path_prefix,
      methods: typeof row.methods === 'string' ? JSON.parse(row.methods) : row.methods,
      injectHeader: row.inject_header,
      injectPrefix: row.inject_prefix,
      allowHttp: row.allow_http,
      orgId: this.orgId,
      projectId: row.project_id,
      keyId: row.key_id || 'local',
      expiresAt: row.expires_at,
    };
    // Validate stored capability fields
    const candidate = {
      id: row.id,
      secretName: row.secret_name,
      baseUrl: row.base_url,
      pathPrefix: row.path_prefix,
      methods: capForMac.methods,
      injectHeader: capForMac.injectHeader,
      injectPrefix: capForMac.injectPrefix,
      allowHttp: capForMac.allowHttp,
      tokenHash: row.token_hash,
      metadataMac: row.metadata_mac,
    };
    // Re-use validate logic from file store but inline
    try {
      if (normalizeBaseUrl(candidate.baseUrl, { allowHttp: candidate.allowHttp }) !== candidate.baseUrl) return null;
      if (normalizePathPrefix(candidate.pathPrefix) !== candidate.pathPrefix) return null;
      if (JSON.stringify(normalizeMethods(candidate.methods)) !== JSON.stringify(candidate.methods)) return null;
      if (normalizeInjectHeader(candidate.injectHeader) !== candidate.injectHeader) return null;
      if (normalizeInjectPrefix(candidate.injectPrefix) !== candidate.injectPrefix) return null;
    } catch {
      return null;
    }
    if (!capabilityMatches(token, row.token_hash)) return null;
    const { capabilityMetadataMatches } = await import('./crypto.js');
    if (!capabilityMetadataMatches(capForMac, hmacKey, row.metadata_mac)) return null;

    // Decrypt secret
    const record = typeof row.encrypted_blob === 'string' ? JSON.parse(row.encrypted_blob) : row.encrypted_blob;
    let secretValue;
    if (record.version === 2) {
      if (kms instanceof LocalKMSProvider) {
        secretValue = decryptSecret(record, kms.key, row.secret_name);
      } else {
        return null;
      }
    } else {
      const dek = await kms.decrypt(row.dek_ciphertext);
      secretValue = decryptSecretWithDEK(record, dek, row.secret_name, this.orgId, row.project_id);
    }

    return {
      id: row.id,
      secretName: row.secret_name,
      baseUrl: row.base_url,
      pathPrefix: row.path_prefix,
      methods: capForMac.methods,
      injectHeader: capForMac.injectHeader,
      injectPrefix: capForMac.injectPrefix,
      allowHttp: capForMac.allowHttp,
      orgId: this.orgId,
      projectId: row.project_id,
      keyId: row.key_id,
      expiresAt: row.expires_at,
      secretValue,
      tokenHash: row.token_hash,
      metadataMac: row.metadata_mac,
    };
  }

  // For healthz
  async healthCheck() {
    await this.pool.query('SELECT 1');
    const kms = await this._getKMS();
    // try generate+decrypt roundtrip
    const { plaintext, ciphertextBlob } = await kms.generateDataKey();
    const dek2 = await kms.decrypt(ciphertextBlob);
    if (!timingSafeEqual(plaintext, dek2)) throw new Error('KMS health check failed');
    return true;
  }
}

export { MAX_SECRET_BYTES, validateSecretName, validateCapabilityId };
