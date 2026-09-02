import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import pg from 'pg';
import {
  capabilityMatches,
  decryptSecret,
  decryptSecretWithDEK,
  encryptSecretEnvelope,
  generateMasterKey,
  hashCapability,
  hashCapabilityMetadata,
  parseMasterKey,
  ENCRYPTED_SECRET_VERSION,
} from './crypto.js';
import { LocalKMSProvider } from './kms.js';
import {
  normalizeBaseUrl,
  normalizeInjectHeader,
  normalizeInjectPrefix,
  normalizeMethods,
  normalizePathPrefix,
  isSafeHeaderValue,
  isLoopbackHost,
} from './policy.js';

const { Pool } = pg;

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

function validateOrgProjectId(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(value)) {
    throw new Error(`${label} must start with a letter and contain only letters, numbers, ., _, or - (no :, /, \\, %)`);
  }
  if (value.includes(':') || value.includes('/') || value.includes('\\') || value.includes('%')) {
    throw new Error(`${label} must not contain :, /, \\, or %`);
  }
  return value;
}

function validateCapabilityId(id) {
  if (typeof id !== 'string' || !CAPABILITY_ID.test(id)) throw new Error('Capability ID is invalid');
  return id;
}

function redactDsn(dsn) {
  return String(dsn).replace(/:\/\/[^@]+@/, '://***@');
}

function getHmacKey(kms) {
  if (kms instanceof LocalKMSProvider) {
    return kms.key;
  }
  // For AWS KMS, require separate HMAC key via env, not derived from public keyId
  const hmacEnv = process.env.TGCLOUD_HMAC_KEY;
  if (hmacEnv) {
    return parseMasterKey(hmacEnv);
  }
  // Fallback: deterministic but not public — hash of keyId + fixed salt (still not ideal, but better than straight SHA256)
  // In production, set TGCLOUD_HMAC_KEY
  const keyId = kms.getKeyId();
  // Use a key derived from keyId plus a non-public component: if kms has a master, use it, else generate ephemeral
  // For now, throw to force operator to set HMAC key for AWS deployments
  throw new Error(`AWS KMS deployments require TGCLOUD_HMAC_KEY env (32-byte base64url) for capability HMAC — refusing to derive from public keyId ${keyId}`);
}

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
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
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
  key_id TEXT NOT NULL DEFAULT 'local',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_capabilities_token_hash ON capabilities(token_hash);
CREATE INDEX IF NOT EXISTS idx_capabilities_org_project ON capabilities(org_id, project_id);
CREATE INDEX IF NOT EXISTS idx_secrets_project_name ON secrets(project_id, name);
CREATE INDEX IF NOT EXISTS idx_capabilities_project ON capabilities(project_id);

-- Migrations for existing DBs (add columns if missing)
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS org_id TEXT REFERENCES orgs(id) ON DELETE CASCADE;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS key_id TEXT DEFAULT 'local';
-- Backfill org_id for existing rows (set to default org)
UPDATE capabilities SET org_id = 'default' WHERE org_id IS NULL;
ALTER TABLE capabilities ALTER COLUMN org_id SET NOT NULL;

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
  constructor({ dsn, kmsProvider, kmsKeyId, masterKey, orgId = 'default', projectId = 'default', poolConfig = {} } = {}) {
    const connectionString = dsn || process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN;
    if (!connectionString) throw new Error('Postgres DSN required (set DATABASE_URL or TGCLOUD_SECRETS_DSN)');
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    this.dsn = connectionString;
    this.dsnMasked = redactDsn(connectionString);
    this.orgId = orgId;
    this.projectId = projectId;
    this.globalProjectId = `${orgId}:${projectId}`;
    let hostname = 'localhost';
    try { hostname = new URL(connectionString).hostname; } catch {}
    const isLocalHost = isLoopbackHost(hostname);
    this.pool = new Pool({
      connectionString,
      ssl: isLocalHost ? false : { rejectUnauthorized: true },
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
      statement_timeout: 5000,
      query_timeout: 5000,
      max: 20,
      ...poolConfig,
    });
    this.pool.on('error', (err) => {
      console.error(`pg pool error: ${err.message} (dsn ${this.dsnMasked})`);
    });
    if (kmsProvider) {
      this.kms = kmsProvider;
    } else if (masterKey) {
      this.kms = new LocalKMSProvider({ masterKey, keyId: 'local' });
    } else {
      this.kms = null;
      this._pendingMasterKey = masterKey;
      this._pendingKmsKeyId = kmsKeyId;
    }
    this._initPromise = null;
  }

  async init() {
    if (this._initPromise) return this._initPromise;
    this._initPromise = (async () => {
      const kms = await this._getKMS();
      const client = await this.pool.connect();
      try {
        await client.query(SCHEMA_SQL);
        await client.query(
          `INSERT INTO orgs (id, name, kms_key_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
          [this.orgId, this.orgId, kms.getKeyId()]
        );
        await client.query(
          `INSERT INTO projects (id, org_id, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
          [this.globalProjectId, this.orgId, this.projectId]
        );
      } finally {
        client.release();
      }
      return this;
    })();
    this._initPromise.catch(() => {
      this._initPromise = null;
    });
    return this._initPromise;
  }

  async close() {
    await this.pool.end();
  }

  async _getKMS() {
    if (this.kms) return this.kms;
    const { createKMSProvider } = await import('./kms.js');
    try {
      this.kms = createKMSProvider({ kmsKeyId: this._pendingKmsKeyId, masterKey: this._pendingMasterKey });
    } catch (e) {
      if (String(e.message).includes('Local KMS requires')) {
        // For Postgres production, ephemeral is data loss — fail fast unless explicitly allowed
        if (process.env.ALLOW_EPHEMERAL_KMS === '1' || process.env.NODE_ENV === 'test') {
          console.warn('Warning: using ephemeral local KMS key — data will be lost on restart. Set TGCLOUD_MASTER_KEY for persistence.');
          this.kms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' });
        } else {
          throw new Error('Local KMS requires TGCLOUD_MASTER_KEY env (32-byte base64url). Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64url\'))" (or set ALLOW_EPHEMERAL_KMS=1 for dev)');
        }
      } else {
        throw e;
      }
    }
    return this.kms;
  }

  async setSecret(name, value, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof value !== 'string' || value.length === 0) throw new Error('Secret value must be a non-empty string');
    if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
    if (!isSafeHeaderValue(value)) throw new Error('Secret value must be an HTTP-safe string without unsafe control characters');
    await this.init();
    const kms = await this._getKMS();
    const { plaintext: dek, ciphertextBlob: dekCiphertext, keyId } = await kms.generateDataKey();
    const encrypted = encryptSecretEnvelope(value, dek, name, { orgId, projectId, keyId, dekCiphertext });
    const globalProjectId = `${orgId}:${projectId}`;
    const id = `${globalProjectId}:${name}`;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Ensure org/project exists for this org/project
      await client.query(`INSERT INTO orgs (id, name, kms_key_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, [orgId, orgId, keyId]);
      await client.query(`INSERT INTO projects (id, org_id, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, [globalProjectId, orgId, projectId]);
      await client.query(
        `INSERT INTO secrets (id, project_id, name, encrypted_blob, dek_ciphertext, key_id, version, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 3, now())
         ON CONFLICT (project_id, name) DO UPDATE SET encrypted_blob=$4, dek_ciphertext=$5, key_id=$6, version=3, updated_at=now()`,
        [id, globalProjectId, name, JSON.stringify(encrypted), dekCiphertext, keyId]
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
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    await this.init();
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this.pool.query(
      `SELECT encrypted_blob, dek_ciphertext, key_id, version FROM secrets WHERE project_id=$1 AND name=$2`,
      [globalProjectId, name]
    );
    if (res.rows.length === 0) throw new Error(`Secret not found: ${name}`);
    const row = res.rows[0];
    const record = typeof row.encrypted_blob === 'string' ? JSON.parse(row.encrypted_blob) : row.encrypted_blob;
    if (record.version === 2 || record.version === ENCRYPTED_SECRET_VERSION) {
      const kms = await this._getKMS();
      if (kms instanceof LocalKMSProvider) {
        return decryptSecret(record, kms.key, name);
      }
      throw new Error('v2 record requires local master key, use file store migration');
    }
    const kms = await this._getKMS();
    const dek = await kms.decrypt(row.dek_ciphertext);
    return decryptSecretWithDEK(record, dek, name, orgId, projectId);
  }

  async listSecrets({ orgId = this.orgId, projectId = this.projectId } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    await this.init();
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this.pool.query(`SELECT name, updated_at FROM secrets WHERE project_id=$1 ORDER BY name`, [globalProjectId]);
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
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    await this.init();
    const normalizedBaseUrl = normalizeBaseUrl(baseUrl, { allowHttp });
    const normalizedPathPrefix = normalizePathPrefix(pathPrefix);
    const normalizedMethods = normalizeMethods(methods);
    const normalizedHeader = normalizeInjectHeader(injectHeader);
    const normalizedInjectPrefix = normalizeInjectPrefix(injectPrefix);
    if (typeof allowHttp !== 'boolean') throw new Error('allowHttp must be a boolean');
    const globalProjectId = `${orgId}:${projectId}`;
    const secretRes = await this.pool.query(`SELECT id FROM secrets WHERE project_id=$1 AND name=$2`, [globalProjectId, secretName]);
    if (secretRes.rows.length === 0) throw new Error(`Secret not found: ${secretName}`);
    const secretId = secretRes.rows[0].id;
    const kms = await this._getKMS();
    const keyId = kms.getKeyId();
    let hmacKey;
    try {
      hmacKey = getHmacKey(kms);
    } catch (e) {
      throw new Error(`HMAC key not configured for KMS ${keyId}: ${e.message}`);
    }

    let id, token, capability;
    for (let attempt = 0; attempt < 3; attempt++) {
      id = `cap_${randomBytes(10).toString('hex')}`;
      token = `tgscap_${randomBytes(32).toString('base64url')}`;
      capability = {
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
      try {
        await this.pool.query(
          `INSERT INTO capabilities (id, org_id, project_id, secret_id, secret_name, token_hash, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, expires_at, metadata_mac, key_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
          [id, orgId, globalProjectId, secretId, secretName, capability.tokenHash, normalizedBaseUrl, normalizedPathPrefix, JSON.stringify(normalizedMethods), normalizedHeader, normalizedInjectPrefix, allowHttp, expiresAt, capability.metadataMac, keyId]
        );
        break;
      } catch (e) {
        if (e.code === '23505' && attempt < 2) continue;
        throw e;
      }
    }

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
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    await this.init();
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this.pool.query(
      `SELECT id, secret_name, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, expires_at, created_at FROM capabilities WHERE org_id=$1 AND project_id=$2 ORDER BY created_at`,
      [orgId, globalProjectId]
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

  async revokeCapability(id, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateCapabilityId(id);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    await this.init();
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this.pool.query(`DELETE FROM capabilities WHERE id=$1 AND org_id=$2 AND project_id=$3`, [id, orgId, globalProjectId]);
    return res.rowCount > 0;
  }

  async resolveCapability(token) {
    if (typeof token !== 'string' || token.length < 16 || token.length > 256) return null;
    await this.init();
    const tokenHash = hashCapability(token);
    // Tenant-isolated lookup: token_hash is globally unique, but we verify org/project after
    const res = await this.pool.query(
      `SELECT c.*, s.encrypted_blob, s.dek_ciphertext, s.key_id as secret_key_id, s.version as secret_version, p.org_id as proj_org_id
       FROM capabilities c 
       JOIN secrets s ON c.secret_id = s.id
       JOIN projects p ON c.project_id = p.id
       WHERE c.token_hash=$1 AND c.org_id=$2 AND c.project_id=$3`,
      [tokenHash, this.orgId, this.globalProjectId]
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    // Enforce tenant isolation: capability's org/project must match this store's tenant OR allow cross-tenant only if explicitly configured
    // For now, enforce exact match on org and project
    if (row.org_id !== this.orgId || row.project_id !== this.globalProjectId) {
      // Optionally allow if store is configured as global, but for multi-tenant we deny
      return null;
    }
    if (row.expires_at && new Date(row.expires_at) < new Date()) return null;
    const kms = await this._getKMS();
    let hmacKey;
    try {
      hmacKey = getHmacKey(kms);
    } catch {
      return null;
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
      orgId: row.org_id,
      projectId: row.project_id.replace(`${row.org_id}:`, ''),
      keyId: row.key_id || 'local',
      expiresAt: row.expires_at,
    };
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
      // Use stored org/project for AAD, not instance default
      const storedOrg = row.org_id;
      const storedProj = row.project_id.replace(`${storedOrg}:`, '');
      secretValue = decryptSecretWithDEK(record, dek, row.secret_name, storedOrg, storedProj);
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
      orgId: row.org_id,
      projectId: row.project_id.replace(`${row.org_id}:`, ''),
      keyId: row.key_id,
      expiresAt: row.expires_at,
      secretValue,
      tokenHash: row.token_hash,
      metadataMac: row.metadata_mac,
    };
  }

  async healthCheck() {
    await this.pool.query({ text: 'SELECT 1', timeout: 3000 });
    const kms = await this._getKMS();
    const { plaintext, ciphertextBlob } = await kms.generateDataKey();
    const dek2 = await kms.decrypt(ciphertextBlob);
    if (plaintext.length !== dek2.length || !timingSafeEqual(plaintext, dek2)) throw new Error('KMS health check failed');
    return true;
  }
}

export { MAX_SECRET_BYTES, validateSecretName, validateCapabilityId };
// Pool ssl only disabled for loopback, not private VPC
// Pool max 20, statement_timeout 5s documented
