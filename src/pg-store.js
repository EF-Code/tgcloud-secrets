import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import pg from 'pg';
import {
  capabilityMatches,
  decryptSecret,
  decryptSecretWithDEK,
  encryptSecretWithDEK,
  encryptSecretEnvelope,
  generateMasterKey,
  hashCapability,
  hashCapabilityMetadata,
  ENCRYPTED_SECRET_VERSION,
} from './crypto.js';
import { LocalKMSProvider } from './kms.js';
import { assertSchemaReady, CURRENT_SCHEMA_VERSION } from './migrations.js';
import { hmacKeyRingForProvider } from './hmac.js';
import { createRedactingLogger } from './observability.js';
import { sanitizeAuditPayload } from './audit.js';
import { parseStrictJson } from './json.js';
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
const DEFAULT_CAPABILITY_LIFETIME_MS = 90 * 24 * 60 * 60 * 1_000;
const MAX_CAPABILITY_LIFETIME_MS = 365 * 24 * 60 * 60 * 1_000;

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

function validKmsKeyId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 512
    && value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value) && value !== 'unknown';
}

function assertKmsKeyId(value, label = 'KMS key id') {
  if (!validKmsKeyId(value)) throw new Error(`${label} is invalid`);
  return value;
}

function kmsEncryptionContext(orgId, projectId, secretName) {
  return {
    application: 'tgcloud-secrets',
    org_id: orgId,
    project_id: projectId,
    secret_name: secretName,
  };
}

function idempotencyEncryptionContext(orgId, projectId, idempotencyKey) {
  return kmsEncryptionContext(orgId, projectId, `idempotency/${idempotencyKey}`);
}

function getHmacKeyRing(kms) {
  try {
    return hmacKeyRingForProvider(kms);
  } catch (error) {
    const keyId = kms?.getKeyId?.() || 'unknown';
    throw new Error(`HMAC key ring is not configured for KMS ${keyId}: ${error.message}`);
  }
}

function normalizeCapabilityExpiry(expiresAt, { production = false, now = Date.now(), maxLifetimeMs = DEFAULT_CAPABILITY_LIFETIME_MS } = {}) {
  if (expiresAt === null || expiresAt === undefined || expiresAt === '') {
    if (!production) return null;
    return new Date(now + maxLifetimeMs).toISOString();
  }
  const date = new Date(expiresAt);
  if (Number.isNaN(date.getTime())) throw new Error('expiresAt must be a valid ISO8601 timestamp');
  if (date.getTime() <= now) throw new Error('expiresAt must be in the future');
  if (date.getTime() - now > maxLifetimeMs) throw new Error(`expiresAt must be no more than ${Math.ceil(maxLifetimeMs / 86_400_000)} days in the future`);
  return date.toISOString();
}

function tenantDisabledError() {
  return Object.assign(new Error('Tenant is disabled'), { code: 'TGCLOUD_TENANT_DISABLED', statusCode: 423, publicCode: 'tenant_disabled' });
}

const LIFECYCLE_STATES = new Set(['active', 'disabling', 'revoking', 'erasing', 'completed']);
const LIFECYCLE_TRANSITIONS = Object.freeze({
  active: Object.freeze(['disabling']),
  disabling: Object.freeze(['revoking']),
  revoking: Object.freeze(['erasing']),
  erasing: Object.freeze(['completed']),
  completed: Object.freeze([]),
});

function lifecycleError(message, code = 'TGCLOUD_LIFECYCLE_CONFLICT', statusCode = 409) {
  return Object.assign(new Error(message), { code, statusCode });
}

function validateBooleanOption(value, label) {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

function providerKeyId(provider, label = 'KMS key id') {
  if (!provider || typeof provider.getKeyId !== 'function') throw new Error(`${label} provider is invalid`);
  return assertKmsKeyId(provider.getKeyId(), label);
}

function generatedKeyId(generated, expectedKeyId, label) {
  const keyId = generated?.keyId === undefined ? expectedKeyId : generated.keyId;
  assertKmsKeyId(keyId, label);
  if (keyId !== expectedKeyId) throw new Error(`${label} does not match the configured KMS provider`);
  return keyId;
}

function assertEncryptedEnvelopeMetadata(record, expectedKeyId, label = 'Encrypted record') {
  if (!record || typeof record !== 'object' || Array.isArray(record)
    || record.version !== 3 || record.algorithm !== 'aes-256-gcm'
    || record.kmsContextVersion !== 1 || typeof record.keyId !== 'string'
    || typeof record.dekCiphertext !== 'string' || record.dekCiphertext.length === 0 || record.dekCiphertext.length > 16 * 1024
    || /[\u0000-\u001f\u007f]/.test(record.dekCiphertext)) {
    throw new Error(`${label} metadata is invalid`);
  }
  assertKmsKeyId(record.keyId, `${label} key id`);
  if (record.keyId !== expectedKeyId) throw new Error(`${label} key id does not match the configured KMS provider`);
  return record;
}

function assertStoredRecordKey(record, rowKeyId, expectedKeyId, rowDekCiphertext, label = 'Encrypted record') {
  assertEncryptedEnvelopeMetadata(record, expectedKeyId, label);
  if (rowKeyId !== expectedKeyId) throw new Error(`${label} database key id does not match the configured KMS provider`);
  if (rowDekCiphertext !== record.dekCiphertext) throw new Error(`${label} database DEK ciphertext does not match the encrypted envelope`);
  return record;
}

function recordEncryptionContext(record, orgId, projectId, secretName) {
  if (!record || record.version !== 3 || record.kmsContextVersion !== 1) {
    throw new Error('Unsupported KMS encryption context version');
  }
  return { encryptionContext: kmsEncryptionContext(orgId, projectId, secretName) };
}

function parseDatabaseJson(value, label = 'Database JSON') {
  if (typeof value !== 'string') return value;
  try {
    return parseStrictJson(value, {
      maxBytes: 64 * 1024,
      maxDepth: 8,
      maxFields: 128,
      maxArrayItems: 128,
      maxStringBytes: 32 * 1024,
    });
  } catch (error) {
    throw new Error(`${label} is invalid`, { cause: error });
  }
}

function serializeAuditPayload(value) {
  const serialized = JSON.stringify(sanitizeAuditPayload(value));
  if (Buffer.byteLength(serialized, 'utf8') > 32 * 1024) throw new Error('Audit payload is too large');
  return serialized;
}

function assertProductionPgStoreConfig(connectionString, usesLocalKms) {
  if (usesLocalKms) {
    throw new Error('Production PgStore requires a managed KMS key; local KMS is development-only');
  }
  let parsed;
  try {
    parsed = new URL(connectionString);
  } catch {
    throw new Error('Production PgStore requires a valid postgres:// or postgresql:// DSN');
  }
  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new Error('Production PgStore requires a valid postgres:// or postgresql:// DSN');
  }
  if (!parsed.hostname || isLoopbackHost(parsed.hostname)) {
    throw new Error('Production PgStore requires a managed/private Postgres endpoint, not loopback or a local socket');
  }
  const sslModes = parsed.searchParams.getAll('sslmode');
  if (sslModes.length !== 1 || !['verify-ca', 'verify-full'].includes(sslModes[0])) {
    throw new Error('Production PgStore requires database sslmode=verify-ca or sslmode=verify-full');
  }
  let username;
  let password;
  try {
    username = decodeURIComponent(parsed.username);
    password = decodeURIComponent(parsed.password);
  } catch {
    throw new Error('Production PgStore DSN credentials are malformed');
  }
  if (username === 'postgres' && password === 'postgres') {
    throw new Error('Default Postgres credentials are not allowed in production');
  }
}

export class PgStore {
  constructor({ dsn, kmsProvider, kmsKeyId, masterKey, orgId = 'default', projectId = 'default', poolConfig = {}, maxCapabilityLifetimeMs = DEFAULT_CAPABILITY_LIFETIME_MS, autoProvisionTenant = (process.env.TGCLOUD_ENV !== 'production' && process.env.NODE_ENV !== 'production') } = {}) {
    const connectionString = dsn !== undefined && dsn !== null
      ? dsn
      : (process.env.DATABASE_URL !== undefined
        ? process.env.DATABASE_URL
        : process.env.TGCLOUD_SECRETS_DSN);
    if (connectionString === undefined || connectionString === null || connectionString === '') throw new Error('Postgres DSN required (set DATABASE_URL or TGCLOUD_SECRETS_DSN)');
    const configuredKmsKeyId = kmsKeyId !== undefined && kmsKeyId !== null
      ? kmsKeyId
      : (process.env.TGCLOUD_KMS_KEY_ID !== undefined
        ? process.env.TGCLOUD_KMS_KEY_ID
        : (process.env.AWS_KMS_KEY_ID !== undefined ? process.env.AWS_KMS_KEY_ID : null));
    let selectedKmsKeyId = configuredKmsKeyId === null ? 'local' : configuredKmsKeyId;
    if (kmsProvider) {
      if (typeof kmsProvider.generateDataKey !== 'function' || typeof kmsProvider.decrypt !== 'function' || typeof kmsProvider.getKeyId !== 'function') {
        throw new Error('kmsProvider must implement getKeyId(), generateDataKey(), and decrypt()');
      }
      const providerId = kmsProvider.getKeyId();
      assertKmsKeyId(providerId, 'kmsProvider returned an invalid key id');
      if (configuredKmsKeyId === null) selectedKmsKeyId = providerId;
      if (selectedKmsKeyId !== providerId) {
        throw new Error('Configured KMS key id does not match the supplied KMS provider');
      }
    }
    assertKmsKeyId(selectedKmsKeyId);
    const selectedLocalKms = kmsProvider instanceof LocalKMSProvider
      || selectedKmsKeyId === 'local' || selectedKmsKeyId.startsWith('local:');
    if (masterKey && !selectedLocalKms) {
      throw new Error('A local master key cannot be combined with a managed KMS key');
    }
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    this.dsn = connectionString;
    this.dsnMasked = redactDsn(connectionString);
    this.orgId = orgId;
    this.projectId = projectId;
    this.globalProjectId = `${orgId}:${projectId}`;
    if (!Number.isSafeInteger(maxCapabilityLifetimeMs) || maxCapabilityLifetimeMs <= 0 || maxCapabilityLifetimeMs > MAX_CAPABILITY_LIFETIME_MS) {
      throw new Error(`maxCapabilityLifetimeMs must be a positive integer no greater than ${MAX_CAPABILITY_LIFETIME_MS}`);
    }
    this.maxCapabilityLifetimeMs = maxCapabilityLifetimeMs;
    if (typeof autoProvisionTenant !== 'boolean') throw new Error('autoProvisionTenant must be a boolean');
    const production = process.env.TGCLOUD_ENV === 'production' || process.env.NODE_ENV === 'production';
    if (production && autoProvisionTenant) throw new Error('Production PgStore cannot auto-provision tenant rows; use the approved provisioning workflow');
    if (production) assertProductionPgStoreConfig(connectionString, selectedLocalKms);
    this.autoProvisionTenant = autoProvisionTenant;
    let hostname = 'localhost';
    try { hostname = new URL(connectionString).hostname; } catch {}
    const isLocalHost = isLoopbackHost(hostname);
    const poolMax = poolConfig.max === undefined ? 20 : poolConfig.max;
    if (!Number.isSafeInteger(poolMax) || poolMax < 1 || poolMax > 100) throw new Error('poolConfig.max must be between 1 and 100');
    this.pool = new Pool({
      ...poolConfig,
      connectionString,
      ssl: isLocalHost ? false : { rejectUnauthorized: true },
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
      statement_timeout: 5000,
      query_timeout: 5000,
      max: poolMax,
    });
    const safeLogger = createRedactingLogger(console);
    this.pool.on('error', (err) => {
      safeLogger.error('pg pool error', { errorName: err.name || 'Error', dsn: this.dsnMasked });
    });
    if (kmsProvider) {
      this.kms = kmsProvider;
    } else if (masterKey && selectedLocalKms) {
      this.kms = new LocalKMSProvider({ masterKey, keyId: selectedKmsKeyId });
    } else {
      this.kms = null;
      this._pendingMasterKey = selectedLocalKms ? masterKey : undefined;
      this._pendingKmsKeyId = selectedKmsKeyId;
    }
    this._initPromise = null;
    this._closePromise = null;
  }

  async init() {
    if (this._initPromise) return this._initPromise;
    this._initPromise = (async () => {
      const kms = await this._getKMS();
      const client = await this.pool.connect();
      try {
        await assertSchemaReady(client, CURRENT_SCHEMA_VERSION);
        await client.query('BEGIN');
        await this._setTenantContext(client, this.orgId, this.globalProjectId);
        if (this.autoProvisionTenant) {
          await client.query(
            `INSERT INTO orgs (id, name, kms_key_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
            [this.orgId, this.orgId, kms.getKeyId()]
          );
          await client.query(
            `INSERT INTO projects (id, org_id, name, kms_key_id) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`,
            [this.globalProjectId, this.orgId, this.projectId, providerKeyId(kms)]
          );
        }
        const tenant = await client.query(
          `SELECT p.kms_key_id
           FROM projects p JOIN orgs o ON o.id=p.org_id
           WHERE p.id=$1 AND p.org_id=$2`,
          [this.globalProjectId, this.orgId],
        );
        if (tenant.rows.length !== 1) {
          throw new Error(this.autoProvisionTenant
            ? 'Provisioned tenant could not be established'
            : 'Production tenant is not provisioned; create it through the authenticated control plane or migration operator');
        }
        if (tenant.rows[0].kms_key_id !== providerKeyId(kms)) {
          throw new Error('Configured KMS key does not match the provisioned tenant key for this project; run the approved key rotation workflow');
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
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

  close() {
    if (!this._closePromise) this._closePromise = this.pool.end();
    return this._closePromise;
  }

  async _setTenantContext(client, orgId = this.orgId, globalProjectId = this.globalProjectId) {
    await client.query(
      `SELECT set_config('app.org_id', $1, true), set_config('app.project_id', $2, true)`,
      [orgId, globalProjectId],
    );
  }

  async _assertTenantKmsKeyInClient(client, orgId, projectId) {
    const tenant = await client.query(
      `SELECT kms_key_id FROM projects WHERE org_id=$1 AND id=$2`,
      [orgId, projectId],
    );
    if (tenant.rows.length !== 1) {
      throw new Error('Tenant project is not provisioned');
    }
    const kms = await this._getKMS();
    if (tenant.rows[0].kms_key_id !== providerKeyId(kms)) {
      throw new Error('Configured KMS key does not match the provisioned tenant key for this project; run the approved key rotation workflow');
    }
  }

  async _assertProjectActiveInClient(client, orgId, projectId) {
    const result = await client.query(
       `SELECT o.lifecycle_state AS org_state, o.disabled_at AS org_disabled_at,
              p.lifecycle_state AS project_state, p.disabled_at AS project_disabled_at
       FROM projects p JOIN orgs o ON o.id=p.org_id
       WHERE p.org_id=$1 AND p.id=$2
         AND NOT EXISTS (
           SELECT 1 FROM tenant_revocations tr
           WHERE tr.org_id=$1 AND tr.active
             AND (tr.project_id IS NULL OR tr.project_id=$2)
         )`,
      [orgId, projectId],
    );
    const row = result.rows[0];
    if (!row || row.org_state !== 'active' || row.project_state !== 'active' || row.org_disabled_at || row.project_disabled_at) throw tenantDisabledError();
  }

  async _withTenantTransaction(callback, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    await this.init();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Serialize all operations for a logical tenant across replicas. This
      // closes the small commit/switch window during KMS rotation and keeps
      // optimistic writes, revocation, and resolution on one ordering line.
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
        [`tgcloud:tenant:${orgId}:${projectId}`],
      );
      await this._setTenantContext(client, orgId, `${orgId}:${projectId}`);
      await this._assertTenantKmsKeyInClient(client, orgId, `${orgId}:${projectId}`);
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async runIdempotent({ idempotencyKey, requestHash, orgId = this.orgId, projectId = this.projectId, mutation, ttlMs = 24 * 60 * 60 * 1_000 } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9._:-]{8,128}$/.test(idempotencyKey)) throw new Error('Idempotency key is invalid');
    if (typeof requestHash !== 'string' || !/^[a-f0-9]{64}$/.test(requestHash)) throw new Error('Idempotency request hash is invalid');
    if (typeof mutation !== 'function') throw new Error('Idempotency mutation is required');
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 7 * 24 * 60 * 60 * 1_000) throw new Error('Idempotency TTL is invalid');
    const globalProjectId = `${orgId}:${projectId}`;
    return this._withTenantTransaction(async (client) => {
      await client.query(
        `DELETE FROM idempotency_keys
         WHERE org_id=$1 AND project_id=$2 AND idempotency_key=$3 AND expires_at <= now()`,
        [orgId, globalProjectId, idempotencyKey],
      );
      await client.query(
        `INSERT INTO idempotency_keys (org_id, project_id, idempotency_key, request_hash, expires_at)
         VALUES ($1,$2,$3,$4,now() + ($5 * interval '1 millisecond'))
         ON CONFLICT (org_id, project_id, idempotency_key) DO NOTHING`,
        [orgId, globalProjectId, idempotencyKey, requestHash, ttlMs],
      );
      const existing = await client.query(
        `SELECT request_hash, response_envelope, completed_at
         FROM idempotency_keys
         WHERE org_id=$1 AND project_id=$2 AND idempotency_key=$3 FOR UPDATE`,
        [orgId, globalProjectId, idempotencyKey],
      );
      if (existing.rows.length !== 1) throw new Error('Idempotency record could not be established');
      const row = existing.rows[0];
      if (row.request_hash !== requestHash) throw Object.assign(new Error('Idempotency key was reused for a different request'), { code: 'TGCLOUD_IDEMPOTENCY_CONFLICT' });
      if (row.completed_at) {
        if (!row.response_envelope) {
          throw Object.assign(new Error('Legacy idempotency response is unavailable; retry with a new idempotency key'), { code: 'TGCLOUD_IDEMPOTENCY_REPLAY_UNAVAILABLE' });
        }
        const kms = await this._getKMS();
        const expectedKeyId = providerKeyId(kms);
        const envelope = typeof row.response_envelope === 'string'
          ? parseStrictJson(row.response_envelope, { maxBytes: 96 * 1024, maxDepth: 6, maxFields: 32, maxArrayItems: 32, maxStringBytes: 16 * 1024 })
          : row.response_envelope;
        assertEncryptedEnvelopeMetadata(envelope, expectedKeyId, 'Encrypted idempotency envelope');
        const responseName = `idempotency/${idempotencyKey}`;
        const dek = await kms.decrypt(envelope.dekCiphertext, { encryptionContext: idempotencyEncryptionContext(orgId, projectId, idempotencyKey) });
        try {
          return parseStrictJson(decryptSecretWithDEK(envelope, dek, responseName, orgId, projectId), { maxBytes: 64 * 1024, maxDepth: 10, maxFields: 128, maxArrayItems: 128, maxStringBytes: 64 * 1024 });
        } finally {
          dek.fill(0);
        }
      }
      const response = await mutation(client);
      const serialized = JSON.stringify(response);
      if (Buffer.byteLength(serialized, 'utf8') > 64 * 1024) throw new Error('Idempotency response is too large');
      const kms = await this._getKMS();
      const expectedKeyId = providerKeyId(kms);
      const context = idempotencyEncryptionContext(orgId, projectId, idempotencyKey);
      const generated = await kms.generateDataKey({ encryptionContext: context });
      if (!generated.plaintext || generated.plaintext.length !== 32 || typeof generated.ciphertextBlob !== 'string') {
        generated.plaintext?.fill?.(0);
        throw new Error('KMS returned an invalid idempotency DEK');
      }
      let keyId;
      try {
        keyId = generatedKeyId(generated, expectedKeyId, 'KMS returned an invalid key id');
      } catch (error) {
        generated.plaintext.fill(0);
        throw error;
      }
      let responseEnvelope;
      try {
        const encrypted = encryptSecretWithDEK(serialized, generated.plaintext, `idempotency/${idempotencyKey}`, orgId, projectId);
        responseEnvelope = {
          version: 3,
          algorithm: 'aes-256-gcm',
          keyId,
          kmsContextVersion: 1,
          ...encrypted,
          dekCiphertext: generated.ciphertextBlob,
        };
      } finally {
        generated.plaintext.fill(0);
      }
      await client.query(
        `UPDATE idempotency_keys SET response_envelope=$4, completed_at=now()
         WHERE org_id=$1 AND project_id=$2 AND idempotency_key=$3`,
        [orgId, globalProjectId, idempotencyKey, JSON.stringify(responseEnvelope)],
      );
      return response;
    }, { orgId, projectId });
  }

  async _getKMS() {
    if (this.kms) return this.kms;
    const { createKMSProvider } = await import('./kms.js');
    try {
      this.kms = createKMSProvider({ kmsKeyId: this._pendingKmsKeyId, masterKey: this._pendingMasterKey });
    } catch (e) {
      if (String(e.message).includes('Local KMS requires')) {
        // For Postgres production, ephemeral is data loss — fail fast unless explicitly allowed
        const production = process.env.TGCLOUD_ENV === 'production' || process.env.NODE_ENV === 'production';
        if (!production && (process.env.ALLOW_EPHEMERAL_KMS === '1' || process.env.NODE_ENV === 'test')) {
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

  async _setSecretInClient(client, { name, value, orgId, projectId, expectedVersion = null, emitAudit = true, auditActor = 'local-process' } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof value !== 'string' || value.length === 0) throw new Error('Secret value must be a non-empty string');
    if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
    if (!isSafeHeaderValue(value)) throw new Error('Secret value must be an HTTP-safe string without unsafe control characters');
    if (expectedVersion !== null && (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0)) throw new Error('expectedVersion must be a non-negative integer');
    const globalProjectId = `${orgId}:${projectId}`;
    await this._assertProjectActiveInClient(client, orgId, globalProjectId);
    const kms = await this._getKMS();
    const expectedKeyId = providerKeyId(kms);
    const encryptionContext = kmsEncryptionContext(orgId, projectId, name);
    const generated = await kms.generateDataKey({ encryptionContext });
    if (!generated.plaintext || generated.plaintext.length !== 32 || typeof generated.ciphertextBlob !== 'string') {
      generated.plaintext?.fill?.(0);
      throw new Error('KMS GenerateDataKey returned an invalid DEK');
    }
    const { plaintext: dek, ciphertextBlob: dekCiphertext } = generated;
    let keyId;
    try {
      keyId = generatedKeyId(generated, expectedKeyId, 'KMS GenerateDataKey returned an invalid key id');
    } catch (error) {
      dek?.fill?.(0);
      throw error;
    }
    try {
      const encrypted = encryptSecretEnvelope(value, dek, name, { orgId, projectId, keyId, dekCiphertext });
      const id = `${globalProjectId}:${name}`;
      const eventId = randomUUID();
      // Ensure org/project exists for this org/project
      if (this.autoProvisionTenant) {
        await client.query(`INSERT INTO orgs (id, name, kms_key_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, [orgId, orgId, keyId]);
        await client.query(`INSERT INTO projects (id, org_id, name, kms_key_id) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`, [globalProjectId, orgId, projectId, keyId]);
      }
      const existing = await client.query(
        `SELECT id, encrypted_blob, dek_ciphertext, key_id, version, current_version
         FROM secrets WHERE org_id=$1 AND project_id=$2 AND name=$3 FOR UPDATE`,
        [orgId, globalProjectId, name],
      );
      if (existing.rows.length === 0) {
        if (expectedVersion !== null && expectedVersion !== 0) {
          throw Object.assign(new Error('Secret version conflict'), { code: 'TGCLOUD_VERSION_CONFLICT' });
        }
        await client.query(
          `INSERT INTO secrets (id, org_id, project_id, name, encrypted_blob, dek_ciphertext, key_id, version, current_version, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 3, 1, now())`,
          [id, orgId, globalProjectId, name, JSON.stringify(encrypted), dekCiphertext, keyId],
        );
      } else {
        const row = existing.rows[0];
        const currentVersion = Number(row.current_version || 1);
        if (expectedVersion !== null && expectedVersion !== currentVersion) {
          throw Object.assign(new Error('Secret version conflict'), { code: 'TGCLOUD_VERSION_CONFLICT' });
        }
        await client.query(
          `INSERT INTO secret_versions (secret_id, org_id, project_id, name, version, encrypted_blob, dek_ciphertext, key_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (secret_id, version) DO NOTHING`,
          [row.id, orgId, globalProjectId, name, currentVersion, JSON.stringify(row.encrypted_blob), row.dek_ciphertext, row.key_id],
        );
        await client.query(
          `UPDATE secrets
           SET encrypted_blob=$4, dek_ciphertext=$5, key_id=$6, version=3, current_version=$7, updated_at=now()
           WHERE id=$1 AND org_id=$2 AND project_id=$3`,
          [row.id, orgId, globalProjectId, JSON.stringify(encrypted), dekCiphertext, keyId, currentVersion + 1],
        );
      }
      if (emitAudit) {
        await client.query(
          `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
           VALUES ($1,$2,$3,$4,$5)`,
          [eventId, orgId, globalProjectId, 'secret.upsert', serializeAuditPayload({
            eventId,
            eventType: 'secret.upsert',
            actor: auditActor,
            orgId,
            projectId,
            secretName: name,
            expectedVersion,
            createdAt: new Date().toISOString(),
          })],
        );
      }
      return { name, version: existing.rows.length === 0 ? 1 : Number(existing.rows[0].current_version || 1) + 1 };
    } finally {
      dek.fill(0);
    }
  }

  async setSecret(name, value, { orgId = this.orgId, projectId = this.projectId, expectedVersion = null, auditActor = 'local-process' } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof value !== 'string' || value.length === 0) throw new Error('Secret value must be a non-empty string');
    if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
    if (!isSafeHeaderValue(value)) throw new Error('Secret value must be an HTTP-safe string without unsafe control characters');
    if (expectedVersion !== null && (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0)) throw new Error('expectedVersion must be a non-negative integer');
    return this._withTenantTransaction((client) => this._setSecretInClient(client, { name, value, orgId, projectId, expectedVersion, auditActor }), { orgId, projectId });
  }

  async getSecret(name, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this._withTenantTransaction(async (client) => {
      await this._assertProjectActiveInClient(client, orgId, globalProjectId);
      return client.query(
        `SELECT encrypted_blob, dek_ciphertext, key_id, version FROM secrets WHERE org_id=$1 AND project_id=$2 AND name=$3`,
        [orgId, globalProjectId, name],
      );
    }, { orgId, projectId });
    if (res.rows.length === 0) throw new Error(`Secret not found: ${name}`);
    const row = res.rows[0];
    const record = typeof row.encrypted_blob === 'string'
      ? parseStrictJson(row.encrypted_blob, { maxBytes: 96 * 1024, maxDepth: 6, maxFields: 32, maxArrayItems: 32, maxStringBytes: 16 * 1024 })
      : row.encrypted_blob;
    if (record.version === 2 || record.version === ENCRYPTED_SECRET_VERSION) {
      const kms = await this._getKMS();
      if (kms instanceof LocalKMSProvider) {
        return decryptSecret(record, kms.key, name);
      }
      throw new Error('v2 record requires local master key, use file store migration');
    }
    if (record.version !== 3) throw new Error('Unsupported encrypted secret record');
    const kms = await this._getKMS();
    const expectedKeyId = providerKeyId(kms);
    assertStoredRecordKey(record, row.key_id, expectedKeyId, row.dek_ciphertext, 'Encrypted secret record');
    const dek = await kms.decrypt(row.dek_ciphertext, recordEncryptionContext(record, orgId, projectId, name));
    try {
      return decryptSecretWithDEK(record, dek, name, orgId, projectId);
    } finally {
      dek.fill(0);
    }
  }

  async listSecrets({ orgId = this.orgId, projectId = this.projectId } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this._withTenantTransaction(async (client) => {
      await this._assertProjectActiveInClient(client, orgId, globalProjectId);
      return client.query(
        `SELECT name, updated_at FROM secrets WHERE org_id=$1 AND project_id=$2 ORDER BY name`,
        [orgId, globalProjectId],
      );
    }, { orgId, projectId });
    return res.rows.map((r) => ({ name: r.name, updatedAt: r.updated_at.toISOString() }));
  }

  async listSecretVersions(name, { orgId = this.orgId, projectId = this.projectId } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this._withTenantTransaction(async (client) => {
      await this._assertProjectActiveInClient(client, orgId, globalProjectId);
      return client.query(
        `SELECT version, key_id, created_at
         FROM secret_versions WHERE org_id=$1 AND project_id=$2 AND name=$3 ORDER BY version DESC`,
        [orgId, globalProjectId, name],
      );
    }, { orgId, projectId });
    return res.rows.map((row) => ({ version: Number(row.version), keyId: row.key_id, createdAt: row.created_at.toISOString() }));
  }

  async _deleteSecretInClient(client, { name, orgId = this.orgId, projectId = this.projectId, expectedVersion = null, emitAudit = true, auditActor = 'local-process' } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (expectedVersion !== null && (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1)) throw new Error('expectedVersion must be a positive integer');
    const globalProjectId = `${orgId}:${projectId}`;
    await this._assertProjectActiveInClient(client, orgId, globalProjectId);
    const current = await client.query(
      `SELECT id, current_version FROM secrets WHERE org_id=$1 AND project_id=$2 AND name=$3 FOR UPDATE`,
      [orgId, globalProjectId, name],
    );
    if (current.rows.length === 0) return null;
    const currentVersion = Number(current.rows[0].current_version || 1);
    if (expectedVersion !== null && expectedVersion !== currentVersion) throw lifecycleError('Secret version conflict', 'TGCLOUD_VERSION_CONFLICT', 409);
    await client.query(`DELETE FROM secrets WHERE id=$1 AND org_id=$2 AND project_id=$3`, [current.rows[0].id, orgId, globalProjectId]);
    if (emitAudit) {
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [randomUUID(), orgId, globalProjectId, 'secret.delete', serializeAuditPayload({
          eventType: 'secret.delete', actor: auditActor, orgId, projectId, secretName: name,
          previousVersion: currentVersion, createdAt: new Date().toISOString(),
        })],
      );
    }
    return { name, deleted: true };
  }

  async deleteSecret(name, { orgId = this.orgId, projectId = this.projectId, expectedVersion = null, auditActor = 'local-process' } = {}) {
    return this._withTenantTransaction(
      (client) => this._deleteSecretInClient(client, { name, orgId, projectId, expectedVersion, auditActor }),
      { orgId, projectId },
    );
  }

  async getTenantLifecycle({ orgId = this.orgId, projectId = this.projectId, organization = false } = {}) {
    validateBooleanOption(organization, 'organization');
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = `${orgId}:${projectId}`;
    return this._withTenantTransaction(async (client) => {
      const result = await client.query(
        organization
          ? `SELECT lifecycle_state, lifecycle_reason, lifecycle_updated_at, offboarding_completed_at, disabled_at
             FROM orgs WHERE id=$1`
          : `SELECT lifecycle_state, lifecycle_reason, lifecycle_updated_at, offboarding_completed_at, disabled_at
             FROM projects WHERE org_id=$1 AND id=$2`,
        organization ? [orgId] : [orgId, globalProjectId],
      );
      if (result.rows.length !== 1) throw new Error('Tenant not found');
      const row = result.rows[0];
      return {
        orgId,
        projectId: organization ? null : projectId,
        organization,
        state: row.lifecycle_state,
        reason: row.lifecycle_reason,
        updatedAt: row.lifecycle_updated_at?.toISOString?.() || null,
        completedAt: row.offboarding_completed_at?.toISOString?.() || null,
        disabledAt: row.disabled_at?.toISOString?.() || null,
      };
    }, { orgId, projectId });
  }

  async _transitionOffboardingInClient(client, {
    state,
    orgId = this.orgId,
    projectId = this.projectId,
    organization = false,
    reason = 'tenant_offboarding',
    expectedState = null,
    eraseConfirmed = false,
    emitAudit = true,
    auditActor = 'local-process',
  } = {}) {
    validateBooleanOption(organization, 'organization');
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (!LIFECYCLE_STATES.has(state) || state === 'active') throw Object.assign(new Error('Offboarding state is invalid'), { statusCode: 400 });
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) throw Object.assign(new Error('Offboarding reason is invalid'), { statusCode: 400 });
    if (expectedState !== null && !LIFECYCLE_STATES.has(expectedState)) throw Object.assign(new Error('Expected offboarding state is invalid'), { statusCode: 400 });
    if ((state === 'erasing' || state === 'completed') && eraseConfirmed !== true) throw lifecycleError('Explicit erasure confirmation is required', 'TGCLOUD_ERASURE_CONFIRMATION_REQUIRED', 400);
    if (organization && (state === 'erasing' || state === 'completed')) throw Object.assign(new Error('Organization erasure must be executed per project by an approved workflow'), { statusCode: 400 });
    const globalProjectId = `${orgId}:${projectId}`;
      const table = organization ? 'orgs' : 'projects';
      const result = await client.query(
        organization
          ? `SELECT lifecycle_state FROM orgs WHERE id=$1 FOR UPDATE`
          : `SELECT lifecycle_state FROM projects WHERE org_id=$1 AND id=$2 FOR UPDATE`,
        organization ? [orgId] : [orgId, globalProjectId],
      );
      if (result.rows.length !== 1) throw new Error('Tenant not found');
      const currentState = result.rows[0].lifecycle_state;
      if (expectedState !== null && expectedState !== currentState) throw lifecycleError('Offboarding state conflict');
      if (!LIFECYCLE_TRANSITIONS[currentState]?.includes(state)) throw lifecycleError(`Invalid offboarding transition from ${currentState} to ${state}`);
      if (state === 'revoking' || state === 'erasing' || state === 'completed') {
        await this._setTenantRevocationInClient(client, { orgId, projectId, organization, active: true, reason });
      }
      if (!organization && (state === 'erasing' || state === 'completed')) {
        // Retain the project and audit trail, but remove encrypted data and
        // encrypted idempotency responses. KMS key disablement and backup
        // expiry remain explicit external controls.
        await client.query(`DELETE FROM idempotency_keys WHERE org_id=$1 AND project_id=$2`, [orgId, globalProjectId]);
        await client.query(`DELETE FROM secrets WHERE org_id=$1 AND project_id=$2`, [orgId, globalProjectId]);
      }
      const completedAt = state === 'completed' ? 'now()' : 'offboarding_completed_at';
      await client.query(
        `UPDATE ${table}
         SET lifecycle_state=$${organization ? 2 : 3}, lifecycle_reason=$${organization ? 3 : 4},
             lifecycle_updated_at=now(), disabled_at=now(),
             offboarding_completed_at=${completedAt}
         WHERE ${organization ? 'id=$1' : 'org_id=$1 AND id=$2'}`,
        organization
          ? [orgId, state, reason]
          : [orgId, globalProjectId, state, reason],
      );
      if (emitAudit) {
        await client.query(
          `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
           VALUES ($1,$2,$3,$4,$5)`,
          [randomUUID(), orgId, globalProjectId, 'tenant.offboarding', serializeAuditPayload({
            eventType: 'tenant.offboarding', actor: auditActor, orgId, projectId: organization ? null : projectId,
            organization, from: currentState, state, reason, eraseConfirmed,
            createdAt: new Date().toISOString(),
          })],
        );
      }
    return { orgId, projectId: organization ? null : projectId, organization, state, previousState: currentState };
  }

  async transitionOffboarding(options = {}) {
    const orgId = options.orgId ?? this.orgId;
    const projectId = options.projectId ?? this.projectId;
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    validateBooleanOption(options.organization ?? false, 'organization');
    return this._withTenantTransaction(
      (client) => this._transitionOffboardingInClient(client, { ...options, orgId, projectId }),
      { orgId, projectId },
    );
  }

  async _rollbackSecretInClient(client, { name, version, orgId = this.orgId, projectId = this.projectId, expectedVersion = null, emitAudit = true, auditActor = 'local-process' } = {}) {
    validateSecretName(name);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (!Number.isSafeInteger(version) || version <= 0) throw new Error('Secret version must be a positive integer');
    if (expectedVersion !== null && (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0)) throw new Error('expectedVersion must be a non-negative integer');
    const globalProjectId = `${orgId}:${projectId}`;
    await this._assertProjectActiveInClient(client, orgId, globalProjectId);
    const current = await client.query(
        `SELECT id, encrypted_blob, dek_ciphertext, key_id, version, current_version
         FROM secrets WHERE org_id=$1 AND project_id=$2 AND name=$3 FOR UPDATE`,
        [orgId, globalProjectId, name],
    );
    if (current.rows.length === 0) throw new Error(`Secret not found: ${name}`);
    const currentRow = current.rows[0];
    const currentVersion = Number(currentRow.current_version || 1);
    if (expectedVersion !== null && expectedVersion !== currentVersion) throw Object.assign(new Error('Secret version conflict'), { code: 'TGCLOUD_VERSION_CONFLICT' });
    const target = await client.query(
        `SELECT encrypted_blob, dek_ciphertext, key_id, version
         FROM secret_versions WHERE org_id=$1 AND project_id=$2 AND secret_id=$3 AND version=$4`,
        [orgId, globalProjectId, currentRow.id, version],
    );
    if (target.rows.length === 0) throw new Error(`Secret version not found: ${name}@${version}`);
    await client.query(
        `INSERT INTO secret_versions (secret_id, org_id, project_id, name, version, encrypted_blob, dek_ciphertext, key_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (secret_id, version) DO NOTHING`,
        [currentRow.id, orgId, globalProjectId, name, currentVersion, JSON.stringify(currentRow.encrypted_blob), currentRow.dek_ciphertext, currentRow.key_id],
    );
    const replacement = target.rows[0];
    const replacementRecord = parseDatabaseJson(replacement.encrypted_blob, 'Secret version encrypted record');
    const kms = await this._getKMS();
    if (replacementRecord?.version === 3) {
      const expectedKeyId = providerKeyId(kms);
      assertStoredRecordKey(replacementRecord, replacement.key_id, expectedKeyId, replacement.dek_ciphertext, 'Secret version encrypted record');
      const dek = await kms.decrypt(replacement.dek_ciphertext, recordEncryptionContext(replacementRecord, orgId, projectId, name));
      try {
        decryptSecretWithDEK(replacementRecord, dek, name, orgId, projectId);
      } finally {
        dek.fill(0);
      }
    } else if (replacementRecord?.version === 2 && kms instanceof LocalKMSProvider) {
      decryptSecret(replacementRecord, kms.key, name);
    } else {
      throw new Error('Secret version uses an unsupported or non-current KMS format');
    }
    const nextVersion = currentVersion + 1;
    await client.query(
        `UPDATE secrets
         SET encrypted_blob=$2, dek_ciphertext=$3, key_id=$4, version=$5, current_version=$6, updated_at=now()
         WHERE id=$1 AND org_id=$7 AND project_id=$8`,
        [currentRow.id, JSON.stringify(replacementRecord), replacement.dek_ciphertext, replacement.key_id, replacementRecord.version, nextVersion, orgId, globalProjectId],
    );
    if (emitAudit) {
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [randomUUID(), orgId, globalProjectId, 'secret.rollback', serializeAuditPayload({
          eventType: 'secret.rollback',
          actor: auditActor,
          orgId,
          projectId,
          secretName: name,
          restoredVersion: version,
          newVersion: nextVersion,
          expectedVersion,
          createdAt: new Date().toISOString(),
        })],
      );
    }
    return { name, version: nextVersion, restoredVersion: version };
  }

  async rollbackSecret(name, version, { orgId = this.orgId, projectId = this.projectId, expectedVersion = null, auditActor = 'local-process' } = {}) {
    return this._withTenantTransaction(
      (client) => this._rollbackSecretInClient(client, { name, version, orgId, projectId, expectedVersion, auditActor }),
      { orgId, projectId },
    );
  }

  async clearKmsCache() {
    const kms = await this._getKMS();
    kms.clearCache?.();
  }

  async rotateSecrets({ newKmsProvider, orgId = this.orgId, projectId = this.projectId, auditActor = 'local-process' } = {}) {
    if (!newKmsProvider || typeof newKmsProvider.generateDataKey !== 'function' || typeof newKmsProvider.decrypt !== 'function' || typeof newKmsProvider.getKeyId !== 'function') {
      throw new Error('newKmsProvider must implement getKeyId(), generateDataKey(), and decrypt()');
    }
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const oldKms = await this._getKMS();
    const newKeyId = assertKmsKeyId(newKmsProvider.getKeyId(), 'new KMS provider key id');
    const production = process.env.TGCLOUD_ENV === 'production' || process.env.NODE_ENV === 'production';
    if (production && (newKmsProvider instanceof LocalKMSProvider || newKeyId === 'local' || newKeyId.startsWith('local:'))) {
      throw new Error('Production KMS rotation requires a managed KMS provider');
    }
    const newHmacRing = getHmacKeyRing(newKmsProvider);
    const globalProjectId = `${orgId}:${projectId}`;
    let rotated;
    try {
      rotated = await this._withTenantTransaction(async (client) => {
      await this._assertProjectActiveInClient(client, orgId, globalProjectId);
      const current = await client.query(
        `SELECT id, name, encrypted_blob, dek_ciphertext, key_id, version, 'current' AS source
         FROM secrets WHERE org_id=$1 AND project_id=$2`,
        [orgId, globalProjectId],
      );
      const history = await client.query(
        `SELECT id, name, encrypted_blob, dek_ciphertext, key_id, version, 'history' AS source
         FROM secret_versions WHERE org_id=$1 AND project_id=$2`,
        [orgId, globalProjectId],
      );
      let count = 0;
      for (const row of [...current.rows, ...history.rows]) {
        const record = typeof row.encrypted_blob === 'string'
          ? parseStrictJson(row.encrypted_blob, { maxBytes: 96 * 1024, maxDepth: 6, maxFields: 32, maxArrayItems: 32, maxStringBytes: 16 * 1024 })
          : row.encrypted_blob;
        let value;
        let oldDek;
        let newDek;
        try {
          if (record.version === 2) {
            if (!(oldKms instanceof LocalKMSProvider)) throw new Error('Legacy v2 records require local KMS');
            value = decryptSecret(record, oldKms.key, row.name);
          } else {
            const oldKeyId = providerKeyId(oldKms);
            assertStoredRecordKey(record, row.key_id, oldKeyId, row.dek_ciphertext, 'KMS rotation record');
            const context = recordEncryptionContext(record, orgId, projectId, row.name);
            oldDek = await oldKms.decrypt(row.dek_ciphertext, context);
            value = decryptSecretWithDEK(record, oldDek, row.name, orgId, projectId);
          }
          const context = kmsEncryptionContext(orgId, projectId, row.name);
          const generated = await newKmsProvider.generateDataKey({ encryptionContext: context });
          if (!generated.plaintext || generated.plaintext.length !== 32 || typeof generated.ciphertextBlob !== 'string') {
            generated.plaintext?.fill?.(0);
            throw new Error('KMS rotation returned an invalid DEK');
          }
          newDek = generated.plaintext;
          const keyId = generatedKeyId(generated, newKeyId, 'KMS rotation returned an invalid key id');
          const encrypted = encryptSecretEnvelope(value, generated.plaintext, row.name, {
            orgId,
            projectId,
            keyId,
            dekCiphertext: generated.ciphertextBlob,
          });
          if (row.source === 'current') {
            await client.query(
              `UPDATE secrets SET encrypted_blob=$2, dek_ciphertext=$3, key_id=$4, version=3, updated_at=now() WHERE id=$1 AND org_id=$5 AND project_id=$6`,
              [row.id, JSON.stringify(encrypted), generated.ciphertextBlob, keyId, orgId, globalProjectId],
            );
          } else {
            await client.query(
              `UPDATE secret_versions SET encrypted_blob=$2, dek_ciphertext=$3, key_id=$4 WHERE id=$1 AND org_id=$5 AND project_id=$6`,
              [row.id, JSON.stringify(encrypted), generated.ciphertextBlob, keyId, orgId, globalProjectId],
            );
          }
          count += 1;
        } finally {
          newDek?.fill(0);
          oldDek?.fill(0);
        }
      }

      const idempotency = await client.query(
        `SELECT id, idempotency_key, response_envelope
         FROM idempotency_keys
         WHERE org_id=$1 AND project_id=$2 AND response_envelope IS NOT NULL
         FOR UPDATE`,
        [orgId, globalProjectId],
      );
      let rotatedIdempotencyResponses = 0;
      for (const row of idempotency.rows) {
        const responseName = `idempotency/${row.idempotency_key}`;
        const envelope = typeof row.response_envelope === 'string'
          ? parseStrictJson(row.response_envelope, { maxBytes: 96 * 1024, maxDepth: 6, maxFields: 32, maxArrayItems: 32, maxStringBytes: 16 * 1024 })
          : row.response_envelope;
        const oldKeyId = providerKeyId(oldKms);
        assertEncryptedEnvelopeMetadata(envelope, oldKeyId, 'KMS rotation idempotency envelope');
        let oldDek;
        let newDek;
        try {
          oldDek = await oldKms.decrypt(envelope.dekCiphertext, {
            encryptionContext: idempotencyEncryptionContext(orgId, projectId, row.idempotency_key),
          });
          const response = decryptSecretWithDEK(envelope, oldDek, responseName, orgId, projectId);
          const generated = await newKmsProvider.generateDataKey({
            encryptionContext: idempotencyEncryptionContext(orgId, projectId, row.idempotency_key),
          });
          if (!generated.plaintext || generated.plaintext.length !== 32 || typeof generated.ciphertextBlob !== 'string') {
            generated.plaintext?.fill?.(0);
            throw new Error('KMS rotation returned an invalid idempotency DEK');
          }
          newDek = generated.plaintext;
          const encrypted = encryptSecretWithDEK(response, newDek, responseName, orgId, projectId);
          const keyId = generatedKeyId(generated, newKeyId, 'KMS rotation returned an invalid idempotency key id');
          const nextEnvelope = {
            version: 3,
            algorithm: 'aes-256-gcm',
            keyId,
            kmsContextVersion: 1,
            ...encrypted,
            dekCiphertext: generated.ciphertextBlob,
          };
          await client.query(
            `UPDATE idempotency_keys
             SET response_envelope=$4
             WHERE id=$1 AND org_id=$2 AND project_id=$3`,
            [row.id, orgId, globalProjectId, JSON.stringify(nextEnvelope)],
          );
          rotatedIdempotencyResponses += 1;
        } finally {
          newDek?.fill(0);
          oldDek?.fill(0);
        }
      }

      const capabilities = await client.query(
        `SELECT id, token_hash, secret_name, base_url, path_prefix, methods,
                inject_header, inject_prefix, allow_http, expires_at
         FROM capabilities
         WHERE org_id=$1 AND project_id=$2
         FOR UPDATE`,
        [orgId, globalProjectId],
      );
      let rotatedCapabilities = 0;
      for (const row of capabilities.rows) {
        const capability = {
          id: row.id,
          tokenHash: row.token_hash,
          secretName: row.secret_name,
          baseUrl: row.base_url,
          pathPrefix: row.path_prefix,
          methods: parseDatabaseJson(row.methods, 'Capability methods'),
          injectHeader: row.inject_header,
          injectPrefix: row.inject_prefix,
          allowHttp: row.allow_http,
          orgId,
          projectId,
          keyId: newKeyId,
          expiresAt: row.expires_at,
        };
        const metadataMac = hashCapabilityMetadata(capability, newHmacRing.active.key);
        await client.query(
          `UPDATE capabilities
           SET key_id=$4, mac_key_id=$5, metadata_mac=$6, mutation_version=mutation_version+1, updated_at=now()
           WHERE id=$1 AND org_id=$2 AND project_id=$3`,
          [row.id, orgId, globalProjectId, newKeyId, newHmacRing.active.id, metadataMac],
        );
        rotatedCapabilities += 1;
      }

      await client.query(
        `UPDATE projects SET kms_key_id=$3
         WHERE org_id=$1 AND id=$2`,
        [orgId, globalProjectId, newKeyId],
      );
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [randomUUID(), orgId, globalProjectId, 'kms.rotate', serializeAuditPayload({
          eventType: 'kms.rotate', actor: auditActor, orgId, projectId, rotatedRecords: count,
          rotatedIdempotencyResponses, rotatedCapabilities, createdAt: new Date().toISOString(),
        })],
      );
        return { rotatedRecords: count, rotatedIdempotencyResponses, rotatedCapabilities };
      }, { orgId, projectId });
    } catch (error) {
      newKmsProvider.clearCache?.();
      throw error;
    }
    this.kms = newKmsProvider;
    if (oldKms !== newKmsProvider) oldKms.clearCache?.();
    return { ...rotated, keyId: newKeyId === 'unknown' ? null : newKeyId };
  }

  async _createCapabilityInClient(client, {
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
    emitAudit = true,
    auditActor = 'local-process',
  } = {}) {
    validateSecretName(secretName);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof allowHttp !== 'boolean') throw new Error('allowHttp must be a boolean');
    const production = process.env.TGCLOUD_ENV === 'production' || process.env.NODE_ENV === 'production';
    if (production && allowHttp) throw new Error('HTTP upstreams are disabled in production');
    const normalizedExpiresAt = normalizeCapabilityExpiry(expiresAt, {
      production,
      maxLifetimeMs: this.maxCapabilityLifetimeMs,
    });
    const normalizedBaseUrl = normalizeBaseUrl(baseUrl, { allowHttp });
    const normalizedPathPrefix = normalizePathPrefix(pathPrefix);
    const normalizedMethods = normalizeMethods(methods);
    const normalizedHeader = normalizeInjectHeader(injectHeader);
    const normalizedInjectPrefix = normalizeInjectPrefix(injectPrefix);
    const globalProjectId = `${orgId}:${projectId}`;
    await this._assertProjectActiveInClient(client, orgId, globalProjectId);
    const secretRes = await client.query(
      `SELECT id FROM secrets WHERE org_id=$1 AND project_id=$2 AND name=$3`,
      [orgId, globalProjectId, secretName],
    );
    if (secretRes.rows.length === 0) throw new Error(`Secret not found: ${secretName}`);
    const secretId = secretRes.rows[0].id;
    const kms = await this._getKMS();
    const keyId = providerKeyId(kms);
    const hmacRing = getHmacKeyRing(kms);
    const hmacKey = hmacRing.active.key;
    const macKeyId = hmacRing.active.id;
    const notBefore = new Date().toISOString();

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
        expiresAt: normalizedExpiresAt,
        macKeyId,
        createdAt: new Date().toISOString(),
      };
      capability.metadataMac = hashCapabilityMetadata(capability, hmacKey);
      try {
        await client.query(
          `INSERT INTO capabilities (id, org_id, project_id, secret_id, secret_name, token_hash, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, not_before, expires_at, metadata_mac, key_id, mac_key_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
          [id, orgId, globalProjectId, secretId, secretName, capability.tokenHash, normalizedBaseUrl, normalizedPathPrefix, JSON.stringify(normalizedMethods), normalizedHeader, normalizedInjectPrefix, allowHttp, notBefore, normalizedExpiresAt, capability.metadataMac, keyId, macKeyId]
        );
        break;
      } catch (e) {
        if (e.code === '23505' && attempt < 2) continue;
        throw e;
      }
    }

    if (emitAudit) {
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [randomUUID(), orgId, globalProjectId, 'capability.issue', serializeAuditPayload({
          eventType: 'capability.issue', actor: auditActor, orgId, projectId,
          capabilityId: id, secretName, baseUrl: normalizedBaseUrl,
          pathPrefix: normalizedPathPrefix, methods: normalizedMethods,
          injectHeader: normalizedHeader, expiresAt: normalizedExpiresAt,
          createdAt: new Date().toISOString(),
        })],
      );
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
      expiresAt: normalizedExpiresAt,
      macKeyId,
    };
  }

  async createCapability(options = {}) {
    const orgId = options.orgId ?? this.orgId;
    const projectId = options.projectId ?? this.projectId;
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    return this._withTenantTransaction((client) => this._createCapabilityInClient(client, { ...options, orgId, projectId }), { orgId, projectId });
  }

  async listCapabilities({ orgId = this.orgId, projectId = this.projectId } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this._withTenantTransaction((client) => client.query(
      `SELECT id, secret_name, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http,
              not_before, expires_at, revoked_at, revoked_reason, scheduled_revoke_at, last_used_at, use_count, mac_key_id, mutation_version, created_at
       FROM capabilities WHERE org_id=$1 AND project_id=$2 ORDER BY created_at`,
      [orgId, globalProjectId],
    ), { orgId, projectId });
    return res.rows.map((r) => ({
      id: r.id,
      secretName: r.secret_name,
      baseUrl: r.base_url,
      pathPrefix: r.path_prefix,
      methods: parseDatabaseJson(r.methods, 'Capability methods'),
      injectHeader: r.inject_header,
      injectPrefix: r.inject_prefix,
      allowHttp: r.allow_http,
      notBefore: r.not_before,
      expiresAt: r.expires_at,
      revokedAt: r.revoked_at,
      revokedReason: r.revoked_reason,
      scheduledRevokeAt: r.scheduled_revoke_at,
      lastUsedAt: r.last_used_at,
      useCount: Number(r.use_count || 0),
      macKeyId: r.mac_key_id,
      mutationVersion: Number(r.mutation_version || 1),
      createdAt: r.created_at,
    }));
  }

  async _revokeCapabilityInClient(client, id, { orgId, projectId, reason = 'operator_revocation', expectedVersion = null } = {}) {
    validateCapabilityId(id);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) throw new Error('Revocation reason is invalid');
    if (expectedVersion !== null && (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1)) throw new Error('expectedVersion must be a positive integer');
    const globalProjectId = `${orgId}:${projectId}`;
    const updated = await client.query(
      `UPDATE capabilities
       SET revoked_at=COALESCE(revoked_at, now()), scheduled_revoke_at=NULL,
           revoked_reason=COALESCE($4, revoked_reason), mutation_version=mutation_version+1, updated_at=now()
       WHERE id=$1 AND org_id=$2 AND project_id=$3
         AND ($5::int IS NULL OR mutation_version=$5)
       RETURNING id, mutation_version, revoked_at, revoked_reason`,
      [id, orgId, globalProjectId, reason, expectedVersion],
    );
    if (updated.rows.length === 0 && expectedVersion !== null) {
      const current = await client.query(
        `SELECT mutation_version FROM capabilities WHERE id=$1 AND org_id=$2 AND project_id=$3`,
        [id, orgId, globalProjectId],
      );
      if (current.rows.length === 1) throw lifecycleError('Capability version conflict', 'TGCLOUD_VERSION_CONFLICT', 409);
    }
    return updated.rows[0] || null;
  }

  async revokeCapability(id, { orgId = this.orgId, projectId = this.projectId, reason = 'operator_revocation', expectedVersion = null, auditActor = 'local-process' } = {}) {
    validateCapabilityId(id);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this._withTenantTransaction(async (client) => {
      const updated = await this._revokeCapabilityInClient(client, id, { orgId, projectId, reason, expectedVersion });
      if (updated) {
        const eventId = randomUUID();
        await client.query(
          `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
           VALUES ($1,$2,$3,$4,$5)`,
          [eventId, orgId, globalProjectId, 'capability.revoke', serializeAuditPayload({
            eventId, eventType: 'capability.revoke', actor: auditActor, orgId, projectId, capabilityId: id, reason, createdAt: new Date().toISOString(),
          })],
        );
      }
      return updated;
    }, { orgId, projectId });
    return Boolean(res);
  }

  async _rotateCapabilityInClient(client, { id, orgId = this.orgId, projectId = this.projectId, overlapMs = 0, expectedVersion = null, emitAudit = true, auditActor = 'local-process' } = {}) {
    validateCapabilityId(id);
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (!Number.isSafeInteger(overlapMs) || overlapMs < 0 || overlapMs > 24 * 60 * 60 * 1_000) throw new Error('overlapMs must be between 0 and 86400000');
    if (expectedVersion !== null && (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1)) throw new Error('expectedVersion must be a positive integer');
    const globalProjectId = `${orgId}:${projectId}`;
    await this._assertProjectActiveInClient(client, orgId, globalProjectId);
    const existing = await client.query(
        `SELECT secret_name, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, expires_at, mutation_version
         FROM capabilities
         WHERE id=$1 AND org_id=$2 AND project_id=$3 AND revoked_at IS NULL
           AND (scheduled_revoke_at IS NULL OR scheduled_revoke_at > now())
           AND (expires_at IS NULL OR expires_at > now())
        FOR UPDATE`,
        [id, orgId, globalProjectId],
    );
    if (existing.rows.length === 0) throw Object.assign(new Error('Capability is not active'), { statusCode: 404, publicCode: 'not_found' });
    const row = existing.rows[0];
    const currentVersion = Number(row.mutation_version || 1);
    if (expectedVersion !== null && expectedVersion !== currentVersion) throw lifecycleError('Capability version conflict', 'TGCLOUD_VERSION_CONFLICT', 409);
    const replacement = await this._createCapabilityInClient(client, {
        secretName: row.secret_name,
        baseUrl: row.base_url,
        pathPrefix: row.path_prefix,
        methods: parseDatabaseJson(row.methods, 'Capability methods'),
        injectHeader: row.inject_header,
        injectPrefix: row.inject_prefix,
        allowHttp: row.allow_http,
        expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
        orgId,
        projectId,
        emitAudit: false,
      });
    const scheduledRevokeAt = new Date(Date.now() + overlapMs).toISOString();
    const updated = await client.query(
      `UPDATE capabilities SET scheduled_revoke_at=$4, revoked_reason=$5, mutation_version=mutation_version+1, updated_at=now()
       WHERE id=$1 AND org_id=$2 AND project_id=$3 AND revoked_at IS NULL
         AND (scheduled_revoke_at IS NULL OR scheduled_revoke_at > now())
         AND (expires_at IS NULL OR expires_at > now())
         AND ($6::int IS NULL OR mutation_version=$6)`,
      [id, orgId, globalProjectId, scheduledRevokeAt, 'rotation_pending', expectedVersion],
    );
    if (updated.rowCount !== 1) throw lifecycleError('Capability changed during rotation');
    if (emitAudit) {
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [randomUUID(), orgId, globalProjectId, 'capability.rotate', serializeAuditPayload({
          eventType: 'capability.rotate', actor: auditActor, orgId, projectId, oldCapabilityId: id,
          newCapabilityId: replacement.id, overlapMs, createdAt: new Date().toISOString(),
        })],
      );
    }
    return { ...replacement, replaces: id, overlapUntil: scheduledRevokeAt };
  }

  async rotateCapability(id, { orgId = this.orgId, projectId = this.projectId, overlapMs = 0, expectedVersion = null, auditActor = 'local-process' } = {}) {
    return this._withTenantTransaction(
      (client) => this._rotateCapabilityInClient(client, { id, orgId, projectId, overlapMs, expectedVersion, auditActor }),
      { orgId, projectId },
    );
  }

  async _setTenantRevocationInClient(client, { orgId, projectId, organization = false, active = true, reason = 'emergency_revocation' } = {}) {
    validateBooleanOption(organization, 'organization');
    validateBooleanOption(active, 'active');
    validateOrgProjectId(orgId, 'orgId');
    if (!organization) validateOrgProjectId(projectId, 'projectId');
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) throw new Error('Revocation reason is invalid');
    const globalProjectId = organization ? null : `${orgId}:${projectId}`;
      if (organization) {
        await client.query(
          `INSERT INTO tenant_revocations (org_id, project_id, reason, active)
           VALUES ($1,NULL,$2,$3)
           ON CONFLICT (org_id) WHERE project_id IS NULL
           DO UPDATE SET revoked_at=CASE WHEN $3 THEN now() ELSE tenant_revocations.revoked_at END, reason=$2, active=$3`,
          [orgId, reason, active],
        );
      } else {
        await client.query(
          `INSERT INTO tenant_revocations (org_id, project_id, reason, active)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT (org_id, project_id)
           DO UPDATE SET revoked_at=CASE WHEN $4 THEN now() ELSE tenant_revocations.revoked_at END, reason=$3, active=$4`,
          [orgId, globalProjectId, reason, active],
        );
      }
      if (organization) {
        await client.query(
          `UPDATE orgs
           SET disabled_at=CASE WHEN $2 THEN now() WHEN lifecycle_state='active' THEN NULL ELSE disabled_at END
           WHERE id=$1`,
          [orgId, active],
        );
      } else {
        await client.query(
          `UPDATE projects
           SET disabled_at=CASE WHEN $3 THEN now() WHEN lifecycle_state='active' THEN NULL ELSE disabled_at END
           WHERE org_id=$1 AND id=$2`,
          [orgId, globalProjectId, active],
        );
      }
      return { orgId, projectId: organization ? null : projectId, organization, active, reason };
  }

  async setTenantRevocation({ orgId = this.orgId, projectId = this.projectId, organization = false, reason = 'emergency_revocation', auditActor = 'local-process' } = {}) {
    validateBooleanOption(organization, 'organization');
    validateOrgProjectId(orgId, 'orgId');
    if (!organization) validateOrgProjectId(projectId, 'projectId');
    const globalProjectId = organization ? `${orgId}:${this.projectId}` : `${orgId}:${projectId}`;
    const eventId = randomUUID();
    await this._withTenantTransaction(async (client) => {
      await this._setTenantRevocationInClient(client, { orgId, projectId, organization, active: true, reason });
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [eventId, orgId, globalProjectId, 'tenant.revoke', serializeAuditPayload({
          eventId,
          eventType: 'tenant.revoke',
          actor: auditActor,
          orgId,
          projectId: organization ? null : projectId,
          organization,
          reason,
          createdAt: new Date().toISOString(),
        })],
      );
    }, { orgId, projectId: organization ? this.projectId : projectId });
  }

  async clearTenantRevocation({ orgId = this.orgId, projectId = this.projectId, organization = false, reason = 'revocation_cleared', auditActor = 'local-process' } = {}) {
    validateBooleanOption(organization, 'organization');
    validateOrgProjectId(orgId, 'orgId');
    if (!organization) validateOrgProjectId(projectId, 'projectId');
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) throw new Error('Revocation reason is invalid');
    const globalProjectId = organization ? `${orgId}:${this.projectId}` : `${orgId}:${projectId}`;
    const eventId = randomUUID();
    await this._withTenantTransaction(async (client) => {
      await this._setTenantRevocationInClient(client, { orgId, projectId, organization, active: false, reason });
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [eventId, orgId, organization ? `${orgId}:${this.projectId}` : globalProjectId, 'tenant.revoke.clear', serializeAuditPayload({
          eventId,
          eventType: 'tenant.revoke.clear',
          actor: auditActor,
          orgId,
          projectId: organization ? null : projectId,
          organization,
          reason,
          createdAt: new Date().toISOString(),
        })],
      );
    }, { orgId, projectId: organization ? this.projectId : projectId });
  }

  async recordCapabilityUse({ capabilityId, status, method, path, peer = null, requestId = null, upstreamOrigin = null, softwareVersion = process.env.npm_package_version || 'unknown' } = {}) {
    validateCapabilityId(capabilityId);
    validateOrgProjectId(this.orgId, 'orgId');
    validateOrgProjectId(this.projectId, 'projectId');
    if (!Number.isInteger(status) || status < 100 || status > 599) throw new Error('Audit status must be an HTTP status');
    if (typeof method !== 'string' || !/^[A-Z]+$/.test(method) || method.length > 16) throw new Error('Audit method is invalid');
    if (typeof path !== 'string' || path.length === 0 || path.length > 2_048 || /[\u0000-\u001f\u007f]/.test(path)) throw new Error('Audit path is invalid');
    if (peer !== null && (typeof peer !== 'string' || peer.length > 128 || /[\u0000-\u001f\u007f]/.test(peer))) throw new Error('Audit peer is invalid');
    if (requestId !== null && (typeof requestId !== 'string' || requestId.length > 128 || /[\u0000-\u001f\u007f]/.test(requestId))) throw new Error('Audit request ID is invalid');
    if (upstreamOrigin !== null && (typeof upstreamOrigin !== 'string' || upstreamOrigin.length > 512 || /[\u0000-\u001f\u007f]/.test(upstreamOrigin))) throw new Error('Audit upstream origin is invalid');
    if (softwareVersion !== null && (typeof softwareVersion !== 'string' || softwareVersion.length > 128 || /[\u0000-\u001f\u007f]/.test(softwareVersion))) throw new Error('Audit software version is invalid');
    const eventId = randomUUID();
    const now = new Date().toISOString();
    const payload = sanitizeAuditPayload({ actor: 'broker-runtime', eventId, eventType: 'proxy_request', capabilityId, orgId: this.orgId, projectId: this.projectId, method, path, status, peer, requestId, upstreamOrigin, softwareVersion, createdAt: now });
    await this._withTenantTransaction(async (client) => {
      const updated = await client.query(
        `UPDATE capabilities
         SET last_used_at=now(), use_count=use_count+1, updated_at=now()
         WHERE id=$1 AND org_id=$2 AND project_id=$3`,
        [capabilityId, this.orgId, this.globalProjectId],
      );
      if (updated.rowCount === 0) return;
      await client.query(
        `INSERT INTO capability_audit (capability_id, org_id, project_id, peer, path, method, status, event_type, outcome, request_id, upstream_origin, software_version)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [capabilityId, this.orgId, this.globalProjectId, peer, path, method, status, 'proxy_request', status >= 400 ? 'failure' : 'success', requestId, upstreamOrigin, softwareVersion],
      );
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [eventId, this.orgId, this.globalProjectId, 'proxy_request', serializeAuditPayload(payload)],
      );
    });
  }

  async recordAuditEvent({ eventType, payload = {}, orgId = this.orgId, projectId = this.projectId } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (typeof eventType !== 'string' || !/^[a-z][a-z0-9_.-]{1,63}$/.test(eventType)) throw new Error('Audit event type is invalid');
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Audit payload must be an object');
    const safePayload = sanitizeAuditPayload(payload);
    const serialized = JSON.stringify(safePayload);
    if (Buffer.byteLength(serialized, 'utf8') > 32 * 1024) throw new Error('Audit payload is too large');
    await this._withTenantTransaction(async (client) => {
      await client.query(
        `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
         VALUES ($1,$2,$3,$4,$5)`,
        [randomUUID(), orgId, `${orgId}:${projectId}`, eventType, serialized],
      );
    }, { orgId, projectId });
  }

  async listAudit({ orgId = this.orgId, projectId = this.projectId, limit = 100, before = null } = {}) {
    validateOrgProjectId(orgId, 'orgId');
    validateOrgProjectId(projectId, 'projectId');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new Error('Audit limit must be between 1 and 1000');
    const globalProjectId = `${orgId}:${projectId}`;
    const res = await this._withTenantTransaction((client) => client.query(
      `SELECT event_id, event_type, payload, created_at, published_at, attempts
       FROM audit_outbox
       WHERE org_id=$1 AND project_id=$2
         AND ($3::timestamptz IS NULL OR created_at < $3)
       ORDER BY created_at DESC, id DESC LIMIT $4`,
      [orgId, globalProjectId, before, limit],
    ), { orgId, projectId });
    return res.rows.map((row) => ({
      eventId: row.event_id,
      eventType: row.event_type,
      payload: sanitizeAuditPayload(typeof row.payload === 'string'
        ? parseStrictJson(row.payload, { maxBytes: 96 * 1024, maxDepth: 10, maxFields: 128, maxArrayItems: 128, maxStringBytes: 64 * 1024 })
        : row.payload),
      createdAt: row.created_at.toISOString(),
      publishedAt: row.published_at?.toISOString?.() || null,
      attempts: Number(row.attempts || 0),
    }));
  }

  async resolveCapability(token) {
    if (typeof token !== 'string' || token.length < 16 || token.length > 256) return null;
    const tokenHash = hashCapability(token);
    // Tenant-isolated lookup: token_hash is globally unique, but we verify org/project after
    const res = await this._withTenantTransaction((client) => client.query(
      `SELECT c.*, s.encrypted_blob, s.dek_ciphertext, s.key_id as secret_key_id, s.version as secret_version,
              p.org_id as proj_org_id, p.disabled_at as project_disabled_at, p.lifecycle_state as project_lifecycle_state,
              o.disabled_at as org_disabled_at, o.lifecycle_state as org_lifecycle_state
       FROM capabilities c 
       JOIN secrets s ON c.secret_id = s.id AND s.org_id = c.org_id AND s.project_id = c.project_id
       JOIN projects p ON c.project_id = p.id
       JOIN orgs o ON p.org_id = o.id
       WHERE c.token_hash=$1 AND c.org_id=$2 AND c.project_id=$3
         AND NOT EXISTS (
           SELECT 1 FROM tenant_revocations tr
           WHERE tr.org_id = c.org_id AND tr.active
             AND (tr.project_id IS NULL OR tr.project_id = c.project_id)
         )`,
      [tokenHash, this.orgId, this.globalProjectId],
    ));
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    // Enforce tenant isolation: capability's org/project must match this store's tenant OR allow cross-tenant only if explicitly configured
    // For now, enforce exact match on org and project
    if (row.org_id !== this.orgId || row.project_id !== this.globalProjectId) {
      // Optionally allow if store is configured as global, but for multi-tenant we deny
      return null;
    }
    const now = Date.now();
    if (row.revoked_at
      || (row.scheduled_revoke_at && new Date(row.scheduled_revoke_at).getTime() <= now)
      || (row.not_before && new Date(row.not_before).getTime() > now)
      || (row.expires_at && new Date(row.expires_at).getTime() <= now)) return null;
    if (row.org_disabled_at || row.project_disabled_at || row.org_lifecycle_state !== 'active' || row.project_lifecycle_state !== 'active') return null;
    const kms = await this._getKMS();
    let expectedKeyId;
    try {
      expectedKeyId = providerKeyId(kms);
      if (row.key_id !== expectedKeyId) return null;
    } catch {
      return null;
    }
    let hmacRing;
    try {
      hmacRing = getHmacKeyRing(kms);
    } catch {
      return null;
    }
    const hmacEntry = hmacRing.get(row.mac_key_id || 'env-v1');
    if (!hmacEntry) return null;
    let capForMac;
    let candidate;
    try {
      capForMac = {
        id: row.id,
        tokenHash: row.token_hash,
        secretName: row.secret_name,
        baseUrl: row.base_url,
        pathPrefix: row.path_prefix,
        methods: parseDatabaseJson(row.methods, 'Capability methods'),
        injectHeader: row.inject_header,
        injectPrefix: row.inject_prefix,
        allowHttp: row.allow_http,
        orgId: row.org_id,
        projectId: row.project_id.replace(`${row.org_id}:`, ''),
        keyId: row.key_id || 'local',
        expiresAt: row.expires_at,
      };
      candidate = {
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
    if (!capabilityMetadataMatches(capForMac, hmacEntry.key, row.metadata_mac)) return null;

    let record;
    let secretValue;
    try {
      record = typeof row.encrypted_blob === 'string'
        ? parseStrictJson(row.encrypted_blob, { maxBytes: 96 * 1024, maxDepth: 6, maxFields: 32, maxArrayItems: 32, maxStringBytes: 16 * 1024 })
        : row.encrypted_blob;
      if (!record || typeof record !== 'object') return null;
      if (record.version === 2) {
        if (kms instanceof LocalKMSProvider) {
          secretValue = decryptSecret(record, kms.key, row.secret_name);
        } else {
          return null;
        }
      } else {
        // Use stored org/project for AAD, not instance default
        const storedOrg = row.org_id;
        const storedProj = row.project_id.replace(`${storedOrg}:`, '');
        assertStoredRecordKey(record, row.secret_key_id, expectedKeyId, row.dek_ciphertext, 'Capability secret record');
        const dek = await kms.decrypt(row.dek_ciphertext, recordEncryptionContext(record, storedOrg, storedProj, row.secret_name));
        try {
          secretValue = decryptSecretWithDEK(record, dek, row.secret_name, storedOrg, storedProj);
        } finally {
          dek.fill(0);
        }
      }
    } catch {
      return null;
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
    await this.init();
    await this.pool.query({ text: 'SELECT 1', query_timeout: 3000 });
    const kms = await this._getKMS();
    const expectedKeyId = providerKeyId(kms);
    const context = kmsEncryptionContext(this.orgId, this.projectId, '__healthcheck__');
    const generated = await kms.generateDataKey({ encryptionContext: context });
    if (!generated || !generated.plaintext || generated.plaintext.length !== 32 || typeof generated.ciphertextBlob !== 'string') {
      generated?.plaintext?.fill?.(0);
      throw new Error('KMS health check returned an invalid DEK');
    }
    try {
      generatedKeyId(generated, expectedKeyId, 'KMS health check returned an invalid key id');
    } catch (error) {
      generated.plaintext.fill(0);
      throw error;
    }
    const { plaintext, ciphertextBlob } = generated;
    try {
      // A generated DEK is cached by the AWS provider. Bypass that entry so
      // readiness verifies the live Decrypt permission/API rather than only
      // the in-process cache.
      const dek2 = await kms.decrypt(ciphertextBlob, { encryptionContext: context, bypassCache: true });
      try {
        if (plaintext.length !== dek2.length || !timingSafeEqual(plaintext, dek2)) throw new Error('KMS health check failed');
        return true;
      } finally {
        dek2.fill(0);
      }
    } finally {
      plaintext.fill(0);
    }
  }
}

export { MAX_SECRET_BYTES, validateSecretName, validateCapabilityId };
