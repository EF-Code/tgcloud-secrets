import { isLoopbackHost } from './policy.js';
import { parseMasterKey } from './crypto.js';
import { parseStrictJson } from './json.js';

const KNOWN_ENV_KEYS = new Set([
  'TGCLOUD_ENV', 'NODE_ENV', 'DATABASE_URL', 'TGCLOUD_SECRETS_DSN',
  'TGCLOUD_SECRETS_DATA_DIR', 'TGCLOUD_ORG_ID', 'TGCLOUD_PROJECT_ID',
  'TGCLOUD_HOST', 'TGCLOUD_PORT', 'TGCLOUD_BROKER_REPLICAS',
  'TGCLOUD_KMS_KEY_ID', 'AWS_KMS_KEY_ID', 'TGCLOUD_MASTER_KEY',
  'TGCLOUD_HMAC_KEY', 'TGCLOUD_HMAC_KEY_ID', 'TGCLOUD_HMAC_PREVIOUS_KEYS',
  'TGCLOUD_KMS_CACHE_TTL_MS', 'TGCLOUD_KMS_CACHE_MAX_ENTRIES', 'TGCLOUD_KMS_OPERATION_TIMEOUT_MS',
  'TGCLOUD_MAX_CAPABILITY_LIFETIME_MS',
  'TGCLOUD_ALLOW_HTTP', 'TGCLOUD_TLS_TERMINATED', 'TGCLOUD_EDGE_AUTHENTICATED',
  'TGCLOUD_DISTRIBUTED_LIMITER', 'TGCLOUD_AUDIT_REQUIRED',
  'TGCLOUD_RATE_LIMITER_MODULE',
  'TGCLOUD_TRUSTED_PROXY_ADDRESSES', 'ALLOW_EPHEMERAL_KMS',
]);

const HMAC_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TENANT_ID = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const MAX_PREVIOUS_HMAC_KEYS = 16;
const MAX_PREVIOUS_HMAC_CONFIG_BYTES = 64 * 1024;
const DEFAULT_MAX_CAPABILITY_LIFETIME_MS = 90 * 24 * 60 * 60 * 1_000;
const MAX_CAPABILITY_LIFETIME_MS = 365 * 24 * 60 * 60 * 1_000;

function validTenantId(value) {
  return typeof value === 'string' && TENANT_ID.test(value);
}

function optionalPositiveInteger(value, fallback, name, maximum = Number.MAX_SAFE_INTEGER) {
  if (value === undefined) return fallback;
  if (value === '') throw new Error(`${name} must not be empty`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) throw new Error(`${name} must be a positive integer no greater than ${maximum}`);
  return parsed;
}

function optionalNonNegativeInteger(value, fallback, name, maximum = Number.MAX_SAFE_INTEGER) {
  if (value === undefined) return fallback;
  if (value === '') throw new Error(`${name} must not be empty`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) throw new Error(`${name} must be a non-negative integer no greater than ${maximum}`);
  return parsed;
}

function flag(value, fallback = false) {
  if (value === undefined) return fallback;
  if (value === true || value === '1' || value === 'true') return true;
  if (value === false || value === '0' || value === 'false') return false;
  throw new Error(`Invalid boolean configuration value: ${value}`);
}

function dsnHost(dsn) {
  try {
    return new URL(dsn).hostname;
  } catch {
    return null;
  }
}

function dsnDetails(dsn) {
  if (dsn === undefined || dsn === null) return { valid: true, host: null, sslMode: null, sslModeCount: 0, defaultCredentials: false };
  try {
    const parsed = new URL(dsn);
    const username = decodeURIComponent(parsed.username);
    const password = decodeURIComponent(parsed.password);
    return {
      valid: parsed.protocol === 'postgres:' || parsed.protocol === 'postgresql:',
      host: parsed.hostname,
      sslMode: parsed.searchParams.get('sslmode'),
      sslModeCount: parsed.searchParams.getAll('sslmode').length,
      defaultCredentials: username === 'postgres' && password === 'postgres',
    };
  } catch {
    return { valid: false, host: null, sslMode: null, sslModeCount: 0, defaultCredentials: false };
  }
}

function validMasterKey(value) {
  if (!value) return false;
  try {
    parseMasterKey(value);
    return true;
  } catch {
    return false;
  }
}

function validKmsKeyId(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 512
    && value.trim() === value && value !== 'unknown' && !/[\u0000-\u001f\u007f]/.test(value);
}

function validRateLimiterModule(value) {
  return value === undefined || (typeof value === 'string' && value.length > 0 && value.length <= 4 * 1024
    && !/[\u0000-\u001f\u007f]/.test(value));
}

function validPreviousHmacKeys(value, activeId) {
  if (value === undefined || value === '') return true;
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_PREVIOUS_HMAC_CONFIG_BYTES) return false;
  try {
    const entries = parseStrictJson(value, {
      maxBytes: MAX_PREVIOUS_HMAC_CONFIG_BYTES,
      maxDepth: 4,
      maxFields: 64,
      maxArrayItems: MAX_PREVIOUS_HMAC_KEYS,
      maxStringBytes: MAX_PREVIOUS_HMAC_CONFIG_BYTES,
    });
    if (!Array.isArray(entries) || entries.length > MAX_PREVIOUS_HMAC_KEYS) return false;
    const ids = new Set();
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || typeof entry.id !== 'string' || !HMAC_KEY_ID.test(entry.id) || entry.id === activeId || ids.has(entry.id)
        || !validMasterKey(entry.key)) return false;
      ids.add(entry.id);
    }
    return true;
  } catch {
    return false;
  }
}

export function readConfig(env = process.env) {
  const environment = env.TGCLOUD_ENV !== undefined ? env.TGCLOUD_ENV : (env.NODE_ENV !== undefined ? env.NODE_ENV : 'development');
  const environmentConflict = Boolean(env.TGCLOUD_ENV && env.NODE_ENV && env.TGCLOUD_ENV !== env.NODE_ENV);
  const dsn = env.DATABASE_URL !== undefined ? env.DATABASE_URL : (env.TGCLOUD_SECRETS_DSN !== undefined ? env.TGCLOUD_SECRETS_DSN : null);
  const dsnSourceConflict = Boolean(env.DATABASE_URL && env.TGCLOUD_SECRETS_DSN && env.DATABASE_URL !== env.TGCLOUD_SECRETS_DSN);
  const host = env.TGCLOUD_HOST !== undefined ? env.TGCLOUD_HOST : '127.0.0.1';
  const replicas = optionalPositiveInteger(env.TGCLOUD_BROKER_REPLICAS, 1, 'TGCLOUD_BROKER_REPLICAS', 1_000);
  const kmsKeyId = env.TGCLOUD_KMS_KEY_ID !== undefined
    ? env.TGCLOUD_KMS_KEY_ID
    : (env.AWS_KMS_KEY_ID !== undefined ? env.AWS_KMS_KEY_ID : 'local');
  const localKms = typeof kmsKeyId === 'string' && (kmsKeyId === 'local' || kmsKeyId.startsWith('local:'));
  const dsnInfo = dsnDetails(dsn);
  const hmacConfigured = env.TGCLOUD_HMAC_KEY !== undefined;
  const orgId = env.TGCLOUD_ORG_ID !== undefined ? env.TGCLOUD_ORG_ID : 'default';
  const projectId = env.TGCLOUD_PROJECT_ID !== undefined ? env.TGCLOUD_PROJECT_ID : 'default';
  const hmacKeyIdConfigured = env.TGCLOUD_HMAC_KEY_ID !== undefined;
  const hmacKeyId = hmacKeyIdConfigured ? env.TGCLOUD_HMAC_KEY_ID : (localKms ? 'local-v1' : 'env-v1');
  return Object.freeze({
    environment,
    environmentConflict,
    production: environment === 'production',
    dsn,
    dsnHost: dsnInfo.host || dsnHost(dsn),
    dsnValid: dsnInfo.valid,
    dsnSslMode: dsnInfo.sslMode,
    dsnSslModeCount: dsnInfo.sslModeCount,
    dsnSourceConflict,
    defaultDsnCredentials: dsnInfo.defaultCredentials,
    orgId,
    projectId,
    tenantIdsValid: validTenantId(orgId) && validTenantId(projectId),
    host,
    hostValid: typeof host === 'string' && host.length > 0 && host.length <= 255
      && host.trim() === host && !/[\u0000-\u001f\u007f]/.test(host),
    port: optionalPositiveInteger(env.TGCLOUD_PORT, 8787, 'TGCLOUD_PORT', 65_535),
    replicas,
    localKms,
    kmsKeyId,
    kmsKeyIdValid: validKmsKeyId(kmsKeyId),
    masterKeyConfigured: env.TGCLOUD_MASTER_KEY !== undefined,
    hmacConfigured,
    hmacValid: !hmacConfigured || validMasterKey(env.TGCLOUD_HMAC_KEY),
    hmacKeyIdConfigured,
    hmacKeyIdValid: !hmacKeyIdConfigured || HMAC_KEY_ID.test(env.TGCLOUD_HMAC_KEY_ID),
    hmacKeyId,
    hmacPreviousKeysValid: validPreviousHmacKeys(env.TGCLOUD_HMAC_PREVIOUS_KEYS, hmacKeyId),
    kmsCacheTtlMs: optionalNonNegativeInteger(env.TGCLOUD_KMS_CACHE_TTL_MS, null, 'TGCLOUD_KMS_CACHE_TTL_MS', 60 * 60 * 1_000),
    kmsCacheMaxEntries: optionalPositiveInteger(env.TGCLOUD_KMS_CACHE_MAX_ENTRIES, null, 'TGCLOUD_KMS_CACHE_MAX_ENTRIES', 10_000),
    kmsOperationTimeoutMs: optionalPositiveInteger(env.TGCLOUD_KMS_OPERATION_TIMEOUT_MS, 15_000, 'TGCLOUD_KMS_OPERATION_TIMEOUT_MS', 120_000),
    maxCapabilityLifetimeMs: optionalPositiveInteger(env.TGCLOUD_MAX_CAPABILITY_LIFETIME_MS, DEFAULT_MAX_CAPABILITY_LIFETIME_MS, 'TGCLOUD_MAX_CAPABILITY_LIFETIME_MS', MAX_CAPABILITY_LIFETIME_MS),
    allowHttp: flag(env.TGCLOUD_ALLOW_HTTP),
    tlsTerminated: flag(env.TGCLOUD_TLS_TERMINATED),
    edgeAuthenticated: flag(env.TGCLOUD_EDGE_AUTHENTICATED),
    distributedLimiter: flag(env.TGCLOUD_DISTRIBUTED_LIMITER),
    rateLimiterModule: env.TGCLOUD_RATE_LIMITER_MODULE,
    rateLimiterModuleValid: validRateLimiterModule(env.TGCLOUD_RATE_LIMITER_MODULE),
    auditRequired: flag(env.TGCLOUD_AUDIT_REQUIRED, true),
    ephemeralKms: flag(env.ALLOW_EPHEMERAL_KMS),
    unknownKeys: Object.keys(env).filter((key) => key.startsWith('TGCLOUD_') && !KNOWN_ENV_KEYS.has(key)),
    conflictingKmsKeys: Boolean(env.TGCLOUD_KMS_KEY_ID && env.AWS_KMS_KEY_ID && env.TGCLOUD_KMS_KEY_ID !== env.AWS_KMS_KEY_ID),
  });
}

function validateCommonConfig(config) {
  const errors = [];
  if (!['development', 'staging', 'production', 'test'].includes(config.environment)) errors.push('TGCLOUD_ENV/NODE_ENV must be development, staging, production, or test');
  if (config.environmentConflict) errors.push('TGCLOUD_ENV and NODE_ENV must agree when both are set');
  if (config.unknownKeys?.length) errors.push(`unknown configuration keys: ${config.unknownKeys.join(', ')}`);
  if (config.dsnSourceConflict) errors.push('DATABASE_URL and TGCLOUD_SECRETS_DSN must not disagree');
  if (config.conflictingKmsKeys) errors.push('TGCLOUD_KMS_KEY_ID and AWS_KMS_KEY_ID must not disagree');
  if (config.dsn !== null && config.dsn !== undefined && !config.dsnValid) errors.push('DATABASE_URL must be a valid postgres:// or postgresql:// URL');
  if (!config.kmsKeyIdValid) errors.push('KMS key ID must be a non-empty, bounded string without control characters');
  if (!config.rateLimiterModuleValid) errors.push('TGCLOUD_RATE_LIMITER_MODULE must be a non-empty local module path of at most 4096 bytes');
  if (!config.hostValid) errors.push('TGCLOUD_HOST must be a non-empty host name or IP address without control characters');
  if (config.hmacConfigured && !config.hmacValid) errors.push('TGCLOUD_HMAC_KEY must be a valid 32-byte base64url key');
  if (config.hmacKeyIdConfigured && !config.hmacKeyIdValid) errors.push('TGCLOUD_HMAC_KEY_ID is invalid');
  if (!config.hmacPreviousKeysValid) errors.push('TGCLOUD_HMAC_PREVIOUS_KEYS must contain at most 16 valid, unique {id,key} entries');
  if (config.kmsOperationTimeoutMs < 100) errors.push('TGCLOUD_KMS_OPERATION_TIMEOUT_MS must be at least 100 milliseconds');
  if (config.maxCapabilityLifetimeMs <= 0 || config.maxCapabilityLifetimeMs > MAX_CAPABILITY_LIFETIME_MS) errors.push(`TGCLOUD_MAX_CAPABILITY_LIFETIME_MS must be between 1 and ${MAX_CAPABILITY_LIFETIME_MS}`);
  if (!config.tenantIdsValid) errors.push('TGCLOUD_ORG_ID and TGCLOUD_PROJECT_ID must be valid tenant identifiers');
  return errors;
}

function appendProductionDatabaseErrors(config, errors) {
  if (!config.dsn) errors.push('DATABASE_URL or TGCLOUD_SECRETS_DSN is required in production');
  if (config.dsn && !['verify-ca', 'verify-full'].includes(config.dsnSslMode)) errors.push('production database sslmode must be explicitly verify-ca or verify-full');
  if (config.dsn && config.dsnValid && config.dsnSslModeCount !== 1) errors.push('production database sslmode must be specified exactly once');
  if (config.dsn && config.dsnValid && !config.dsnHost) errors.push('production Postgres DSN must include a managed/private endpoint hostname, not a local socket');
  if (config.dsnHost && isLoopbackHost(config.dsnHost)) errors.push('production Postgres must use a managed/private endpoint with TLS, not loopback');
  if (config.defaultDsnCredentials) errors.push('default Postgres credentials are not allowed in production');
}

export function validateDatabaseConfig(config = readConfig()) {
  const errors = validateCommonConfig(config);
  if (config.production) appendProductionDatabaseErrors(config, errors);
  return errors;
}

export function validateProductionConfig(config = readConfig()) {
  const errors = validateDatabaseConfig(config);
  if (!config.production) return errors;
  if (config.localKms) errors.push('a managed KMS key is required in production; local KMS is development-only');
  if (config.masterKeyConfigured) errors.push('TGCLOUD_MASTER_KEY must not be configured in managed production');
  if (config.ephemeralKms) errors.push('ALLOW_EPHEMERAL_KMS must not be enabled in production');
  if (config.allowHttp) errors.push('TGCLOUD_ALLOW_HTTP must be disabled in production');
  if (!isLoopbackHost(config.host) && !config.tlsTerminated) errors.push('TGCLOUD_TLS_TERMINATED=true is required for a public broker bind');
  if (!isLoopbackHost(config.host) && !config.edgeAuthenticated) errors.push('TGCLOUD_EDGE_AUTHENTICATED=true is required for a public broker bind');
  if (!config.distributedLimiter) errors.push('TGCLOUD_DISTRIBUTED_LIMITER=true is required in production');
  if (config.auditRequired && !config.dsn) errors.push('durable audit requires Postgres in production');
  if (!config.auditRequired) errors.push('TGCLOUD_AUDIT_REQUIRED must remain enabled in production');
  if (config.kmsKeyId !== 'local' && !config.dsn) errors.push('a KMS-backed deployment requires Postgres in production');
  if (config.kmsKeyId !== 'local' && !config.hmacConfigured) errors.push('TGCLOUD_HMAC_KEY is required for managed KMS capability metadata authentication');
  if (config.kmsKeyId !== 'local' && !config.hmacKeyIdConfigured) errors.push('TGCLOUD_HMAC_KEY_ID is required for managed HMAC key rotation');
  return errors;
}

export function assertProductionConfig(config = readConfig()) {
  const errors = validateProductionConfig(config);
  if (errors.length > 0) throw new Error(`Production configuration is invalid:\n- ${errors.join('\n- ')}`);
  return config;
}

export function assertDatabaseConfig(config = readConfig()) {
  const errors = validateDatabaseConfig(config);
  if (errors.length > 0) throw new Error(`Database configuration is invalid:\n- ${errors.join('\n- ')}`);
  return config;
}
