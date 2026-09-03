import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readConfig, validateProductionConfig } from '../src/config.js';

test('configuration validation rejects insecure production combinations', () => {
  const errors = validateProductionConfig(readConfig({ TGCLOUD_ENV: 'production' }));
  assert.ok(errors.some((error) => error.includes('DATABASE_URL')));
  assert.ok(errors.some((error) => error.includes('managed KMS')));
  assert.ok(errors.some((error) => error.includes('ALLOW_EPHEMERAL_KMS')) === false);
});

test('configuration validation accepts an explicit managed, private production profile', () => {
  const config = readConfig({
    TGCLOUD_ENV: 'production',
    DATABASE_URL: 'postgres://runtime:password@db.internal:5432/tgcloud?sslmode=verify-full',
    TGCLOUD_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/example',
    TGCLOUD_HMAC_KEY: 'Z5zvyC7Tx4iQbiOrZY6ugPukxdNHisYw6BEoIeh8HNQ',
    TGCLOUD_HMAC_KEY_ID: 'hmac-2026',
    TGCLOUD_HOST: '127.0.0.1',
    TGCLOUD_BROKER_REPLICAS: '2',
    TGCLOUD_DISTRIBUTED_LIMITER: 'true',
  });
  assert.equal(config.hmacConfigured, true);
  assert.deepEqual(validateProductionConfig(config), []);
});

test('configuration validation rejects public binds without explicit edge controls', () => {
  const config = readConfig({
    TGCLOUD_ENV: 'production',
    DATABASE_URL: 'postgres://runtime:password@db.internal:5432/tgcloud?sslmode=verify-full',
    TGCLOUD_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/example',
    TGCLOUD_HMAC_KEY: 'Z5zvyC7Tx4iQbiOrZY6ugPukxdNHisYw6BEoIeh8HNQ',
    TGCLOUD_HOST: '0.0.0.0',
  });
  const errors = validateProductionConfig(config);
  assert.ok(errors.some((error) => error.includes('TLS_TERMINATED')));
  assert.ok(errors.some((error) => error.includes('EDGE_AUTHENTICATED')));
});

test('configuration validation rejects unknown and unsafe production settings', () => {
  const config = readConfig({
    TGCLOUD_ENV: 'production',
    DATABASE_URL: 'postgres://postgres:postgres@db.internal:5432/tgcloud?sslmode=disable',
    TGCLOUD_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/example',
    TGCLOUD_HMAC_KEY: 'not-a-key',
    TGCLOUD_UNKNOWN_SETTING: 'unexpected',
  });
  const errors = validateProductionConfig(config);
  assert.ok(errors.some((error) => error.includes('unknown configuration')));
  assert.ok(errors.some((error) => error.includes('sslmode')));
  assert.ok(errors.some((error) => error.includes('default Postgres')));
  assert.ok(errors.some((error) => error.includes('32-byte')));
});

test('configuration validation requires distributed limiting and an unambiguous database endpoint', () => {
  const config = readConfig({
    TGCLOUD_ENV: 'production',
    DATABASE_URL: 'postgres://runtime:password@db.internal:5432/tgcloud?sslmode=verify-full&sslmode=verify-ca',
    TGCLOUD_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/example',
    TGCLOUD_HMAC_KEY: 'Z5zvyC7Tx4iQbiOrZY6ugPukxdNHisYw6BEoIeh8HNQ',
    TGCLOUD_HMAC_KEY_ID: 'hmac-2026',
  });
  const errors = validateProductionConfig(config);
  assert.ok(errors.some((error) => error.includes('specified exactly once')));
  assert.ok(errors.some((error) => error.includes('DISTRIBUTED_LIMITER')));

  const socketConfig = readConfig({
    TGCLOUD_ENV: 'production',
    DATABASE_URL: 'postgres:///tgcloud?sslmode=verify-full',
    TGCLOUD_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123456789012:key/example',
    TGCLOUD_HMAC_KEY: 'Z5zvyC7Tx4iQbiOrZY6ugPukxdNHisYw6BEoIeh8HNQ',
    TGCLOUD_HMAC_KEY_ID: 'hmac-2026',
    TGCLOUD_DISTRIBUTED_LIMITER: 'true',
  });
  assert.ok(validateProductionConfig(socketConfig).some((error) => error.includes('endpoint')));
});

test('configuration validation rejects conflicting environment modes and malformed HMAC rotation state', () => {
  const config = readConfig({
    TGCLOUD_ENV: 'development',
    NODE_ENV: 'production',
    TGCLOUD_HMAC_KEY_ID: 'bad key id',
    TGCLOUD_HMAC_PREVIOUS_KEYS: JSON.stringify([{ id: 'old', key: 'not-a-key' }]),
  });
  const errors = validateProductionConfig(config);
  assert.ok(errors.some((error) => error.includes('must agree')));
  assert.ok(errors.some((error) => error.includes('HMAC_KEY_ID')));
  assert.ok(errors.some((error) => error.includes('HMAC_PREVIOUS_KEYS')));
});

test('configuration accepts disabled KMS caching and bounds capability lifetime', () => {
  const config = readConfig({
    TGCLOUD_KMS_CACHE_TTL_MS: '0',
    TGCLOUD_MAX_CAPABILITY_LIFETIME_MS: '3600000',
  });
  assert.equal(config.kmsCacheTtlMs, 0);
  assert.equal(config.maxCapabilityLifetimeMs, 3600000);
  assert.throws(() => readConfig({ TGCLOUD_MAX_CAPABILITY_LIFETIME_MS: String(366 * 24 * 60 * 60 * 1000) }), /no greater/);
});

test('configuration does not silently replace explicitly empty security values', () => {
  assert.ok(validateProductionConfig(readConfig({ TGCLOUD_KMS_KEY_ID: '' })).some((error) => error.includes('KMS key ID')));
  assert.ok(validateProductionConfig(readConfig({ TGCLOUD_HMAC_KEY_ID: '' })).some((error) => error.includes('HMAC_KEY_ID')));
  assert.ok(validateProductionConfig(readConfig({ TGCLOUD_HOST: ' 127.0.0.1' })).some((error) => error.includes('TGCLOUD_HOST')));
  assert.ok(validateProductionConfig(readConfig({ TGCLOUD_RATE_LIMITER_MODULE: '' })).some((error) => error.includes('TGCLOUD_RATE_LIMITER_MODULE')));
  assert.throws(() => readConfig({ TGCLOUD_KMS_OPERATION_TIMEOUT_MS: '' }), /must not be empty/);
});
