import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PgStore } from '../src/pg-store.js';
import { LocalKMSProvider } from '../src/kms.js';
import { generateMasterKey } from '../src/crypto.js';

const dsn = process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN || 'postgres://postgres:postgres@localhost:5433/tgcloud';

async function storeFor(label) {
  const orgId = `lifeorg_${label}_${Date.now()}_${Math.random().toString(36).slice(2, 5)}`;
  const projectId = `lifeproj_${Date.now()}_${Math.random().toString(36).slice(2, 5)}`;
  const store = new PgStore({ dsn, kmsProvider: new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' }), orgId, projectId });
  await store.init();
  return store;
}

test('secret versioning supports optimistic writes and rollback', async (t) => {
  const store = await storeFor('versions');
  t.after(() => store.close().catch(() => {}));
  assert.deepEqual(await store.setSecret('rotating', 'v1'), { name: 'rotating', version: 1 });
  assert.deepEqual(await store.setSecret('rotating', 'v2', { expectedVersion: 1 }), { name: 'rotating', version: 2 });
  assert.equal(await store.getSecret('rotating'), 'v2');
  await assert.rejects(() => store.setSecret('rotating', 'wrong', { expectedVersion: 1 }), (error) => error.code === 'TGCLOUD_VERSION_CONFLICT');
  assert.deepEqual((await store.listSecretVersions('rotating')).map((item) => item.version), [1]);
  assert.deepEqual(await store.rollbackSecret('rotating', 1, { expectedVersion: 2 }), { name: 'rotating', version: 3, restoredVersion: 1 });
  assert.equal(await store.getSecret('rotating'), 'v1');
  assert.deepEqual((await store.listSecretVersions('rotating')).map((item) => item.version), [2, 1]);
});

test('capability rotation has bounded overlap and tenant kill switches', async (t) => {
  const store = await storeFor('capabilities');
  t.after(() => store.close().catch(() => {}));
  await store.setSecret('service', 'synthetic-value');
  const capability = await store.createCapability({ secretName: 'service', baseUrl: 'https://api.example.com' });
  const replacement = await store.rotateCapability(capability.id, { overlapMs: 50 });
  assert.ok(await store.resolveCapability(capability.token));
  assert.ok(await store.resolveCapability(replacement.token));
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(await store.resolveCapability(capability.token), null);
  assert.ok(await store.resolveCapability(replacement.token));
  await store.setTenantRevocation({ reason: 'synthetic-kill' });
  assert.equal(await store.resolveCapability(replacement.token), null);
  await store.clearTenantRevocation();
  assert.ok(await store.resolveCapability(replacement.token));
  assert.equal((await store.listCapabilities()).find((item) => item.id === capability.id).revokedAt, null);
  await store.revokeCapability(replacement.id, { reason: 'cleanup' });
});

test('idempotency replays the encrypted response and detects request reuse', async (t) => {
  const store = await storeFor('idempotency');
  t.after(() => store.close().catch(() => {}));
  let calls = 0;
  const first = await store.runIdempotent({ idempotencyKey: 'idem-key-1', requestHash: 'a'.repeat(64), mutation: async () => ({ result: ++calls, marker: 'synthetic' }) });
  const replay = await store.runIdempotent({ idempotencyKey: 'idem-key-1', requestHash: 'a'.repeat(64), mutation: async () => ({ result: ++calls }) });
  assert.deepEqual(replay, first);
  assert.equal(calls, 1);
  await assert.rejects(() => store.runIdempotent({ idempotencyKey: 'idem-key-1', requestHash: 'b'.repeat(64), mutation: async () => ({}) }), (error) => error.code === 'TGCLOUD_IDEMPOTENCY_CONFLICT');
});

test('KMS rotation re-encrypts current and historical secret records', async (t) => {
  const oldKey = generateMasterKey();
  const oldKms = new LocalKMSProvider({ masterKey: oldKey, keyId: 'local-old' });
  const store = new PgStore({ dsn, kmsProvider: oldKms, orgId: `lifeorg_kms_${Date.now()}`, projectId: `lifeproj_kms_${Date.now()}` });
  await store.init();
  t.after(() => store.close().catch(() => {}));
  await store.setSecret('encrypted', 'before-rotation');
  await store.setSecret('encrypted', 'after-rotation');
  const newKms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local-new' });
  const result = await store.rotateSecrets({ newKmsProvider: newKms });
  assert.equal(result.keyId, 'local-new');
  assert.equal(result.rotatedRecords, 2);
  assert.equal(await store.getSecret('encrypted'), 'after-rotation');
  assert.deepEqual((await store.listSecretVersions('encrypted')).map((item) => item.keyId), ['local-new']);
  assert.equal((await store.getSecret('encrypted')), 'after-rotation');
});

test('KMS rotation preserves encrypted idempotency replays and capability tokens', async (t) => {
  const oldKms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local-rotate-old' });
  const orgId = `lifeorg_kms_refs_${Date.now()}`;
  const projectId = `lifeproj_kms_refs_${Date.now()}`;
  const store = new PgStore({ dsn, kmsProvider: oldKms, orgId, projectId });
  await store.init();
  t.after(() => store.close().catch(() => {}));
  await store.setSecret('service', 'before-rotation');
  const capability = await store.createCapability({ secretName: 'service', baseUrl: 'https://api.example.com' });
  let calls = 0;
  const requestHash = 'c'.repeat(64);
  const first = await store.runIdempotent({
    idempotencyKey: 'rotate-replay-1',
    requestHash,
    mutation: async () => ({ result: ++calls, marker: 'synthetic' }),
  });
  const newKms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local-rotate-new' });
  const result = await store.rotateSecrets({ newKmsProvider: newKms });
  assert.equal(result.rotatedIdempotencyResponses, 1);
  assert.equal(result.rotatedCapabilities, 1);
  assert.deepEqual(await store.runIdempotent({
    idempotencyKey: 'rotate-replay-1',
    requestHash,
    mutation: async () => ({ result: ++calls }),
  }), first);
  assert.equal(calls, 1);
  assert.equal((await store.resolveCapability(capability.token)).secretValue, 'before-rotation');
  assert.equal((await store.listCapabilities()).find((entry) => entry.id === capability.id).macKeyId, 'local-v1');
});

test('KMS rotation is isolated to the selected project within an organization', async (t) => {
  const orgId = `lifeorg_kms_sibling_${Date.now()}`;
  const oldKms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local-sibling-old' });
  const projectA = `lifeproj_a_${Date.now()}`;
  const projectB = `lifeproj_b_${Date.now()}`;
  const storeA = new PgStore({ dsn, kmsProvider: oldKms, orgId, projectId: projectA });
  const storeB = new PgStore({ dsn, kmsProvider: oldKms, orgId, projectId: projectB });
  await storeA.init();
  await storeB.init();
  t.after(() => Promise.all([storeA.close().catch(() => {}), storeB.close().catch(() => {})]));
  await storeA.setSecret('project_a_secret', 'a-value');
  await storeB.setSecret('project_b_secret', 'b-value');

  const newKms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local-sibling-new' });
  const result = await storeA.rotateSecrets({ newKmsProvider: newKms });
  assert.equal(result.keyId, 'local-sibling-new');
  assert.equal(await storeA.getSecret('project_a_secret'), 'a-value');
  assert.equal(await storeB.getSecret('project_b_secret'), 'b-value');
});

test('tenant offboarding is an ordered, auditable state machine with erasure confirmation', async (t) => {
  const store = await storeFor('offboarding');
  t.after(() => store.close().catch(() => {}));
  await store.setSecret('to_erase', 'synthetic-value');
  const cap = await store.createCapability({ secretName: 'to_erase', baseUrl: 'https://api.example.com' });
  assert.equal((await store.getTenantLifecycle()).state, 'active');
  await assert.rejects(() => store.transitionOffboarding({ state: 'erasing', expectedState: 'active', eraseConfirmed: true }), (error) => error.code === 'TGCLOUD_LIFECYCLE_CONFLICT');
  await store.transitionOffboarding({ state: 'disabling', expectedState: 'active', reason: 'synthetic-offboarding' });
  assert.equal((await store.getTenantLifecycle()).state, 'disabling');
  await assert.rejects(() => store.setSecret('blocked', 'value'), (error) => error.code === 'TGCLOUD_TENANT_DISABLED');
  assert.equal(await store.resolveCapability(cap.token), null);
  await store.transitionOffboarding({ state: 'revoking', expectedState: 'disabling', reason: 'synthetic-offboarding' });
  await assert.rejects(() => store.transitionOffboarding({ state: 'erasing', expectedState: 'revoking' }), (error) => error.code === 'TGCLOUD_ERASURE_CONFIRMATION_REQUIRED');
  await store.transitionOffboarding({ state: 'erasing', expectedState: 'revoking', eraseConfirmed: true, reason: 'synthetic-erasure' });
  await assert.rejects(() => store.getSecret('to_erase'), (error) => error.code === 'TGCLOUD_TENANT_DISABLED');
  assert.equal((await store.listCapabilities()).length, 0);
  await store.transitionOffboarding({ state: 'completed', expectedState: 'erasing', eraseConfirmed: true, reason: 'synthetic-erasure' });
  assert.equal((await store.getTenantLifecycle()).state, 'completed');
  const events = await store.listAudit({ limit: 50 });
  assert.ok(events.some((event) => event.eventType === 'tenant.offboarding'));
});
