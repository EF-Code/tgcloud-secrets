import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PgStore } from '../src/pg-store.js';
import { LocalKMSProvider } from '../src/kms.js';
import { generateMasterKey } from '../src/crypto.js';
import { createAdminServer } from '../src/admin.js';

const dsn = process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN || 'postgres://postgres:postgres@localhost:5433/tgcloud';

test('admin control plane authenticates, authorizes, audits, and encrypts idempotent responses', async (t) => {
  const orgId = `adminorg_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const projectId = `adminproj_${Date.now()}`;
  const store = new PgStore({ dsn, kmsProvider: new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' }), orgId, projectId });
  await store.init();
  t.after(() => store.close().catch(() => {}));
  const admin = createAdminServer({
    store,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => ({ authenticated: true, subject: 'owner@example.test', roles: ['organization_owner'], orgId, projectId, mfaSatisfied: true }),
    logger: { error() {} },
  });
  const address = await admin.listen();
  t.after(() => admin.close().catch(() => {}));
  const endpoint = `http://127.0.0.1:${address.port}`;
  const marker = `synthetic-${Date.now()}`;
  const malformed = await fetch(`${endpoint}/v1/admin/secrets`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'malformed-key-1' },
    body: '{"name":',
  });
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: 'invalid_request' });
  const wrongMediaType = await fetch(`${endpoint}/v1/admin/secrets`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain', 'idempotency-key': 'media-key-1' },
    body: '{}',
  });
  assert.equal(wrongMediaType.status, 415);
  assert.deepEqual(await wrongMediaType.json(), { error: 'unsupported_media_type' });
  const queryMutation = await fetch(`${endpoint}/v1/admin/secrets?value=${encodeURIComponent(marker)}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'query-key-1' },
    body: '{}',
  });
  assert.equal(queryMutation.status, 400);
  assert.deepEqual(await queryMutation.json(), { error: 'invalid_request' });
  const secretBody = JSON.stringify({ name: 'admin_secret', value: marker });
  const secretOptions = { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'secret-key-1' }, body: secretBody };
  const first = await fetch(`${endpoint}/v1/admin/secrets`, secretOptions);
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { name: 'admin_secret', version: 1 });
  assert.equal(await store.getSecret('admin_secret'), marker);
  const replay = await fetch(`${endpoint}/v1/admin/secrets`, secretOptions);
  assert.equal(replay.status, 200);
  assert.deepEqual(await replay.json(), { name: 'admin_secret', version: 1 });
  const conflict = await fetch(`${endpoint}/v1/admin/secrets`, { ...secretOptions, body: JSON.stringify({ name: 'admin_secret', value: 'different' }) });
  assert.equal(conflict.status, 409);

  const capabilityBody = JSON.stringify({ secretName: 'admin_secret', baseUrl: 'https://api.example.com', methods: ['GET'] });
  const grant = await fetch(`${endpoint}/v1/admin/capabilities`, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'grant-key-1' }, body: capabilityBody });
  assert.equal(grant.status, 201);
  const capability = await grant.json();
  assert.match(capability.token, /^tgscap_/);
  const idempotency = await store._withTenantTransaction((client) => client.query(
    `SELECT response, response_envelope FROM idempotency_keys WHERE org_id=$1 AND project_id=$2 ORDER BY id`,
    [orgId, `${orgId}:${projectId}`],
  ));
  assert.equal(idempotency.rows.every((row) => row.response === null), true);
  assert.equal(idempotency.rows.every((row) => row.response_envelope !== null), true);
  assert.equal(JSON.stringify(idempotency.rows).includes(capability.token), false);

  const revoke = await fetch(`${endpoint}/v1/admin/capabilities/${capability.id}/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'revoke-key-1' },
    body: JSON.stringify({ reason: 'test-revocation' }),
  });
  assert.equal(revoke.status, 200);
  assert.equal((await revoke.json()).revoked, true);
  assert.equal(await store.resolveCapability(capability.token), null);

  const audit = await fetch(`${endpoint}/v1/admin/audit?limit=20`);
  assert.equal(audit.status, 200);
  const events = (await audit.json()).events;
  assert.ok(events.some((event) => event.eventType === 'admin.secret.upsert'));
  assert.equal(JSON.stringify(events).includes(marker), false);
  assert.equal(JSON.stringify(events).includes(capability.token), false);
});

test('admin destructive actions cannot use a caller-supplied approval identity', async (t) => {
  const orgId = `adminorg_delete_${Date.now()}`;
  const projectId = `adminproj_delete_${Date.now()}`;
  const store = new PgStore({ dsn, kmsProvider: new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' }), orgId, projectId });
  await store.init();
  await store.setSecret('deletable', 'synthetic-value');
  t.after(() => store.close().catch(() => {}));
  const admin = createAdminServer({
    store,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => ({ authenticated: true, subject: 'owner@example.test', roles: ['organization_owner'], orgId, projectId, mfaSatisfied: false }),
    logger: { error() {} },
  });
  const address = await admin.listen();
  t.after(() => admin.close().catch(() => {}));
  const endpoint = `http://127.0.0.1:${address.port}/v1/admin/secrets/deletable/delete`;
  const denied = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'delete-key-1' }, body: JSON.stringify({}) });
  assert.equal(denied.status, 403);
  const claimed = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'delete-key-2' }, body: JSON.stringify({ approvedBy: 'second@example.test' }) });
  assert.equal(claimed.status, 400);
  assert.equal(await store.getSecret('deletable'), 'synthetic-value');
});

test('admin audit rejects bearer material in a user-supplied reason without committing the mutation', async (t) => {
  const orgId = `adminorg_audit_${Date.now()}`;
  const projectId = `adminproj_audit_${Date.now()}`;
  const store = new PgStore({ dsn, kmsProvider: new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' }), orgId, projectId });
  await store.init();
  await store.setSecret('audited', 'synthetic-value');
  const capability = await store.createCapability({ secretName: 'audited', baseUrl: 'https://api.example.com' });
  t.after(() => store.close().catch(() => {}));
  const admin = createAdminServer({
    store,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => ({ authenticated: true, subject: 'owner@example.test', roles: ['organization_owner'], orgId, projectId, mfaSatisfied: true }),
    logger: { error() {} },
  });
  const address = await admin.listen();
  t.after(() => admin.close().catch(() => {}));
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/admin/capabilities/${capability.id}/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'unsafe-audit-1' },
    body: JSON.stringify({ reason: 'Bearer tgscap_1234567890123456' }),
  });
  assert.equal(response.status, 400);
  assert.equal((await store.resolveCapability(capability.token))?.secretValue, 'synthetic-value');
});

test('admin exposes audited rollback and capability rotation with durable idempotency', async (t) => {
  const orgId = `adminorg_rotate_${Date.now()}`;
  const projectId = `adminproj_rotate_${Date.now()}`;
  const store = new PgStore({ dsn, kmsProvider: new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' }), orgId, projectId });
  await store.init();
  await store.setSecret('rotatable', 'version-one');
  await store.setSecret('rotatable', 'version-two', { expectedVersion: 1 });
  const original = await store.createCapability({ secretName: 'rotatable', baseUrl: 'https://api.example.com' });
  t.after(() => store.close().catch(() => {}));
  const admin = createAdminServer({
    store,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => ({ authenticated: true, subject: 'owner@example.test', roles: ['organization_owner'], orgId, projectId, mfaSatisfied: true, stepUpAt: new Date().toISOString() }),
    logger: { error() {} },
  });
  const address = await admin.listen();
  t.after(() => admin.close().catch(() => {}));
  const endpoint = `http://127.0.0.1:${address.port}`;

  const rollbackOptions = {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'rollback-key-1' },
    body: JSON.stringify({ version: 1, expectedVersion: 2 }),
  };
  const rollback = await fetch(`${endpoint}/v1/admin/secrets/rotatable/rollback`, rollbackOptions);
  assert.equal(rollback.status, 200);
  assert.deepEqual(await rollback.json(), { name: 'rotatable', version: 3, restoredVersion: 1 });
  assert.equal(await store.getSecret('rotatable'), 'version-one');
  const rollbackReplay = await fetch(`${endpoint}/v1/admin/secrets/rotatable/rollback`, rollbackOptions);
  assert.equal(rollbackReplay.status, 200);
  assert.deepEqual(await rollbackReplay.json(), { name: 'rotatable', version: 3, restoredVersion: 1 });

  const rotate = await fetch(`${endpoint}/v1/admin/capabilities/${original.id}/rotate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'rotate-key-1' },
    body: JSON.stringify({ overlapMs: 0 }),
  });
  assert.equal(rotate.status, 200);
  const replacement = await rotate.json();
  assert.match(replacement.token, /^tgscap_/);
  assert.notEqual(replacement.id, original.id);
  assert.equal((await store.resolveCapability(original.token)), null);
  assert.equal((await store.resolveCapability(replacement.token))?.secretValue, 'version-one');

  const audit = await fetch(`${endpoint}/v1/admin/audit?limit=100`);
  assert.equal(audit.status, 200);
  const events = (await audit.json()).events;
  const rollbackEvent = events.find((event) => event.eventType === 'admin.secret.rollback');
  const rotateEvent = events.find((event) => event.eventType === 'admin.capability.rotate');
  assert.equal(rollbackEvent?.payload?.decisionEvidence?.mfaSatisfied, true);
  assert.equal(rollbackEvent?.payload?.decisionEvidence?.stepUpAt !== null, true);
  assert.equal(rotateEvent?.payload?.decisionEvidence?.mfaSatisfied, true);
  assert.equal(JSON.stringify(events).includes(original.token), false);
  assert.equal(JSON.stringify(events).includes(replacement.token), false);
});

test('admin authentication adapters are bounded and fail as dependency errors', async (t) => {
  const admin = createAdminServer({
    store: { runIdempotent: async () => { throw new Error('must not mutate'); } },
    host: '127.0.0.1',
    port: 0,
    authTimeoutMs: 100,
    authenticate: async () => new Promise(() => {}),
    logger: { error() {} },
  });
  const address = await admin.listen();
  t.after(() => admin.close().catch(() => {}));
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/admin/secrets`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'auth-timeout-1' },
    body: JSON.stringify({ name: 'never-written', value: 'synthetic' }),
  });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'dependency_unavailable' });
});

test('tenant revocation routes retain organization scope and reject downgrade attempts', async (t) => {
  const orgId = `scopeorg_${Date.now()}`;
  const projectId = `scopeproj_${Date.now()}`;
  let mutationScope;
  const store = {
    async runIdempotent({ mutation }) {
      return mutation({ query: async () => ({ rows: [] }) });
    },
    async _setTenantRevocationInClient(_client, options) {
      mutationScope = options;
    },
  };
  const admin = createAdminServer({
    store,
    host: '127.0.0.1',
    port: 0,
    authenticate: async () => ({ authenticated: true, subject: 'owner@example.test', roles: ['organization_owner'], orgId, projectId, mfaSatisfied: true }),
    logger: { error() {} },
  });
  const address = await admin.listen();
  t.after(() => admin.close().catch(() => {}));
  const endpoint = `http://127.0.0.1:${address.port}/v1/admin/tenants/revoke`;
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'tenant-scope-1' },
    body: JSON.stringify({ reason: 'organization-test' }),
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { orgId, projectId: null, revoked: true });
  assert.equal(mutationScope.organization, true);

  const downgrade = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'idempotency-key': 'tenant-scope-2' },
    body: JSON.stringify({ organization: false }),
  });
  assert.equal(downgrade.status, 400);
  assert.deepEqual(await downgrade.json(), { error: 'invalid_request' });
});
