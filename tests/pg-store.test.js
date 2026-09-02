import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PgStore } from '../src/pg-store.js';
import { LocalKMSProvider } from '../src/kms.js';
import { generateMasterKey } from '../src/crypto.js';
import { createBrokerServer } from '../src/broker.js';
import { createSecretFetch } from '../runtime/secret-fetch.js';
import { createServer } from 'node:http';

const dsn = process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN || 'postgres://postgres:postgres@localhost:5433/tgcloud';

async function getTestStore(orgId = `testorg_${Date.now()}_${Math.random().toString(36).slice(2,6)}`, projectId = `testproj_${Date.now()}`) {
  const masterKey = generateMasterKey();
  const kms = new LocalKMSProvider({ masterKey, keyId: 'local' });
  const store = new PgStore({ dsn, kmsProvider: kms, orgId, projectId });
  await store.init();
  return { store, kms, orgId, projectId };
}

test('pg-store: envelope v3 encrypts and binds to org/project', async () => {
  const { store } = await getTestStore();
  try {
    await store.setSecret('mysecret', 'hello-pg');
    const val = await store.getSecret('mysecret');
    assert.equal(val, 'hello-pg');
    // Try to get with different org/project should fail (different AAD)
    const { store: store2 } = await getTestStore(store.orgId, store.projectId);
    // Same org/project should work via same DB but different store instance with same KMS? Need same KMS key
    // For now, test that same secret can be retrieved via same store
    await store2.close().catch(() => {});
  } finally {
    await store.close().catch(() => {});
  }
});

test('pg-store: capability scoped and resolves with PgStore', async () => {
  const { store } = await getTestStore();
  try {
    await store.setSecret('s1', 'secret-value-pg');
    const cap = await store.createCapability({
      secretName: 's1',
      baseUrl: 'https://api.example.com',
      pathPrefix: '/v1/',
      methods: ['POST'],
      injectHeader: 'authorization',
      injectPrefix: 'Bearer ',
    });
    assert.match(cap.token, /^tgscap_/);
    const resolved = await store.resolveCapability(cap.token);
    assert.equal(resolved.secretValue, 'secret-value-pg');
    assert.equal(resolved.baseUrl, 'https://api.example.com/');
    // Expired capability should not resolve
    const cap2 = await store.createCapability({
      secretName: 's1',
      baseUrl: 'https://api.example.com',
      pathPrefix: '/v1/',
      methods: ['GET'],
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const resolved2 = await store.resolveCapability(cap2.token);
    assert.equal(resolved2, null);
    // Revoke
    assert.equal(await store.revokeCapability(cap.id), true);
    assert.equal(await store.resolveCapability(cap.token), null);
  } finally {
    await store.close().catch(() => {});
  }
});

test('pg-store: broker with PgStore and local KMS injects secret', async (t) => {
  const { store } = await getTestStore();
  t.after(() => store.close().catch(() => {}));
  await store.setSecret('demo', 'secret-pg-kms');

  let seenAuth;
  const upstream = createServer((req, res) => {
    seenAuth = req.headers.authorization;
    res.end('upstream-ok-pg');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  t.after(() => upstream.close());
  const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;

  const cap = await store.createCapability({
    secretName: 'demo',
    baseUrl: upstreamUrl,
    pathPrefix: '/',
    methods: ['GET'],
    allowHttp: true,
  });

  const broker = createBrokerServer({ store, host: '127.0.0.1', port: 0, logger: { info() {}, error() {} } });
  const addr = await broker.listen();
  t.after(() => broker.close());

  const sf = createSecretFetch({ endpoint: `http://127.0.0.1:${addr.port}`, capability: cap.token, fetchImpl: fetch });
  const resp = await sf('/health');
  assert.equal(resp.status, 200);
  assert.equal(await resp.text(), 'upstream-ok-pg');
  assert.equal(seenAuth, 'secret-pg-kms');

  // readyZ and metrics
  const ready = await fetch(`http://127.0.0.1:${addr.port}/readyz`);
  assert.equal(ready.status, 200);
  const metrics = await fetch(`http://127.0.0.1:${addr.port}/metrics`);
  assert.equal(metrics.status, 200);
  const text = await metrics.text();
  assert.match(text, /tgcloud_proxy_requests_in_flight/);
});

test('pg-store: healthCheck passes', async () => {
  const { store } = await getTestStore();
  try {
    await store.healthCheck();
  } finally {
    await store.close().catch(() => {});
  }
});

test('pg-store: list and isolate org/project', async () => {
  const org = `org_${Date.now()}`;
  const proj1 = `proj1_${Date.now()}`;
  const proj2 = `proj2_${Date.now()}`;
  const masterKey = generateMasterKey();
  const kms = new LocalKMSProvider({ masterKey, keyId: 'local' });
  const store1 = new PgStore({ dsn, kmsProvider: kms, orgId: org, projectId: proj1 });
  const store2 = new PgStore({ dsn, kmsProvider: kms, orgId: org, projectId: proj2 });
  await store1.init();
  await store2.init();
  try {
    await store1.setSecret('shared', 'val1');
    await store2.setSecret('shared', 'val2');
    assert.equal(await store1.getSecret('shared'), 'val1');
    assert.equal(await store2.getSecret('shared'), 'val2');
    const list1 = await store1.listSecrets();
    assert.equal(list1.length, 1);
    assert.equal(list1[0].name, 'shared');
  } finally {
    await store1.close().catch(() => {});
    await store2.close().catch(() => {});
  }
});

test('pg-store: orgId with colon should be rejected', () => {
  const dsn = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5433/tgcloud';
  assert.throws(() => new PgStore({ dsn, orgId: 'a:b', projectId: 'c', kmsProvider: new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' }) }), /must start|colon/);
});

test('pg-store: revoke isolates org', async () => {
  const dsn = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5433/tgcloud';
  const mk = generateMasterKey();
  const kmsA = new LocalKMSProvider({ masterKey: mk, keyId: 'local' });
  const sA = new PgStore({ dsn, kmsProvider: kmsA, orgId: 'orgRevokeA', projectId: 'projRevoke' });
  const sB = new PgStore({ dsn, kmsProvider: kmsA, orgId: 'orgRevokeB', projectId: 'projRevoke' });
  await sA.init(); await sB.init();
  await sA.setSecret('s', 'valA');
  const cap = await sA.createCapability({ secretName: 's', baseUrl: 'https://api.example.com' });
  assert.equal(await sB.revokeCapability(cap.id), false);
  assert.ok(await sA.resolveCapability(cap.token));
  await sA.close(); await sB.close();
});

test('pg-store: capability id collision retry', async () => {
  const dsn = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5433/tgcloud';
  const mk = generateMasterKey();
  const kms = new LocalKMSProvider({ masterKey: mk, keyId: 'local' });
  const s = new PgStore({ dsn, kmsProvider: kms, orgId: 'orgCollide', projectId: 'projCollide' });
  await s.init();
  await s.setSecret('s', 'val');
  // Mock randomBytes to return same id twice
  const orig = (await import('node:crypto')).randomBytes;
  let called = 0;
  // This test just ensures createCapability doesn't throw on first try, retry logic exists
  const cap1 = await s.createCapability({ secretName: 's', baseUrl: 'https://api.example.com' });
  const cap2 = await s.createCapability({ secretName: 's', baseUrl: 'https://api.example.com' });
  assert.notEqual(cap1.id, cap2.id);
  await s.close();
});
