import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createBrokerServer, performFetch } from '../src/broker.js';
import { decryptSecret, encryptSecret, generateMasterKey } from '../src/crypto.js';
import { isPathAllowed, normalizeBaseUrl, normalizeInjectPrefix, resolveUpstreamUrl } from '../src/policy.js';
import { SecretStore } from '../src/store.js';
import { createSecretFetch } from '../runtime/secret-fetch.js';

async function temporaryStore() {
  const dataDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-'));
  return { dataDir, store: new SecretStore({ dataDir }) };
}

async function listenHttp(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function closeHttp(server) {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(() => resolve()));
}

test('encrypts and authenticates secret values', () => {
  const key = generateMasterKey();
  const record = encryptSecret('do-not-leak', key);
  assert.notEqual(JSON.stringify(record).includes('do-not-leak'), true);
  assert.equal(decryptSecret(record, key), 'do-not-leak');
  assert.throws(() => decryptSecret(record, generateMasterKey()));
});

test('stores secrets privately and keeps capability tokens out of disk', async () => {
  const { dataDir, store } = await temporaryStore();
  await store.init();
  await store.setSecret('github', 'ghs_super_secret');
  const capability = await store.createCapability({
    secretName: 'github',
    baseUrl: 'https://api.github.com',
    pathPrefix: '/user',
    methods: ['GET'],
    injectHeader: 'authorization',
    injectPrefix: 'Bearer ',
  });

  const directory = await stat(dataDir);
  const keyFile = await stat(join(dataDir, 'master.key'));
  const storeFile = await stat(join(dataDir, 'store.json'));
  assert.equal(directory.mode & 0o077, 0);
  assert.equal(keyFile.mode & 0o077, 0);
  assert.equal(storeFile.mode & 0o077, 0);

  const onDisk = await readFile(join(dataDir, 'store.json'), 'utf8');
  assert.equal(onDisk.includes('ghs_super_secret'), false);
  assert.equal(onDisk.includes(capability.token), false);
  assert.equal((await store.getSecret('github')), 'ghs_super_secret');
  assert.equal((await store.resolveCapability(capability.token)).secretValue, 'ghs_super_secret');
  assert.equal(await store.revokeCapability(capability.id), true);
  assert.equal(await store.resolveCapability(capability.token), null);
});

test('policy rejects insecure or cross-origin requests', () => {
  assert.throws(() => normalizeBaseUrl('http://api.example.com'));
  assert.equal(normalizeBaseUrl('http://127.0.0.1:8080', { allowHttp: true }), 'http://127.0.0.1:8080/');
  assert.throws(() => normalizeBaseUrl('https://127.0.0.1'));
  assert.throws(() => normalizeBaseUrl('https://[::1]'));
  assert.throws(() => normalizeBaseUrl('https://[::ffff:127.0.0.1]'));
  assert.throws(() => normalizeInjectPrefix('Bearer\r\nInjected: yes'));
  assert.equal(isPathAllowed('/v1/models', '/v1/'), true);
  assert.equal(isPathAllowed('/v10/models', '/v1/'), false);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', 'https://evil.example/', '/'));
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2e%2e/admin', '/v1/'));
});

test('concurrent writers preserve both secret updates and symlinked stores are rejected', async () => {
  const { dataDir, store } = await temporaryStore();
  await Promise.all([
    store.setSecret('first', 'one'),
    store.setSecret('second', 'two'),
  ]);
  assert.deepEqual((await store.listSecrets()).map(({ name }) => name).sort(), ['first', 'second']);

  const linkedDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-link-'));
  await writeFile(join(linkedDir, 'target.key'), 'not-a-key');
  await symlink(join(linkedDir, 'target.key'), join(linkedDir, 'master.key'));
  const linkedStore = new SecretStore({ dataDir: linkedDir });
  await assert.rejects(() => linkedStore.init(), /non-regular secret file/);
  assert.equal(dataDir.startsWith(tmpdir()), true);
});

test('broker enforces the response limit while reading the stream', async () => {
  const capability = {
    baseUrl: 'https://api.example.com/',
    pathPrefix: '/',
    methods: ['GET'],
    injectHeader: 'x-api-key',
    injectPrefix: '',
    secretValue: 'secret-value',
  };
  await assert.rejects(
    () => performFetch({
      capability,
      requestPayload: { path: '/large' },
      maxResponseBytes: 4,
      timeoutMs: 1_000,
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: async () => new Response('12345', { headers: { 'content-type': 'text/plain' } }),
    }),
    /Upstream response is too large/,
  );
});

test('broker refuses DNS results that resolve into private networks', async () => {
  const capability = {
    baseUrl: 'https://api.example.com/',
    pathPrefix: '/',
    methods: ['GET'],
    injectHeader: 'x-api-key',
    injectPrefix: '',
    secretValue: 'secret-value',
  };
  let called = false;
  await assert.rejects(
    () => performFetch({
      capability,
      requestPayload: { path: '/health' },
      maxResponseBytes: 1_024,
      timeoutMs: 1_000,
      lookupImpl: async () => [{ address: '169.254.169.254', family: 4 }],
      fetchImpl: async () => {
        called = true;
        return new Response('unexpected');
      },
    }),
    /private or link-local/,
  );
  assert.equal(called, false);
});

test('broker injects the secret and runtime helper receives the upstream response', async (t) => {
  const { store } = await temporaryStore();
  await store.init();
  await store.setSecret('demo', 'secret-value');

  let seenAuthorization;
  const upstream = createServer((request, response) => {
    seenAuthorization = request.headers.authorization;
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('upstream-ok');
  });
  const upstreamBase = await listenHttp(upstream);
  t.after(() => closeHttp(upstream));

  const capability = await store.createCapability({
    secretName: 'demo',
    baseUrl: upstreamBase,
    pathPrefix: '/v1/',
    methods: ['GET'],
    injectHeader: 'authorization',
    injectPrefix: 'Bearer ',
    allowHttp: true,
  });
  const broker = createBrokerServer({
    store,
    host: '127.0.0.1',
    port: 0,
    logger: { info() {}, error() {} },
  });
  const brokerAddress = await broker.listen();
  t.after(() => broker.close());
  const endpoint = `http://127.0.0.1:${brokerAddress.port}`;

  const secretFetch = createSecretFetch({ endpoint, capability: capability.token });
  const response = await secretFetch('/v1/health');
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'upstream-ok');
  assert.equal(seenAuthorization, 'Bearer secret-value');
});

test('broker rejects invalid capabilities, disallowed methods, and injected-header overrides', async (t) => {
  const { store } = await temporaryStore();
  await store.init();
  await store.setSecret('demo', 'secret-value');
  const upstream = createServer((_request, response) => response.end('should-not-run'));
  const upstreamBase = await listenHttp(upstream);
  t.after(() => closeHttp(upstream));
  const capability = await store.createCapability({ secretName: 'demo', baseUrl: upstreamBase, pathPrefix: '/v1/', methods: ['GET'], allowHttp: true });
  const broker = createBrokerServer({ store, host: '127.0.0.1', port: 0, logger: { info() {}, error() {} } });
  const address = await broker.listen();
  t.after(() => broker.close());
  const endpoint = `http://127.0.0.1:${address.port}/v1/fetch`;

  const invalid = await fetch(endpoint, { method: 'POST', headers: { 'x-tgcloud-capability': 'tgscap_invalid', 'content-type': 'application/json' }, body: JSON.stringify({ path: '/v1/health' }) });
  assert.equal(invalid.status, 401);

  const disallowed = await fetch(endpoint, { method: 'POST', headers: { 'x-tgcloud-capability': capability.token, 'content-type': 'application/json' }, body: JSON.stringify({ path: '/v1/health', method: 'POST' }) });
  assert.equal(disallowed.status, 400);

  const override = await fetch(endpoint, { method: 'POST', headers: { 'x-tgcloud-capability': capability.token, 'content-type': 'application/json' }, body: JSON.stringify({ path: '/v1/health', headers: { authorization: 'attacker-value' } }) });
  assert.equal(override.status, 400);
});

test('broker rate-limits each capability', async (t) => {
  const { store } = await temporaryStore();
  await store.init();
  await store.setSecret('demo', 'secret-value');
  const capability = await store.createCapability({ secretName: 'demo', baseUrl: 'https://api.example.com', pathPrefix: '/', methods: ['GET'] });
  const broker = createBrokerServer({
    store,
    host: '127.0.0.1',
    port: 0,
    maxRequestsPerMinute: 1,
    lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
    fetchImpl: async () => new Response('ok'),
    logger: { info() {}, error() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const endpoint = `http://127.0.0.1:${address.port}/v1/fetch`;
  const options = { method: 'POST', headers: { 'x-tgcloud-capability': capability.token, 'content-type': 'application/json' }, body: JSON.stringify({ path: '/health' }) };
  assert.equal((await fetch(endpoint, options)).status, 200);
  const limited = await fetch(endpoint, options);
  assert.equal(limited.status, 429);
  assert.equal(Number(limited.headers.get('retry-after')) > 0, true);
});
