import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createBrokerServer } from '../src/broker.js';
import { decryptSecret, encryptSecret, generateMasterKey } from '../src/crypto.js';
import { isPathAllowed, normalizeBaseUrl, resolveUpstreamUrl } from '../src/policy.js';
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
  assert.equal(isPathAllowed('/v1/models', '/v1/'), true);
  assert.equal(isPathAllowed('/v10/models', '/v1/'), false);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', 'https://evil.example/', '/'));
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2e%2e/admin', '/v1/'));
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
