import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, stat, symlink, unlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createBrokerServer, fetchWithPinnedAddress, performFetch, readBody } from '../src/broker.js';
import { decryptSecret, encryptSecret, generateMasterKey } from '../src/crypto.js';
import {
  isPathAllowed,
  isPrivateHost,
  normalizeBaseUrl,
  normalizeInjectPrefix,
  normalizePathPrefix,
  resolveUpstreamUrl,
  sanitizeForwardHeaders,
} from '../src/policy.js';
import { SecretStore } from '../src/store.js';
import { createSecretFetch } from '../runtime/secret-fetch.js';
import { parseRequestFraming } from '../src/http.js';

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
  const record = encryptSecret('do-not-leak', key, 'demo');
  assert.notEqual(JSON.stringify(record).includes('do-not-leak'), true);
  assert.equal(record.version, 2);
  assert.equal(decryptSecret(record, key, 'demo'), 'do-not-leak');
  assert.throws(() => decryptSecret(record, key, 'other'));
  assert.throws(() => decryptSecret(record, generateMasterKey(), 'demo'));
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
  assert.throws(() => normalizeInjectPrefix('prefix\u0000value'));
  assert.equal(isPathAllowed('/v1/models', '/v1/'), true);
  assert.equal(isPathAllowed('/v10/models', '/v1/'), false);
  assert.equal(isPrivateHost('fed0::1'), true);
  assert.equal(isPrivateHost('0:0:0:0:0:ffff:7f00:1'), true);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', 'https://evil.example/', '/'));
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2e%2e/admin', '/v1/'));
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2e%2e%5cadmin', '/v1/'));
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%00/admin', '/v1/'));
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%252e%252e/admin', '/v1/'));
  for (const encodedControl of ['%01', '%09', '%0a', '%0d', '%1f', '%7f', '%250a']) {
    assert.throws(() => resolveUpstreamUrl('https://api.example.com/', `/v1/${encodedControl}health`, '/v1/'));
  }
  assert.throws(() => normalizePathPrefix('/v1/%0d/'));
  assert.equal(normalizeBaseUrl('http://127.0.0.2', { allowHttp: true }), 'http://127.0.0.2/');
  assert.equal(isPrivateHost('64:ff9b::7f00:1'), true);
  assert.equal(isPrivateHost('2002:7f00:1::'), true);
  assert.equal(isPrivateHost('2001:0:4136:e378:8000:63bf:3fff:fdd2'), true);
  assert.equal(sanitizeForwardHeaders({ 'x-http-method-override': 'DELETE' }, 'authorization').has('x-http-method-override'), false);
  assert.throws(() => sanitizeForwardHeaders([], 'authorization'));
});

test('store rejects unsafe secret values and invalid capability IDs', async () => {
  const { store } = await temporaryStore();
  await assert.rejects(() => store.setSecret('unsafe', 'prefix\u0000SECRET-DO-NOT-LOG'), /unsafe control characters/);
  await assert.rejects(() => store.setSecret('unicode', 'secret-😀'), /HTTP-safe string/);
  await assert.rejects(() => store.getSecret('toString'), /Secret not found/);
  await assert.rejects(() => store.revokeCapability('toString'), /Capability ID is invalid/);
});

test('store rejects a mismatched supplied master key', async () => {
  const { dataDir } = await temporaryStore();
  const first = new SecretStore({ dataDir, masterKey: generateMasterKey() });
  await first.init();
  const second = new SecretStore({ dataDir, masterKey: generateMasterKey() });
  await assert.rejects(() => second.init(), /does not match the existing store key/);
});

test('store refuses capability metadata tampering and malformed JSON shapes', async () => {
  const { dataDir, store } = await temporaryStore();
  await store.init();
  await store.setSecret('low', 'low-secret');
  await store.setSecret('high', 'high-secret');
  const capability = await store.createCapability({ secretName: 'low', baseUrl: 'https://api.example.com' });
  const storePath = join(dataDir, 'store.json');
  const parsed = JSON.parse(await readFile(storePath, 'utf8'));
  parsed.capabilities[capability.id].secretName = 'high';
  await writeFile(storePath, `${JSON.stringify(parsed)}\n`);
  assert.equal(await store.resolveCapability(capability.token), null);
  await writeFile(storePath, 'null\n');
  await assert.rejects(() => store.listSecrets(), /Unsupported secret store format/);
});

test('store binds each capability token to its authenticated policy', async () => {
  const { dataDir, store } = await temporaryStore();
  await store.init();
  await store.setSecret('low', 'low-secret');
  await store.setSecret('high', 'high-secret');
  const low = await store.createCapability({ secretName: 'low', baseUrl: 'https://low.example.com' });
  const high = await store.createCapability({ secretName: 'high', baseUrl: 'https://high.example.com' });

  const storePath = join(dataDir, 'store.json');
  const parsed = JSON.parse(await readFile(storePath, 'utf8'));
  const lowHash = parsed.capabilities[low.id].tokenHash;
  parsed.capabilities[low.id].tokenHash = parsed.capabilities[high.id].tokenHash;
  parsed.capabilities[high.id].tokenHash = lowHash;
  await writeFile(storePath, `${JSON.stringify(parsed)}\n`);

  assert.equal(await store.resolveCapability(low.token), null);
  assert.equal(await store.resolveCapability(high.token), null);
});

test('store binds encrypted secret records to their logical names', async () => {
  const { dataDir, store } = await temporaryStore();
  await store.init();
  await store.setSecret('low', 'low-secret');
  await store.setSecret('high', 'high-secret');
  const low = await store.createCapability({ secretName: 'low', baseUrl: 'https://low.example.com' });

  const storePath = join(dataDir, 'store.json');
  const parsed = JSON.parse(await readFile(storePath, 'utf8'));
  const lowRecord = parsed.secrets.low.encrypted;
  parsed.secrets.low.encrypted = parsed.secrets.high.encrypted;
  parsed.secrets.high.encrypted = lowRecord;
  await writeFile(storePath, `${JSON.stringify(parsed)}\n`);

  await assert.rejects(() => store.getSecret('low'), /Unsupported encrypted secret record/);
  await assert.rejects(() => store.resolveCapability(low.token), /Unsupported encrypted secret record/);
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

test('stale dead lock is reaped before the next writer proceeds', async () => {
  const { dataDir, store } = await temporaryStore();
  await store.init();
  const lockPath = join(dataDir, '.lock');
  await writeFile(lockPath, '{"pid":0,"createdAt":"2000-01-01T00:00:00.000Z"}\n', { mode: 0o600 });
  const stale = new Date(Date.now() - 6 * 60 * 1_000);
  await utimes(lockPath, stale, stale);

  await store.setSecret('after-lock', 'value');
  assert.equal(await store.getSecret('after-lock'), 'value');
  await assert.rejects(() => stat(lockPath), { code: 'ENOENT' });
});

test('lock quarantine remains held until reclamation completes', async () => {
  const { dataDir, store } = await temporaryStore();
  await store.init();
  const quarantinePath = join(dataDir, '.lock.stale-test');
  await writeFile(quarantinePath, `{"pid":${process.pid}}\n`, { mode: 0o600 });
  const stale = new Date(Date.now() - 6 * 60 * 1_000);
  await utimes(quarantinePath, stale, stale);
  const releaseQuarantine = setTimeout(() => unlink(quarantinePath).catch(() => {}), 100);
  const startedAt = Date.now();
  await store.setSecret('after-quarantine', 'value');
  clearTimeout(releaseQuarantine);
  assert.ok(Date.now() - startedAt >= 75);
  assert.equal(await store.getSecret('after-quarantine'), 'value');
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

test('broker pins the verified address while preserving the upstream host', async (t) => {
  let seenHost;
  const upstream = createServer((request, response) => {
    seenHost = request.headers.host;
    response.end('pinned-ok');
  });
  const upstreamBase = await listenHttp(upstream);
  t.after(() => closeHttp(upstream));
  const target = new URL(`http://api.example.com:${new URL(upstreamBase).port}/health`);
  const response = await fetchWithPinnedAddress(
    target,
    { method: 'GET', headers: new Headers(), signal: new AbortController().signal },
    { address: '127.0.0.1', family: 4 },
  );
  assert.equal(await response.text(), 'pinned-ok');
  assert.equal(seenHost, `api.example.com:${new URL(upstreamBase).port}`);
});

test('broker refuses private literal targets even in a malformed capability', async () => {
  let called = false;
  await assert.rejects(
    () => performFetch({
      capability: {
        baseUrl: 'https://127.0.0.1/',
        pathPrefix: '/',
        methods: ['GET'],
        injectHeader: 'x-api-key',
        injectPrefix: '',
        secretValue: 'secret-value',
      },
      requestPayload: { path: '/health' },
      maxResponseBytes: 1_024,
      timeoutMs: 1_000,
      fetchImpl: async () => {
        called = true;
        return new Response('unexpected');
      },
    }),
    /private or link-local/,
  );
  assert.equal(called, false);
});

test('broker refuses remote HTTP targets even in malformed capabilities', async () => {
  let called = false;
  await assert.rejects(
    () => performFetch({
      capability: {
        baseUrl: 'http://api.example.com/',
        pathPrefix: '/',
        methods: ['GET'],
        injectHeader: 'x-api-key',
        injectPrefix: '',
        secretValue: 'secret-value',
        allowHttp: false,
      },
      requestPayload: { path: '/health' },
      maxResponseBytes: 1_024,
      timeoutMs: 1_000,
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: async () => {
        called = true;
        return new Response('unexpected');
      },
    }),
    /HTTP upstreams are restricted/,
  );
  assert.equal(called, false);
});

test('broker cancels declared oversized upstream responses', async () => {
  let canceled = false;
  await assert.rejects(
    () => performFetch({
      capability: {
        baseUrl: 'https://api.example.com/',
        pathPrefix: '/',
        methods: ['GET'],
        injectHeader: 'x-api-key',
        injectPrefix: '',
        secretValue: 'secret-value',
      },
      requestPayload: { path: '/large' },
      maxResponseBytes: 4,
      timeoutMs: 1_000,
      lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
      fetchImpl: async () => ({
        headers: new Headers({ 'content-length': '5' }),
        body: { cancel: async () => { canceled = true; } },
      }),
    }),
    /Upstream response is too large/,
  );
  assert.equal(canceled, true);
});

test('broker strips representation headers after buffering upstream bytes', async () => {
  let requestHeaders;
  const result = await performFetch({
    capability: {
      baseUrl: 'https://api.example.com/',
      pathPrefix: '/',
      methods: ['GET'],
      injectHeader: 'x-api-key',
      injectPrefix: '',
      secretValue: 'secret-value',
    },
    requestPayload: { path: '/health' },
    maxResponseBytes: 1_024,
    timeoutMs: 1_000,
    lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
    fetchImpl: async (_url, options) => {
      requestHeaders = options.headers;
      return new Response('decoded bytes', { headers: {
        'content-encoding': 'gzip',
        etag: '"compressed"',
        digest: 'sha-256=bad-for-decoded-bytes',
        'content-type': 'text/plain',
      } });
    },
  });
  assert.equal(requestHeaders.get('accept-encoding'), 'identity');
  assert.equal(result.headers['content-encoding'], undefined);
  assert.equal(result.headers.etag, undefined);
  assert.equal(result.headers.digest, undefined);
  assert.equal(result.headers['content-type'], 'text/plain');
});

test('broker forwards non-redirect 3xx statuses', async () => {
  const capability = {
    baseUrl: 'https://api.example.com/',
    pathPrefix: '/',
    methods: ['GET'],
    injectHeader: 'x-api-key',
    injectPrefix: '',
    secretValue: 'secret-value',
  };
  const options = {
    capability,
    requestPayload: { path: '/health' },
    maxResponseBytes: 1_024,
    timeoutMs: 1_000,
    lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
  };
  const notModified = await performFetch({ ...options, fetchImpl: async () => new Response(null, { status: 304 }) });
  assert.equal(notModified.status, 304);
  const other = await performFetch({ ...options, fetchImpl: async () => new Response('choice', { status: 399 }) });
  assert.equal(other.status, 399);
});

test('broker does not log malformed secret values', async (t) => {
  const token = `tgscap_${'b'.repeat(32)}`;
  const leakedValue = 'prefix\u0000SECRET-DO-NOT-LOG';
  const errors = [];
  const broker = createBrokerServer({
    store: { resolveCapability: async () => ({
      id: 'cap_00000000000000000000',
      baseUrl: 'https://api.example.com/',
      pathPrefix: '/',
      methods: ['GET'],
      injectHeader: 'x-api-key',
      injectPrefix: '',
      secretValue: leakedValue,
    }) },
    host: '127.0.0.1',
    port: 0,
    logger: { info() {}, error(...args) { errors.push(args); } },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/fetch`, {
    method: 'POST',
    headers: { 'x-tgcloud-capability': token, 'content-type': 'application/json' },
    body: JSON.stringify({ path: '/health' }),
  });
  assert.equal(response.status, 502);
  assert.equal(JSON.stringify(errors).includes(leakedValue), false);
});

test('runtime helper rejects remote HTTP broker endpoints', () => {
  const capability = `tgscap_${'a'.repeat(32)}`;
  assert.throws(
    () => createSecretFetch({ endpoint: 'http://secrets.example.com', capability, fetchImpl: async () => new Response() }),
    /HTTP broker endpoints are allowed only for loopback/,
  );
  assert.doesNotThrow(() => createSecretFetch({ endpoint: 'http://127.0.0.1:8787', capability, fetchImpl: async () => new Response() }));
});

test('runtime helper forbids redirects and forwards caller cancellation', async () => {
  const capability = `tgscap_${'c'.repeat(32)}`;
  const controller = new AbortController();
  let seen;
  const secretFetch = createSecretFetch({
    endpoint: 'https://secrets.example.com',
    capability,
    fetchImpl: async (_url, options) => {
      seen = options;
      return new Response('ok');
    },
  });
  const response = await secretFetch('/v1/health', { signal: controller.signal });
  assert.equal(response.status, 200);
  assert.equal(seen.redirect, 'error');
  assert.equal(seen.credentials, 'omit');
  assert.equal(seen.signal, controller.signal);
});

test('runtime helper bounds serialized client requests before sending them', async () => {
  let called = false;
  const secretFetch = createSecretFetch({
    endpoint: 'https://secrets.example.com',
    capability: `tgscap_${'h'.repeat(32)}`,
    fetchImpl: async () => {
      called = true;
      return new Response('unexpected');
    },
  });
  await assert.rejects(
    () => secretFetch('/v1/large', { body: 'x'.repeat(1024 * 1024) }),
    /request is too large/,
  );
  assert.equal(called, false);
});

test('request body limit is marked for connection close', async () => {
  const request = { headers: { 'content-length': '10' } };
  await assert.rejects(
    () => readBody(request, 4),
    (error) => error.statusCode === 413 && error.closeConnection === true,
  );
});

test('HTTP framing rejects ambiguous or non-canonical lengths', () => {
  assert.deepEqual(parseRequestFraming({ headers: { 'content-length': '5' } }), { contentLength: 5, chunked: false, hasBody: true });
  assert.deepEqual(parseRequestFraming({ headers: { 'transfer-encoding': 'chunked' } }), { contentLength: null, chunked: true, hasBody: true });
  assert.throws(() => parseRequestFraming({ headers: { 'content-length': '5', 'transfer-encoding': 'chunked' } }), /framing/);
  assert.throws(() => parseRequestFraming({ headers: { 'content-length': '01' } }), /Content-Length/);
  assert.throws(() => parseRequestFraming({ headers: { 'content-length': '5, 5' } }), /Content-Length/);
});

test('broker returns a stable unsupported media type error', async (t) => {
  const token = `tgscap_${'d'.repeat(32)}`;
  const broker = createBrokerServer({
    store: {
      resolveCapability: async () => ({
        id: 'cap_11111111111111111111',
        baseUrl: 'https://api.example.com/',
        pathPrefix: '/',
        methods: ['GET'],
        injectHeader: 'x-api-key',
        injectPrefix: '',
        secretValue: 'synthetic-value',
      }),
    },
    host: '127.0.0.1',
    port: 0,
    logger: { info() {}, error() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/fetch`, {
    method: 'POST',
    headers: { 'x-tgcloud-capability': token, 'content-type': 'text/plain' },
    body: JSON.stringify({ path: '/health' }),
  });
  assert.equal(response.status, 415);
  assert.deepEqual(await response.json(), { error: 'unsupported_media_type' });
});

test('broker bounds capability resolution and fails closed when the store is unavailable', async (t) => {
  const broker = createBrokerServer({
    store: { resolveCapability: async () => new Promise(() => {}) },
    host: '127.0.0.1',
    port: 0,
    timeoutMs: 100,
    logger: { info() {}, error() {}, warn() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/fetch`, {
    method: 'POST',
    headers: { 'x-tgcloud-capability': `tgscap_${'e'.repeat(32)}`, 'content-type': 'application/json' },
    body: JSON.stringify({ path: '/health' }),
  });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'dependency_unavailable' });
});

test('broker bounds readiness checks when a store health check hangs', async (t) => {
  const broker = createBrokerServer({
    store: { healthCheck: async () => new Promise(() => {}) },
    host: '127.0.0.1',
    port: 0,
    timeoutMs: 100,
    logger: { info() {}, error() {}, warn() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const startedAt = Date.now();
  const response = await fetch(`http://127.0.0.1:${address.port}/readyz`);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { ok: false, error: 'not_ready' });
  assert.ok(Date.now() - startedAt < 1_000);
});

test('broker enforces source and global ceilings before capability resolution', async (t) => {
  let resolutions = 0;
  const broker = createBrokerServer({
    store: { resolveCapability: async () => { resolutions += 1; return null; } },
    host: '127.0.0.1',
    port: 0,
    globalRateLimiter: { check: () => ({ allowed: false, retryAfter: 7 }) },
    logger: { info() {}, error() {}, warn() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/fetch`, {
    method: 'POST',
    headers: { 'x-tgcloud-capability': `tgscap_${'f'.repeat(32)}`, 'content-type': 'application/json' },
    body: JSON.stringify({ path: '/health' }),
  });
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('retry-after'), '7');
  assert.equal(resolutions, 0);
});

test('broker fails closed when required audit delivery times out', async (t) => {
  const broker = createBrokerServer({
    store: {
      resolveCapability: async () => ({
        id: 'cap_22222222222222222222',
        baseUrl: 'https://api.example.com/',
        pathPrefix: '/',
        methods: ['GET'],
        injectHeader: 'x-api-key',
        injectPrefix: '',
        secretValue: 'synthetic-value',
      }),
    },
    host: '127.0.0.1',
    port: 0,
    timeoutMs: 100,
    fetchImpl: async () => new Response('ok'),
    lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
    auditLogger: async () => new Promise(() => {}),
    logger: { info() {}, error() {}, warn() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const response = await fetch(`http://127.0.0.1:${address.port}/v1/fetch`, {
    method: 'POST',
    headers: { 'x-tgcloud-capability': `tgscap_${'g'.repeat(32)}`, 'content-type': 'application/json' },
    body: JSON.stringify({ path: '/health' }),
  });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'dependency_unavailable' });
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

test('broker keys invalid-attempt limits by forwarded clients only through a trusted proxy', async (t) => {
  const token = `tgscap_${'d'.repeat(32)}`;
  const broker = createBrokerServer({
    store: { resolveCapability: async () => null },
    host: '127.0.0.1',
    port: 0,
    maxInvalidAttemptsPerMinute: 1,
    trustedProxyAddresses: ['127.0.0.1'],
    logger: { info() {}, error() {}, warn() {} },
  });
  const address = await broker.listen();
  t.after(() => broker.close());
  const endpoint = `http://127.0.0.1:${address.port}/v1/fetch`;
  const attempt = (forwarded) => fetch(endpoint, {
    method: 'POST',
    headers: {
      'x-tgcloud-capability': token,
      'x-forwarded-for': forwarded,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ path: '/health' }),
  });

  assert.equal((await attempt('198.51.100.1')).status, 401);
  assert.equal((await attempt('198.51.100.2')).status, 401);
  assert.equal((await attempt('198.51.100.1')).status, 429);

  const untrustedBroker = createBrokerServer({
    store: { resolveCapability: async () => null },
    host: '127.0.0.1',
    port: 0,
    maxInvalidAttemptsPerMinute: 1,
    trustedProxyAddresses: ['192.0.2.10'],
    logger: { info() {}, error() {}, warn() {} },
  });
  const untrustedAddress = await untrustedBroker.listen();
  t.after(() => untrustedBroker.close());
  const untrustedEndpoint = `http://127.0.0.1:${untrustedAddress.port}/v1/fetch`;
  const untrustedAttempt = (forwarded) => fetch(untrustedEndpoint, {
    method: 'POST',
    headers: {
      'x-tgcloud-capability': token,
      'x-forwarded-for': forwarded,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ path: '/health' }),
  });
  assert.equal((await untrustedAttempt('198.51.100.1')).status, 401);
  assert.equal((await untrustedAttempt('198.51.100.2')).status, 429);
});

test('broker rejects non-loopback binds without an explicit trusted proxy', () => {
  assert.throws(
    () => createBrokerServer({ store: { resolveCapability: async () => null }, host: '0.0.0.0' }),
    /trustedProxyAddresses/,
  );
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
