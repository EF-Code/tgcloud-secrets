import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isPrivateHost, normalizeBaseUrl, resolveUpstreamUrl } from '../src/policy.js';
import { SecretStore } from '../src/store.js';
import { createBrokerServer } from '../src/broker.js';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Security regression tests

test('1 - isPrivateHost strips zone identifier %lo0', () => {
  assert.equal(isPrivateHost('fe80::1%lo0'), true);
  assert.equal(isPrivateHost('fe80::1%eth0'), true);
});


test('2 - decodePathForPolicy blocks encoded slash %2f', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2fadmin', '/v1/'), /forbidden encoded/);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2Fadmin', '/v1/'), /forbidden encoded/);
});


test('3 - trailing dot rejected in normalizeBaseUrl', () => {
  assert.throws(() => normalizeBaseUrl('https://api.example.com.'), /trailing dot/);
  assert.throws(() => normalizeBaseUrl('https://api.example.com./'), /trailing dot/);
});


test('4 - nested encoded slash %252f blocked', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%252fadmin', '/v1/'), /forbidden encoded/);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%25252fadmin', '/v1/'), /forbidden encoded/);
});


test('5 - search control characters rejected', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/health?evil=\u0000', '/v1/'), /forbidden character/);
});


test('6 - hash control characters rejected', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/health#frag\u0000', '/v1/'), /forbidden character/);
});


test('7 - encoded null %00 in query blocked', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/health?evil=%00', '/v1/'), /forbidden encoded/);
});


test('8 - isPrivateIpv4 precise TEST-NET-1 192.0.2.1', () => {
  assert.equal(isPrivateHost('192.0.2.1'), true);
  assert.equal(isPrivateHost('192.0.1.1'), false);
});


test('9 - isPrivateIpv4 TEST-NET-2 198.51.100.1', () => {
  assert.equal(isPrivateHost('198.51.100.1'), true);
  assert.equal(isPrivateHost('198.51.100.5'), true);
  assert.equal(isPrivateHost('198.51.101.1'), false);
});


test('10 - isPrivateIpv4 TEST-NET-3 203.0.113.1', () => {
  assert.equal(isPrivateHost('203.0.113.1'), true);
  assert.equal(isPrivateHost('203.0.114.1'), false);
});


test('11 - isPrivateIpv4 6to4 relay 192.88.99.1', () => {
  assert.equal(isPrivateHost('192.88.99.1'), true);
});


test('12 - ::ffff: mapped public vs private', () => {
  assert.equal(isPrivateHost('::ffff:8.8.8.8'), false);
  assert.equal(isPrivateHost('::ffff:10.0.0.1'), true);
  assert.equal(isPrivateHost('::ffff:192.0.2.1'), true);
});


test('13 - query allowed with safe characters', () => {
  const url = resolveUpstreamUrl('https://api.example.com/', '/v1/health?evil=1', '/v1/');
  assert.equal(url.search, '?evil=1');
});


test('14 - broker secret injection sanitizes unsafe header', async () => {
  const { performFetch } = await import('../src/broker.js');
  await assert.rejects(() => performFetch({
    capability: { baseUrl: 'https://api.example.com/', pathPrefix: '/', methods: ['GET'], injectHeader: 'x-api-key', injectPrefix: '', secretValue: 'bad\nvalue' },
    requestPayload: { path: '/health' },
    maxResponseBytes: 1024,
    lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }],
    fetchImpl: async () => new Response('ok'),
  }), (e) => e.statusCode === 502 && !String(e.cause).includes('bad'));
});


test('15 - broker invalid limiter does not block valid token', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tg-test-'));
  const store = new SecretStore({ dataDir });
  await store.init();
  await store.setSecret('demo', 'secret-value');
  const cap = await store.createCapability({ secretName: 'demo', baseUrl: 'https://api.example.com', pathPrefix: '/', methods: ['GET'] });
  const broker = createBrokerServer({ store, host: '127.0.0.1', port: 0, maxInvalidAttemptsPerMinute: 1, lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }], fetchImpl: async () => new Response('ok'), logger: { info() {}, error() {}, warn() {} } });
  const addr = await broker.listen();
  const ep = 'http://127.0.0.1:' + addr.port + '/v1/fetch';
  await fetch(ep, { method: 'POST', headers: { 'x-tgcloud-capability': 'tgscap_invalid1_invalid1_invalid1_', 'content-type': 'application/json' }, body: JSON.stringify({ path: '/health' }) });
  await fetch(ep, { method: 'POST', headers: { 'x-tgcloud-capability': 'tgscap_invalid2_invalid2_invalid2_', 'content-type': 'application/json' }, body: JSON.stringify({ path: '/health' }) });
  const good = await fetch(ep, { method: 'POST', headers: { 'x-tgcloud-capability': cap.token, 'content-type': 'application/json' }, body: JSON.stringify({ path: '/health' }) });
  assert.notEqual(good.status, 429, 'valid token must not be throttled by invalid limiter');
  await broker.close();
});


test('16 - broker healthz HEAD with query', async () => {
  const store = new SecretStore({ dataDir: await mkdtemp(join(tmpdir(), 'tg-test-')) });
  await store.init();
  const broker = createBrokerServer({ store, host: '127.0.0.1', port: 0, logger: { info() {}, error() {}, warn() {} } });
  const addr = await broker.listen();
  const base = 'http://127.0.0.1:' + addr.port;
  assert.equal((await fetch(base + '/healthz?foo=bar')).status, 200);
  assert.equal((await fetch(base + '/healthz?foo=bar', { method: 'HEAD' })).status, 200);
  await broker.close();
});


test('17 - broker graceful drain awaits inFlight', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tg-test-'));
  const store = new SecretStore({ dataDir });
  await store.init();
  await store.setSecret('demo', 'secret-value');
  const cap = await store.createCapability({ secretName: 'demo', baseUrl: 'https://api.example.com', pathPrefix: '/', methods: ['GET'] });
  const broker = createBrokerServer({ store, host: '127.0.0.1', port: 0, lookupImpl: async () => [{ address: '93.184.216.34', family: 4 }], fetchImpl: async () => { await new Promise((r) => setTimeout(r, 100)); return new Response('ok'); }, logger: { info() {}, error() {} } });
  const addr = await broker.listen();
  const ep = 'http://127.0.0.1:' + addr.port + '/v1/fetch';
  const req = fetch(ep, { method: 'POST', headers: { 'x-tgcloud-capability': cap.token, 'content-type': 'application/json' }, body: JSON.stringify({ path: '/health' }) });
  await new Promise((r) => setTimeout(r, 20));
  const start = Date.now();
  await broker.close();
  assert.ok(Date.now() - start >= 50, 'close should wait for inFlight');
  const res = await req;
  assert.equal(res.status, 200);
});


test('18 - store reserves constructor/prototype', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tg-test-'));
  const store = new SecretStore({ dataDir });
  await store.init();
  await assert.rejects(() => store.setSecret('constructor', 'val'), /reserved/);
  await assert.rejects(() => store.setSecret('prototype', 'val'), /reserved/);
});


test('19 - store fchmod auto-fixes 0644 to 0600', async () => {
  const { chmod, stat } = await import('node:fs/promises');
  const dataDir = await mkdtemp(join(tmpdir(), 'tg-test-'));
  const store = new SecretStore({ dataDir });
  await store.init();
  const keyPath = join(dataDir, 'master.key');
  await chmod(keyPath, 0o644);
  await store.init();
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
});


test('20 - runtime strips fragment and validates header', async () => {
  const { createSecretFetch } = await import('../runtime/secret-fetch.js');
  const cap = 'tgscap_' + 'a'.repeat(32);
  let seenPath;
  const sf = createSecretFetch({ endpoint: 'https://secrets.example.com', capability: cap, fetchImpl: async (url, opts) => { seenPath = JSON.parse(opts.body).path; return new Response('ok'); } });
  await sf('/v1/health#frag');
  assert.equal(seenPath, '/v1/health');
  await assert.rejects(() => sf('/v1/health', { headers: { 'x-test': 'bad\u0000' } }), /unsafe/);
});


test('double-encoded query %250a should be blocked', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/health?evil=%250a', '/v1/'), /forbidden/);
});

test('isLoopbackHost handles 127.000.0.1', async () => {
  const { isLoopbackHost } = await import('../src/policy.js');
  assert.equal(isLoopbackHost('127.000.0.1'), true);
});
