import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CircuitBreaker, CircuitOpenError } from '../src/circuit-breaker.js';
import { MemoryRateLimiter, RedisRateLimiter } from '../src/rate-limit.js';
import { createAuditOutboxWorker } from '../src/audit-outbox.js';
import { parseRequestFraming } from '../src/http.js';

test('HTTP framing rejects duplicate wire headers and ambiguous length transfer encoding', () => {
  assert.throws(() => parseRequestFraming({
    headers: { 'content-length': '4' },
    rawHeaders: ['Content-Length', '4', 'content-length', '4'],
  }), /must not be repeated/);
  assert.throws(() => parseRequestFraming({
    headers: { 'content-length': '4', 'transfer-encoding': 'chunked' },
    rawHeaders: ['Content-Length', '4', 'Transfer-Encoding', 'chunked'],
  }), /framing is invalid/);
  assert.deepEqual(parseRequestFraming({
    headers: { 'content-length': '0' },
    rawHeaders: ['Content-Length', '0'],
  }), { contentLength: 0, chunked: false, hasBody: false });
});

test('memory limiter is bounded and returns retry metadata', () => {
  const limiter = new MemoryRateLimiter({ maxRequestsPerMinute: 1, maxBuckets: 1 });
  assert.deepEqual(limiter.check('a').allowed, true);
  const limited = limiter.check('a');
  assert.equal(limited.allowed, false);
  assert.ok(limited.retryAfter >= 1);
  limiter.check('b');
  assert.ok(limiter.buckets.size <= 1);
});

test('Redis limiter uses an atomic script and fails closed with a local fallback', async () => {
  let calls = 0;
  const client = { eval: async (_script, args) => { calls += 1; assert.deepEqual(args.keys, ['prefix:a']); return [0, 4]; } };
  const limiter = new RedisRateLimiter({ client, maxRequestsPerMinute: 2, keyPrefix: 'prefix', fallback: new MemoryRateLimiter({ maxRequestsPerMinute: 2 }) });
  assert.deepEqual(await limiter.check('a'), { allowed: false, retryAfter: 4 });
  assert.equal(calls, 1);
  const unavailable = new RedisRateLimiter({ client: { eval: async () => { throw new Error('down'); } }, maxRequestsPerMinute: 1, fallback: new MemoryRateLimiter({ maxRequestsPerMinute: 1 }) });
  assert.equal((await unavailable.check('a')).allowed, true);
  assert.equal((await unavailable.check('a')).allowed, false);
});

test('Redis limiter bounds a hanging backend operation', async () => {
  const limiter = new RedisRateLimiter({
    client: { eval: async () => new Promise(() => {}) },
    maxRequestsPerMinute: 1,
    operationTimeoutMs: 100,
  });
  const startedAt = Date.now();
  const result = await limiter.check('timeout');
  assert.equal(result.reason, 'limiter_unavailable');
  assert.equal(result.allowed, false);
  assert.ok(Date.now() - startedAt < 1_000);
});

test('circuit breaker opens after dependency failures and probes after cooldown', async () => {
  const breaker = new CircuitBreaker({ failureThreshold: 2, cooldownMs: 100, successThreshold: 1 });
  await assert.rejects(() => breaker.execute(async () => { throw new Error('first'); }));
  await assert.rejects(() => breaker.execute(async () => { throw new Error('second'); }));
  await assert.rejects(() => breaker.execute(async () => 'blocked'), CircuitOpenError);
  await new Promise((resolve) => setTimeout(resolve, 120));
  assert.equal(await breaker.execute(async () => 'recovered'), 'recovered');
  assert.equal(breaker.snapshot().state, 'closed');
});

test('circuit breaker counts dependency failure responses without treating policy responses as outages', async () => {
  const breaker = new CircuitBreaker({ failureThreshold: 2, cooldownMs: 100, successThreshold: 1 });
  assert.deepEqual(await breaker.execute(async () => ({ status: 500 }), { isFailure: (result) => result.status >= 500 }), { status: 500 });
  assert.deepEqual(await breaker.execute(async () => ({ status: 503 }), { isFailure: (result) => result.status >= 500 }), { status: 503 });
  await assert.rejects(() => breaker.execute(async () => ({ status: 500 }), { isFailure: (result) => result.status >= 500 }), CircuitOpenError);

  const policyBreaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 100, successThreshold: 1 });
  const policyError = Object.assign(new Error('blocked by policy'), { circuitFailure: false });
  await assert.rejects(() => policyBreaker.execute(async () => { throw policyError; }));
  assert.equal(policyBreaker.snapshot().state, 'closed');
});

test('audit outbox worker requires and applies an explicit tenant scope', async () => {
  assert.throws(() => createAuditOutboxWorker({ pool: { connect() {} }, publish() {} }), /orgId/);
  const queries = [];
  let claimed = false;
  const client = {
    async query(sql, params) {
      queries.push({ sql, params });
      if (sql.startsWith('WITH candidate') && !claimed) {
        claimed = true;
        return { rows: [{ id: 7, event_id: 'event-1', event_type: 'test.event', org_id: 'org1', project_id: 'org1:proj1', payload: { ok: true }, attempts: 0, claim_token: 'claim-1' }] };
      }
      return { rows: [] };
    },
    release() {},
  };
  const worker = createAuditOutboxWorker({
    pool: { async connect() { return client; } },
    publish: async (event) => { assert.equal(event.projectId, 'org1:proj1'); },
    orgId: 'org1',
    projectId: 'proj1',
    logger: { error() {} },
  });
  assert.equal(await worker.deliverOnce(), 1);
  const context = queries.find((entry) => entry.sql.includes('set_config'));
  assert.deepEqual(context.params, ['org1', 'org1:proj1']);
  const role = queries.find((entry) => entry.sql === 'SET LOCAL ROLE tgcloud_audit_worker');
  assert.ok(role, 'outbox delivery must use the dedicated worker role');
  assert.ok(queries.some((entry) => entry.sql === "SET LOCAL statement_timeout = '10000ms'"), 'outbox delivery must bound database waits');
  const claim = queries.find((entry) => entry.sql.includes('FROM audit_outbox'));
  assert.deepEqual(claim.params.slice(0, 2), ['org1', 'org1:proj1']);
  assert.match(claim.params[2], /^[0-9a-f-]{36}$/);
  assert.equal(typeof claim.params[3], 'number');
  const update = queries.find((entry) => entry.sql.includes('published_at=now()'));
  assert.deepEqual(update.params.slice(1, 3), ['org1', 'org1:proj1']);
  assert.equal(update.params[3], 'claim-1');
});

test('audit outbox worker stop waits for an in-flight publish and prevents overlap', async () => {
  let claimed = false;
  let publishCalls = 0;
  let resolvePublishStarted;
  const publishStarted = new Promise((resolve) => { resolvePublishStarted = resolve; });
  const client = {
    async query(sql) {
      if (sql.startsWith('WITH candidate') && !claimed) {
        claimed = true;
        return { rows: [{ id: 8, event_id: 'event-2', event_type: 'test.event', org_id: 'org1', project_id: 'org1:proj1', payload: { ok: true }, attempts: 0, claim_token: 'claim-2' }] };
      }
      return { rows: [] };
    },
    release() {},
  };
  const worker = createAuditOutboxWorker({
    pool: { async connect() { return client; } },
    publish: async () => {
      publishCalls += 1;
      resolvePublishStarted();
      return new Promise(() => {});
    },
    orgId: 'org1',
    projectId: 'proj1',
    publishTimeoutMs: 100,
    logger: { error() {} },
  });

  const delivery = worker.deliverOnce();
  await publishStarted;
  const secondDelivery = worker.deliverOnce();
  let stopped = false;
  const stop = worker.stop().then(() => { stopped = true; });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(stopped, false, 'stop must wait for the bounded publisher and claim release');
  await stop;
  assert.equal(stopped, true);
  assert.deepEqual(await Promise.all([delivery, secondDelivery]), [1, 1]);
  assert.equal(publishCalls, 1, 'manual and polling delivery must share one in-flight operation');
});
