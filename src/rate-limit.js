const DEFAULT_BUCKETS = 10_000;
const WINDOW_SECONDS = 60;
const DEFAULT_OPERATION_TIMEOUT_MS = 5_000;

function validateLimit(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

export function normalizeRateLimitDecision(result) {
  if (!result || typeof result.allowed !== 'boolean') throw new Error('Rate limiter returned an invalid decision');
  if (result.allowed) return { allowed: true, retryAfter: 0 };
  const parsedRetryAfter = result.retryAfter === undefined ? 1 : Number(result.retryAfter);
  if (!Number.isFinite(parsedRetryAfter) || parsedRetryAfter < 0) throw new Error('Rate limiter returned an invalid retryAfter value');
  const retryAfter = Math.min(86_400, Math.max(1, Math.ceil(parsedRetryAfter)));
  return {
    allowed: false,
    retryAfter,
    ...(typeof result.reason === 'string' ? { reason: result.reason } : {}),
  };
}

export class MemoryRateLimiter {
  constructor({ maxRequestsPerMinute, maxBuckets = DEFAULT_BUCKETS } = {}) {
    this.maxRequestsPerMinute = validateLimit(maxRequestsPerMinute, 'maxRequestsPerMinute');
    this.maxBuckets = validateLimit(maxBuckets, 'maxBuckets');
    this.buckets = new Map();
  }

  check(key) {
    if (typeof key !== 'string' || key.length === 0 || key.length > 512) throw new Error('Rate-limit key is invalid');
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      if (!bucket && this.buckets.size >= this.maxBuckets) {
        for (const [candidate, value] of this.buckets) {
          if (value.resetAt <= now) this.buckets.delete(candidate);
        }
        if (this.buckets.size >= this.maxBuckets) this.buckets.delete(this.buckets.keys().next().value);
      }
      bucket = { count: 0, resetAt: now + WINDOW_SECONDS * 1_000 };
      this.buckets.set(key, bucket);
    }
    if (bucket.count >= this.maxRequestsPerMinute) {
      return { allowed: false, retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000)) };
    }
    bucket.count += 1;
    return { allowed: true, retryAfter: 0 };
  }

  release(key) {
    const bucket = this.buckets.get(key);
    if (!bucket) return;
    bucket.count = Math.max(0, bucket.count - 1);
    if (bucket.count === 0 && Date.now() >= bucket.resetAt) this.buckets.delete(key);
  }

  clear() {
    this.buckets.clear();
  }
}

const REDIS_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
local ttl = redis.call('TTL', KEYS[1])
if count > tonumber(ARGV[1]) then return {0, ttl} end
return {1, ttl}
`;

export class RedisRateLimiter {
  constructor({ client, maxRequestsPerMinute, keyPrefix = 'tgcloud:rate', fallback, failClosed = true, operationTimeoutMs = DEFAULT_OPERATION_TIMEOUT_MS } = {}) {
    if (!client || typeof client.eval !== 'function') throw new Error('RedisRateLimiter requires a client with eval()');
    this.client = client;
    this.maxRequestsPerMinute = validateLimit(maxRequestsPerMinute, 'maxRequestsPerMinute');
    this.keyPrefix = String(keyPrefix).replace(/[^A-Za-z0-9:_-]/g, '_');
    this.fallback = fallback;
    this.failClosed = Boolean(failClosed);
    if (!Number.isSafeInteger(operationTimeoutMs) || operationTimeoutMs < 100 || operationTimeoutMs > 120_000) throw new Error('RedisRateLimiter operationTimeoutMs must be between 100 and 120000');
    this.operationTimeoutMs = operationTimeoutMs;
  }

  async check(key) {
    if (typeof key !== 'string' || key.length === 0 || key.length > 512) throw new Error('Rate-limit key is invalid');
    const redisKey = `${this.keyPrefix}:${key}`;
    try {
      const operation = Promise.resolve().then(() => this.client.eval(REDIS_SCRIPT, {
        keys: [redisKey],
        arguments: [String(this.maxRequestsPerMinute), String(WINDOW_SECONDS)],
      }));
      operation.catch(() => {});
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('Redis rate limiter timed out'), { code: 'TGCLOUD_RATE_LIMIT_TIMEOUT' })), this.operationTimeoutMs);
        timer.unref?.();
      });
      let result;
      try {
        result = await Promise.race([operation, timeout]);
      } finally {
        clearTimeout(timer);
      }
      const allowed = Number(result?.[0]) === 1;
      return normalizeRateLimitDecision({ allowed, retryAfter: allowed ? 0 : Math.max(1, Number(result?.[1]) || WINDOW_SECONDS) });
    } catch (error) {
      if (this.fallback) {
        const fallbackResult = normalizeRateLimitDecision(await Promise.resolve(this.fallback.check(key)));
        return { ...fallbackResult, reason: 'limiter_unavailable' };
      }
      if (this.failClosed) return { allowed: false, retryAfter: 1, reason: 'limiter_unavailable' };
      return { allowed: true, retryAfter: 0, reason: 'limiter_unavailable' };
    }
  }
}

export function createRateLimiter({ maxRequestsPerMinute, backend, keyPrefix, maxBuckets = DEFAULT_BUCKETS, fallback, failClosed = true, operationTimeoutMs = DEFAULT_OPERATION_TIMEOUT_MS } = {}) {
  if (!backend) return new MemoryRateLimiter({ maxRequestsPerMinute, maxBuckets });
  return new RedisRateLimiter({ client: backend, maxRequestsPerMinute, keyPrefix, fallback, failClosed, operationTimeoutMs });
}
