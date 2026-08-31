import { createServer } from 'node:http';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { assertAllowedMethod, isPrivateHost, isSafeHttpHost, resolveUpstreamUrl, sanitizeForwardHeaders } from './policy.js';

const DEFAULT_MAX_REQUEST_BYTES = 1 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 30 * 1024 * 1024;

function assertPositiveLimit(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function jsonResponse(response, status, payload, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(payload));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  response.end(body);
}

function extractCapability(request) {
  const value = request.headers['x-tgcloud-capability'];
  if (Array.isArray(value)) return value[0];
  return value;
}

function createRateLimiter(maxRequestsPerMinute) {
  const windowMs = 60_000;
  const buckets = new Map();
  return {
    check(key) {
      const now = Date.now();
      let bucket = buckets.get(key);
      if (!bucket || now >= bucket.resetAt) {
        bucket = { count: 0, resetAt: now + windowMs };
        buckets.set(key, bucket);
      }
      if (bucket.count >= maxRequestsPerMinute) {
        return { allowed: false, retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000)) };
      }
      bucket.count += 1;
      if (buckets.size > 10_000) {
        for (const [candidate, value] of buckets) if (value.resetAt <= now) buckets.delete(candidate);
      }
      return { allowed: true, retryAfter: 0 };
    },
  };
}

async function readBody(request, maximumBytes) {
  const declared = Number(request.headers['content-length']);
  if (Number.isFinite(declared) && declared > maximumBytes) {
    throw Object.assign(new Error('Request body is too large'), { statusCode: 413 });
  }

  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > maximumBytes) {
      throw Object.assign(new Error('Request body is too large'), { statusCode: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function forwardedResponseHeaders(upstreamHeaders) {
  const headers = {};
  for (const [name, value] of upstreamHeaders.entries()) {
    const lower = name.toLowerCase();
    if (['connection', 'content-length', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'].includes(lower)) continue;
    headers[name] = value;
  }
  headers['cache-control'] = 'no-store';
  headers['x-content-type-options'] = 'nosniff';
  return headers;
}

async function readResponseBody(upstream, maximumBytes) {
  const declared = Number(upstream.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > maximumBytes) {
    throw Object.assign(new Error('Upstream response is too large'), { statusCode: 502 });
  }

  if (!upstream.body?.getReader) {
    const bytes = Buffer.from(await upstream.arrayBuffer());
    if (bytes.length > maximumBytes) throw Object.assign(new Error('Upstream response is too large'), { statusCode: 502 });
    return bytes;
  }

  const reader = upstream.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maximumBytes) {
        await reader.cancel();
        throw Object.assign(new Error('Upstream response is too large'), { statusCode: 502 });
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

async function assertSafeResolvedHost(target, capability, lookupImpl) {
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname) || (capability.allowHttp && isSafeHttpHost(hostname))) return;
  let addresses;
  try {
    addresses = await lookupImpl(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw Object.assign(new Error('Upstream hostname could not be resolved'), { cause: error, statusCode: 502 });
  }
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some(({ address }) => isPrivateHost(address))) {
    throw Object.assign(new Error('Upstream hostname resolved to a private or link-local address'), { statusCode: 502 });
  }
}

async function performFetch({ capability, requestPayload, maxResponseBytes, fetchImpl = fetch, timeoutMs, lookupImpl = lookup }) {
  let method;
  let target;
  let headers;
  try {
    method = assertAllowedMethod(requestPayload.method || 'GET', capability.methods);
    target = resolveUpstreamUrl(capability.baseUrl, requestPayload.path, capability.pathPrefix);
    headers = sanitizeForwardHeaders(requestPayload.headers, capability.injectHeader);
  } catch (error) {
    if (error.statusCode) throw error;
    throw Object.assign(error, { statusCode: 400 });
  }
  if ((method === 'GET' || method === 'HEAD') && requestPayload.body !== undefined && requestPayload.body !== '') {
    throw Object.assign(new Error(`${method} requests cannot include a body`), { statusCode: 400 });
  }
  if (requestPayload.body !== undefined && typeof requestPayload.body !== 'string') {
    throw Object.assign(new Error('Request body must be a string'), { statusCode: 400 });
  }

  headers.set(capability.injectHeader, `${capability.injectPrefix}${capability.secretValue}`);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  let upstream;
  try {
    await assertSafeResolvedHost(target, capability, lookupImpl);
    upstream = await fetchImpl(target, {
      method,
      headers,
      body: requestPayload.body || undefined,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (upstream.status >= 300 && upstream.status < 400) {
      throw Object.assign(new Error('Upstream redirects are not allowed'), { statusCode: 502 });
    }

    const bytes = await readResponseBody(upstream, maxResponseBytes);

    return {
      status: upstream.status,
      headers: forwardedResponseHeaders(upstream.headers),
      bytes,
    };
  } catch (error) {
    if (error.statusCode) throw error;
    throw Object.assign(new Error('Upstream request failed'), { cause: error, statusCode: 502 });
  } finally {
    clearTimeout(timer);
  }
}

export function createBrokerServer({
  store,
  host = '127.0.0.1',
  port = 8787,
  maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  timeoutMs = 15_000,
  maxRequestsPerMinute = 120,
  maxInvalidAttemptsPerMinute = 60,
  fetchImpl,
  lookupImpl,
  logger = console,
} = {}) {
  if (!store) throw new Error('A SecretStore is required');
  assertPositiveLimit(maxRequestBytes, 'maxRequestBytes');
  assertPositiveLimit(maxResponseBytes, 'maxResponseBytes');
  assertPositiveLimit(timeoutMs, 'timeoutMs');
  assertPositiveLimit(maxRequestsPerMinute, 'maxRequestsPerMinute');
  assertPositiveLimit(maxInvalidAttemptsPerMinute, 'maxInvalidAttemptsPerMinute');
  const rateLimiter = createRateLimiter(maxRequestsPerMinute);
  const invalidRateLimiter = createRateLimiter(maxInvalidAttemptsPerMinute);

  const server = createServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/healthz') {
        jsonResponse(response, 200, { ok: true });
        return;
      }
      if (request.method !== 'POST' || request.url !== '/v1/fetch') {
        request.resume();
        jsonResponse(response, 404, { error: 'not_found' });
        return;
      }

      const capabilityToken = extractCapability(request);
      const capability = await store.resolveCapability(capabilityToken);
      if (!capability) {
        request.resume();
        const rate = invalidRateLimiter.check(request.socket.remoteAddress || 'unknown');
        if (!rate.allowed) {
          jsonResponse(response, 429, { error: 'rate_limited' }, { 'retry-after': rate.retryAfter });
        } else {
          jsonResponse(response, 401, { error: 'invalid_capability' });
        }
        return;
      }
      const rate = rateLimiter.check(capability.id);
      if (!rate.allowed) {
        request.resume();
        jsonResponse(response, 429, { error: 'rate_limited' }, { 'retry-after': rate.retryAfter });
        return;
      }

      const rawBody = await readBody(request, maxRequestBytes);
      let payload;
      try {
        payload = JSON.parse(rawBody);
      } catch {
        throw Object.assign(new Error('Request body must be valid JSON'), { statusCode: 400 });
      }
      if (!payload || typeof payload.path !== 'string') {
        throw Object.assign(new Error('Request must include a path'), { statusCode: 400 });
      }

      const result = await performFetch({
        capability,
        requestPayload: payload,
        maxResponseBytes,
        fetchImpl,
        lookupImpl,
        timeoutMs,
      });
      for (const [name, value] of Object.entries(result.headers)) response.setHeader(name, value);
      response.statusCode = result.status;
      response.end(result.bytes);
      logger.info?.('proxy request', {
        capabilityId: capability.id,
        method: payload.method || 'GET',
        path: new URL(payload.path, 'https://tgcloud.invalid').pathname,
        status: result.status,
      });
    } catch (error) {
      const status = Number.isInteger(error.statusCode) ? error.statusCode : 500;
      if (status >= 500) logger.error?.('proxy request failed', { status, message: error.message });
      request.resume();
      if (!response.headersSent) jsonResponse(response, status, { error: status === 500 ? 'internal_error' : error.message });
      else response.end();
    }
  });

  server.on('error', (error) => logger.error?.('broker server error', { message: error.message }));
  server.on('clientError', (error, socket) => {
    logger.warn?.('broker client error', { message: error.message });
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  server.requestTimeout = timeoutMs;
  server.timeout = timeoutMs;
  server.keepAliveTimeout = 5_000;
  server.headersTimeout = Math.max(timeoutMs, 5_000);
  server.maxHeadersCount = 100;
  return {
    server,
    listen() {
      return new Promise((resolve, reject) => {
        const onError = (error) => {
          server.off('listening', onListening);
          reject(error);
        };
        const onListening = () => {
          server.off('error', onError);
          resolve(server.address());
        };
        server.once('error', onError);
        server.once('listening', onListening);
        server.listen(port, host);
      });
    },
    close() {
      return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    },
  };
}

export { performFetch, readBody, readResponseBody };
