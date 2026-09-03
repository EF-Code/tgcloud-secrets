import { createServer, request as httpRequest } from 'node:http';
import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { Readable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { assertAllowedMethod, isLoopbackHost, isPrivateHost, isSafeHeaderValue, isSafeHttpHost, resolveUpstreamUrl, sanitizeForwardHeaders } from './policy.js';
import { createRateLimiter, MemoryRateLimiter, normalizeRateLimitDecision } from './rate-limit.js';
import { CircuitBreakerPool } from './circuit-breaker.js';
import { createRedactingLogger } from './observability.js';
import { parseStrictJson } from './json.js';
import { parseRequestFraming } from './http.js';

const DEFAULT_MAX_REQUEST_BYTES = 1 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 30 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CAPABILITY = 8;
const DEFAULT_MAX_CONCURRENT_REQUESTS = 32;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function assertPositiveLimit(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function boundedOperation(operation, timeoutMs, message, statusCode = 503, publicCode = 'dependency_unavailable') {
  const pending = Promise.resolve().then(operation);
  // A timed-out dependency can still reject later. Observe that rejection so
  // a dead database, limiter, or audit adapter cannot create an unhandled
  // rejection after the request has been answered.
  pending.catch(() => {});
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error(message), { statusCode, publicCode })), timeoutMs);
    timer.unref?.();
  });
  return Promise.race([pending, timeout]).finally(() => clearTimeout(timer));
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

function publicErrorCode(status) {
  switch (status) {
    case 400: return 'invalid_request';
    case 401: return 'invalid_capability';
    case 408: return 'request_timeout';
    case 413: return 'request_too_large';
    case 415: return 'unsupported_media_type';
    case 429: return 'rate_limited';
    case 423: return 'tenant_disabled';
    case 502: return 'upstream_error';
    case 503: return 'dependency_unavailable';
    default: return 'internal_error';
  }
}

function extractCapability(request) {
  const value = request.headers['x-tgcloud-capability'];
  if (Array.isArray(value)) return undefined;
  return value;
}

function looksLikeCapabilityToken(value) {
  return typeof value === 'string' && /^tgscap_[A-Za-z0-9_-]{16,256}$/.test(value);
}

function normalizeIpAddress(value) {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (normalized.startsWith('::ffff:') && isIP(normalized.slice(7)) === 4) return normalized.slice(7);
  return isIP(normalized) === 0 ? undefined : normalized;
}

function normalizeTrustedProxyAddresses(value) {
  if (value === undefined) return new Set();
  if (!Array.isArray(value)) throw new Error('trustedProxyAddresses must be an array of IP addresses');
  const addresses = new Set();
  for (const candidate of value) {
    const normalized = normalizeIpAddress(candidate);
    if (!normalized) throw new Error('trustedProxyAddresses must contain only IP addresses');
    addresses.add(normalized);
  }
  return addresses;
}

function requestClientKey(request, trustedProxyAddresses) {
  const peer = normalizeIpAddress(request.socket.remoteAddress) || 'unknown';
  if (trustedProxyAddresses.has(peer)) {
    const forwarded = request.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      // Trusted proxy must strip incoming XFF and set single IP — reject multi-entry to avoid spoofing
      if (forwarded.includes(',')) return `peer:${peer}`;
      const client = normalizeIpAddress(forwarded);
      if (client) return `client:${client}`;
    }
  }
  return `peer:${peer}`;
}

function closeResponse(response, request, status, payload, extraHeaders = {}) {
  response.shouldKeepAlive = false;
  response.once('finish', () => {
    if (!request.destroyed) request.destroy();
  });
  if (!response.headersSent) jsonResponse(response, status, payload, { connection: 'close', ...extraHeaders });
  else response.end();
}

function auditPath(value) {
  try {
    return new URL(value, 'https://tgcloud.invalid').pathname;
  } catch {
    return '/invalid';
  }
}

async function readBody(request, maximumBytes, timeoutMs = 15_000) {
  const { contentLength: declared } = parseRequestFraming(request);
  if (declared !== null && declared > maximumBytes) {
    throw Object.assign(new Error('Request body is too large'), { statusCode: 413, closeConnection: true });
  }

  const read = (async () => {
    const chunks = [];
    let total = 0;
    for await (const chunk of request) {
      total += chunk.length;
      if (total > maximumBytes) {
        throw Object.assign(new Error('Request body is too large'), { statusCode: 413, closeConnection: true });
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  })();
  // The iterator may settle after the timeout destroys the socket. Observe
  // that late rejection so it cannot become an unhandled promise rejection.
  read.catch(() => {});
  let timeoutHandle;
  const deadline = new Promise((_, reject) => {
    timeoutHandle = setTimeout(() => {
      reject(Object.assign(new Error('Request body timed out'), { statusCode: 408, closeConnection: true }));
    }, timeoutMs);
    timeoutHandle.unref?.();
  });
  try {
    return await Promise.race([read, deadline]);
  } finally {
    clearTimeout(timeoutHandle);
  }
}

function forwardedResponseHeaders(upstreamHeaders) {
  const headers = {};
  for (const [name, value] of upstreamHeaders.entries()) {
    const lower = name.toLowerCase();
    if (['connection', 'content-encoding', 'content-length', 'content-md5', 'digest', 'etag', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'].includes(lower)) continue;
    headers[name] = value;
  }
  headers['cache-control'] = 'no-store';
  headers['x-content-type-options'] = 'nosniff';
  return headers;
}

async function readResponseBody(upstream, maximumBytes) {
  const declared = Number(upstream.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > maximumBytes) {
    await cancelUpstreamBody(upstream);
    throw Object.assign(new Error('Upstream response is too large'), { statusCode: 502 });
  }

  if (!upstream.body?.getReader) {
    const bytes = Buffer.from(await upstream.arrayBuffer());
    if (bytes.length > maximumBytes) {
      await cancelUpstreamBody(upstream);
      throw Object.assign(new Error('Upstream response is too large'), { statusCode: 502 });
    }
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

async function cancelUpstreamBody(upstream) {
  try {
    await upstream?.body?.cancel?.();
  } catch {
    // The response is already being rejected; cancellation is best effort.
  }
}

function nodeResponseHeaders(response) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(response.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else if (value !== undefined) {
      headers.set(name, value);
    }
  }
  return headers;
}

function fetchWithPinnedAddress(target, options, resolvedAddress) {
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  const requestOptions = {
    protocol: target.protocol,
    hostname,
    port: target.port || undefined,
    path: `${target.pathname}${target.search}`,
    method: options.method,
    headers: Object.fromEntries(options.headers.entries()),
    signal: options.signal,
    lookup(_name, lookupOptions, callback) {
      const result = { address: resolvedAddress.address, family: resolvedAddress.family };
      if (lookupOptions?.all) callback(null, [result]);
      else callback(null, result.address, result.family);
    },
  };
  if (options.body !== undefined && !Object.hasOwn(requestOptions.headers, 'content-length')) {
    requestOptions.headers['content-length'] = Buffer.byteLength(options.body);
  }
  if (target.protocol === 'https:' && isIP(hostname) === 0) requestOptions.servername = hostname;

  const request = target.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const clientRequest = request(requestOptions, (response) => {
      const status = response.statusCode;
      if (!Number.isInteger(status) || status < 200 || status > 599) {
        response.resume();
        reject(new Error('Upstream returned an unsupported HTTP status'));
        return;
      }
      try {
        const body = [204, 205, 304].includes(status) ? null : Readable.toWeb(response);
        if (body === null) response.resume();
        resolve(new Response(body, {
          status,
          statusText: response.statusMessage,
          headers: nodeResponseHeaders(response),
        }));
      } catch (error) {
        response.destroy();
        reject(error);
      }
    });
    clientRequest.once('error', reject);
    if (options.body === undefined) clientRequest.end();
    else clientRequest.end(options.body);
  });
}

async function assertSafeResolvedHost(target, capability, lookupImpl) {
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    throw Object.assign(new Error('Upstream URL must use HTTP or HTTPS'), { statusCode: 502, circuitFailure: false });
  }
  const localHttp = target.protocol === 'http:' && capability.allowHttp === true && isSafeHttpHost(hostname);
  if (target.protocol === 'http:' && !localHttp) {
    throw Object.assign(new Error('HTTP upstreams are restricted to explicit loopback development targets'), { statusCode: 502, circuitFailure: false });
  }
  if (localHttp) return undefined;
  if (isIP(hostname)) {
    if (isPrivateHost(hostname)) {
      throw Object.assign(new Error('Upstream hostname resolved to a private or link-local address'), { statusCode: 502, circuitFailure: false });
    }
    return { address: hostname, family: isIP(hostname) };
  }
  let addresses;
  try {
    addresses = await lookupImpl(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw Object.assign(new Error('Upstream hostname could not be resolved'), { cause: error, statusCode: 502 });
  }
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.length > 16 || addresses.some((entry) => {
    const address = entry?.address;
    return !address || isIP(address) === 0 || isPrivateHost(address);
  })) {
    throw Object.assign(new Error('Upstream hostname resolved to a private or link-local address'), { statusCode: 502, circuitFailure: false });
  }
  const address = addresses[0].address;
  return { address, family: isIP(address) };
}

async function performFetch({ capability, requestPayload, maxResponseBytes, fetchImpl, timeoutMs = 15_000, lookupImpl = lookup, signal: requestSignal }) {
  let method;
  let target;
  let headers;
  try {
    method = assertAllowedMethod(requestPayload.method === undefined ? 'GET' : requestPayload.method, capability.methods);
    target = resolveUpstreamUrl(capability.baseUrl, requestPayload.path, capability.pathPrefix);
    headers = sanitizeForwardHeaders(requestPayload.headers, capability.injectHeader);
  } catch (error) {
    if (error?.statusCode) throw error;
    throw Object.assign(error, { statusCode: 400, circuitFailure: false });
  }
  if ((method === 'GET' || method === 'HEAD') && requestPayload.body !== undefined && requestPayload.body !== '') {
    throw Object.assign(new Error(`${method} requests cannot include a body`), { statusCode: 400, circuitFailure: false });
  }
  if (requestPayload.body !== undefined && typeof requestPayload.body !== 'string') {
    throw Object.assign(new Error('Request body must be a string'), { statusCode: 400, circuitFailure: false });
  }

  const controller = new AbortController();
  let rejectClientCancellation;
  const clientCancellation = requestSignal ? new Promise((_, reject) => {
    rejectClientCancellation = () => reject(Object.assign(new Error('Client disconnected'), { statusCode: 499, clientAborted: true, circuitFailure: false }));
  }) : undefined;
  const abortFromRequest = () => {
    controller.abort(requestSignal?.reason);
    rejectClientCancellation?.();
  };
  if (requestSignal) {
    if (requestSignal.aborted) abortFromRequest();
    else requestSignal.addEventListener('abort', abortFromRequest, { once: true });
  }
  let timeoutHandle;
  const deadline = new Promise((_, reject) => {
    timeoutHandle = setTimeout(() => {
      controller.abort();
      reject(Object.assign(new Error('Upstream request timed out'), { statusCode: 502 }));
    }, timeoutMs);
    timeoutHandle.unref?.();
  });
  const raceWithDeadline = (promise) => {
    promise.catch(() => {});
    const pending = [promise, deadline];
    if (clientCancellation) pending.push(clientCancellation);
    return Promise.race(pending);
  };
  let upstream;
  try {
    const injectValue = `${capability.injectPrefix}${capability.secretValue}`;
    if (!isSafeHeaderValue(injectValue)) {
      throw Object.assign(new Error('Capability secret cannot be injected as an HTTP header value'), { statusCode: 502, circuitFailure: false });
    }
    try {
      headers.set(capability.injectHeader, injectValue);
    } catch (error) {
      throw Object.assign(new Error('Capability secret cannot be injected as an HTTP header value'), { statusCode: 502, circuitFailure: false });
    }
    // Prevent transparent decompression from producing a body whose encoding
    // header no longer matches what is sent to the capability caller.
    headers.set('accept-encoding', 'identity');
    const resolvedAddress = await raceWithDeadline(assertSafeResolvedHost(target, capability, lookupImpl));
    const fetchOptions = {
      method,
      headers,
      body: requestPayload.body || undefined,
      redirect: 'manual',
      signal: controller.signal,
    };
    upstream = await raceWithDeadline(Promise.resolve().then(() => {
      if (fetchImpl) return fetchImpl(target, fetchOptions);
      if (resolvedAddress) return fetchWithPinnedAddress(target, fetchOptions, resolvedAddress);
      return fetch(target, fetchOptions);
    }));
    if (REDIRECT_STATUSES.has(upstream.status)) {
      await cancelUpstreamBody(upstream);
      throw Object.assign(new Error('Upstream redirects are not allowed'), { statusCode: 502, circuitFailure: false });
    }

    const bytes = await raceWithDeadline(readResponseBody(upstream, maxResponseBytes));

    return {
      status: upstream.status,
      headers: forwardedResponseHeaders(upstream.headers),
      bytes,
    };
  } catch (error) {
    await cancelUpstreamBody(upstream);
    if (error?.statusCode) throw error;
    throw Object.assign(new Error('Upstream request failed'), { cause: error, statusCode: 502 });
  } finally {
    clearTimeout(timeoutHandle);
    requestSignal?.removeEventListener('abort', abortFromRequest);
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
  maxRequestsPerTenantPerMinute = 600,
  maxRequestsPerSourcePerMinute = 600,
  maxGlobalRequestsPerMinute = 10_000,
  maxInvalidAttemptsPerMinute = 60,
  maxConcurrentRequestsPerCapability = DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CAPABILITY,
  maxConcurrentRequests = DEFAULT_MAX_CONCURRENT_REQUESTS,
  trustedProxyAddresses = [],
  rateLimiter,
  invalidRateLimiter,
  rateLimiterBackend,
  invalidRateLimiterBackend,
  tenantRateLimiter,
  globalRateLimiter,
  sourceRateLimiter,
  circuitBreakerPool,
  auditRequired = true,
  auditLogger,
  fetchImpl,
  lookupImpl,
  logger = console,
} = {}) {
  if (!store) throw new Error('A SecretStore is required');
  assertPositiveLimit(maxRequestBytes, 'maxRequestBytes');
  assertPositiveLimit(maxResponseBytes, 'maxResponseBytes');
  assertPositiveLimit(timeoutMs, 'timeoutMs');
  assertPositiveLimit(maxRequestsPerMinute, 'maxRequestsPerMinute');
  assertPositiveLimit(maxRequestsPerTenantPerMinute, 'maxRequestsPerTenantPerMinute');
  assertPositiveLimit(maxRequestsPerSourcePerMinute, 'maxRequestsPerSourcePerMinute');
  assertPositiveLimit(maxGlobalRequestsPerMinute, 'maxGlobalRequestsPerMinute');
  assertPositiveLimit(maxInvalidAttemptsPerMinute, 'maxInvalidAttemptsPerMinute');
  assertPositiveLimit(maxConcurrentRequestsPerCapability, 'maxConcurrentRequestsPerCapability');
  assertPositiveLimit(maxConcurrentRequests, 'maxConcurrentRequests');
  if (typeof auditRequired !== 'boolean') throw new Error('auditRequired must be a boolean');
  const trustedProxySet = normalizeTrustedProxyAddresses(trustedProxyAddresses);
  if (!isLoopbackHost(host) && trustedProxySet.size === 0) {
    throw new Error('Non-loopback broker binds require trustedProxyAddresses for client-aware rate limiting');
  }
  const requestEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute, maxBuckets: 10_000 });
  const tenantEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute: maxRequestsPerTenantPerMinute, maxBuckets: 10_000 });
  const sourceEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute: maxRequestsPerSourcePerMinute, maxBuckets: 10_000 });
  const globalEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute: maxGlobalRequestsPerMinute, maxBuckets: 1 });
  const authEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute: maxInvalidAttemptsPerMinute, maxBuckets: 10_000 });
  const productionRuntime = process.env.TGCLOUD_ENV === 'production' || process.env.NODE_ENV === 'production';
  const enabled = (value) => value === true || value === '1' || value === 'true';
  if (productionRuntime && (fetchImpl || lookupImpl)) {
    throw new Error('Production broker does not allow custom network transports');
  }
  if (productionRuntime && !isLoopbackHost(host)
    && (!enabled(process.env.TGCLOUD_TLS_TERMINATED) || !enabled(process.env.TGCLOUD_EDGE_AUTHENTICATED))) {
    throw new Error('Production public broker binds require verified TLS termination and edge authentication');
  }
  if (productionRuntime && !auditRequired) {
    throw new Error('Production broker requires auditRequired=true');
  }
  const customLimitersComplete = [rateLimiter, invalidRateLimiter, tenantRateLimiter, sourceRateLimiter, globalRateLimiter].every(Boolean);
  if (productionRuntime && !rateLimiterBackend && !customLimitersComplete) {
    throw new Error('Production broker requires a distributed limiter backend or an explicit limiter for every route');
  }
  const limiterTimeoutMs = Math.max(100, Math.min(timeoutMs, 5_000));
  const requestLimiter = rateLimiter || createRateLimiter({ maxRequestsPerMinute, backend: rateLimiterBackend, fallback: requestEmergencyLimiter, keyPrefix: 'tgcloud:proxy', operationTimeoutMs: limiterTimeoutMs });
  const authLimiter = invalidRateLimiter || createRateLimiter({ maxRequestsPerMinute: maxInvalidAttemptsPerMinute, backend: invalidRateLimiterBackend || rateLimiterBackend, fallback: authEmergencyLimiter, keyPrefix: 'tgcloud:auth', operationTimeoutMs: limiterTimeoutMs });
  const tenantLimiter = tenantRateLimiter || createRateLimiter({ maxRequestsPerMinute: maxRequestsPerTenantPerMinute, backend: rateLimiterBackend, fallback: tenantEmergencyLimiter, keyPrefix: 'tgcloud:tenant', operationTimeoutMs: limiterTimeoutMs });
  const sourceLimiter = sourceRateLimiter || createRateLimiter({ maxRequestsPerMinute: maxRequestsPerSourcePerMinute, backend: rateLimiterBackend, fallback: sourceEmergencyLimiter, keyPrefix: 'tgcloud:source', operationTimeoutMs: limiterTimeoutMs });
  const globalLimiter = globalRateLimiter || createRateLimiter({ maxRequestsPerMinute: maxGlobalRequestsPerMinute, backend: rateLimiterBackend, fallback: globalEmergencyLimiter, keyPrefix: 'tgcloud:global', operationTimeoutMs: limiterTimeoutMs });
  const breakers = circuitBreakerPool || new CircuitBreakerPool({ maxEntries: 1_000 });
  const safeLogger = createRedactingLogger(logger);
  const writeAudit = auditLogger || (typeof store.recordCapabilityUse === 'function' ? (event) => store.recordCapabilityUse(event) : null);
  if (auditRequired && productionRuntime && !writeAudit) {
    throw new Error('Production broker requires a durable audit logger');
  }
  const inFlight = new Map();
  const eventLoopDelay = monitorEventLoopDelay({ resolution: 20 });
  eventLoopDelay.enable();
  let totalInFlight = 0;
  let readyzCache = null;
  let requestsTotal = 0;
  let rateLimitedTotal = 0;
  let authFailedTotal = 0;
  let upstreamErrorsTotal = 0;
  let limiterErrorsTotal = 0;
  let requestLatencyTotalMs = 0;
  let requestLatencyMaxMs = 0;

  const checkLimiter = async (limiter, key) => {
    try {
      const result = normalizeRateLimitDecision(await boundedOperation(
        () => limiter.check(key),
        limiterTimeoutMs,
        'Rate limiter timed out',
      ));
      if (productionRuntime && result.reason === 'limiter_unavailable') {
        return { allowed: false, retryAfter: 1, reason: 'limiter_unavailable' };
      }
      return result;
    } catch (error) {
      limiterErrorsTotal += 1;
      safeLogger.error('rate limiter failed', { code: 'limiter_unavailable', errorName: error?.name || 'Error' });
      return { allowed: false, retryAfter: 1, reason: 'limiter_unavailable' };
    }
  };

  const server = createServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
    const clientAbort = new AbortController();
    request.once('aborted', () => clientAbort.abort());
    response.once('close', () => {
      if (!response.writableFinished) clientAbort.abort();
    });
    try {
      const framing = parseRequestFraming(request);
      const declaredRequestBytes = framing.contentLength ?? 0;
      if (declaredRequestBytes > maxRequestBytes) {
        closeResponse(response, request, 413, { error: 'request_too_large' });
        return;
      }
      let healthPath;
      try {
        healthPath = new URL(request.url, 'http://localhost').pathname;
      } catch {
        healthPath = request.url;
      }
      if ((request.method === 'GET' || request.method === 'HEAD') && healthPath === '/healthz') {
        if (framing.hasBody) closeResponse(response, request, 400, { error: 'invalid_request' });
        else if (request.method === 'HEAD') {
          response.writeHead(200, { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-type': 'application/json; charset=utf-8' });
          response.end();
        } else jsonResponse(response, 200, { ok: true });
        return;
      }
      if (request.method === 'GET' && healthPath === '/readyz') {
        if (framing.hasBody) {
          closeResponse(response, request, 400, { error: 'invalid_request' });
          return;
        }
        const now = Date.now();
        if (!readyzCache || now - readyzCache.ts > 10000) {
          try {
            if (typeof store.healthCheck === 'function') {
              await boundedOperation(() => store.healthCheck(), timeoutMs, 'Readiness dependency timed out');
            } else if (typeof store._readStore === 'function') {
              await boundedOperation(() => store._readStore().catch(() => { throw new Error('store not ready'); }), timeoutMs, 'Readiness dependency timed out');
            }
            readyzCache = { ts: now, ok: true };
          } catch (e) {
            readyzCache = { ts: now, ok: false };
          }
        }
        if (readyzCache.ok) jsonResponse(response, 200, { ok: true, store: store.constructor.name, inFlight: totalInFlight });
        else jsonResponse(response, 503, { ok: false, error: 'not_ready' });
        return;
      }
      if (request.method === 'GET' && healthPath === '/metrics') {
        if (framing.hasBody) {
          closeResponse(response, request, 400, { error: 'invalid_request' });
          return;
        }
        // Restrict metrics to loopback or trusted proxy to avoid leaking cap IDs
        const peer = normalizeIpAddress(request.socket.remoteAddress) || 'unknown';
        const isLoopback = isLoopbackHost(peer);
        const isTrusted = trustedProxySet.has(peer);
        if (!isLoopback && !isTrusted) {
          closeResponse(response, request, 403, { error: 'forbidden' });
          return;
        }
        // Return metrics without high-cardinality cap IDs (hash instead)
        const lines = [
          '# HELP tgcloud_proxy_requests_in_flight Current in-flight proxy requests',
          '# TYPE tgcloud_proxy_requests_in_flight gauge',
          `tgcloud_proxy_requests_in_flight ${totalInFlight}`,
          '# HELP tgcloud_proxy_capability_in_flight_count Number of capabilities with in-flight requests',
          '# TYPE tgcloud_proxy_capability_in_flight_count gauge',
          `tgcloud_proxy_capability_in_flight_count ${inFlight.size}`,
          '# HELP tgcloud_proxy_max_concurrent_requests_per_capability Max per capability',
          '# TYPE tgcloud_proxy_max_concurrent_requests_per_capability gauge',
          `tgcloud_proxy_max_concurrent_requests_per_capability ${maxConcurrentRequestsPerCapability}`,
          '# HELP tgcloud_proxy_requests_total Total proxy requests completed or rejected after authentication',
          '# TYPE tgcloud_proxy_requests_total counter',
          `tgcloud_proxy_requests_total ${requestsTotal}`,
          '# HELP tgcloud_proxy_rate_limited_total Total rate-limited requests',
          '# TYPE tgcloud_proxy_rate_limited_total counter',
          `tgcloud_proxy_rate_limited_total ${rateLimitedTotal}`,
          '# HELP tgcloud_proxy_auth_failures_total Total invalid capability attempts',
          '# TYPE tgcloud_proxy_auth_failures_total counter',
          `tgcloud_proxy_auth_failures_total ${authFailedTotal}`,
          '# HELP tgcloud_proxy_upstream_errors_total Total upstream failures',
          '# TYPE tgcloud_proxy_upstream_errors_total counter',
          `tgcloud_proxy_upstream_errors_total ${upstreamErrorsTotal}`,
          '# HELP tgcloud_proxy_limiter_errors_total Rate limiter failures handled by fail-closed controls',
          '# TYPE tgcloud_proxy_limiter_errors_total counter',
          `tgcloud_proxy_limiter_errors_total ${limiterErrorsTotal}`,
          '# HELP tgcloud_proxy_request_latency_average_ms Average proxy request latency in milliseconds',
          '# TYPE tgcloud_proxy_request_latency_average_ms gauge',
          `tgcloud_proxy_request_latency_average_ms ${requestsTotal === 0 ? 0 : (requestLatencyTotalMs / requestsTotal).toFixed(3)}`,
          '# HELP tgcloud_proxy_request_latency_max_ms Maximum observed proxy request latency in milliseconds',
          '# TYPE tgcloud_proxy_request_latency_max_ms gauge',
          `tgcloud_proxy_request_latency_max_ms ${requestLatencyMaxMs.toFixed(3)}`,
          '# HELP tgcloud_proxy_event_loop_delay_p99_ms Event loop delay p99 in milliseconds',
          '# TYPE tgcloud_proxy_event_loop_delay_p99_ms gauge',
          `tgcloud_proxy_event_loop_delay_p99_ms ${(Number.isFinite(eventLoopDelay.percentile(99)) ? eventLoopDelay.percentile(99) / 1e6 : 0).toFixed(3)}`,
        ];
        const body = Buffer.from(lines.join('\n') + '\n');
        response.writeHead(200, { 'content-type': 'text/plain; version=0.0.4', 'content-length': body.length, 'cache-control': 'no-store' });
        response.end(body);
        return;
      }
      if (request.method !== 'POST' || request.url !== '/v1/fetch') {
        closeResponse(response, request, 404, { error: 'not_found' });
        return;
      }

      const peer = requestClientKey(request, trustedProxySet);
      const preAuthRates = await Promise.all([
        checkLimiter(sourceLimiter, peer),
        checkLimiter(globalLimiter, 'all'),
      ]);
      const preAuthRate = preAuthRates.find((candidate) => !candidate.allowed) || preAuthRates[0];
      if (!preAuthRate.allowed) {
        rateLimitedTotal += 1;
        closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': preAuthRate.retryAfter });
        return;
      }
      const capabilityToken = extractCapability(request);
      if (!looksLikeCapabilityToken(capabilityToken)) {
        authFailedTotal += 1;
        const authRate = await checkLimiter(authLimiter, peer);
        if (!authRate.allowed) {
          rateLimitedTotal += 1;
          closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': authRate.retryAfter });
          return;
        }
        closeResponse(response, request, 401, { error: 'invalid_capability' });
        return;
      }
      let capability;
      try {
        capability = await boundedOperation(
          () => store.resolveCapability(capabilityToken),
          timeoutMs,
          'Capability store timed out',
        );
      } catch (error) {
        if (error?.statusCode === 423 || error?.statusCode === 503) throw error;
        throw Object.assign(new Error('Capability store unavailable'), { statusCode: 503, publicCode: 'dependency_unavailable', cause: error });
      }
      if (!capability) {
        authFailedTotal += 1;
        const authRate = await checkLimiter(authLimiter, peer);
        if (!authRate.allowed) {
          rateLimitedTotal += 1;
          closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': authRate.retryAfter });
          return;
        }
        closeResponse(response, request, 401, { error: 'invalid_capability' });
        return;
      }
      const rates = await Promise.all([
        checkLimiter(requestLimiter, `capability:${capability.id}`),
        checkLimiter(tenantLimiter, `tenant:${capability.orgId}:${capability.projectId}`),
      ]);
      const rate = rates.find((candidate) => !candidate.allowed) || rates[0];
      if (!rate.allowed) {
        rateLimitedTotal += 1;
        closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': rate.retryAfter });
        return;
      }

      const rawBody = await readBody(request, maxRequestBytes, timeoutMs);
      if (typeof request.headers['content-type'] !== 'string' || !/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'])) {
        throw Object.assign(new Error('Request content type must be application/json'), { statusCode: 415 });
      }
      let payload;
      try {
        payload = parseStrictJson(rawBody, { maxBytes: maxRequestBytes, maxDepth: 10, maxFields: 128, maxArrayItems: 128, maxStringBytes: Math.min(maxRequestBytes, 256 * 1024) });
      } catch (error) {
        throw error?.statusCode ? error : Object.assign(new Error('Request body must be valid JSON'), { statusCode: 400 });
      }
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) || typeof payload.path !== 'string') {
        throw Object.assign(new Error('Request must include a path'), { statusCode: 400 });
      }
      const allowedPayloadKeys = new Set(['path', 'method', 'headers', 'body']);
      if (Object.keys(payload).some((key) => !allowedPayloadKeys.has(key))) {
        throw Object.assign(new Error('Request contains unsupported fields'), { statusCode: 400 });
      }
      if (payload.path.length === 0 || payload.path.length > 4_096) throw Object.assign(new Error('Request path is invalid'), { statusCode: 400 });
      if (payload.method !== undefined && (typeof payload.method !== 'string' || payload.method.length === 0 || payload.method.length > 16)) throw Object.assign(new Error('Request method is invalid'), { statusCode: 400 });
      if (payload.headers !== undefined && (!payload.headers || typeof payload.headers !== 'object' || Array.isArray(payload.headers))) throw Object.assign(new Error('Request headers must be an object'), { statusCode: 400 });
      if (payload.body !== undefined && typeof payload.body !== 'string') throw Object.assign(new Error('Request body must be a string'), { statusCode: 400 });

      const active = inFlight.get(capability.id) || 0;
      if (active >= maxConcurrentRequestsPerCapability || totalInFlight >= maxConcurrentRequests) {
        closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': 1 });
        return;
      }
      inFlight.set(capability.id, active + 1);
      totalInFlight += 1;
      const requestId = randomUUID();
      const requestStartedAt = Date.now();
      let auditStatus = 500;
      response.setHeader('x-request-id', requestId);
      requestsTotal += 1;

      let result;
      let failure;
      try {
        result = await breakers.for(capability.baseUrl).execute(
          () => performFetch({
            capability,
            requestPayload: payload,
            maxResponseBytes,
            fetchImpl,
            lookupImpl,
            timeoutMs,
            signal: clientAbort.signal,
          }),
          { isFailure: (candidate) => candidate?.status >= 500 },
        );
        auditStatus = result.status;
      } catch (error) {
        auditStatus = Number.isInteger(error?.statusCode) ? error.statusCode : 502;
        failure = error;
      } finally {
        if (writeAudit) {
          try {
            await boundedOperation(() => writeAudit({
              capabilityId: capability.id,
              status: auditStatus,
              method: typeof payload.method === 'string' && /^[A-Za-z]+$/.test(payload.method) && payload.method.length <= 16 ? payload.method.toUpperCase() : 'INVALID',
              path: auditPath(payload.path),
              peer,
              requestId,
              upstreamOrigin: (() => {
                try { return new URL(capability.baseUrl).origin; } catch { return null; }
              })(),
              softwareVersion: process.env.npm_package_version || 'unknown',
            }), timeoutMs, 'Audit dependency timed out');
          } catch (error) {
            safeLogger.error('proxy audit failed', { code: 'audit_unavailable', message: error?.message || 'Audit dependency failed' });
            if (auditRequired) failure = Object.assign(new Error('Audit dependency unavailable'), { statusCode: 503 });
          }
        }
        totalInFlight -= 1;
        const latencyMs = Math.max(0, Date.now() - requestStartedAt);
        requestLatencyTotalMs += latencyMs;
        requestLatencyMaxMs = Math.max(requestLatencyMaxMs, latencyMs);
        const remaining = inFlight.get(capability.id) - 1;
        if (remaining > 0) inFlight.set(capability.id, remaining);
        else inFlight.delete(capability.id);
      }
      if (failure) throw failure;
      for (const [name, value] of Object.entries(result.headers)) response.setHeader(name, value);
      response.statusCode = result.status;
      response.end(result.bytes);
      safeLogger.info('proxy request', {
        capabilityId: capability.id,
        method: payload.method === undefined ? 'GET' : String(payload.method).toUpperCase(),
        path: auditPath(payload.path),
        status: result.status,
      });
    } catch (error) {
      if (request.aborted || error?.clientAborted) return;
      const status = Number.isInteger(error?.statusCode) ? error.statusCode : 500;
      if (status >= 500) {
        upstreamErrorsTotal += status === 502 ? 1 : 0;
        safeLogger.error('proxy request failed', { status, code: publicErrorCode(status) });
      }
      const close = Boolean(error?.closeConnection) || !request.readableEnded;
      if (close) closeResponse(response, request, status, { error: publicErrorCode(status) });
      else if (!response.headersSent) jsonResponse(response, status, { error: publicErrorCode(status) });
      else response.end();
    }
  });

  server.on('error', (error) => safeLogger.error('broker server error', { errorName: error?.name || 'Error' }));
  server.on('clientError', (_error, socket) => {
    safeLogger.warn('broker client error', { code: 'client_protocol_error' });
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  server.requestTimeout = timeoutMs;
  // Keep active proxy requests alive until the explicit upstream deadline.
  // Node's generic socket timeout destroys the connection without allowing
  // the broker to return its bounded 502 response.
  server.timeout = 0;
  server.keepAliveTimeout = 5_000;
  server.headersTimeout = Math.max(timeoutMs, 5_000);
  server.maxHeadersCount = 100;
  let closePromise;
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
      if (closePromise) return closePromise;
      closePromise = new Promise((resolve, reject) => {
        const finish = () => {
          if (!server.listening) {
            eventLoopDelay.disable();
            resolve();
            return;
          }
          server.close((error) => {
            eventLoopDelay.disable();
            if (error) reject(error);
            else resolve();
          });
        };
        const deadline = Date.now() + Math.max(timeoutMs + 5_000, 10_000);
        const drain = () => {
          if (totalInFlight === 0) {
            finish();
            return;
          }
          if (Date.now() >= deadline) {
            // Do not wait forever on a client that holds a socket open after
            // the bounded upstream/request deadline has elapsed.
            server.closeAllConnections?.();
            finish();
            return;
          }
          setTimeout(drain, 25).unref?.();
        };
        drain();
      });
      return closePromise;
    },
  };
}

export { fetchWithPinnedAddress, performFetch, readBody, readResponseBody };

// metrics now correctly treats unknown as not loopback
// readyzCache per-instance, 10s TTL for both ok and !ok
// XFF multi-entry now rejected (peer fallback)
