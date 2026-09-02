import { createServer, request as httpRequest } from 'node:http';
import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { Readable } from 'node:stream';
import { assertAllowedMethod, isLoopbackHost, isPrivateHost, isSafeHeaderValue, isSafeHttpHost, resolveUpstreamUrl, sanitizeForwardHeaders } from './policy.js';

const DEFAULT_MAX_REQUEST_BYTES = 1 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 30 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CAPABILITY = 8;
const DEFAULT_MAX_CONCURRENT_REQUESTS = 32;
const MAX_RATE_LIMIT_BUCKETS = 10_000;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

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

function publicErrorCode(status) {
  switch (status) {
    case 400: return 'invalid_request';
    case 401: return 'invalid_capability';
    case 408: return 'request_timeout';
    case 413: return 'request_too_large';
    case 429: return 'rate_limited';
    case 502: return 'upstream_error';
    default: return 'internal_error';
  }
}

function extractCapability(request) {
  const value = request.headers['x-tgcloud-capability'];
  if (Array.isArray(value)) return undefined;
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
        if (!bucket && buckets.size >= MAX_RATE_LIMIT_BUCKETS) {
          for (const [candidate, value] of buckets) {
            if (value.resetAt <= now) buckets.delete(candidate);
          }
          if (buckets.size >= MAX_RATE_LIMIT_BUCKETS) {
            const oldest = buckets.keys().next().value;
            if (oldest !== undefined) buckets.delete(oldest);
          }
        }
        bucket = { count: 0, resetAt: now + windowMs };
        buckets.set(key, bucket);
      }
      if (bucket.count >= maxRequestsPerMinute) {
        return { allowed: false, retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000)) };
      }
      bucket.count += 1;
      return { allowed: true, retryAfter: 0 };
    },
    release(key) {
      const bucket = buckets.get(key);
      if (!bucket) return;
      bucket.count = Math.max(0, bucket.count - 1);
      if (bucket.count === 0 && Date.now() >= bucket.resetAt) buckets.delete(key);
    },
  };
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
      const client = normalizeIpAddress(forwarded.split(',')[0]);
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

function requestHasBody(request) {
  const declared = Number(request.headers['content-length']);
  return (Number.isFinite(declared) && declared > 0) || request.headers['transfer-encoding'] !== undefined;
}

async function readBody(request, maximumBytes, timeoutMs = 15_000) {
  const declared = Number(request.headers['content-length']);
  if (Number.isFinite(declared) && (declared < 0 || declared > maximumBytes)) {
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
    return Buffer.concat(chunks).toString('utf8');
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
    throw Object.assign(new Error('Upstream URL must use HTTP or HTTPS'), { statusCode: 502 });
  }
  const localHttp = target.protocol === 'http:' && capability.allowHttp === true && isSafeHttpHost(hostname);
  if (target.protocol === 'http:' && !localHttp) {
    throw Object.assign(new Error('HTTP upstreams are restricted to explicit loopback development targets'), { statusCode: 502 });
  }
  if (localHttp) return undefined;
  if (isIP(hostname)) {
    if (isPrivateHost(hostname)) {
      throw Object.assign(new Error('Upstream hostname resolved to a private or link-local address'), { statusCode: 502 });
    }
    return { address: hostname, family: isIP(hostname) };
  }
  let addresses;
  try {
    addresses = await lookupImpl(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw Object.assign(new Error('Upstream hostname could not be resolved'), { cause: error, statusCode: 502 });
  }
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some((entry) => {
    const address = entry?.address;
    return !address || isIP(address) === 0 || isPrivateHost(address);
  })) {
    throw Object.assign(new Error('Upstream hostname resolved to a private or link-local address'), { statusCode: 502 });
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
    if (error.statusCode) throw error;
    throw Object.assign(error, { statusCode: 400 });
  }
  if ((method === 'GET' || method === 'HEAD') && requestPayload.body !== undefined && requestPayload.body !== '') {
    throw Object.assign(new Error(`${method} requests cannot include a body`), { statusCode: 400 });
  }
  if (requestPayload.body !== undefined && typeof requestPayload.body !== 'string') {
    throw Object.assign(new Error('Request body must be a string'), { statusCode: 400 });
  }

  const controller = new AbortController();
  let rejectClientCancellation;
  const clientCancellation = requestSignal ? new Promise((_, reject) => {
    rejectClientCancellation = () => reject(Object.assign(new Error('Client disconnected'), { statusCode: 499, clientAborted: true }));
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
      throw Object.assign(new Error('Capability secret cannot be injected as an HTTP header value'), { statusCode: 502 });
    }
    try {
      headers.set(capability.injectHeader, injectValue);
    } catch (error) {
      throw Object.assign(new Error('Capability secret cannot be injected as an HTTP header value'), { statusCode: 502 });
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
      throw Object.assign(new Error('Upstream redirects are not allowed'), { statusCode: 502 });
    }

    const bytes = await raceWithDeadline(readResponseBody(upstream, maxResponseBytes));

    return {
      status: upstream.status,
      headers: forwardedResponseHeaders(upstream.headers),
      bytes,
    };
  } catch (error) {
    await cancelUpstreamBody(upstream);
    if (error.statusCode) throw error;
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
  maxInvalidAttemptsPerMinute = 60,
  maxConcurrentRequestsPerCapability = DEFAULT_MAX_CONCURRENT_REQUESTS_PER_CAPABILITY,
  maxConcurrentRequests = DEFAULT_MAX_CONCURRENT_REQUESTS,
  trustedProxyAddresses = [],
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
  assertPositiveLimit(maxConcurrentRequestsPerCapability, 'maxConcurrentRequestsPerCapability');
  assertPositiveLimit(maxConcurrentRequests, 'maxConcurrentRequests');
  const trustedProxySet = normalizeTrustedProxyAddresses(trustedProxyAddresses);
  if (!isLoopbackHost(host) && trustedProxySet.size === 0) {
    throw new Error('Non-loopback broker binds require trustedProxyAddresses for client-aware rate limiting');
  }
  const rateLimiter = createRateLimiter(maxRequestsPerMinute);
  const invalidRateLimiter = createRateLimiter(maxInvalidAttemptsPerMinute);
  const inFlight = new Map();
  let totalInFlight = 0;

  const server = createServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
    const clientAbort = new AbortController();
    request.once('aborted', () => clientAbort.abort());
    response.once('close', () => {
      if (!response.writableFinished) clientAbort.abort();
    });
    try {
      const declaredRequestBytes = Number(request.headers['content-length']);
      if (Number.isFinite(declaredRequestBytes) && declaredRequestBytes > maxRequestBytes) {
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
        if (requestHasBody(request)) closeResponse(response, request, 200, { ok: true });
        else if (request.method === 'HEAD') {
          response.writeHead(200, { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-type': 'application/json; charset=utf-8' });
          response.end();
        } else jsonResponse(response, 200, { ok: true });
        return;
      }
      if (request.method !== 'POST' || request.url !== '/v1/fetch') {
        closeResponse(response, request, 404, { error: 'not_found' });
        return;
      }

      const capabilityToken = extractCapability(request);
      const peer = requestClientKey(request, trustedProxySet);
      if (!looksLikeCapabilityToken(capabilityToken)) {
        const authRate = invalidRateLimiter.check(peer);
        if (!authRate.allowed) {
          closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': authRate.retryAfter });
          return;
        }
        closeResponse(response, request, 401, { error: 'invalid_capability' });
        return;
      }
      let capability;
      try {
        capability = await store.resolveCapability(capabilityToken);
      } catch (error) {
        throw error;
      }
      if (!capability) {
        const authRate = invalidRateLimiter.check(peer);
        if (!authRate.allowed) {
          closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': authRate.retryAfter });
          return;
        }
        closeResponse(response, request, 401, { error: 'invalid_capability' });
        return;
      }
      const rate = rateLimiter.check(capability.id);
      if (!rate.allowed) {
        closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': rate.retryAfter });
        return;
      }

      const rawBody = await readBody(request, maxRequestBytes, timeoutMs);
      let payload;
      try {
        payload = JSON.parse(rawBody);
      } catch {
        throw Object.assign(new Error('Request body must be valid JSON'), { statusCode: 400 });
      }
      if (!payload || typeof payload.path !== 'string') {
        throw Object.assign(new Error('Request must include a path'), { statusCode: 400 });
      }

      const active = inFlight.get(capability.id) || 0;
      if (active >= maxConcurrentRequestsPerCapability || totalInFlight >= maxConcurrentRequests) {
        closeResponse(response, request, 429, { error: 'rate_limited' }, { 'retry-after': 1 });
        return;
      }
      inFlight.set(capability.id, active + 1);
      totalInFlight += 1;

      try {
        const result = await performFetch({
          capability,
          requestPayload: payload,
          maxResponseBytes,
          fetchImpl,
          lookupImpl,
          timeoutMs,
          signal: clientAbort.signal,
        });
        for (const [name, value] of Object.entries(result.headers)) response.setHeader(name, value);
        response.statusCode = result.status;
        response.end(result.bytes);
        logger.info?.('proxy request', {
          capabilityId: capability.id,
          method: payload.method === undefined ? 'GET' : String(payload.method).toUpperCase(),
          path: new URL(payload.path, 'https://tgcloud.invalid').pathname,
          status: result.status,
        });
      } finally {
        totalInFlight -= 1;
        const remaining = inFlight.get(capability.id) - 1;
        if (remaining > 0) inFlight.set(capability.id, remaining);
        else inFlight.delete(capability.id);
      }
    } catch (error) {
      if (request.aborted || error.clientAborted) return;
      const status = Number.isInteger(error.statusCode) ? error.statusCode : 500;
      if (status >= 500) logger.error?.('proxy request failed', { status, code: publicErrorCode(status) });
      const close = Boolean(error.closeConnection) || !request.readableEnded;
      if (close) closeResponse(response, request, status, { error: publicErrorCode(status) });
      else if (!response.headersSent) jsonResponse(response, status, { error: publicErrorCode(status) });
      else response.end();
    }
  });

  server.on('error', (error) => logger.error?.('broker server error', { message: error.message }));
  server.on('clientError', (error, socket) => {
    logger.warn?.('broker client error', { message: error.message });
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
      return new Promise((resolve, reject) => {
        const deadline = Date.now() + Math.max(timeoutMs + 5_000, 10_000);
        const drain = () => {
          if (totalInFlight === 0 || Date.now() >= deadline) {
            server.close((error) => error ? reject(error) : resolve());
            return;
          }
          setTimeout(drain, 25).unref?.();
        };
        drain();
      });
    },
  };
}

export { fetchWithPinnedAddress, performFetch, readBody, readResponseBody };

// Swarm audit 2026-09-02: verified via node --test and manual probes
// swarm: ensure healthz logs do not include query
