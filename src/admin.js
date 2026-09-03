import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { authorize, AuthenticationError, AuthorizationError, normalizePrincipal, validateId } from './auth.js';
import { MAX_SECRET_BYTES, validateSecretName } from './pg-store.js';
import { isLoopbackHost, isSafeHeaderValue, normalizeBaseUrl, normalizeInjectHeader, normalizeInjectPrefix, normalizeMethods, normalizePathPrefix } from './policy.js';
import { createRedactingLogger } from './observability.js';
import { parseStrictJson } from './json.js';
import { sanitizeAuditPayload } from './audit.js';
import { parseRequestFraming } from './http.js';
import { createRateLimiter, MemoryRateLimiter, normalizeRateLimitDecision } from './rate-limit.js';

const MAX_BODY_BYTES = 64 * 1024;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,128}$/;
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_AUTH_TIMEOUT_MS = 5_000;

function boundedOperation(operation, timeoutMs, message, statusCode = 503, publicCode = 'dependency_unavailable') {
  const pending = Promise.resolve().then(operation);
  // A timed-out adapter can still reject later. Observe that rejection so a
  // broken authentication or authorization integration cannot crash the
  // process after the request has already been answered.
  pending.catch(() => {});
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error(message), { statusCode, publicCode })), timeoutMs);
    timer.unref?.();
  });
  return Promise.race([pending, timeout]).finally(() => clearTimeout(timer));
}

function publicError(error) {
  if (error instanceof AuthenticationError || error?.statusCode === 401) return { status: 401, code: 'unauthenticated' };
  if (error instanceof AuthorizationError || error?.statusCode === 403) return { status: 403, code: 'forbidden' };
  if (error?.code === 'TGCLOUD_IDEMPOTENCY_CONFLICT') return { status: 409, code: 'idempotency_conflict' };
  if (error?.code === 'TGCLOUD_IDEMPOTENCY_REPLAY_UNAVAILABLE') return { status: 409, code: 'idempotency_replay_unavailable' };
  if (error?.code === 'TGCLOUD_VERSION_CONFLICT') return { status: 409, code: 'version_conflict' };
  if (error?.code === 'TGCLOUD_LIFECYCLE_CONFLICT') return { status: 409, code: 'lifecycle_conflict' };
  if (error?.code === 'TGCLOUD_TENANT_DISABLED') return { status: 423, code: 'tenant_disabled' };
  if (error?.code === 'TGCLOUD_ERASURE_CONFIRMATION_REQUIRED') return { status: 400, code: 'erasure_confirmation_required' };
  if (error?.statusCode === 408) return { status: 408, code: 'request_timeout' };
  if (error?.statusCode === 415) return { status: 415, code: 'unsupported_media_type' };
  if (error?.statusCode === 413) return { status: 413, code: 'request_too_large' };
  if (error?.statusCode === 404) return { status: 404, code: 'not_found' };
  if (error?.statusCode === 502 || error?.statusCode === 503 || error?.statusCode === 504) return { status: error.statusCode, code: 'dependency_unavailable' };
  if (Number.isInteger(error?.statusCode) && error.statusCode >= 400 && error.statusCode < 500) return { status: error.statusCode, code: error.publicCode || 'invalid_request' };
  return { status: 500, code: 'internal_error' };
}

function json(response, status, body, extraHeaders = {}) {
  const encoded = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': encoded.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  response.end(encoded);
}

async function readBody(request, { timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS } = {}) {
  const { contentLength: declared } = parseRequestFraming(request);
  if (declared !== null && declared > MAX_BODY_BYTES) throw Object.assign(new Error('Request body is too large'), { statusCode: 413, closeConnection: true });
  const collect = (async () => {
    const chunks = [];
    let total = 0;
    for await (const chunk of request) {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) throw Object.assign(new Error('Request body is too large'), { statusCode: 413, closeConnection: true });
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  })();
  collect.catch(() => {});
  let timer;
  let raw;
  try {
    raw = await Promise.race([
      collect,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('Request body timed out'), { statusCode: 408, publicCode: 'request_timeout', closeConnection: true })), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } catch (error) {
    if (error?.publicCode === 'request_timeout') request.destroy?.();
    throw error;
  } finally {
    clearTimeout(timer);
  }
  let parsed;
  try {
    parsed = parseStrictJson(raw, { maxBytes: MAX_BODY_BYTES, maxDepth: 10, maxFields: 128, maxArrayItems: 128, maxStringBytes: 64 * 1024 });
  } catch (error) {
    throw error?.statusCode ? error : Object.assign(new Error('Request body must be valid JSON'), { statusCode: 400 });
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw Object.assign(new Error('Request body must be an object'), { statusCode: 400 });
  return { parsed, raw };
}

function requestHash(raw) {
  return createHash('sha256').update(raw).digest('hex');
}

function idempotencyKey(request) {
  const value = request.headers['idempotency-key'];
  if (Array.isArray(value) || typeof value !== 'string' || !IDEMPOTENCY_KEY.test(value)) throw Object.assign(new Error('Idempotency-Key is required'), { statusCode: 400 });
  return value;
}

function invalidRequest(message) {
  throw Object.assign(new Error(message), { statusCode: 400, publicCode: 'invalid_request' });
}

function optionalVersion(value, { minimum = 0, label = 'Version' } = {}) {
  if (value === undefined || value === null) return null;
  if (!Number.isSafeInteger(value) || value < minimum) invalidRequest(`${label} is invalid`);
  return value;
}

function optionalReason(value, fallback, label = 'Reason') {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== 'string' || value.length < 1 || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) {
    invalidRequest(`${label} is invalid`);
  }
  return value;
}

function validateMutationBody(target, body, store) {
  if (target.action === 'secret') {
    if (typeof body.name !== 'string' || typeof body.value !== 'string') invalidRequest('Secret name and value are required');
    try { validateSecretName(body.name); } catch { invalidRequest('Secret name is invalid'); }
    if (body.value.length === 0 || Buffer.byteLength(body.value, 'utf8') > MAX_SECRET_BYTES || !isSafeHeaderValue(body.value)) {
      invalidRequest('Secret value is invalid');
    }
    optionalVersion(body.expectedVersion, { label: 'expectedVersion' });
    return;
  }
  if (target.action === 'deleteSecret' || target.action === 'rollbackSecret') {
    try { validateSecretName(target.name); } catch { invalidRequest('Secret name is invalid'); }
  }
  if (target.action === 'deleteSecret') {
    optionalVersion(body.expectedVersion, { minimum: 1, label: 'expectedVersion' });
    return;
  }
  if (target.action === 'rollbackSecret') {
    optionalVersion(body.version, { minimum: 1, label: 'version' });
    if (body.version === undefined || body.version === null) invalidRequest('Secret version is required');
    optionalVersion(body.expectedVersion, { label: 'expectedVersion' });
    return;
  }
  if (target.action === 'capability') {
    if (typeof body.secretName !== 'string' || typeof body.baseUrl !== 'string') invalidRequest('Capability secretName and baseUrl are required');
    try {
      validateSecretName(body.secretName);
      normalizeBaseUrl(body.baseUrl, { allowHttp: body.allowHttp ?? false });
      normalizePathPrefix(body.pathPrefix ?? '/');
      normalizeMethods(body.methods ?? ['GET']);
      normalizeInjectHeader(body.injectHeader ?? 'authorization');
      normalizeInjectPrefix(body.injectPrefix ?? '');
    } catch {
      invalidRequest('Capability policy is invalid');
    }
    if (body.allowHttp !== undefined && typeof body.allowHttp !== 'boolean') invalidRequest('allowHttp is invalid');
    if (body.methods !== undefined && typeof body.methods !== 'string'
      && (!Array.isArray(body.methods) || body.methods.some((method) => typeof method !== 'string'))) invalidRequest('methods is invalid');
    if (body.expiresAt !== undefined && body.expiresAt !== null) {
      if (typeof body.expiresAt !== 'string') invalidRequest('expiresAt is invalid');
      const timestamp = new Date(body.expiresAt).getTime();
      const maximum = Number.isSafeInteger(store.maxCapabilityLifetimeMs) ? store.maxCapabilityLifetimeMs : 365 * 24 * 60 * 60 * 1_000;
      if (!Number.isFinite(timestamp) || timestamp <= Date.now() || timestamp - Date.now() > maximum) invalidRequest('expiresAt is invalid');
    }
    return;
  }
  if (target.action === 'revokeCapability') {
    optionalReason(body.reason, 'admin_revocation', 'Revocation reason');
    optionalVersion(body.expectedVersion, { minimum: 1, label: 'expectedVersion' });
    return;
  }
  if (target.action === 'rotateCapability') {
    if (body.overlapMs !== undefined && (!Number.isSafeInteger(body.overlapMs) || body.overlapMs < 0 || body.overlapMs > 24 * 60 * 60 * 1_000)) {
      invalidRequest('overlapMs is invalid');
    }
    optionalVersion(body.expectedVersion, { minimum: 1, label: 'expectedVersion' });
    return;
  }
  if (target.action === 'offboardTenant') {
    if (typeof body.state !== 'string') invalidRequest('Offboarding state is required');
    optionalReason(body.reason, 'admin_offboarding', 'Offboarding reason');
    if (body.expectedState !== undefined && body.expectedState !== null && typeof body.expectedState !== 'string') invalidRequest('expectedState is invalid');
    if (body.eraseConfirmed !== undefined && typeof body.eraseConfirmed !== 'boolean') invalidRequest('eraseConfirmed is invalid');
    return;
  }
  optionalReason(body.reason, target.action === 'restoreTenant' || target.action === 'restoreProject' ? 'admin_restore' : 'admin_revocation', 'Revocation reason');
}

function route(pathname) {
  if (pathname === '/v1/admin/secrets') return { action: 'secret' };
  const deleteSecret = /^\/v1\/admin\/secrets\/([A-Za-z][A-Za-z0-9_.-]{0,63})\/delete$/.exec(pathname);
  if (deleteSecret) return { action: 'deleteSecret', name: deleteSecret[1] };
  if (pathname === '/v1/admin/capabilities') return { action: 'capability' };
  const revoke = /^\/v1\/admin\/capabilities\/(cap_[a-f0-9]{20})\/revoke$/.exec(pathname);
  if (revoke) return { action: 'revokeCapability', id: revoke[1] };
  const rotate = /^\/v1\/admin\/capabilities\/(cap_[a-f0-9]{20})\/rotate$/.exec(pathname);
  if (rotate) return { action: 'rotateCapability', id: rotate[1] };
  const rollback = /^\/v1\/admin\/secrets\/([A-Za-z][A-Za-z0-9_.-]{0,63})\/rollback$/.exec(pathname);
  if (rollback) return { action: 'rollbackSecret', name: rollback[1] };
  if (pathname === '/v1/admin/tenants/revoke') return { action: 'revokeTenant' };
  if (pathname === '/v1/admin/tenants/restore') return { action: 'restoreTenant' };
  if (pathname === '/v1/admin/projects/revoke') return { action: 'revokeProject' };
  if (pathname === '/v1/admin/projects/restore') return { action: 'restoreProject' };
  if (pathname === '/v1/admin/tenants/offboard') return { action: 'offboardTenant' };
  if (pathname === '/v1/admin/tenants/lifecycle') return { action: 'lifecycle' };
  if (pathname === '/v1/admin/audit') return { action: 'audit' };
  return null;
}

function tenantResourceId(value, label) {
  if (typeof value !== 'string') throw Object.assign(new Error('Tenant resource is invalid'), { statusCode: 400 });
  try {
    return validateId(value, label);
  } catch {
    throw Object.assign(new Error('Tenant resource is invalid'), { statusCode: 400 });
  }
}

function singleQueryValue(url, name) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) throw Object.assign(new Error('Duplicate query parameter'), { statusCode: 400 });
  return values[0] ?? null;
}

function auditQueryOptions(url, { cursor = true } = {}) {
  const allowed = new Set(cursor ? ['orgId', 'projectId', 'limit', 'before'] : ['orgId', 'projectId']);
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key)) throw Object.assign(new Error('Unsupported query parameter'), { statusCode: 400 });
  }
  const rawLimit = singleQueryValue(url, 'limit');
  const limit = rawLimit === null ? 100 : Number(rawLimit);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw Object.assign(new Error('Audit limit is invalid'), { statusCode: 400 });
  const before = singleQueryValue(url, 'before');
  if (before !== null && Number.isNaN(new Date(before).getTime())) throw Object.assign(new Error('Audit cursor is invalid'), { statusCode: 400 });
  return {
    orgId: singleQueryValue(url, 'orgId'),
    projectId: singleQueryValue(url, 'projectId'),
    limit,
    before,
  };
}

async function writeAudit(client, { eventType, principal, orgId, projectId, target = null, outcome, requestId, detail = {} }) {
  const eventId = randomUUID();
  let payload;
  try {
    payload = sanitizeAuditPayload({
      eventId,
      eventType,
      actor: principal.subject,
      orgId,
      projectId,
      target,
      outcome,
      requestId,
      decisionEvidence: {
        mfaSatisfied: principal.mfaSatisfied,
        approvedBy: principal.approvedBy,
        stepUpAt: principal.stepUpAt,
      },
      detail,
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    throw Object.assign(error, { statusCode: 400, publicCode: 'invalid_request' });
  }
  await client.query(
    `INSERT INTO audit_outbox (event_id, org_id, project_id, event_type, payload)
     VALUES ($1,$2,$3,$4,$5)`,
    [eventId, orgId, `${orgId}:${projectId}`, eventType, JSON.stringify(payload)],
  );
}

export function createAdminServer({
  store,
  host = '127.0.0.1',
  port = 8788,
  authenticate,
  authorize: authorizeFn = authorize,
  tlsTerminated = false,
  allowPublic = false,
  maxRequestsPerMinute = 120,
  maxInvalidAttemptsPerMinute = 30,
  rateLimiter,
  invalidRateLimiter,
  rateLimiterBackend,
  invalidRateLimiterBackend,
  requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  authTimeoutMs = DEFAULT_AUTH_TIMEOUT_MS,
  logger = console,
} = {}) {
  if (!store || typeof store.runIdempotent !== 'function') throw new Error('Admin server requires a Postgres store with durable idempotency');
  if (typeof authenticate !== 'function') throw new Error('Admin server requires an external authentication adapter');
  if (!isLoopbackHost(host) && (!allowPublic || !tlsTerminated)) throw new Error('Public admin binds require authenticated TLS termination and explicit allowPublic');
  if (!Number.isSafeInteger(maxRequestsPerMinute) || maxRequestsPerMinute < 1) throw new Error('maxRequestsPerMinute must be a positive integer');
  if (!Number.isSafeInteger(maxInvalidAttemptsPerMinute) || maxInvalidAttemptsPerMinute < 1) throw new Error('maxInvalidAttemptsPerMinute must be a positive integer');
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 100 || requestTimeoutMs > 120_000) throw new Error('requestTimeoutMs must be between 100 and 120000');
  if (!Number.isSafeInteger(authTimeoutMs) || authTimeoutMs < 100 || authTimeoutMs > 30_000) throw new Error('authTimeoutMs must be between 100 and 30000');
  const productionRuntime = process.env.TGCLOUD_ENV === 'production' || process.env.NODE_ENV === 'production';
  if (productionRuntime && !rateLimiterBackend && !(rateLimiter && invalidRateLimiter)) {
    throw new Error('Production admin server requires a distributed limiter backend or explicit limiters for both request and authentication buckets');
  }
  const requestEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute, maxBuckets: 10_000 });
  const invalidEmergencyLimiter = new MemoryRateLimiter({ maxRequestsPerMinute: maxInvalidAttemptsPerMinute, maxBuckets: 10_000 });
  const limiterTimeoutMs = Math.max(100, Math.min(requestTimeoutMs, 5_000));
  const requestLimiter = rateLimiter || createRateLimiter({ maxRequestsPerMinute, backend: rateLimiterBackend, fallback: requestEmergencyLimiter, keyPrefix: 'tgcloud:admin', operationTimeoutMs: limiterTimeoutMs });
  const authLimiter = invalidRateLimiter || createRateLimiter({ maxRequestsPerMinute: maxInvalidAttemptsPerMinute, backend: invalidRateLimiterBackend || rateLimiterBackend, fallback: invalidEmergencyLimiter, keyPrefix: 'tgcloud:admin-auth', operationTimeoutMs: limiterTimeoutMs });
  const clientKey = (request) => {
    const peer = request.socket?.remoteAddress;
    return typeof peer === 'string' && peer.length > 0 && peer.length <= 128 ? `peer:${peer}` : 'peer:unknown';
  };
  const checkLimiter = async (limiter, key) => {
    try {
      const decision = normalizeRateLimitDecision(await boundedOperation(
        () => limiter.check(key),
        limiterTimeoutMs,
        'Rate limiter timed out',
      ));
      if (productionRuntime && decision.reason === 'limiter_unavailable') return { allowed: false, retryAfter: 1 };
      return decision;
    } catch (error) {
      safeLogger.error('admin rate limiter failed', { code: 'limiter_unavailable', errorName: error?.name || 'Error' });
      return { allowed: false, retryAfter: 1 };
    }
  };
  const rateLimitError = () => Object.assign(new Error('Too many requests'), { statusCode: 429, publicCode: 'rate_limited', retryAfter: 1 });
  const authorizeRequest = async (principal, permission, resource) => {
    const normalized = authorize(principal, permission, resource);
    const decision = await boundedOperation(
      () => authorizeFn(normalized, permission, resource),
      authTimeoutMs,
      'Authorization adapter timed out',
    );
    if (decision === false) throw new AuthorizationError();
    return normalized;
  };
  const safeLogger = createRedactingLogger(logger);
  const authenticatePrincipal = (request) => boundedOperation(
    async () => normalizePrincipal(await authenticate(request)),
    authTimeoutMs,
    'Authentication adapter timed out',
  );
  const authenticateForRequest = async (request) => {
    try {
      return await authenticatePrincipal(request);
    } catch (error) {
      if (error?.statusCode === 401) {
        const invalidRate = await checkLimiter(authLimiter, clientKey(request));
        if (!invalidRate.allowed) throw rateLimitError();
      }
      throw error;
    }
  };

  const server = createServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
    const requestId = randomUUID();
    response.setHeader('x-request-id', requestId);
    try {
      const framing = parseRequestFraming(request);
      const requestRate = await checkLimiter(requestLimiter, clientKey(request));
      if (!requestRate.allowed) {
        return json(response, 429, { error: 'rate_limited' }, { 'retry-after': Math.max(1, requestRate.retryAfter || 1) });
      }
      const url = new URL(request.url, 'http://admin.invalid');
      if (framing.hasBody && request.method !== 'POST') {
        response.shouldKeepAlive = false;
        return json(response, 400, { error: 'invalid_request' }, { connection: 'close' });
      }
      const target = route(url.pathname);
      if (!target) {
        if (framing.hasBody) {
          response.shouldKeepAlive = false;
          return json(response, 404, { error: 'not_found' }, { connection: 'close' });
        }
        return json(response, 404, { error: 'not_found' });
      }
      if (target.action === 'audit' && request.method === 'GET') {
        const principal = await authenticateForRequest(request);
        const query = auditQueryOptions(url);
        const orgId = tenantResourceId(query.orgId ?? principal.orgId, 'resource.orgId');
        const projectId = tenantResourceId(query.projectId ?? principal.projectId, 'resource.projectId');
        await authorizeRequest(principal, 'audit:read', { orgId, projectId });
        if (typeof store.listAudit !== 'function') return json(response, 501, { error: 'not_implemented' });
        const events = await store.listAudit({ orgId, projectId, limit: query.limit, before: query.before });
        return json(response, 200, { events });
      }
      if (target.action === 'lifecycle' && request.method === 'GET') {
        const principal = await authenticateForRequest(request);
        const query = auditQueryOptions(url, { cursor: false });
        const orgId = tenantResourceId(query.orgId ?? principal.orgId, 'resource.orgId');
        const projectId = tenantResourceId(query.projectId ?? principal.projectId, 'resource.projectId');
        await authorizeRequest(principal, 'tenant:read', { orgId, projectId });
        if (typeof store.getTenantLifecycle !== 'function') return json(response, 501, { error: 'not_implemented' });
        const lifecycle = await store.getTenantLifecycle({ orgId, projectId });
        return json(response, 200, lifecycle);
      }
      if (target.action === 'audit') return json(response, 405, { error: 'method_not_allowed' }, { allow: 'GET' });
      if (target.action === 'lifecycle') return json(response, 405, { error: 'method_not_allowed' }, { allow: 'GET' });
      if (request.method !== 'POST') return json(response, 405, { error: 'method_not_allowed' }, { allow: 'POST' });
      if ([...url.searchParams].length > 0) throw Object.assign(new Error('Mutation query parameters are not supported'), { statusCode: 400 });
      if (typeof request.headers['content-type'] !== 'string' || !/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'])) {
        response.shouldKeepAlive = false;
        return json(response, 415, { error: 'unsupported_media_type' }, { connection: 'close' });
      }
      const { parsed: body, raw } = await readBody(request, { timeoutMs: requestTimeoutMs });
      const permission = target.action === 'secret' ? 'secret:write'
        : target.action === 'deleteSecret' ? 'secret:delete'
        : target.action === 'capability' ? 'capability:issue'
        : target.action === 'revokeCapability' ? 'capability:revoke'
          : target.action === 'rotateCapability' ? 'capability:rotate'
            : target.action === 'rollbackSecret' ? 'secret:write'
            : target.action === 'offboardTenant' ? 'tenant:offboard'
              : 'tenant:revoke';
      const principal = await authenticateForRequest(request);
      const allowedFields = target.action === 'secret'
        ? ['name', 'value', 'orgId', 'projectId', 'expectedVersion']
        : target.action === 'deleteSecret'
          ? ['orgId', 'projectId', 'expectedVersion']
        : target.action === 'rollbackSecret'
          ? ['version', 'orgId', 'projectId', 'expectedVersion']
        : target.action === 'capability'
          ? ['secretName', 'baseUrl', 'pathPrefix', 'methods', 'injectHeader', 'injectPrefix', 'allowHttp', 'expiresAt', 'orgId', 'projectId']
          : target.action === 'revokeCapability'
            ? ['reason', 'orgId', 'projectId', 'expectedVersion']
        : target.action === 'rotateCapability'
            ? ['overlapMs', 'orgId', 'projectId', 'expectedVersion']
            : target.action === 'offboardTenant'
              ? ['state', 'organization', 'expectedState', 'eraseConfirmed', 'reason', 'orgId', 'projectId']
              : target.action === 'revokeTenant' || target.action === 'restoreTenant'
                ? ['reason', 'organization', 'orgId', 'projectId']
                : ['reason', 'orgId', 'projectId'];
      if (Object.keys(body).some((key) => !allowedFields.includes(key))) throw Object.assign(new Error('Unsupported request field'), { statusCode: 400 });
      if (Object.hasOwn(body, 'organization') && typeof body.organization !== 'boolean') throw Object.assign(new Error('Organization scope must be boolean'), { statusCode: 400 });
      validateMutationBody(target, body, store);
      if ((target.action === 'revokeTenant' || target.action === 'restoreTenant')
        && body.organization !== undefined && body.organization !== true) {
        invalidRequest('Tenant revocation routes require organization scope');
      }
      const organizationScope = target.action === 'revokeTenant' || target.action === 'restoreTenant'
        ? true
        : target.action === 'offboardTenant' && body.organization === true;
      const orgId = tenantResourceId(body.orgId ?? principal.orgId, 'resource.orgId');
      // Organization mutations still need one project context for the
      // RLS-protected idempotency and audit rows written in the same tx.
      const projectId = tenantResourceId(body.projectId ?? principal.projectId, 'resource.projectId');
      const destructive = target.action === 'deleteSecret'
        || target.action === 'rollbackSecret'
        || target.action === 'revokeTenant'
        || target.action === 'restoreTenant'
        || target.action === 'revokeProject'
        || target.action === 'restoreProject'
        || target.action === 'offboardTenant';
      const resource = organizationScope
        ? { orgId, action: target.action, target: target.name || target.id || body.name || body.secretName || null, destructive, approvedBy: principal.approvedBy }
        : { orgId, projectId, action: target.action, target: target.name || target.id || body.name || body.secretName || null, destructive, approvedBy: principal.approvedBy };
      await authorizeRequest(principal, permission, resource);
      const key = idempotencyKey(request);
      const hash = requestHash(raw);
      const result = await store.runIdempotent({ idempotencyKey: key, requestHash: hash, orgId, projectId, mutation: async (client) => {
        let value;
        if (target.action === 'secret') {
          if (typeof body.name !== 'string' || typeof body.value !== 'string') throw Object.assign(new Error('Secret name and value are required'), { statusCode: 400 });
          value = await store._setSecretInClient(client, { name: body.name, value: body.value, orgId, projectId, expectedVersion: body.expectedVersion ?? null, emitAudit: false });
          await writeAudit(client, { eventType: 'admin.secret.upsert', principal, orgId, projectId, target: body.name, outcome: 'success', requestId, detail: { version: value.version } });
          return { name: body.name, version: value.version };
        }
        if (target.action === 'deleteSecret') {
          value = await store._deleteSecretInClient(client, { name: target.name, orgId, projectId, expectedVersion: body.expectedVersion ?? null, emitAudit: false });
          if (!value) throw Object.assign(new Error('Secret not found'), { statusCode: 404 });
          await writeAudit(client, { eventType: 'admin.secret.delete', principal, orgId, projectId, target: target.name, outcome: 'success', requestId, detail: { previousVersion: body.expectedVersion ?? null } });
          return value;
        }
        if (target.action === 'rollbackSecret') {
          value = await store._rollbackSecretInClient(client, {
            name: target.name,
            version: body.version,
            orgId,
            projectId,
            expectedVersion: body.expectedVersion ?? null,
            emitAudit: false,
          });
          await writeAudit(client, { eventType: 'admin.secret.rollback', principal, orgId, projectId, target: target.name, outcome: 'success', requestId, detail: { restoredVersion: value.restoredVersion, newVersion: value.version } });
          return value;
        }
        if (target.action === 'capability') {
          value = await store._createCapabilityInClient(client, { ...body, orgId, projectId, emitAudit: false });
          await writeAudit(client, { eventType: 'admin.capability.issue', principal, orgId, projectId, target: value.id, outcome: 'success', requestId, detail: { secretName: value.secretName } });
          return value;
        }
        if (target.action === 'revokeCapability') {
          value = await store._revokeCapabilityInClient(client, target.id, { orgId, projectId, reason: body.reason || 'admin_revocation', expectedVersion: body.expectedVersion ?? null });
          if (!value) throw Object.assign(new Error('Capability not found'), { statusCode: 404 });
          await writeAudit(client, { eventType: 'admin.capability.revoke', principal, orgId, projectId, target: target.id, outcome: 'success', requestId, detail: { reason: body.reason || 'admin_revocation' } });
          return { id: target.id, revoked: true };
        }
        if (target.action === 'rotateCapability') {
          value = await store._rotateCapabilityInClient(client, {
            id: target.id,
            orgId,
            projectId,
            overlapMs: body.overlapMs ?? 0,
            expectedVersion: body.expectedVersion ?? null,
            emitAudit: false,
          });
          await writeAudit(client, { eventType: 'admin.capability.rotate', principal, orgId, projectId, target: target.id, outcome: 'success', requestId, detail: { newCapabilityId: value.id, overlapUntil: value.overlapUntil } });
          return value;
        }
        if (target.action === 'offboardTenant') {
          if (typeof body.state !== 'string') throw Object.assign(new Error('Offboarding state is required'), { statusCode: 400 });
          const organization = organizationScope;
          value = await store._transitionOffboardingInClient(client, { state: body.state, orgId, projectId, organization, reason: body.reason || 'admin_offboarding', expectedState: body.expectedState ?? null, eraseConfirmed: body.eraseConfirmed === true, emitAudit: false });
          await writeAudit(client, { eventType: 'admin.tenant.offboard', principal, orgId, projectId, target: organization ? orgId : `${orgId}:${projectId}`, outcome: 'success', requestId, detail: { state: body.state, organization } });
          return value;
        }
        const organization = organizationScope;
        const active = target.action === 'revokeTenant' || target.action === 'revokeProject';
        await store._setTenantRevocationInClient(client, { orgId, projectId, organization, active, reason: body.reason || (active ? 'admin_revocation' : 'admin_restore') });
        const eventType = organization
          ? (active ? 'admin.tenant.revoke' : 'admin.tenant.restore')
          : (active ? 'admin.project.revoke' : 'admin.project.restore');
        await writeAudit(client, { eventType, principal, orgId, projectId, target: organization ? orgId : `${orgId}:${projectId}`, outcome: 'success', requestId, detail: { reason: body.reason || (active ? 'admin_revocation' : 'admin_restore') } });
        return { orgId, projectId: organization ? null : projectId, revoked: active };
      }});
      return json(response, target.action === 'capability' ? 201 : 200, result);
    } catch (error) {
      const result = publicError(error);
      if (result.status >= 500) safeLogger.error('admin request failed', { requestId, code: result.code });
      if (error?.closeConnection) {
        response.shouldKeepAlive = false;
        return json(response, result.status, { error: result.code }, { connection: 'close' });
      }
      return json(response, result.status, { error: result.code });
    }
  });
  server.on('clientError', (_error, socket) => socket.writable && socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
  server.requestTimeout = requestTimeoutMs;
  server.timeout = 0;
  server.keepAliveTimeout = 5_000;
  server.headersTimeout = Math.min(120_000, requestTimeoutMs + 5_000);
  let closePromise;
  return {
    server,
    listen() {
      return new Promise((resolve, reject) => {
        const onError = (error) => { server.off('listening', onListening); reject(error); };
        const onListening = () => { server.off('error', onError); resolve(server.address()); };
        server.once('error', onError);
        server.once('listening', onListening);
        server.listen(port, host);
      });
    },
    close() {
      if (closePromise) return closePromise;
      closePromise = new Promise((resolve, reject) => {
        if (!server.listening) {
          resolve();
          return;
        }
        const deadline = setTimeout(() => server.closeAllConnections?.(), 20_000);
        deadline.unref?.();
        try {
          server.close((error) => {
            clearTimeout(deadline);
            if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
            else resolve();
          });
          server.closeIdleConnections?.();
        } catch (error) {
          clearTimeout(deadline);
          reject(error);
        }
      });
      return closePromise;
    },
  };
}

export { MAX_BODY_BYTES };
