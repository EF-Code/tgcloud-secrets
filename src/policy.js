const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'content-length',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export function normalizeMethods(value = ['GET']) {
  const values = Array.isArray(value) ? value : String(value).split(',');
  const methods = [...new Set(values.map((method) => String(method).trim().toUpperCase()).filter(Boolean))];
  if (methods.length === 0 || methods.some((method) => !METHODS.has(method))) {
    throw new Error(`Methods must be one or more of: ${[...METHODS].join(', ')}`);
  }
  return methods;
}

export function normalizeBaseUrl(value, { allowHttp = false } = {}) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Base URL must be a valid HTTPS URL');
  }

  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Base URL must not contain credentials, query parameters, or a fragment');
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new Error('Base URL must use HTTPS (use --allow-http only for local development)');
  }
  if (url.pathname !== '/' && url.pathname !== '') {
    throw new Error('Base URL must contain only an origin; put the API path in --path-prefix');
  }

  url.pathname = '/';
  return url.origin + '/';
}

export function normalizePathPrefix(value = '/') {
  const prefix = String(value);
  if (!prefix.startsWith('/') || prefix.startsWith('//') || prefix.includes('\\') || prefix.includes('\0')) {
    throw new Error('Path prefix must be an absolute URL path');
  }
  if (prefix.includes('?') || prefix.includes('#')) {
    throw new Error('Path prefix must not contain a query or fragment');
  }

  let decoded;
  try {
    decoded = decodeURIComponent(prefix);
  } catch {
    throw new Error('Path prefix contains invalid percent-encoding');
  }
  if (decoded.split('/').some((part) => part === '..')) {
    throw new Error('Path prefix must not contain parent-directory segments');
  }
  return prefix.length > 1 && !prefix.endsWith('/') ? `${prefix}/` : prefix;
}

export function isPathAllowed(pathname, prefix) {
  if (prefix === '/') return pathname.startsWith('/');
  const withoutTrailingSlash = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  return pathname === withoutTrailingSlash || pathname.startsWith(prefix);
}

export function resolveUpstreamUrl(baseUrl, requestPath, pathPrefix) {
  if (typeof requestPath !== 'string' || !requestPath.startsWith('/') || requestPath.startsWith('//')) {
    throw new Error('Request path must be an absolute path, not a URL');
  }
  if (requestPath.includes('\\') || requestPath.includes('\0')) {
    throw new Error('Request path contains a forbidden character');
  }

  let url;
  try {
    url = new URL(requestPath, baseUrl);
  } catch {
    throw new Error('Request path is not valid');
  }
  if (url.origin !== new URL(baseUrl).origin || !isPathAllowed(url.pathname, pathPrefix)) {
    throw new Error('Request path is outside this capability path policy');
  }

  let decoded;
  try {
    decoded = decodeURIComponent(url.pathname);
  } catch {
    throw new Error('Request path contains invalid percent-encoding');
  }
  if (decoded.split('/').some((part) => part === '..')) {
    throw new Error('Request path must not contain parent-directory segments');
  }
  return url;
}

export function normalizeInjectHeader(value = 'authorization') {
  const header = String(value).trim().toLowerCase();
  if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(header)) {
    throw new Error('Injection header is not a valid HTTP header name');
  }
  if (HOP_BY_HOP_HEADERS.has(header) || header.startsWith('x-tgcloud-')) {
    throw new Error('Injection header is reserved');
  }
  return header;
}

export function sanitizeForwardHeaders(input, injectedHeader) {
  const output = new Headers();
  const entries = input && typeof input === 'object' ? Object.entries(input) : [];
  for (const [name, value] of entries) {
    const lower = String(name).toLowerCase();
    if (lower === injectedHeader) {
      throw new Error(`The ${injectedHeader} header is managed by the capability`);
    }
    if (lower === 'x-tgcloud-capability' || HOP_BY_HOP_HEADERS.has(lower)) continue;
    if (Array.isArray(value) || typeof value === 'object') {
      throw new Error(`Header ${name} must have a string value`);
    }
    output.set(name, String(value));
  }
  return output;
}

export function assertAllowedMethod(method, allowedMethods) {
  const normalized = String(method || 'GET').toUpperCase();
  if (!allowedMethods.includes(normalized)) {
    throw new Error(`Method ${normalized} is not allowed by this capability`);
  }
  return normalized;
}

export function isSafeHttpHost(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === 'localhost'
    || normalized === '127.0.0.1'
    || normalized === '::1';
}

export { HOP_BY_HOP_HEADERS };
