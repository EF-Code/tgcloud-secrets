import { isIP } from 'node:net';

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'content-length',
  'forwarded',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-forwarded-proto',
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
  if (url.protocol === 'http:' && !(allowHttp && isSafeHttpHost(url.hostname))) {
    throw new Error('HTTP is allowed only for loopback development targets; production capabilities require HTTPS');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('Base URL must use HTTPS (use --allow-http only for local development)');
  }
  if (isPrivateHost(url.hostname) && !(allowHttp && url.protocol === 'http:' && isSafeHttpHost(url.hostname))) {
    throw new Error('Base URL must not target localhost or a private/link-local IP address');
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

export function normalizeInjectPrefix(value = '') {
  if (typeof value !== 'string' || value.length > 128 || /[\r\n]/.test(value)) {
    throw new Error('Injection prefix must be a string of at most 128 characters without CR or LF');
  }
  return value;
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

export function isLoopbackHost(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (normalized === 'localhost' || normalized === '::1') return true;
  return isIP(normalized) === 4 && normalized.startsWith('127.');
}

function isPrivateIpv4(hostname) {
  const octets = hostname.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
  const [first, second] = octets;
  return first === 0
    || first === 10
    || first === 127
    || (first === 100 && second >= 64 && second <= 127)
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 0)
    || (first === 192 && second === 168)
    || (first === 198 && (second === 18 || second === 19))
    || first >= 224;
}

export function isPrivateHost(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  // URL parsers may canonicalize an IPv4-mapped address to hexadecimal form;
  // reject the entire mapped range rather than risk missing a private target.
  if (normalized.startsWith('::ffff:')) return true;
  if (isSafeHttpHost(normalized)) return true;
  if (isIP(normalized) === 4) return isPrivateIpv4(normalized);
  if (isIP(normalized) === 6) {
    return normalized === '::'
      || normalized === '::1'
      || normalized.startsWith('fc')
      || normalized.startsWith('fd')
      || normalized.startsWith('fe8')
      || normalized.startsWith('fe9')
      || normalized.startsWith('fea')
      || normalized.startsWith('feb')
      || normalized.startsWith('fec')
      || normalized.startsWith('ff');
  }
  return false;
}

export { HOP_BY_HOP_HEADERS };
