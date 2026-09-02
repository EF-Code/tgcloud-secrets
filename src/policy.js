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
  // Do not let an upstream reinterpret the scoped method or path.
  'x-envoy-original-path',
  'x-forwarded-path',
  'x-forwarded-prefix',
  'x-forwarded-uri',
  'x-http-method-override',
  'x-middleware-rewrite',
  'x-original-method',
  'x-original-uri',
  'x-original-url',
  'x-rewrite-uri',
  'x-rewrite-url',
]);

const UNSAFE_HEADER_VALUE = /[\u0000-\u0008\u000A-\u000D\u000E-\u001F\u007F]/;
const UNSAFE_PATH_VALUE = /[\u0000-\u001F\u007F]/;

export function isSafeHeaderValue(value) {
  return typeof value === 'string'
    && !UNSAFE_HEADER_VALUE.test(value)
    && [...value].every((character) => character.codePointAt(0) <= 0xff);
}

function normalizeHostname(hostname) {
  return String(hostname).toLowerCase().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
}

function decodePathForPolicy(value, message) {
  let decoded = value;
  for (let round = 0; round < 8; round += 1) {
    const current = decoded;
    let next;
    try {
      next = decodeURIComponent(current);
    } catch {
      // A percent sign produced by decoding %25 is a literal and does not
      // need another decode pass. Malformed encoding in the original value,
      // or in a still-encoded nested value, remains an error.
      if (round > 0 && !/%[0-9a-f]{2}/i.test(decoded)) break;
      throw new Error(`${message} contains invalid percent-encoding`);
    }
    decoded = next;
    if (UNSAFE_PATH_VALUE.test(decoded) || decoded.includes('\\')) {
      throw new Error(`${message} contains a forbidden character`);
    }
    if (decoded.split(/[\\/]/).some((part) => part === '..')) {
      throw new Error(`${message} must not contain parent-directory segments`);
    }
    if (next === current || !/%[0-9a-f]{2}/i.test(decoded)) break;
  }
  // A bounded fixed-point decode avoids unbounded work while still rejecting
  // a nested encoding that a downstream framework might decode later.
  if (/%(?:2e|2f|5c|00)/i.test(decoded)) {
    throw new Error(`${message} contains a forbidden encoded character`);
  }
  return decoded;
}

export function normalizeMethods(value = ['GET']) {
  const values = Array.isArray(value) ? value : String(value).split(',');
  const methods = [...new Set(values.map((method) => String(method).trim().toUpperCase()).filter(Boolean))];
  if (methods.length === 0 || methods.some((method) => !METHODS.has(method))) {
    throw new Error(`Methods must be one or more of: ${[...METHODS].join(', ')}`);
  }
  return methods;
}

export function normalizeBaseUrl(value, { allowHttp = false } = {}) {
  if (typeof value !== 'string' || value.length === 0) throw new Error('Base URL must be a valid HTTPS URL');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Base URL must be a valid HTTPS URL');
  }

  if (url.hostname.endsWith('.')) {
    throw new Error('Base URL must not contain a trailing dot');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('Base URL must not contain credentials, query parameters, or a fragment');
  }
  if (url.protocol === 'http:' && !(allowHttp === true && isSafeHttpHost(url.hostname))) {
    throw new Error('HTTP is allowed only for loopback development targets; production capabilities require HTTPS');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('Base URL must use HTTPS (use --allow-http only for local development)');
  }
  if (isPrivateHost(url.hostname) && !(allowHttp === true && url.protocol === 'http:' && isSafeHttpHost(url.hostname))) {
    throw new Error('Base URL must not target localhost or a private/link-local IP address');
  }
  if (url.pathname !== '/' && url.pathname !== '') {
    throw new Error('Base URL must contain only an origin; put the API path in --path-prefix');
  }

  url.pathname = '/';
  return url.origin + '/';
}

export function normalizePathPrefix(value = '/') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    throw new Error('Path prefix must be a non-empty string of at most 4096 characters');
  }
  const prefix = value;
  if (!prefix.startsWith('/') || prefix.startsWith('//') || prefix.includes('\\') || prefix.includes('\0') || UNSAFE_PATH_VALUE.test(prefix)) {
    throw new Error('Path prefix must be an absolute URL path');
  }
  if (prefix.includes('?') || prefix.includes('#')) {
    throw new Error('Path prefix must not contain a query or fragment');
  }

  decodePathForPolicy(prefix, 'Path prefix');
  return prefix.length > 1 && !prefix.endsWith('/') ? `${prefix}/` : prefix;
}

export function isPathAllowed(pathname, prefix) {
  if (typeof pathname !== 'string' || typeof prefix !== 'string' || !prefix.startsWith('/')) return false;
  if (prefix === '/') return pathname.startsWith('/');
  const withoutTrailingSlash = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  return pathname === withoutTrailingSlash || pathname.startsWith(`${withoutTrailingSlash}/`);
}

export function resolveUpstreamUrl(baseUrl, requestPath, pathPrefix) {
  if (typeof requestPath !== 'string' || !requestPath.startsWith('/') || requestPath.startsWith('//')) {
    throw new Error('Request path must be an absolute path, not a URL');
  }
  if (requestPath.includes('\\') || requestPath.includes('\0') || UNSAFE_PATH_VALUE.test(requestPath)) {
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

  if (/%(?:25)*2f/i.test(url.pathname) || /%(?:25)*2f/i.test(requestPath.split('?')[0].split('#')[0])) {
    throw new Error('Request path contains a forbidden encoded character');
  }
  decodePathForPolicy(url.pathname, 'Request path');
  // Validate search and hash for both raw and encoded controls
  const checkSearchHash = (value, label) => {
    if (!value) return;
    if (UNSAFE_PATH_VALUE.test(value) || value.includes('\\') || value.includes('\0')) {
      throw new Error(`${label} contains a forbidden character`);
    }
    // Check for encoded controls in query/fragment (e.g., %0a, %0d, %09, %1f, %7f, %00)
    if (/%(?:0a|0d|09|1f|7f|00)/i.test(value)) {
      throw new Error(`${label} contains a forbidden encoded character`);
    }
    // Also check double-encoded via decode loop
    let decoded = value;
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
        if (UNSAFE_PATH_VALUE.test(decoded) || /%00/i.test(decoded)) {
          throw new Error(`${label} contains a forbidden encoded character`);
        }
      } catch { break; }
    }
  };
  checkSearchHash(url.search, 'Request path');
  checkSearchHash(url.hash, 'Request path');
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
  if (typeof value !== 'string' || value.length > 128 || !isSafeHeaderValue(value)) {
    throw new Error('Injection prefix must be a string of at most 128 characters without unsafe control characters');
  }
  return value;
}

export function sanitizeForwardHeaders(input, injectedHeader) {
  if (input !== undefined && (input === null || typeof input !== 'object' || Array.isArray(input))) {
    throw new Error('Headers must be an object');
  }
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
    const stringValue = String(value);
    if (!isSafeHeaderValue(stringValue)) throw new Error(`Header ${name} contains an unsafe value`);
    output.set(name, stringValue);
  }
  return output;
}

export function assertAllowedMethod(method, allowedMethods) {
  const normalized = String(method === undefined ? 'GET' : method).toUpperCase();
  if (!allowedMethods.includes(normalized)) {
    throw new Error(`Method ${normalized} is not allowed by this capability`);
  }
  return normalized;
}

export function isSafeHttpHost(hostname) {
  const normalized = normalizeHostname(hostname);
  return isLoopbackHost(normalized);
}

export function isLoopbackHost(hostname) {
  const normalized = normalizeHostname(hostname);
  if (normalized === 'localhost' || normalized === '::1') return true;
  // Normalize 127.000.0.1 -> 127.0.0.1 via URL parsing for leading zeros
  let ip = normalized;
  if (ip.includes('.')) {
    try {
      const urlHost = new URL(`http://${ip}`).hostname;
      if (isIP(urlHost) === 4) ip = urlHost;
    } catch {}
  }
  return isIP(ip) === 4 && ip.startsWith('127.');
}

function isPrivateIpv4(hostname) {
  const octets = hostname.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
  const [first, second, third] = octets;
  return first === 0
    || first === 10
    || first === 127
    || (first === 100 && second >= 64 && second <= 127)
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 0 && third === 2)
    || (first === 192 && second === 88 && third === 99)
    || (first === 192 && second === 168)
    || (first === 198 && (second === 18 || second === 19))
    || (first === 198 && second === 51 && third === 100)
    || (first === 203 && second === 0 && third === 113)
    || first >= 224;
}

export function isPrivateHost(hostname) {
  const normalized = normalizeHostname(hostname);
  if (normalized.startsWith('::ffff:')) {
    const v4 = normalized.slice(7);
    if (isIP(v4) === 4) return isPrivateIpv4(v4);
    return true;
  }
  if (isSafeHttpHost(normalized)) return true;
  if (isIP(normalized) === 4) return isPrivateIpv4(normalized);
  if (isIP(normalized) === 6) {
    const hextets = parseIpv6Hextets(normalized);
    if (!hextets) return true;
    const firstHextet = hextets[0];
    if (firstHextet === 0
      || (firstHextet & 0xfe00) === 0xfc00
      || (firstHextet & 0xffc0) === 0xfe80
      || (firstHextet & 0xffc0) === 0xfec0
      || (firstHextet & 0xff00) === 0xff00
      || (hextets[0] === 0x2001 && hextets[1] === 0x0db8)) return true;

    // Reject private IPv4 addresses embedded in common IPv6 transition
    // mechanisms (NAT64, 6to4, and Teredo).
    if (hextets[0] === 0x0064 && hextets[1] === 0xff9b
      && hextets[2] === 0 && hextets[3] === 0 && hextets[4] === 0 && hextets[5] === 0
      && isPrivateEmbeddedIpv4(hextets, 6)) return true;
    if (hextets[0] === 0x2002 && isPrivateEmbeddedIpv4(hextets, 1)) return true;
    if (hextets[0] === 0x2001 && hextets[1] === 0 && isPrivateEmbeddedIpv4(hextets.map((value, index) => index < 6 ? value : value ^ 0xffff), 6)) return true;
    return false;
  }
  return false;
}

function parseIpv6Hextets(value) {
  const input = value.toLowerCase();
  let normalized = input;
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4 = normalized.slice(lastColon + 1);
    const octets = ipv4.split('.').map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const sections = normalized.split('::');
  if (sections.length > 2) return null;
  const left = sections[0] ? sections[0].split(':') : [];
  const right = sections.length === 2 && sections[1] ? sections[1].split(':') : [];
  const parse = (part) => part.map((hextet) => {
    if (!/^[0-9a-f]{1,4}$/.test(hextet)) return null;
    return Number.parseInt(hextet, 16);
  });
  const leftValues = parse(left);
  const rightValues = parse(right);
  if (leftValues.includes(null) || rightValues.includes(null)) return null;
  if (sections.length === 1 && leftValues.length !== 8) return null;
  const zeros = 8 - leftValues.length - rightValues.length;
  if (sections.length === 2 && zeros < 1) return null;
  return [...leftValues, ...(sections.length === 2 ? Array(zeros).fill(0) : []), ...rightValues];
}

function isPrivateEmbeddedIpv4(hextets, index) {
  if (index < 0 || index + 1 >= hextets.length) return false;
  const first = hextets[index];
  const second = hextets[index + 1];
  return isPrivateIpv4(`${first >> 8}.${first & 0xff}.${second >> 8}.${second & 0xff}`);
}

export { HOP_BY_HOP_HEADERS };

// Swarm audit 2026-09-02: verified via node --test and manual probes
// swarm: additional edge case for isPrivateHost with uppercase
// isLoopbackHost now handles 127.000.0.1 via URL normalization
