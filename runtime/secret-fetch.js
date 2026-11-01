/**
 * Tiny dependency-free helper for a Telegram Serverless module.
 *
 * The capability is intentionally the only credential embedded in the bot
 * module. It is revocable and scoped by the broker to one upstream origin,
 * path prefix, and set of methods; it is not the vendor secret itself.
 */
function isLoopbackHost(hostname) {
  const normalized = String(hostname).toLowerCase().replace(/^\[|\]$/g, '').split('%')[0].replace(/\.+$/, '');
  if (normalized === 'localhost' || normalized === '::1') return true;
  let ip = normalized;
  if (ip.includes('.')) {
    try {
      const urlHost = typeof URL === 'function' ? new URL(`http://${ip}`).hostname : ip;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(urlHost)) ip = urlHost;
    } catch {}
  }
  const octets = ip.split('.').map(Number);
  return octets.length === 4
    && octets[0] === 127
    && octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255);
}

// Telegram's V8 runtime does not expose URL. Accept a deliberately strict
// ASCII-origin subset there instead of installing a global URL polyfill or
// letting the transport reinterpret credentials, paths, or encoded hosts.
function parseBrokerUrl(endpoint) {
  if (typeof URL === 'function') return new URL(endpoint);
  if (endpoint.length > 4_096) throw new Error('Broker endpoint is too long');
  const match = /^(https?):\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?\/?$/i.exec(endpoint);
  if (!match) throw new Error('Broker endpoint must be an ASCII HTTP or HTTPS origin without credentials, path, query, or fragment');
  const protocol = `${match[1].toLowerCase()}:`;
  const hostname = match[2].toLowerCase();
  if (hostname.startsWith('[')) {
    const address = hostname.slice(1, -1);
    const halves = address.split('::');
    const groups = halves.flatMap((half) => half ? half.split(':') : []);
    if (halves.length > 2 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))
      || (halves.length === 1 ? groups.length !== 8 : groups.length >= 8)) {
      throw new Error('Broker endpoint contains an invalid IPv6 address');
    }
  } else {
    const host = hostname.replace(/\.$/, '');
    const labels = host.split('.');
    if (host.length > 253 || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw new Error('Broker endpoint contains an invalid hostname');
    }
    // WHATWG fetch treats numeric-ending hosts as IPv4. Permit only canonical
    // dotted decimal so alternate/octal forms cannot alter the HTTP boundary.
    if (/^(?:[0-9]+|0x[0-9a-f]*)$/.test(labels[labels.length - 1])) {
      if (labels.length !== 4 || labels.some((label) => !/^(?:0|[1-9][0-9]{0,2})$/.test(label) || Number(label) > 255)) {
        throw new Error('Broker endpoint must use a canonical IPv4 address');
      }
    }
  }
  const port = match[3] === undefined ? '' : String(Number(match[3]));
  if (port && Number(port) > 65_535) throw new Error('Broker endpoint contains an invalid port');
  const defaultPort = protocol === 'https:' ? '443' : '80';
  return {
    protocol,
    hostname,
    origin: `${protocol}//${hostname}${port && port !== defaultPort ? `:${port}` : ''}`,
    pathname: '/', username: '', password: '', search: '', hash: '',
  };
}

const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,256}$/;
const UNSAFE_HEADER_VALUE = /[\u0000-\u0008\u000A-\u000D\u000E-\u001F\u007F]/;
const MAX_CLIENT_REQUEST_BYTES = 1 * 1024 * 1024;

function utf8ByteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}

export function createSecretFetch({ endpoint, capability, fetchImpl = globalThis.fetch } = {}) {
  if (typeof endpoint !== 'string' || endpoint.length === 0) throw new Error('A broker endpoint is required');
  if (typeof capability !== 'string' || !/^tgscap_[A-Za-z0-9_-]{16,256}$/.test(capability)) throw new Error('A valid capability is required');
  if (typeof fetchImpl !== 'function') throw new Error('A fetch implementation is required');

  const brokerUrl = parseBrokerUrl(endpoint);
  if (brokerUrl.protocol !== 'https:' && brokerUrl.protocol !== 'http:') throw new Error('Broker endpoint must use HTTP or HTTPS');
  if (brokerUrl.username || brokerUrl.password || brokerUrl.pathname !== '/' || brokerUrl.search || brokerUrl.hash) throw new Error('Broker endpoint must be an origin without credentials, path, query, or fragment');
  if (brokerUrl.protocol === 'http:' && !isLoopbackHost(brokerUrl.hostname)) {
    throw new Error('HTTP broker endpoints are allowed only for loopback development targets; use HTTPS for remote brokers');
  }

  return async function secretFetch(path, init = {}) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) {
      throw new Error('Secret fetch path must be an absolute path');
    }
    const hashIndex = path.indexOf('#');
    if (hashIndex !== -1) path = path.slice(0, hashIndex) || '/';
    if (path.includes('\\') || path.includes('\0') || /[\u0000-\u001F\u007F]/.test(path)) {
      throw new Error('Secret fetch path contains a forbidden character');
    }
    if (!init || typeof init !== 'object' || Array.isArray(init)) throw new Error('Fetch options must be an object');

    const method = String(init.method === undefined ? 'GET' : init.method).toUpperCase();
    const headers = Object.create(null);
    if (init.headers) {
      const source = typeof Headers !== 'undefined' && init.headers instanceof Headers
        ? Object.fromEntries(init.headers.entries())
        : init.headers;
      if (!source || typeof source !== 'object' || Array.isArray(source)) throw new Error('Headers must be an object or Headers instance');
      for (const [name, value] of Object.entries(source)) {
        if (typeof name !== 'string' || !HEADER_NAME.test(name) || typeof value !== 'string') {
          throw new Error(`Header ${name} must have a valid string name and value`);
        }
        if (value.length > 8_192 || UNSAFE_HEADER_VALUE.test(value) || [...value].some((c) => c.codePointAt(0) > 0xff)) {
          throw new Error(`Header ${name} contains an unsafe value`);
        }
        headers[name] = value;
      }
    }

    let body = init.body;
    if (body !== undefined && body !== null && typeof body !== 'string') {
      if (typeof body === 'object' && !(body instanceof Uint8Array)) {
        try {
          body = JSON.stringify(body);
        } catch {
          throw new Error('Request body must be JSON serializable');
        }
        if (typeof body !== 'string') throw new Error('Request body must be JSON serializable');
        if (!Object.keys(headers).some((name) => name.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json';
      } else if (body instanceof Uint8Array) {
        throw new Error('Binary request bodies are not supported by this MVP; encode them before calling secretFetch');
      } else {
        throw new Error('Request body must be a string, JSON object, or Uint8Array');
      }
    }

    const payload = JSON.stringify({ path, method, headers, body: body ?? undefined });
    if (utf8ByteLength(payload) > MAX_CLIENT_REQUEST_BYTES) {
      throw new Error(`Secret fetch request is too large; maximum is ${MAX_CLIENT_REQUEST_BYTES} bytes`);
    }
    // Telegram Serverless documents string URLs and a fetch-like options object.
    // Keep this request inside that documented subset; in particular, do not pass
    // browser-only credential policy fields to the isolated server runtime.
    const fetchOptions = {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-tgcloud-capability': capability,
      },
      body: payload,
      redirect: 'error',
    };
    // AbortController is not part of Telegram's documented Serverless contract.
    // Forward a caller-provided signal for compatible fetch implementations, but
    // do not manufacture or require one in the Serverless adapter.
    if (init.signal !== undefined) fetchOptions.signal = init.signal;
    const brokerResponse = await fetchImpl(`${brokerUrl.origin}/v1/fetch`, fetchOptions);
    return brokerResponse;
  };
}

/**
 * Telegram Serverless adapter.
 *
 * Pass the `fetch` export injected by Telegram's `sdk` module. Keeping it
 * explicit prevents an accidental dependency on a browser or Node global when
 * this file is vendored into a Serverless project's `lib/` directory.
 */
export function createTelegramSecretFetch({ endpoint, capability, fetch: sdkFetch } = {}) {
  if (typeof sdkFetch !== 'function') {
    throw new Error("Telegram Serverless requires the fetch export from 'sdk'");
  }
  return createSecretFetch({ endpoint, capability, fetchImpl: sdkFetch });
}

export function secretFetch(config, path, init) {
  return createSecretFetch(config)(path, init);
}

export { MAX_CLIENT_REQUEST_BYTES };
// runtime isLoopback now aligns with policy
