import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_MODULE_SPEC_BYTES = 4 * 1024;

function validateModuleSpecifier(moduleSpecifier) {
  if (typeof moduleSpecifier !== 'string' || moduleSpecifier.length === 0) {
    throw new Error('TGCLOUD_RATE_LIMITER_MODULE must be a non-empty local module path');
  }
  if (Buffer.byteLength(moduleSpecifier, 'utf8') > MAX_MODULE_SPEC_BYTES
    || /[\u0000-\u001f\u007f]/.test(moduleSpecifier)) {
    throw new Error('TGCLOUD_RATE_LIMITER_MODULE is too long or contains control characters');
  }
  return moduleSpecifier;
}

function moduleResource(value, source) {
  if (typeof value === 'function') return Promise.resolve(value());
  if (value && typeof value === 'object' && Object.hasOwn(value, 'backend')) {
    return Promise.resolve(value);
  }
  if (value && typeof value.eval === 'function') return Promise.resolve(value);
  throw new Error(`${source} must export a Redis-compatible backend or factory`);
}

/**
 * Load an operator-supplied, provider-neutral distributed limiter adapter.
 *
 * The module must be a local file. It may export either:
 *   - createRateLimiterBackend(), returning a client or { backend, close }
 *   - rateLimiterBackend, containing a client or factory
 *   - default, containing a client or factory
 *
 * The returned client only needs an eval(script, options) method. The adapter
 * owns its own credentials and connection setup; this loader never passes the
 * process environment to application code.
 */
export async function loadRateLimiterBackend(moduleSpecifier) {
  if (moduleSpecifier === undefined || moduleSpecifier === null) return null;
  const validatedSpecifier = validateModuleSpecifier(moduleSpecifier);
  const modulePath = resolve(process.cwd(), validatedSpecifier);
  const loaded = await import(pathToFileURL(modulePath).href);

  let resource;
  if (typeof loaded.createRateLimiterBackend === 'function') {
    resource = await loaded.createRateLimiterBackend();
  } else if (loaded.rateLimiterBackend !== undefined) {
    resource = await moduleResource(loaded.rateLimiterBackend, 'rateLimiterBackend');
  } else if (loaded.default !== undefined) {
    resource = await moduleResource(loaded.default, 'default');
  } else {
    throw new Error('Rate limiter module must export createRateLimiterBackend, rateLimiterBackend, or default');
  }

  let backend = resource;
  let close = typeof loaded.close === 'function' ? loaded.close : null;
  if (resource && typeof resource === 'object' && Object.hasOwn(resource, 'backend')) {
    backend = resource.backend;
    close = typeof resource.close === 'function' ? resource.close : close;
  }
  if (!backend || typeof backend.eval !== 'function') {
    throw new Error('Rate limiter adapter must provide a backend with eval()');
  }
  return Object.freeze({ backend, close });
}

export { MAX_MODULE_SPEC_BYTES };
