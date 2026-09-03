import { parseMasterKey } from './crypto.js';
import { parseStrictJson } from './json.js';

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_PREVIOUS_KEYS = 16;
const MAX_PREVIOUS_KEYS_BYTES = 64 * 1024;

function validateKeyId(value, label = 'HMAC key id') {
  if (typeof value !== 'string' || !KEY_ID.test(value)) {
    throw new Error(`${label} must contain only letters, numbers, ., _, :, or -`);
  }
  return value;
}

function parsePreviousKeys(value) {
  if (value === undefined || value === '') return [];
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_PREVIOUS_KEYS_BYTES) {
    throw new Error('TGCLOUD_HMAC_PREVIOUS_KEYS is too large');
  }
  let parsed;
  try {
    parsed = parseStrictJson(value, {
      maxBytes: MAX_PREVIOUS_KEYS_BYTES,
      maxDepth: 4,
      maxFields: 64,
      maxArrayItems: MAX_PREVIOUS_KEYS,
      maxStringBytes: MAX_PREVIOUS_KEYS_BYTES,
    });
  } catch {
    throw new Error('TGCLOUD_HMAC_PREVIOUS_KEYS must be a JSON array of {id,key} objects');
  }
  if (!Array.isArray(parsed) || parsed.length > MAX_PREVIOUS_KEYS) throw new Error('TGCLOUD_HMAC_PREVIOUS_KEYS must be a JSON array of at most 16 {id,key} objects');
  return parsed.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`TGCLOUD_HMAC_PREVIOUS_KEYS[${index}] must be an object`);
    }
    return Object.freeze({
      id: validateKeyId(entry.id, `TGCLOUD_HMAC_PREVIOUS_KEYS[${index}].id`),
      key: parseMasterKey(entry.key),
    });
  });
}

/**
 * Read a versioned HMAC key ring without ever putting key material in logs.
 * The previous-key format is intentionally explicit so rotation is reviewable:
 * TGCLOUD_HMAC_PREVIOUS_KEYS='[{"id":"hmac-2025","key":"..."}]'.
 */
export function readHmacKeyRing(env = process.env, { localKey } = {}) {
  const hasLocalKey = localKey !== undefined && localKey !== null;
  const configuredId = env.TGCLOUD_HMAC_KEY_ID;
  const activeId = validateKeyId(
    configuredId === undefined || configuredId === null ? (hasLocalKey ? 'local-v1' : 'env-v1') : configuredId,
    'TGCLOUD_HMAC_KEY_ID',
  );
  const activeKey = hasLocalKey ? parseMasterKey(localKey) : parseMasterKey(env.TGCLOUD_HMAC_KEY);
  const previous = parsePreviousKeys(env.TGCLOUD_HMAC_PREVIOUS_KEYS);
  const seen = new Set([activeId]);
  for (const entry of previous) {
    if (seen.has(entry.id)) throw new Error(`Duplicate HMAC key id: ${entry.id}`);
    seen.add(entry.id);
  }
  const keys = Object.freeze([Object.freeze({ id: activeId, key: activeKey }), ...previous]);
  return Object.freeze({
    active: keys[0],
    keys,
    get(id) {
      return keys.find((entry) => entry.id === id);
    },
  });
}

export function hmacKeyRingForProvider(kms, env = process.env) {
  if (kms?.key) {
    const ring = readHmacKeyRing(env, { localKey: kms.key });
    const aliases = ['env-v1', 'local']
      .filter((id) => !ring.keys.some((entry) => entry.id === id))
      .map((id) => Object.freeze({ id, key: ring.active.key }));
    const keys = Object.freeze([...ring.keys, ...aliases]);
    return Object.freeze({ active: ring.active, keys, get(id) { return keys.find((entry) => entry.id === id); } });
  }
  return readHmacKeyRing(env);
}

export { validateKeyId };
