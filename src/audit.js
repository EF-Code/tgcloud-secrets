const AUDIT_FIELD = /token|secret(?:Value|_value)?|authorization|credential|password|private(?:Key|_key)?|ciphertext|plaintext|headers?|body|dsn|cookie/i;
const AUDIT_SECRET_TEXT = /(?:postgres(?:ql)?:\/\/|Bearer\s+|tgscap_[A-Za-z0-9_-]{16,256})[^\s]*/i;
const AUDIT_SAFE_REFERENCE_FIELDS = new Set(['secretName', 'secret_name', 'injectHeader', 'inject_header']);

/**
 * Keep audit records useful without allowing secrets, bearer material, or
 * attacker-controlled object structure to enter durable evidence.
 */
export function sanitizeAuditPayload(value, depth = 0, seen = new WeakSet()) {
  if (depth > 8) throw new Error('Audit payload is too deeply nested');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    if (typeof value === 'string') {
      if (value.length > 4_096 || /[\u0000-\u001f\u007f]/.test(value) || AUDIT_SECRET_TEXT.test(value)) {
        throw new Error('Audit payload contains unsafe or sensitive text');
      }
    }
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw new Error('Audit payload contains an unsafe number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('Audit payload contains an unsupported value');
  if (seen.has(value)) throw new Error('Audit payload must not be cyclic');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > 128) throw new Error('Audit payload contains too many array items');
      return value.map((entry) => sanitizeAuditPayload(entry, depth + 1, seen));
    }
    const entries = Object.entries(value);
    if (entries.length > 128) throw new Error('Audit payload contains too many fields');
    const result = {};
    for (const [key, child] of entries) {
      if (!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key) || key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new Error('Audit payload contains an unsafe field');
      }
      // Secret names are useful audit references; secret values and bearer
      // material are not. Keep the distinction explicit at this boundary.
      if (!AUDIT_SAFE_REFERENCE_FIELDS.has(key) && AUDIT_FIELD.test(key)) {
        throw new Error('Audit payload contains a sensitive field');
      }
      result[key] = sanitizeAuditPayload(child, depth + 1, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

export { AUDIT_FIELD, AUDIT_SECRET_TEXT };
