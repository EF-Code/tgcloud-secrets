const SENSITIVE_KEY = /token|secret|authorization|credential|password|private.?key|ciphertext|plaintext|headers?|body|dsn|cookie/i;

function redactText(value) {
  return String(value)
    .replace(/[\u0000-\u001f\u007f]/g, (character) => `\\u${character.codePointAt(0).toString(16).padStart(2, '0')}`)
    .replace(/tgscap_[A-Za-z0-9_-]{16,}/g, '<redacted-capability>')
    .replace(/(postgres(?:ql)?:\/\/)[^\s]+/gi, '$1<redacted>')
    .replace(/(Bearer\s+)[^\s]+/gi, '$1<redacted>');
}

export function sanitizeLogValue(value, depth = 0) {
  if (depth > 4) return '<truncated>';
  if (typeof value === 'string') return redactText(value.length > 2_048 ? `${value.slice(0, 2_048)}…` : value);
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (value instanceof Error) return { name: value.name, message: redactText(value.message) };
  if (Array.isArray(value)) return value.slice(0, 100).map((entry) => sanitizeLogValue(entry, depth + 1));
  if (typeof value === 'object') {
    const result = Object.create(null);
    for (const [key, child] of Object.entries(value).slice(0, 100)) result[key] = SENSITIVE_KEY.test(key) ? '<redacted>' : sanitizeLogValue(child, depth + 1);
    return result;
  }
  return `<${typeof value}>`;
}

export function createRedactingLogger(sink = console) {
  return Object.freeze({
    info(event, fields = {}) { sink.info?.(redactText(event), sanitizeLogValue(fields)); },
    warn(event, fields = {}) { sink.warn?.(redactText(event), sanitizeLogValue(fields)); },
    error(event, fields = {}) { sink.error?.(redactText(event), sanitizeLogValue(fields)); },
  });
}

export { redactText };
