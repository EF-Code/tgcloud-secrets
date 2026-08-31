import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;

function encode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function decode(value) {
  return Buffer.from(value, 'base64url');
}

export function generateMasterKey() {
  return randomBytes(KEY_BYTES);
}

export function parseMasterKey(value) {
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    if (value.byteLength !== KEY_BYTES) {
      throw new Error('Master key must be exactly 32 bytes');
    }
    return Buffer.from(value);
  }

  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Master key must be a 32-byte base64url string');
  }

  const key = decode(value);
  if (key.length !== KEY_BYTES) {
    throw new Error('Master key must be a 32-byte base64url string');
  }
  return key;
}

export function encryptSecret(value, key) {
  const plaintext = Buffer.from(String(value), 'utf8');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, parseMasterKey(key), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return {
    version: 1,
    algorithm: ALGORITHM,
    iv: encode(iv),
    tag: encode(cipher.getAuthTag()),
    ciphertext: encode(ciphertext),
  };
}

export function decryptSecret(record, key) {
  if (!record || record.version !== 1 || record.algorithm !== ALGORITHM) {
    throw new Error('Unsupported encrypted secret record');
  }

  const decipher = createDecipheriv(ALGORITHM, parseMasterKey(key), decode(record.iv));
  decipher.setAuthTag(decode(record.tag));
  const plaintext = Buffer.concat([
    decipher.update(decode(record.ciphertext)),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

export function hashCapability(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

export function capabilityMatches(token, expectedHash) {
  const actual = Buffer.from(hashCapability(token), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function encodeMasterKey(key) {
  return encode(parseMasterKey(key));
}
