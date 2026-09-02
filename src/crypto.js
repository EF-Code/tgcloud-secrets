import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const ENCRYPTED_SECRET_VERSION = 2;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const MAX_ENCRYPTED_SECRET_BYTES = 16 * 1024;

function encode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function decode(value) {
  return Buffer.from(value, 'base64url');
}

function secretAssociatedData(secretName) {
  if (typeof secretName !== 'string' || secretName.length === 0) {
    throw new Error('Secret name is required to encrypt or decrypt a secret');
  }
  return Buffer.from(`tgcloud-secrets/secret/${secretName}`, 'utf8');
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

export function encryptSecret(value, key, secretName) {
  const plaintext = Buffer.from(String(value), 'utf8');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, parseMasterKey(key), iv);
  cipher.setAAD(secretAssociatedData(secretName));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return {
    version: ENCRYPTED_SECRET_VERSION,
    algorithm: ALGORITHM,
    iv: encode(iv),
    tag: encode(cipher.getAuthTag()),
    ciphertext: encode(ciphertext),
  };
}

export function decryptSecret(record, key, secretName) {
  if (!record || record.version !== ENCRYPTED_SECRET_VERSION || record.algorithm !== ALGORITHM) {
    throw new Error('Unsupported encrypted secret record');
  }
  if (typeof record.iv !== 'string' || typeof record.tag !== 'string' || typeof record.ciphertext !== 'string') {
    throw new Error('Unsupported encrypted secret record');
  }
  const iv = decode(record.iv);
  const tag = decode(record.tag);
  const ciphertext = decode(record.ciphertext);
  if (iv.length !== IV_BYTES || tag.length !== 16 || ciphertext.length > MAX_ENCRYPTED_SECRET_BYTES) {
    throw new Error('Unsupported encrypted secret record');
  }

  const decipher = createDecipheriv(ALGORITHM, parseMasterKey(key), iv);
  decipher.setAAD(secretAssociatedData(secretName));
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  } catch {
    throw new Error('Unsupported encrypted secret record');
  }
}

export function hashCapability(token) {
  return createHash('sha256').update(String(token), 'utf8').digest('hex');
}

export function capabilityMatches(token, expectedHash) {
  if (typeof expectedHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedHash)) return false;
  const actual = Buffer.from(hashCapability(token), 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function capabilityMetadata(capability) {
  return JSON.stringify({
    id: capability.id,
    tokenHash: capability.tokenHash,
    secretName: capability.secretName,
    baseUrl: capability.baseUrl,
    pathPrefix: capability.pathPrefix,
    methods: capability.methods,
    injectHeader: capability.injectHeader,
    injectPrefix: capability.injectPrefix,
    allowHttp: capability.allowHttp,
  });
}

export function hashCapabilityMetadata(capability, key) {
  return createHmac('sha256', parseMasterKey(key)).update(capabilityMetadata(capability), 'utf8').digest('hex');
}

export function capabilityMetadataMatches(capability, key, expectedMac) {
  if (typeof expectedMac !== 'string' || !/^[a-f0-9]{64}$/.test(expectedMac)) return false;
  const actual = Buffer.from(hashCapabilityMetadata(capability, key), 'hex');
  const expected = Buffer.from(expectedMac, 'hex');
  return timingSafeEqual(actual, expected);
}

export function encodeMasterKey(key) {
  return encode(parseMasterKey(key));
}
