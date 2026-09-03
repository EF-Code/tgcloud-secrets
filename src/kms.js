import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { parseMasterKey } from './crypto.js';

const KEY_BYTES = 32;
const IV_BYTES = 12;
const ALGORITHM = 'aes-256-gcm';

function encode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}
function decode(value, label = 'Encoded value', { allowEmpty = false, maxBytes = Number.MAX_SAFE_INTEGER } = {}) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes * 4 / 3) + 4
    || (!allowEmpty && value.length === 0) || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length > maxBytes || encode(decoded) !== value) throw new Error(`${label} is invalid`);
  return decoded;
}

function normalizeEncryptionContext(context) {
  if (context === undefined || context === null) return {};
  if (typeof context !== 'object' || Array.isArray(context)) throw new Error('KMS encryption context is invalid');
  const entries = Object.entries(context).map(([key, value]) => {
    if (!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(key) || typeof value !== 'string') throw new Error('KMS encryption context is invalid');
    const normalized = value;
    if (normalized.length === 0 || normalized.length > 256) throw new Error('KMS encryption context is invalid');
    return [key, normalized];
  });
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

function dekAssociatedData(keyId, context) {
  if (context === undefined) return Buffer.from(`tgcloud-secrets/dek/${keyId}`, 'utf8');
  const normalized = normalizeEncryptionContext(context);
  return Buffer.from(`tgcloud-secrets/dek/${keyId}/${JSON.stringify(normalized)}`, 'utf8');
}

// Local KMS provider — encrypts DEK with a local 32-byte master key via AES-GCM
// Suitable for single-team self-hosted, dev, and tests. Not for multi-tenant compliance
export class LocalKMSProvider {
  constructor({ masterKey, keyId = 'local' } = {}) {
    if (!masterKey) throw new Error('LocalKMSProvider requires masterKey');
    if (typeof keyId !== 'string' || keyId.length === 0 || keyId.length > 256 || keyId.trim() !== keyId || /[\u0000-\u001f\u007f]/.test(keyId)) throw new Error('LocalKMSProvider keyId is invalid');
    this.key = parseMasterKey(masterKey);
    this.keyId = keyId;
  }

  getKeyId() {
    return this.keyId;
  }

  async generateDataKey({ encryptionContext } = {}) {
    const dek = randomBytes(KEY_BYTES);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    cipher.setAAD(dekAssociatedData(this.keyId, encryptionContext));
    const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
    return {
      keyId: this.keyId,
      plaintext: dek,
      ciphertextBlob: encode(cipher.getAuthTag()) + '.' + encode(iv) + '.' + encode(ciphertext),
      // stored as tag.iv.ciphertext for easy decode
    };
  }

  async decrypt(ciphertextBlob, { encryptionContext } = {}) {
    if (typeof ciphertextBlob !== 'string') throw new Error('Invalid local DEK ciphertext');
    const raw = ciphertextBlob;
    // Detect AWS format (no dots) vs local format (tag.iv.ct)
    if (!raw.includes('.')) {
      throw new Error(`Local KMS cannot decrypt AWS-format ciphertext (keyId mismatch: expected local, got ${this.keyId})`);
    }
    const parts = raw.split('.');
    if (parts.length !== 3) throw new Error('Invalid local DEK ciphertext');
    const [tagB64, ivB64, ctB64] = parts;
    if (!/^[A-Za-z0-9_-]+$/.test(tagB64) || !/^[A-Za-z0-9_-]+$/.test(ivB64) || !/^[A-Za-z0-9_-]+$/.test(ctB64)) throw new Error('Invalid local DEK ciphertext');
    let tag;
    let iv;
    let ciphertext;
    try {
      tag = decode(tagB64, 'Invalid local DEK authentication tag', { maxBytes: 16 });
      iv = decode(ivB64, 'Invalid local DEK IV', { maxBytes: IV_BYTES });
      ciphertext = decode(ctB64, 'Invalid local DEK ciphertext', { maxBytes: KEY_BYTES });
    } catch {
      throw new Error('Invalid local DEK ciphertext');
    }
    if (iv.length !== IV_BYTES || tag.length !== 16 || ciphertext.length !== KEY_BYTES) throw new Error('Invalid local DEK ciphertext');
    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAAD(dekAssociatedData(this.keyId, encryptionContext));
    decipher.setAuthTag(tag);
    const dek = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (dek.length !== KEY_BYTES) throw new Error('Invalid DEK length');
    return dek;
  }
}

// AWS KMS provider — uses KMS GenerateDataKey/Decrypt, caches DEKs 5m by default.
// Set cacheTtlMs to 0 for tenants that must not retain plaintext DEKs in-process.
export class AwsKMSProvider {
  constructor({ keyId, client, cacheTtlMs = 5 * 60 * 1000, cacheMaxEntries = 1000, operationTimeoutMs = 15_000 } = {}) {
    if (typeof keyId !== 'string' || keyId.length === 0 || keyId.length > 512 || keyId.trim() !== keyId || /[\u0000-\u001f\u007f]/.test(keyId)) throw new Error('AwsKMSProvider requires keyId (alias or ARN)');
    if (!Number.isSafeInteger(cacheTtlMs) || cacheTtlMs < 0 || cacheTtlMs > 60 * 60 * 1_000) throw new Error('AwsKMSProvider cacheTtlMs must be between 0 and 3600000');
    if (!Number.isSafeInteger(cacheMaxEntries) || cacheMaxEntries < 1 || cacheMaxEntries > 10_000) throw new Error('AwsKMSProvider cacheMaxEntries must be between 1 and 10000');
    if (!Number.isSafeInteger(operationTimeoutMs) || operationTimeoutMs < 100 || operationTimeoutMs > 120_000) throw new Error('AwsKMSProvider operationTimeoutMs must be between 100 and 120000');
    this.keyId = keyId;
    this.client = client || new KMSClient({});
    this.cache = new Map(); // ciphertextBlob base64 -> {dek, context, expiresAt}
    this.cacheTtlMs = cacheTtlMs;
    this.cacheMaxEntries = cacheMaxEntries;
    this.operationTimeoutMs = operationTimeoutMs;
  }

  getKeyId() {
    return this.keyId;
  }

  _cacheSet(ciphertextBlob, dek, encryptionContext = {}) {
    if (this.cacheTtlMs === 0) return;
    const existing = this.cache.get(ciphertextBlob);
    if (existing) {
      existing.dek.fill(0);
      this.cache.delete(ciphertextBlob);
    }
    this.cache.set(ciphertextBlob, { dek: Buffer.from(dek), context: JSON.stringify(normalizeEncryptionContext(encryptionContext)), expiresAt: Date.now() + this.cacheTtlMs });
    while (this.cache.size > this.cacheMaxEntries) {
      const oldestKey = this.cache.keys().next().value;
      const oldest = this.cache.get(oldestKey);
      if (oldest) oldest.dek.fill(0);
      this.cache.delete(oldestKey);
    }
  }

  clearCache() {
    for (const entry of this.cache.values()) entry.dek.fill(0);
    this.cache.clear();
  }

  async _send(command) {
    const controller = new AbortController();
    let timer;
    const operation = Promise.resolve().then(() => this.client.send(command, { abortSignal: controller.signal }));
    // A timed-out SDK request may reject after the race has settled. Observe
    // that late rejection so a dependency outage cannot create an unhandled
    // promise rejection in the broker process.
    operation.catch(() => {});
    try {
      return await Promise.race([
        operation,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(Object.assign(new Error('AWS KMS operation timed out'), { code: 'TGCLOUD_KMS_TIMEOUT' }));
          }, this.operationTimeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  async generateDataKey({ encryptionContext } = {}) {
    const context = normalizeEncryptionContext(encryptionContext);
    const resp = await this._send(new GenerateDataKeyCommand({
      KeyId: this.keyId,
      KeySpec: 'AES_256',
      ...(Object.keys(context).length > 0 ? { EncryptionContext: context } : {}),
    }));
    if (!resp.Plaintext || !resp.CiphertextBlob) throw new Error('KMS GenerateDataKey failed');
    const dek = Buffer.from(resp.Plaintext);
    if (dek.length !== KEY_BYTES) {
      dek.fill(0);
      throw new Error('KMS GenerateDataKey returned an invalid DEK length');
    }
    const ciphertextBlob = Buffer.from(resp.CiphertextBlob).toString('base64url');
    // cache the mapping for fast decrypt
    this._cacheSet(ciphertextBlob, dek, context);
    return {
      keyId: this.keyId,
      plaintext: dek,
      ciphertextBlob,
    };
  }

  async decrypt(ciphertextBlob, { encryptionContext, bypassCache = false } = {}) {
    if (typeof ciphertextBlob !== 'string') throw new Error('AWS KMS ciphertext is invalid');
    const raw = ciphertextBlob;
    if (raw.length === 0 || raw.length > 16 * 1024 || !/^[A-Za-z0-9_-]+$/.test(raw)) throw new Error('AWS KMS ciphertext is invalid');
    if (raw.includes('.')) {
      throw new Error(`AWS KMS cannot decrypt local-format ciphertext (keyId mismatch: expected ${this.keyId}, got local)`);
    }
    const context = normalizeEncryptionContext(encryptionContext);
    const contextFingerprint = JSON.stringify(context);
    const cached = this.cache.get(ciphertextBlob);
    if (cached && bypassCache) {
      cached.dek.fill(0);
      this.cache.delete(ciphertextBlob);
    } else if (cached && cached.context === contextFingerprint && Date.now() < cached.expiresAt) {
      this.cache.delete(ciphertextBlob);
      this.cache.set(ciphertextBlob, cached);
      return Buffer.from(cached.dek);
    }
    if (cached) {
      cached.dek.fill(0);
      this.cache.delete(ciphertextBlob);
    }
    const encodedCiphertext = decode(raw, 'AWS KMS ciphertext', { maxBytes: 12 * 1024 });
    const resp = await this._send(new DecryptCommand({
      CiphertextBlob: encodedCiphertext,
      KeyId: this.keyId,
      ...(Object.keys(context).length > 0 ? { EncryptionContext: context } : {}),
    }));
    if (!resp.Plaintext) throw new Error('KMS Decrypt failed');
    const dek = Buffer.from(resp.Plaintext);
    if (dek.length !== KEY_BYTES) {
      dek.fill(0);
      throw new Error('KMS Decrypt returned an invalid DEK length');
    }
    this._cacheSet(ciphertextBlob, dek, context);
    return dek;
  }
}

export function createKMSProvider({ kmsKeyId, masterKey, kmsClient, env = process.env } = {}) {
  const keyId = kmsKeyId !== undefined && kmsKeyId !== null
    ? kmsKeyId
    : (env.TGCLOUD_KMS_KEY_ID !== undefined
      ? env.TGCLOUD_KMS_KEY_ID
      : (env.AWS_KMS_KEY_ID !== undefined ? env.AWS_KMS_KEY_ID : 'local'));
  if (keyId === 'local' || (typeof keyId === 'string' && keyId.startsWith('local:'))) {
    const localKeyId = keyId === 'local' ? 'local' : keyId;
    // masterKey can be supplied or from env/file
    const mk = masterKey !== undefined && masterKey !== null
      ? masterKey
      : (env.TGCLOUD_MASTER_KEY !== undefined ? env.TGCLOUD_MASTER_KEY : null);
    if (!mk) throw new Error('Local KMS requires masterKey or TGCLOUD_MASTER_KEY env');
    return new LocalKMSProvider({ masterKey: mk, keyId: localKeyId });
  }
  const envNumber = (name) => {
    if (env[name] === undefined) return undefined;
    if (env[name] === '') return Number.NaN;
    return Number(env[name]);
  };
  const cacheTtlMs = envNumber('TGCLOUD_KMS_CACHE_TTL_MS');
  const cacheMaxEntries = envNumber('TGCLOUD_KMS_CACHE_MAX_ENTRIES');
  const operationTimeoutMs = envNumber('TGCLOUD_KMS_OPERATION_TIMEOUT_MS');
  return new AwsKMSProvider({ keyId, client: kmsClient, ...(cacheTtlMs === undefined ? {} : { cacheTtlMs }), ...(cacheMaxEntries === undefined ? {} : { cacheMaxEntries }), ...(operationTimeoutMs === undefined ? {} : { operationTimeoutMs }) });
}

export function isKMSAvailable() {
  return Boolean(process.env.TGCLOUD_KMS_KEY_ID || process.env.AWS_KMS_KEY_ID || process.env.TGCLOUD_MASTER_KEY);
}
