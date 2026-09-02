import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { parseMasterKey } from './crypto.js';

const KEY_BYTES = 32;
const IV_BYTES = 12;
const ALGORITHM = 'aes-256-gcm';

function encode(bytes) {
  return Buffer.from(bytes).toString('base64url');
}
function decode(value) {
  return Buffer.from(value, 'base64url');
}

function dekAssociatedData(keyId) {
  return Buffer.from(`tgcloud-secrets/dek/${keyId}`, 'utf8');
}

// Local KMS provider — encrypts DEK with a local 32-byte master key via AES-GCM
// Suitable for single-team self-hosted, dev, and tests. Not for multi-tenant compliance
export class LocalKMSProvider {
  constructor({ masterKey, keyId = 'local' } = {}) {
    if (!masterKey) throw new Error('LocalKMSProvider requires masterKey');
    this.key = parseMasterKey(masterKey);
    this.keyId = keyId;
  }

  getKeyId() {
    return this.keyId;
  }

  async generateDataKey() {
    const dek = randomBytes(KEY_BYTES);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    cipher.setAAD(dekAssociatedData(this.keyId));
    const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
    return {
      keyId: this.keyId,
      plaintext: dek,
      ciphertextBlob: encode(cipher.getAuthTag()) + '.' + encode(iv) + '.' + encode(ciphertext),
      // stored as tag.iv.ciphertext for easy decode
    };
  }

  async decrypt(ciphertextBlob) {
    const raw = String(ciphertextBlob);
    // Detect AWS format (no dots) vs local format (tag.iv.ct)
    if (!raw.includes('.')) {
      throw new Error(`Local KMS cannot decrypt AWS-format ciphertext (keyId mismatch: expected local, got ${this.keyId})`);
    }
    const [tagB64, ivB64, ctB64] = raw.split('.');
    if (!tagB64 || !ivB64 || !ctB64) throw new Error('Invalid local DEK ciphertext');
    const tag = decode(tagB64);
    const iv = decode(ivB64);
    const ciphertext = decode(ctB64);
    if (iv.length !== IV_BYTES || tag.length !== 16) throw new Error('Invalid local DEK ciphertext');
    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAAD(dekAssociatedData(this.keyId));
    decipher.setAuthTag(tag);
    const dek = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (dek.length !== KEY_BYTES) throw new Error('Invalid DEK length');
    return dek;
  }
}

// AWS KMS provider — uses KMS GenerateDataKey/Decrypt, caches DEKs 5m
export class AwsKMSProvider {
  constructor({ keyId, client, cacheTtlMs = 5 * 60 * 1000 } = {}) {
    if (!keyId) throw new Error('AwsKMSProvider requires keyId (alias or ARN)');
    this.keyId = keyId;
    this.client = client || new KMSClient({});
    this.cache = new Map(); // ciphertextBlob base64 -> {dek, expiresAt}
    this.cacheTtlMs = cacheTtlMs;
  }

  getKeyId() {
    return this.keyId;
  }

  async generateDataKey() {
    const resp = await this.client.send(new GenerateDataKeyCommand({
      KeyId: this.keyId,
      KeySpec: 'AES_256',
    }));
    if (!resp.Plaintext || !resp.CiphertextBlob) throw new Error('KMS GenerateDataKey failed');
    const dek = Buffer.from(resp.Plaintext);
    const ciphertextBlob = Buffer.from(resp.CiphertextBlob).toString('base64url');
    // cache the mapping for fast decrypt
    this.cache.set(ciphertextBlob, { dek, expiresAt: Date.now() + this.cacheTtlMs });
    if (this.cache.size > 1000) {
      const first = this.cache.keys().next().value;
      this.cache.delete(first);
    }
    return {
      keyId: this.keyId,
      plaintext: dek,
      ciphertextBlob,
    };
  }

  async decrypt(ciphertextBlob) {
    const raw = String(ciphertextBlob);
    if (raw.includes('.')) {
      throw new Error(`AWS KMS cannot decrypt local-format ciphertext (keyId mismatch: expected ${this.keyId}, got local)`);
    }
    const cached = this.cache.get(ciphertextBlob);
    if (cached && Date.now() < cached.expiresAt) return cached.dek;
    const resp = await this.client.send(new DecryptCommand({
      CiphertextBlob: Buffer.from(raw, 'base64url'),
    }));
    if (!resp.Plaintext) throw new Error('KMS Decrypt failed');
    const dek = Buffer.from(resp.Plaintext);
    this.cache.set(ciphertextBlob, { dek, expiresAt: Date.now() + this.cacheTtlMs });
    if (this.cache.size > 1000) {
      const first = this.cache.keys().next().value;
      this.cache.delete(first);
    }
    return dek;
  }
}

export function createKMSProvider({ kmsKeyId, masterKey, kmsClient } = {}) {
  const keyId = kmsKeyId || process.env.TGCLOUD_KMS_KEY_ID || process.env.AWS_KMS_KEY_ID || 'local';
  if (keyId === 'local' || keyId.startsWith('local:')) {
    const localKeyId = keyId === 'local' ? 'local' : keyId;
    // masterKey can be supplied or from env/file
    const mk = masterKey || process.env.TGCLOUD_MASTER_KEY || null;
    if (!mk) throw new Error('Local KMS requires masterKey or TGCLOUD_MASTER_KEY env');
    return new LocalKMSProvider({ masterKey: mk, keyId: localKeyId });
  }
  return new AwsKMSProvider({ keyId, client: kmsClient });
}

export function isKMSAvailable() {
  return Boolean(process.env.TGCLOUD_KMS_KEY_ID || process.env.AWS_KMS_KEY_ID || process.env.TGCLOUD_MASTER_KEY);
}

// Clear cache (for tests and rotation)
