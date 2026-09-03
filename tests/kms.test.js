import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LocalKMSProvider, AwsKMSProvider, createKMSProvider } from '../src/kms.js';
import { generateMasterKey } from '../src/crypto.js';
import { encryptSecretWithDEK, decryptSecretWithDEK, generateDEK, encryptSecretEnvelope, decryptSecretEnvelope } from '../src/crypto.js';

test('LocalKMSProvider generate and decrypt roundtrip', async () => {
  const masterKey = generateMasterKey();
  const kms = new LocalKMSProvider({ masterKey, keyId: 'local' });
  const { plaintext: dek, ciphertextBlob } = await kms.generateDataKey();
  assert.equal(dek.length, 32);
  const dek2 = await kms.decrypt(ciphertextBlob);
  assert.equal(Buffer.compare(dek, dek2), 0);
  assert.equal(kms.getKeyId(), 'local');
});

test('LocalKMSProvider different keyIds produce different ciphertexts', async () => {
  const masterKey = generateMasterKey();
  const kms1 = new LocalKMSProvider({ masterKey, keyId: 'local' });
  const kms2 = new LocalKMSProvider({ masterKey, keyId: 'local:org1' });
  const { ciphertextBlob: ct1 } = await kms1.generateDataKey();
  const { ciphertextBlob: ct2 } = await kms2.generateDataKey();
  assert.notEqual(ct1, ct2);
  await assert.rejects(() => kms1.decrypt(ct2), /Invalid|Unsupported/);
});

test('LocalKMSProvider binds DEKs to an encryption context', async () => {
  const kms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' });
  const context = { org_id: 'org1', project_id: 'project1', secret_name: 'api-key' };
  const { ciphertextBlob } = await kms.generateDataKey({ encryptionContext: context });
  await assert.rejects(() => kms.decrypt(ciphertextBlob, { encryptionContext: { ...context, project_id: 'other' } }), /Unsupported|unable|authenticate|bad/i);
  const dek = await kms.decrypt(ciphertextBlob, { encryptionContext: context });
  assert.equal(dek.length, 32);
});

test('envelope v3 encrypts with org/project binding', async () => {
  const masterKey = generateMasterKey();
  const kms = new LocalKMSProvider({ masterKey, keyId: 'local' });
  const { plaintext: dek, ciphertextBlob } = await kms.generateDataKey();
  const record = encryptSecretEnvelope('my-secret-value', dek, 'mysecret', { orgId: 'org1', projectId: 'proj1', keyId: 'local', dekCiphertext: ciphertextBlob });
  assert.equal(record.version, 3);
  assert.equal(record.keyId, 'local');
  // decrypt with same org/project
  const dek2 = await kms.decrypt(ciphertextBlob);
  const val = decryptSecretEnvelope(record, dek2, 'mysecret', 'org1', 'proj1');
  assert.equal(val, 'my-secret-value');
  // wrong org should fail
  assert.throws(() => decryptSecretWithDEK(record, dek2, 'mysecret', 'wrong-org', 'proj1'), /Unsupported/);
  assert.throws(() => decryptSecretWithDEK(record, dek2, 'mysecret', 'org1', 'wrong-proj'), /Unsupported/);
  assert.throws(() => decryptSecretWithDEK(record, dek2, 'wrong-name', 'org1', 'proj1'), /Unsupported/);
});

test('AwsKMSProvider caches decrypt', async () => {
  let decryptCalls = 0;
  const mockClient = {
    send: async (cmd) => {
      if (cmd.constructor.name === 'GenerateDataKeyCommand') {
        return { Plaintext: Buffer.from(generateDEK()), CiphertextBlob: Buffer.from('mock-ct-' + Math.random()) };
      }
      if (cmd.constructor.name === 'DecryptCommand') {
        decryptCalls++;
        // echo back a fixed dek for test
        return { Plaintext: Buffer.alloc(32, 1) };
      }
      throw new Error('unknown');
    },
  };
  const kms = new AwsKMSProvider({ keyId: 'arn:aws:kms:us-east-1:123456789:key/abc', client: mockClient, cacheTtlMs: 60000 });
  const ct = Buffer.from('fake-ct').toString('base64url');
  await kms.decrypt(ct);
  await kms.decrypt(ct);
  assert.equal(decryptCalls, 1, 'second decrypt should be cached');
  const cached = kms.cache.get(ct).dek;
  kms.clearCache();
  assert.equal(kms.cache.size, 0);
  assert.ok(cached.every((byte) => byte === 0));
});

test('AwsKMSProvider never reuses a cached DEK for a different encryption context', async () => {
  let decryptCalls = 0;
  const mockClient = {
    send: async (cmd) => {
      if (cmd.constructor.name === 'DecryptCommand') {
        decryptCalls += 1;
        return { Plaintext: Buffer.alloc(32, decryptCalls) };
      }
      throw new Error('unexpected command');
    },
  };
  const kms = new AwsKMSProvider({ keyId: 'arn:aws:kms:us-east-1:123456789:key/context', client: mockClient, cacheTtlMs: 60000 });
  const ct = Buffer.from('context-ct').toString('base64url');
  await kms.decrypt(ct, { encryptionContext: { tenant: 'one' } });
  await kms.decrypt(ct, { encryptionContext: { tenant: 'two' } });
  assert.equal(decryptCalls, 2);
});

test('AwsKMSProvider can bypass its cache for live dependency checks', async () => {
  let decryptCalls = 0;
  const kms = new AwsKMSProvider({
    keyId: 'arn:aws:kms:us-east-1:123456789:key/live-check',
    client: {
      send: async () => {
        decryptCalls += 1;
        return { Plaintext: Buffer.alloc(32, decryptCalls) };
      },
    },
  });
  const ciphertext = Buffer.from('live-check').toString('base64url');
  const first = await kms.decrypt(ciphertext);
  const second = await kms.decrypt(ciphertext, { bypassCache: true });
  assert.equal(decryptCalls, 2);
  assert.equal(first[0], 1);
  assert.equal(second[0], 2);
});

test('AwsKMSProvider can disable plaintext DEK caching', async () => {
  let decryptCalls = 0;
  const kms = new AwsKMSProvider({
    keyId: 'arn:aws:kms:us-east-1:123456789:key/no-cache',
    cacheTtlMs: 0,
    client: {
      send: async () => {
        decryptCalls += 1;
        return { Plaintext: Buffer.alloc(32, decryptCalls) };
      },
    },
  });
  const ciphertext = Buffer.from('no-cache').toString('base64url');
  await kms.decrypt(ciphertext);
  await kms.decrypt(ciphertext);
  assert.equal(decryptCalls, 2);
  assert.equal(kms.cache.size, 0);
});

test('KMS provider factory preserves explicit zero cache TTL and rejects empty overrides', () => {
  const managedKey = 'arn:aws:kms:us-east-1:123456789012:key/factory';
  const noCache = createKMSProvider({
    env: { TGCLOUD_KMS_KEY_ID: managedKey, TGCLOUD_KMS_CACHE_TTL_MS: '0' },
    kmsClient: { send: async () => ({ Plaintext: Buffer.alloc(32, 1) }) },
  });
  assert.equal(noCache.cacheTtlMs, 0);
  assert.throws(() => createKMSProvider({
    kmsKeyId: '',
    masterKey: generateMasterKey(),
    env: { TGCLOUD_KMS_KEY_ID: managedKey },
  }), /requires keyId|invalid|requires masterKey/i);
  assert.throws(() => createKMSProvider({
    kmsKeyId: managedKey,
    env: { TGCLOUD_KMS_CACHE_TTL_MS: '' },
  }), /cacheTtlMs/);
});

test('AwsKMSProvider bounds a hanging KMS operation and aborts its signal', async () => {
  let signal;
  const kms = new AwsKMSProvider({
    keyId: 'arn:aws:kms:us-east-1:123456789:key/timeout',
    operationTimeoutMs: 100,
    client: {
      send: async (_command, options) => {
        signal = options.abortSignal;
        return new Promise(() => {});
      },
    },
  });
  await assert.rejects(() => kms.decrypt(Buffer.from('timeout').toString('base64url')), (error) => error.code === 'TGCLOUD_KMS_TIMEOUT');
  assert.equal(signal.aborted, true);
});

test('LocalKMSProvider invalid ciphertext rejected', async () => {
  const kms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' });
  await assert.rejects(() => kms.decrypt('invalid'), /Invalid|cannot decrypt|keyId mismatch/);
  await assert.rejects(() => kms.decrypt('a.b.c'), /Invalid/);
});
