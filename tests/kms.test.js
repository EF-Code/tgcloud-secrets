import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LocalKMSProvider, AwsKMSProvider } from '../src/kms.js';
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

test('LocalKMSProvider invalid ciphertext rejected', async () => {
  const kms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' });
  await assert.rejects(() => kms.decrypt('invalid'), /Invalid|cannot decrypt|keyId mismatch/);
  await assert.rejects(() => kms.decrypt('a.b.c'), /Invalid/);
});
