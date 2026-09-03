import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateMasterKey, encodeMasterKey } from '../src/crypto.js';
import { hmacKeyRingForProvider, readHmacKeyRing } from '../src/hmac.js';
import { LocalKMSProvider } from '../src/kms.js';

test('HMAC key ring supports active and retiring keys without exposing key material', () => {
  const active = generateMasterKey();
  const previous = generateMasterKey();
  const ring = readHmacKeyRing({
    TGCLOUD_HMAC_KEY_ID: 'hmac-2026',
    TGCLOUD_HMAC_KEY: encodeMasterKey(active),
    TGCLOUD_HMAC_PREVIOUS_KEYS: JSON.stringify([{ id: 'hmac-2025', key: encodeMasterKey(previous) }]),
  });
  assert.equal(ring.active.id, 'hmac-2026');
  assert.deepEqual(ring.keys.map((entry) => entry.id), ['hmac-2026', 'hmac-2025']);
  assert.deepEqual(ring.get('hmac-2025').key, previous);
  assert.throws(() => readHmacKeyRing({ TGCLOUD_HMAC_KEY: encodeMasterKey(active), TGCLOUD_HMAC_PREVIOUS_KEYS: JSON.stringify([{ id: 'env-v1', key: encodeMasterKey(previous) }, { id: 'env-v1', key: encodeMasterKey(previous) }]) }), /Duplicate/);
});

test('local KMS retains legacy HMAC key aliases during upgrade', () => {
  const kms = new LocalKMSProvider({ masterKey: generateMasterKey(), keyId: 'local' });
  const ring = hmacKeyRingForProvider(kms, {});
  assert.equal(ring.active.id, 'local-v1');
  assert.equal(ring.get('env-v1').key.equals(kms.key), true);
  assert.equal(ring.get('local').key.equals(kms.key), true);
});

test('HMAC key ring does not replace an explicitly empty active key id', () => {
  assert.throws(() => readHmacKeyRing({
    TGCLOUD_HMAC_KEY_ID: '',
    TGCLOUD_HMAC_KEY: encodeMasterKey(generateMasterKey()),
  }), /TGCLOUD_HMAC_KEY_ID/);
});
