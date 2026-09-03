import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSecretFetch } from '../runtime/secret-fetch.js';
import { encryptSecretWithDEK, decryptSecretWithDEK, generateDEK } from '../src/crypto.js';
import { validateId } from '../src/auth.js';
import { parseStrictJson } from '../src/json.js';
import {
  normalizePathPrefix,
  resolveUpstreamUrl,
  sanitizeForwardHeaders,
} from '../src/policy.js';
import { validateSecretName } from '../src/store.js';

const CORPUS_ALPHABET = 'abcXYZ012_-~.%/?#\\\u0000\u0009\u000a';

function corpusString(seed, length = 18) {
  let state = (seed ^ 0x9e3779b9) >>> 0;
  let output = '';
  for (let index = 0; index < length; index += 1) {
    state = Math.imul(state ^ (state >>> 15), 0x85ebca6b) >>> 0;
    state = Math.imul(state ^ (state >>> 13), 0xc2b2ae35) >>> 0;
    output += CORPUS_ALPHABET[state % CORPUS_ALPHABET.length];
  }
  return output;
}

function assertOnlyExpectedErrors(run) {
  try {
    return { ok: true, value: run() };
  } catch (error) {
    assert.ok(error instanceof Error, 'boundary failures must be Error instances');
    return { ok: false, error };
  }
}

async function assertOnlyExpectedErrorsAsync(run) {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    assert.ok(error instanceof Error, 'boundary failures must be Error instances');
    return { ok: false, error };
  }
}

test('deterministic URL and header fuzz corpus preserves the security boundary', () => {
  for (let seed = 1; seed <= 512; seed += 1) {
    const suffix = corpusString(seed);
    const pathResult = assertOnlyExpectedErrors(() => resolveUpstreamUrl(
      'https://api.example.com/',
      `/v1/${suffix}`,
      '/v1/',
    ));
    if (pathResult.ok) {
      assert.equal(pathResult.value.origin, 'https://api.example.com');
      assert.match(pathResult.value.pathname, /^\/v1\//);
      assert.doesNotMatch(pathResult.value.pathname, /%(?:2e|2f|5c|00)/i);
    }

    const prefixResult = assertOnlyExpectedErrors(() => normalizePathPrefix(`/v1/${suffix}`));
    if (prefixResult.ok) {
      assert.match(prefixResult.value, /^\/v1\//);
      assert.doesNotMatch(prefixResult.value, /[\\\u0000-\u001f\u007f?#]/);
    }

    const headerName = seed % 3 === 0 ? 'connection' : `x-test-${seed}`;
    const headerResult = assertOnlyExpectedErrors(() => sanitizeForwardHeaders(
      { [headerName]: suffix },
      'authorization',
    ));
    if (headerResult.ok) {
      assert.equal(headerResult.value.has('connection'), false);
      if (headerName !== 'connection') {
        const actual = headerResult.value.get(headerName);
        assert.ok(actual === suffix || actual === suffix.trim(), 'header adapters may normalize optional whitespace only');
      }
    }
  }
});

test('deterministic JSON and tenant-identifier fuzz corpus stays bounded and typed', () => {
  for (let seed = 1; seed <= 256; seed += 1) {
    const key = `field${seed}_${corpusString(seed, 6).replace(/[^A-Za-z0-9_]/g, 'x')}`;
    assert.throws(
      () => parseStrictJson(`{"${key}":1,"${key}":2}`),
      /duplicate/i,
    );

    const candidate = `tenant${seed}`;
    assert.equal(validateId(candidate, 'tenant'), candidate);
    for (const invalid of [`${candidate}:${seed}`, `${candidate}/child`, `${candidate}\u0000`, '']) {
      assert.throws(() => validateId(invalid, 'tenant'), Error);
    }
    assert.equal(validateSecretName(`secret${seed}`), `secret${seed}`);
    assert.throws(() => validateSecretName(`secret${seed}\u000a`), Error);
  }
});

test('encrypted record fuzz mutations never cross the AAD boundary', () => {
  const dek = generateDEK();
  for (let seed = 1; seed <= 128; seed += 1) {
    const name = `secret${seed}`;
    const value = `value-${corpusString(seed, 12).replace(/[\u0000-\u001f#?\\]/g, 'x')}`;
    const record = {
      version: 3,
      algorithm: 'aes-256-gcm',
      ...encryptSecretWithDEK(value, dek, name, 'org1', 'project1'),
    };
    assert.equal(decryptSecretWithDEK(record, dek, name, 'org1', 'project1'), value);
    assert.throws(() => decryptSecretWithDEK(record, dek, name, 'other-org', 'project1'), /Unsupported/);
    assert.throws(() => decryptSecretWithDEK({ ...record, ciphertext: `${record.ciphertext}A` }, dek, name, 'org1', 'project1'), /Unsupported/);
  }
  dek.fill(0);
});

test('runtime helper fuzz corpus either rejects locally or sends a bounded absolute path', async () => {
  const seen = [];
  const secretFetch = createSecretFetch({
    endpoint: 'https://secrets.example.com',
    capability: `tgscap_${'f'.repeat(32)}`,
    fetchImpl: async (_url, options) => {
      const payload = JSON.parse(options.body);
      seen.push(payload.path);
      return new Response('ok');
    },
  });
  for (let seed = 1; seed <= 256; seed += 1) {
    const result = await assertOnlyExpectedErrorsAsync(() => secretFetch(`/v1/${corpusString(seed)}`));
    if (result.ok) assert.equal(result.value.status, 200);
  }
  assert.ok(seen.length > 0, 'the corpus must exercise accepted runtime paths');
  assert.ok(seen.every((path) => path.startsWith('/v1/')));
});
