import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseStrictJson } from '../src/json.js';

test('strict JSON parser rejects duplicate, unsafe, deep, and invalid UTF-8 input', () => {
  assert.deepEqual(parseStrictJson(Buffer.from('{"path":"/v1","method":"GET"}')), { path: '/v1', method: 'GET' });
  for (const source of [
    '{"path":"/one","path":"/two"}',
    '{"__proto__": {"polluted": true}}',
    '{"value":9007199254740993}',
  ]) assert.throws(() => parseStrictJson(source), /JSON/);
  const deep = '{"a":'.repeat(12) + 'null' + '}'.repeat(12);
  assert.throws(() => parseStrictJson(deep, { maxDepth: 5 }), /nesting/);
  assert.throws(() => parseStrictJson(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d])), /UTF-8/);
});

test('strict JSON parser rejects lone surrogate escapes and excessive arrays', () => {
  assert.throws(() => parseStrictJson('{"value":"\\ud800"}'), /Unicode/);
  assert.throws(() => parseStrictJson('[1,2,3]', { maxArrayItems: 2 }), /array/);
});
