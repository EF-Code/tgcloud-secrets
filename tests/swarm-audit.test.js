import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isPrivateHost, normalizeBaseUrl, resolveUpstreamUrl } from '../src/policy.js';
import { SecretStore } from '../src/store.js';
import { createBrokerServer } from '../src/broker.js';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Swarm audit regression tests - neuromancer/wintermute findings 2026-09-02

test('1 - isPrivateHost strips zone identifier %lo0', () => {
  assert.equal(isPrivateHost('fe80::1%lo0'), true);
  assert.equal(isPrivateHost('fe80::1%eth0'), true);
});


test('2 - decodePathForPolicy blocks encoded slash %2f', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2fadmin', '/v1/'), /forbidden encoded/);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%2Fadmin', '/v1/'), /forbidden encoded/);
});


test('3 - trailing dot rejected in normalizeBaseUrl', () => {
  assert.throws(() => normalizeBaseUrl('https://api.example.com.'), /trailing dot/);
  assert.throws(() => normalizeBaseUrl('https://api.example.com./'), /trailing dot/);
});


test('4 - nested encoded slash %252f blocked', () => {
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%252fadmin', '/v1/'), /forbidden encoded/);
  assert.throws(() => resolveUpstreamUrl('https://api.example.com/', '/v1/%25252fadmin', '/v1/'), /forbidden encoded/);
});

