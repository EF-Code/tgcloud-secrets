import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadRateLimiterBackend } from '../src/rate-limiter-adapter.js';

test('loads a local limiter factory without passing process environment and closes it', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'tgcloud-rate-limiter-'));
  const modulePath = join(directory, 'adapter.mjs');
  await writeFile(modulePath, `
    export async function createRateLimiterBackend() {
      return {
        backend: { eval: async () => [1, 60] },
        close: () => { globalThis.__tgcloudLimiterClosed = true; },
      };
    }
  `, 'utf8');
  delete globalThis.__tgcloudLimiterClosed;
  const loaded = await loadRateLimiterBackend(modulePath);
  assert.equal(typeof loaded.backend.eval, 'function');
  assert.equal(Object.hasOwn(loaded, 'close'), true);
  await loaded.close();
  assert.equal(globalThis.__tgcloudLimiterClosed, true);
  delete globalThis.__tgcloudLimiterClosed;
});

test('rejects invalid or unresolvable limiter adapter specifications', async () => {
  await assert.rejects(() => loadRateLimiterBackend(''), /non-empty local module path/);
  await assert.rejects(() => loadRateLimiterBackend(`data:text/javascript,export default {}`));
});
