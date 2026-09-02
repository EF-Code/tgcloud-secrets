import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { MAX_SECRET_BYTES } from '../src/store.js';

function runCli(args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(process.cwd(), 'src', 'cli.js'), ...args], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
    child.stdin.end(input);
  });
}

test('CLI accepts newline-terminated piped secrets', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-cli-'));
  const result = await runCli(['set', 'demo', '--data-dir', dataDir, '--json'], 'cli-secret\n');
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /"name": "demo"/);

  const maxLength = await runCli(
    ['set', 'max', '--data-dir', dataDir, '--json'],
    `${'a'.repeat(MAX_SECRET_BYTES)}\n`,
  );
  assert.equal(maxLength.code, 0, maxLength.stderr);
  assert.match(maxLength.stdout, /"name": "max"/);
});
