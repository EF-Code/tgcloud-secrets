import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { MAX_SECRET_BYTES } from '../src/store.js';
import pg from 'pg';

const { Pool } = pg;
const testDsn = process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN || 'postgres://postgres:postgres@localhost:5433/tgcloud';

function runCli(args, input, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(process.cwd(), 'src', 'cli.js'), ...args], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...extraEnv },
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

test('CLI DATABASE_URL vs --data-dir precedence', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-cli-precedence-'));
  const previous = process.env.DATABASE_URL;
  process.env.DATABASE_URL = 'postgres://invalid:invalid@127.0.0.1:1/unreachable';
  try {
    const result = await runCli(['set', 'demo', '--data-dir', dataDir, '--json'], 'file-secret\n');
    assert.equal(result.code, 0, result.stderr);
    assert.doesNotMatch(result.stderr, /ignored/);
  } finally {
    if (previous === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previous;
  }
});

test('CLI refuses the local file store in production', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-cli-production-'));
  const result = await runCli(['set', 'demo', '--data-dir', dataDir, '--json'], 'must-not-store\n', {
    TGCLOUD_ENV: 'production',
    NODE_ENV: 'production',
    DATABASE_URL: '',
    TGCLOUD_SECRETS_DSN: '',
  });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Production configuration is invalid/);
});

test('CLI rejects empty value options before selecting a backend', async () => {
  const result = await runCli(['serve', '--port', ''], '');
  assert.equal(result.code, 1);
  assert.match(result.stderr, /--port must not be empty/);
});

test('CLI migrate --dry-run does not initialize tenant rows', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-cli-dry-run-'));
  const seeded = await runCli(['set', 'demo', '--data-dir', dataDir, '--json'], 'file-secret\n');
  assert.equal(seeded.code, 0, seeded.stderr);
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const orgId = `dryorg_${suffix}`;
  const projectId = `dryproj_${suffix}`;
  const result = await runCli(['migrate', '--from', dataDir, '--to', testDsn, '--org', orgId, '--project', projectId, '--dry-run']);
  assert.equal(result.code, 0, result.stderr);
  const pool = new Pool({ connectionString: testDsn, ssl: false });
  try {
    const rows = await pool.query('SELECT 1 FROM orgs WHERE id=$1', [orgId]);
    assert.equal(rows.rowCount, 0);
  } finally {
    await pool.end();
  }
});
