import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
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

test('CLI version matches the package version', async () => {
  const packageVersion = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  const result = await runCli(['--version'], '');
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout.trim(), packageVersion);
});

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

test('CLI init output does not disclose its private storage path', async () => {
  const privatePath = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-sensitive-path-'));
  const result = await runCli(['init', '--data-dir', privatePath, '--json'], '');
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { dataDir: '<redacted>' });
  assert.doesNotMatch(result.stdout, new RegExp(privatePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('CLI error output redacts equals-form and canonicalized storage paths', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-canonical-parent-'));
  const directPath = join(parent, 'direct-store');
  await writeFile(directPath, 'not a directory');
  const direct = await runCli(['init', `--data-dir=${directPath}`], '', {
    DATABASE_URL: undefined,
    TGCLOUD_SECRETS_DSN: undefined,
  });
  assert.equal(direct.code, 1);
  assert.match(direct.stderr, /<redacted>/);
  assert.doesNotMatch(direct.stderr, new RegExp(directPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  const canonicalPath = join(parent, 'tgcloud-secrets');
  await writeFile(canonicalPath, 'not a directory');
  const canonical = await runCli(['init'], '', {
    DATABASE_URL: undefined,
    TGCLOUD_SECRETS_DSN: undefined,
    TGCLOUD_SECRETS_DATA_DIR: undefined,
    XDG_DATA_HOME: join(parent, 'unused', '..'),
  });
  assert.equal(canonical.code, 1);
  assert.match(canonical.stderr, /<redacted>/);
  assert.doesNotMatch(canonical.stderr, new RegExp(canonicalPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('CLI redacts rate-limiter module paths and invalid environment values', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'tgcloud-secrets-limiter-store-'));
  const modulePath = '/tmp/private-limiter-adapter-secret.mjs';
  const limiter = await runCli(['serve', '--data-dir', dataDir, `--rate-limiter-module=${modulePath}`], '');
  assert.equal(limiter.code, 1);
  assert.match(limiter.stderr, /<redacted>/);
  assert.doesNotMatch(limiter.stderr, new RegExp(modulePath));

  const invalid = await runCli(['config-check', '--json'], '', { TGCLOUD_ALLOW_HTTP: 'super-secret' });
  assert.equal(invalid.code, 1);
  assert.doesNotMatch(invalid.stdout, /super-secret/);
  assert.deepEqual(JSON.parse(invalid.stdout), {
    ok: false,
    error: 'Boolean configuration values must be true, false, 1, or 0',
  });
});

test('CLI error output redacts database credentials', async () => {
  const credential = 'super-secret-password';
  const dsn = `postgres://runtime:${credential}@127.0.0.1:1/unreachable`;
  const result = await runCli([dsn], '');
  assert.equal(result.code, 1);
  assert.match(result.stderr, /postgres:\/\/<redacted>/);
  assert.doesNotMatch(result.stderr, new RegExp(credential));
  assert.doesNotMatch(result.stderr, /postgres:\/\/runtime:/);
});

test('CLI error output redacts an environment-derived storage path', async () => {
  const privatePath = join(await mkdtemp(join(tmpdir(), 'tgcloud-secrets-private-parent-')), 'private-store');
  await writeFile(privatePath, 'not a directory');
  const result = await runCli(['init'], '', {
    TGCLOUD_SECRETS_DATA_DIR: privatePath,
    DATABASE_URL: undefined,
    TGCLOUD_SECRETS_DSN: undefined,
  });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /<redacted>/);
  assert.doesNotMatch(result.stderr, new RegExp(privatePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
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
  const result = await runCli(['migrate', '--from', dataDir, '--to', testDsn, '--org', orgId, '--project', projectId, '--dry-run', '--json']);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { migratedSecrets: 1, skipped: 0, capabilitiesFound: 0, dryRun: true });
  const pool = new Pool({ connectionString: testDsn, ssl: false });
  try {
    const rows = await pool.query('SELECT 1 FROM orgs WHERE id=$1', [orgId]);
    assert.equal(rows.rowCount, 0);
  } finally {
    await pool.end();
  }
});
