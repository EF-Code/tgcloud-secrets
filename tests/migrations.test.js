import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assertSchemaReady, CURRENT_SCHEMA_VERSION, migrationStatus, runMigrations } from '../src/migrations.js';

const dsn = process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN || 'postgres://postgres:postgres@localhost:5433/tgcloud';

test('migration status is read-only and exposes immutable ordered versions', async () => {
  const status = await migrationStatus({ dsn });
  assert.ok(status.length >= CURRENT_SCHEMA_VERSION);
  assert.deepEqual(status.map((item) => item.version), [...status].sort((a, b) => a - b).map((item) => item.version));
  assert.equal(status.some((item) => Object.hasOwn(item, 'sql') && item.sql !== undefined), false);
});

test('migration dry-run does not mutate the schema', async () => {
  const before = await migrationStatus({ dsn });
  const dryRun = await runMigrations({ dsn, dryRun: true });
  const after = await migrationStatus({ dsn });
  assert.equal(dryRun.length, before.length);
  assert.deepEqual(after.map((item) => item.applied), before.map((item) => item.applied));
});

test('startup rejects a database schema newer than the application', async () => {
  const client = {
    async query(sql) {
      if (sql.includes('MAX(version)')) return { rows: [{ version: CURRENT_SCHEMA_VERSION + 1 }] };
      throw new Error('unexpected query');
    },
  };
  await assert.rejects(() => assertSchemaReady(client, CURRENT_SCHEMA_VERSION), /newer than this application supports/);
});
