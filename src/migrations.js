import { readdir, readFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import pg from 'pg';
import { isLoopbackHost } from './policy.js';

const { Pool } = pg;
const MIGRATION_DIRECTORY = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const MIGRATION_NAME = /^(\d{3})_([a-z0-9_]+)\.sql$/;

function poolForDsn(dsn, { migration = false } = {}) {
  let ssl;
  try {
    const hostname = new URL(dsn).hostname;
    ssl = isLoopbackHost(hostname) ? false : { rejectUnauthorized: true };
  } catch {
    ssl = { rejectUnauthorized: true };
  }
  return new Pool({
    connectionString: dsn,
    ssl,
    connectionTimeoutMillis: 5_000,
    // Migration statements use the server-side timeout configured by
    // runMigrations. A client-side five-second timeout would cancel a valid
    // bounded backfill before the server-side budget can apply.
    query_timeout: migration ? 0 : 5_000,
  });
}

async function loadMigrations() {
  const names = (await readdir(MIGRATION_DIRECTORY))
    .filter((name) => MIGRATION_NAME.test(name))
    .sort();
  const migrations = [];
  for (const name of names) {
    const match = MIGRATION_NAME.exec(name);
    migrations.push({
      version: Number(match[1]),
      name: basename(name, '.sql'),
      sql: await readFile(join(MIGRATION_DIRECTORY, name), 'utf8'),
    });
  }
  if (migrations.length === 0) throw new Error('No database migrations are installed');
  if (migrations[0].version !== 1) throw new Error('Database migrations must start at version 001');
  for (let index = 1; index < migrations.length; index += 1) {
    if (migrations[index].version !== migrations[index - 1].version + 1) {
      throw new Error('Database migration versions must be contiguous');
    }
  }
  return migrations;
}

async function readApplied(client) {
  const table = await client.query(`SELECT to_regclass('public.schema_migrations') AS table_name`);
  if (!table.rows[0].table_name) return [];
  const result = await client.query('SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version');
  return result.rows;
}

function assertKnownAppliedMigrations(migrations, applied) {
  const known = new Map(migrations.map((migration) => [migration.version, migration]));
  for (const row of applied) {
    const version = Number(row.version);
    const migration = known.get(version);
    if (!migration) throw new Error(`Database contains unknown migration version ${version}`);
    const checksum = createHash('sha256').update(migration.sql).digest('hex');
    if (row.name !== migration.name || row.checksum !== checksum) throw new Error(`Applied migration ${version} does not match the installed migration`);
  }
}

function assertAppliedSequence(applied) {
  const versions = applied.map((row) => Number(row.version)).sort((left, right) => left - right);
  for (let index = 0; index < versions.length; index += 1) {
    if (versions[index] !== index + 1) {
      throw new Error(`Database migration history is not contiguous; expected version ${index + 1}`);
    }
  }
}

async function assumeSchemaOwner(client) {
  const result = await client.query(`
    SELECT CASE
      WHEN current_role = 'tgcloud_schema_owner' THEN false
      WHEN current_user_role.rolsuper THEN false
      WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname='tgcloud_schema_owner')
      THEN pg_has_role(current_user, 'tgcloud_schema_owner', 'member')
      ELSE false
    END AS can_assume
    FROM pg_roles AS current_user_role
    WHERE current_user_role.rolname = current_user
  `);
  if (!result.rows[0]?.can_assume) return false;
  await client.query('SET ROLE tgcloud_schema_owner');
  return true;
}

export async function migrationStatus({ dsn, pool } = {}) {
  const connection = pool || poolForDsn(dsn);
  const ownsPool = !pool;
  try {
    const migrations = await loadMigrations();
    const client = await connection.connect();
    try {
      const applied = await readApplied(client);
      assertKnownAppliedMigrations(migrations, applied);
      assertAppliedSequence(applied);
      const appliedByVersion = new Map(applied.map((row) => [Number(row.version), row]));
      return migrations.map(({ sql, ...migration }) => ({
        ...migration,
        checksum: createHash('sha256').update(sql).digest('hex'),
        applied: appliedByVersion.has(migration.version),
        appliedAt: appliedByVersion.get(migration.version)?.applied_at || null,
      }));
    } finally {
      client.release();
    }
  } finally {
    if (ownsPool) await connection.end();
  }
}

export async function runMigrations({ dsn, pool, dryRun = false, statementTimeoutMs = 120_000 } = {}) {
  if (!Number.isSafeInteger(statementTimeoutMs) || statementTimeoutMs < 1_000 || statementTimeoutMs > 30 * 60 * 1_000) {
    throw new Error('statementTimeoutMs must be between 1000 and 1800000');
  }
  const connection = pool || poolForDsn(dsn, { migration: true });
  const ownsPool = !pool;
  try {
    const migrations = await loadMigrations();
    const client = await connection.connect();
    let assumedSchemaOwner = false;
    try {
      if (dryRun) {
        const applied = await readApplied(client);
        assertKnownAppliedMigrations(migrations, applied);
        assertAppliedSequence(applied);
        const appliedVersions = new Set(applied.map((row) => Number(row.version)));
        return migrations.map(({ sql, ...migration }) => ({ ...migration, applied: appliedVersions.has(migration.version) }));
      }
      assumedSchemaOwner = await assumeSchemaOwner(client);
      await client.query(`SET statement_timeout = '10000ms'`);
      await client.query('SELECT pg_advisory_lock(481927, 734001)');
      await client.query(`SET statement_timeout = '${statementTimeoutMs}ms'`);
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS schema_migrations (
            version INT PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
          )
        `);
        const applied = await readApplied(client);
        assertKnownAppliedMigrations(migrations, applied);
        assertAppliedSequence(applied);
        const appliedByVersion = new Map(applied.map((row) => [Number(row.version), row]));
        for (const migration of migrations) {
          const existing = appliedByVersion.get(migration.version);
          const checksum = createHash('sha256').update(migration.sql).digest('hex');
          if (existing) {
            if (existing.name !== migration.name || existing.checksum !== checksum) {
              throw new Error(`Applied migration ${migration.version} does not match the installed migration`);
            }
            continue;
          }
          await client.query('BEGIN');
          try {
            await client.query(migration.sql);
            await client.query('INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)', [migration.version, migration.name, checksum]);
            await client.query('COMMIT');
          } catch (error) {
            await client.query('ROLLBACK');
            throw new Error(`Migration ${migration.name} failed: ${error.message}`, { cause: error });
          }
        }
        return migrations.map(({ sql, ...migration }) => ({ ...migration, applied: true }));
      } finally {
        // Do not return a pooled migration client with an unbounded timeout.
        await client.query(`SET statement_timeout = '10000ms'`).catch(() => {});
        await client.query('SELECT pg_advisory_unlock(481927, 734001)');
      }
    } finally {
      if (assumedSchemaOwner) await client.query('RESET ROLE').catch(() => {});
      client.release();
    }
  } finally {
    if (ownsPool) await connection.end();
  }
}

export async function assertSchemaReady(client, requiredVersion) {
  let result;
  try {
    result = await client.query(`
      SELECT COALESCE(MAX(version), 0) AS version
      FROM schema_migrations
    `);
  } catch (error) {
    if (error.code === '42P01') {
      throw new Error('Database schema is not installed; run the migration command before starting the broker');
    }
    throw error;
  }
  const version = Number(result.rows[0]?.version || 0);
  if (version < requiredVersion) {
    throw new Error(`Database schema version ${version} is older than required version ${requiredVersion}; run the migration command before starting the broker`);
  }
  if (version > requiredVersion) {
    throw new Error(`Database schema version ${version} is newer than this application supports (maximum ${requiredVersion}); deploy a compatible application before serving traffic`);
  }
  const migrations = (await loadMigrations()).filter((migration) => migration.version <= requiredVersion);
  const applied = await client.query('SELECT version, name, checksum FROM schema_migrations ORDER BY version');
  assertKnownAppliedMigrations(migrations, applied.rows);
  assertAppliedSequence(applied.rows);
  const appliedByVersion = new Map(applied.rows.map((row) => [Number(row.version), row]));
  for (const migration of migrations) {
    const row = appliedByVersion.get(migration.version);
    if (!row) throw new Error(`Database schema migration ${migration.version} is missing; run the migration command before starting the broker`);
    const checksum = createHash('sha256').update(migration.sql).digest('hex');
    if (row.name !== migration.name || row.checksum !== checksum) throw new Error(`Database schema migration ${migration.version} does not match the installed migration`);
  }
  if (applied.rows.some((row) => Number(row.version) > requiredVersion)) {
    throw new Error(`Database schema version is newer than this application supports (maximum ${requiredVersion}); deploy a compatible application before serving traffic`);
  }
  const requiredTables = [
    'orgs', 'projects', 'secrets', 'secret_versions', 'capabilities',
    'capability_audit', 'audit_outbox', 'tenant_revocations', 'idempotency_keys',
  ];
  const tables = await client.query(`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = ANY($1::text[])
  `, [requiredTables]);
  const actual = new Set(tables.rows.map((row) => row.table_name));
  const missing = requiredTables.filter((table) => !actual.has(table));
  if (missing.length > 0) throw new Error(`Database is missing required tables: ${missing.join(', ')}`);
  const forced = await client.query(`
    SELECT c.relname, c.relforcerowsecurity
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])
  `, [requiredTables.filter((table) => table !== 'schema_migrations')]);
  const notForced = requiredTables.filter((table) => !forced.rows.some((row) => row.relname === table && row.relforcerowsecurity));
  if (notForced.length > 0) throw new Error(`Database tenant tables are not protected by forced RLS: ${notForced.join(', ')}`);
  return version;
}

export const CURRENT_SCHEMA_VERSION = 18;
