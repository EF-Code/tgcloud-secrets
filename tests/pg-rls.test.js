import assert from 'node:assert/strict';
import { test } from 'node:test';
import pg from 'pg';
import { PgStore } from '../src/pg-store.js';
import { LocalKMSProvider } from '../src/kms.js';
import { generateMasterKey } from '../src/crypto.js';

const { Pool } = pg;
const adminDsn = process.env.DATABASE_URL || process.env.TGCLOUD_SECRETS_DSN || 'postgres://postgres:postgres@localhost:5433/tgcloud';

function identifier(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

test('runtime role is non-owner, cannot DDL, and cannot cross tenant RLS', async () => {
  const admin = new Pool({ connectionString: adminDsn, ssl: false });
  const role = `tgcloud_test_${process.pid}_${Date.now()}`;
  const password = `synthetic_${Math.random().toString(36).slice(2)}`;
  const orgA = `rlsorg_${Date.now()}`;
  const projectA = `rlsproj_a_${Date.now()}`;
  const projectB = `rlsproj_b_${Date.now()}`;
  let runtime;
  let storeA;
  let storeB;
  try {
    await admin.query(`CREATE ROLE ${identifier(role)} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
    const db = await admin.query('SELECT current_database() AS name');
    await admin.query(`GRANT CONNECT ON DATABASE ${identifier(db.rows[0].name)} TO ${identifier(role)}`);
    await admin.query(`GRANT USAGE ON SCHEMA public TO ${identifier(role)}`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE ON orgs, projects TO ${identifier(role)}`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON secrets, idempotency_keys TO ${identifier(role)}`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE ON secret_versions, capabilities, tenant_revocations TO ${identifier(role)}`);
    await admin.query(`GRANT INSERT ON capability_audit TO ${identifier(role)}`);
    await admin.query(`GRANT SELECT, INSERT ON audit_outbox TO ${identifier(role)}`);
    await admin.query(`GRANT SELECT ON schema_migrations TO ${identifier(role)}`);
    await admin.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${identifier(role)}`);
    const url = new URL(adminDsn);
    url.username = role;
    url.password = password;
    runtime = url.toString();
    const key = generateMasterKey();
    storeA = new PgStore({ dsn: runtime, kmsProvider: new LocalKMSProvider({ masterKey: key, keyId: 'local' }), orgId: orgA, projectId: projectA });
    storeB = new PgStore({ dsn: runtime, kmsProvider: new LocalKMSProvider({ masterKey: key, keyId: 'local' }), orgId: orgA, projectId: projectB });
    await storeA.init();
    await storeB.init();
    await storeA.setSecret('only_a', 'synthetic-a');
    await storeB.setSecret('only_b', 'synthetic-b');

    const isolated = await storeA._withTenantTransaction((client) => client.query(`SELECT name FROM secrets ORDER BY name`));
    assert.deepEqual(isolated.rows.map((row) => row.name), ['only_a']);
    const noContext = await storeA.pool.query(`SELECT current_setting('app.org_id', true) AS org_id, count(*)::int AS count FROM secrets`);
    assert.ok(noContext.rows[0].org_id === null || noContext.rows[0].org_id === '');
    assert.equal(noContext.rows[0].count, 0);

    await assert.rejects(() => storeA._withTenantTransaction((client) => client.query(
      `INSERT INTO secrets (id, project_id, name, encrypted_blob, key_id, version) VALUES ($1,$2,$3,$4,$5,$6)`,
      [`${orgA}:${projectB}:cross`, `${orgA}:${projectB}`, 'cross', JSON.stringify({ version: 2 }), 'local', 2],
    )), /row-level security|violates foreign key/);
    const afterCross = await storeB.listSecrets();
    assert.deepEqual(afterCross.map((row) => row.name), ['only_b']);

    const privileges = await admin.query(
      `SELECT r.rolname, r.rolbypassrls, has_schema_privilege(r.rolname, 'public', 'CREATE') AS can_create
       FROM pg_roles r WHERE r.rolname=$1`,
      [role],
    );
    assert.equal(privileges.rows[0].rolbypassrls, false);
    assert.equal(privileges.rows[0].can_create, false);
    await assert.rejects(() => storeA.pool.query(`CREATE TABLE ${identifier(`should_not_exist_${Date.now()}`)} (id int)`), /permission denied/);
    await assert.rejects(() => storeA.pool.query('UPDATE schema_migrations SET name=name'), /permission denied/);
    await assert.rejects(() => storeA.pool.query('DELETE FROM schema_migrations'), /permission denied/);
    await assert.rejects(() => storeA.pool.query('UPDATE audit_outbox SET event_type=event_type'), /permission denied/);
    await assert.rejects(() => storeA.pool.query('DELETE FROM audit_outbox'), /permission denied/);

    const rls = await admin.query(
      `SELECT relname, relforcerowsecurity FROM pg_class
       WHERE relnamespace='public'::regnamespace AND relname = ANY($1::text[])`,
      [['orgs', 'projects', 'secrets', 'secret_versions', 'capabilities', 'capability_audit', 'audit_outbox', 'tenant_revocations', 'idempotency_keys']],
    );
    assert.equal(rls.rows.length, 9);
    assert.equal(rls.rows.every((row) => row.relforcerowsecurity), true);

    const released = await storeA.pool.connect();
    try {
      const context = await released.query(`SELECT current_setting('app.org_id', true) AS org_id, current_setting('app.project_id', true) AS project_id`);
      assert.ok(context.rows[0].org_id === null || context.rows[0].org_id === '');
      assert.ok(context.rows[0].project_id === null || context.rows[0].project_id === '');
    } finally {
      released.release();
    }
  } finally {
    await storeA?.close().catch(() => {});
    await storeB?.close().catch(() => {});
    await admin.query(`DROP ROLE IF EXISTS ${identifier(role)}`).catch(() => {});
    await admin.end();
  }
});
