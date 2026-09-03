-- Run this file as a database administrator after creating the database and
-- again after every migration upgrade (the table grants are conditional so the
-- first pass can safely run before any application tables exist). It contains
-- no passwords. Supply LOGIN credentials through a secret manager.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgcloud_schema_owner') THEN
    CREATE ROLE tgcloud_schema_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgcloud_migrator') THEN
    CREATE ROLE tgcloud_migrator NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgcloud_runtime') THEN
    CREATE ROLE tgcloud_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgcloud_audit_reader') THEN
    CREATE ROLE tgcloud_audit_reader NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tgcloud_audit_worker') THEN
    CREATE ROLE tgcloud_audit_worker NOLOGIN;
  END IF;
END $$;

-- The schema-owner role is the trusted migration boundary. It is NOLOGIN and
-- is only assumable by the migration identity, so it may run data migrations
-- across FORCE RLS tables without granting that power to the runtime roles.
ALTER ROLE tgcloud_schema_owner WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION BYPASSRLS;
ALTER ROLE tgcloud_migrator WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION NOBYPASSRLS INHERIT;
ALTER ROLE tgcloud_runtime WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE tgcloud_audit_reader WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE tgcloud_audit_worker WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION NOBYPASSRLS NOINHERIT;

GRANT tgcloud_schema_owner TO tgcloud_migrator;
REVOKE tgcloud_schema_owner, tgcloud_migrator FROM tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker;
REVOKE tgcloud_audit_reader, tgcloud_audit_worker FROM tgcloud_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker, tgcloud_migrator;
GRANT USAGE, CREATE ON SCHEMA public TO tgcloud_schema_owner;
GRANT USAGE ON SCHEMA public TO tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker, tgcloud_migrator;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
  FROM PUBLIC, tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public
  FROM PUBLIC, tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker;

-- Keep future migration-created objects private too. These defaults apply to
-- objects owned by the trusted schema-owner role; the explicit grants below
-- are re-applied after each migration for the exact application surface.
ALTER DEFAULT PRIVILEGES FOR ROLE tgcloud_schema_owner IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE tgcloud_schema_owner IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, tgcloud_runtime, tgcloud_audit_reader, tgcloud_audit_worker;

-- Run these ownership transfers after the first migration on an existing DB.
-- They are idempotent and make the runtime role subject to FORCE RLS.
ALTER TABLE IF EXISTS orgs OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS projects OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS secrets OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS secret_versions OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS capabilities OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS capability_audit OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS audit_outbox OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS tenant_revocations OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS idempotency_keys OWNER TO tgcloud_schema_owner;
ALTER TABLE IF EXISTS schema_migrations OWNER TO tgcloud_schema_owner;

-- Table and column grants are conditional so the role bootstrap can be run
-- before the migration job and safely repeated after every schema upgrade.
DO $$
BEGIN
  IF to_regclass('public.orgs') IS NOT NULL AND to_regclass('public.projects') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON orgs, projects TO tgcloud_runtime';
    EXECUTE 'GRANT UPDATE (lifecycle_state, lifecycle_reason, lifecycle_updated_at, disabled_at, offboarding_completed_at) ON orgs TO tgcloud_runtime';
    EXECUTE 'GRANT UPDATE (kms_key_id, lifecycle_state, lifecycle_reason, lifecycle_updated_at, disabled_at, offboarding_completed_at) ON projects TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.secrets') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT, DELETE ON secrets TO tgcloud_runtime';
    EXECUTE 'GRANT INSERT (id, org_id, project_id, name, encrypted_blob, dek_ciphertext, key_id, version, current_version, updated_at) ON secrets TO tgcloud_runtime';
    EXECUTE 'GRANT UPDATE (encrypted_blob, dek_ciphertext, key_id, version, current_version, updated_at) ON secrets TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.idempotency_keys') IS NOT NULL THEN
    -- The legacy response column is deliberately excluded. Migration 016
    -- keeps it only as a NULL-enforced tombstone, and the runtime must not
    -- regain a plaintext-response read path through a table-level SELECT.
    EXECUTE 'REVOKE ALL PRIVILEGES ON idempotency_keys FROM tgcloud_runtime';
    EXECUTE 'GRANT SELECT (id, org_id, project_id, idempotency_key, request_hash, created_at, expires_at) ON idempotency_keys TO tgcloud_runtime';
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='idempotency_keys' AND column_name='response_envelope'
    ) THEN
      EXECUTE 'GRANT SELECT (response_envelope) ON idempotency_keys TO tgcloud_runtime';
    END IF;
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name='idempotency_keys' AND column_name='completed_at'
    ) THEN
      EXECUTE 'GRANT SELECT (completed_at) ON idempotency_keys TO tgcloud_runtime';
    END IF;
    EXECUTE 'GRANT DELETE ON idempotency_keys TO tgcloud_runtime';
    EXECUTE 'GRANT INSERT (org_id, project_id, idempotency_key, request_hash, expires_at) ON idempotency_keys TO tgcloud_runtime';
    IF (
      SELECT count(*) = 2
      FROM information_schema.columns
      WHERE table_schema='public' AND table_name='idempotency_keys'
        AND column_name = ANY (ARRAY['response_envelope', 'completed_at'])
    ) THEN
      EXECUTE 'GRANT UPDATE (response_envelope, completed_at) ON idempotency_keys TO tgcloud_runtime';
    END IF;
  END IF;
  IF to_regclass('public.secret_versions') IS NOT NULL
     AND to_regclass('public.capabilities') IS NOT NULL
     AND to_regclass('public.tenant_revocations') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON secret_versions TO tgcloud_runtime';
    EXECUTE 'GRANT INSERT (secret_id, org_id, project_id, name, version, encrypted_blob, dek_ciphertext, key_id) ON secret_versions TO tgcloud_runtime';
    EXECUTE 'GRANT UPDATE (encrypted_blob, dek_ciphertext, key_id) ON secret_versions TO tgcloud_runtime';
    EXECUTE 'GRANT SELECT ON capabilities TO tgcloud_runtime';
    EXECUTE 'GRANT INSERT (id, org_id, project_id, secret_id, secret_name, token_hash, base_url, path_prefix, methods, inject_header, inject_prefix, allow_http, not_before, expires_at, metadata_mac, key_id, mac_key_id) ON capabilities TO tgcloud_runtime';
    EXECUTE 'GRANT UPDATE (revoked_at, revoked_reason, scheduled_revoke_at, last_used_at, use_count, key_id, mac_key_id, metadata_mac, mutation_version, updated_at) ON capabilities TO tgcloud_runtime';
    EXECUTE 'GRANT SELECT ON tenant_revocations TO tgcloud_runtime';
    EXECUTE 'GRANT INSERT (org_id, project_id, reason, active) ON tenant_revocations TO tgcloud_runtime';
    EXECUTE 'GRANT UPDATE (revoked_at, reason, active) ON tenant_revocations TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.capability_audit') IS NOT NULL THEN
    EXECUTE 'GRANT INSERT (capability_id, org_id, project_id, peer, path, method, status, event_type, outcome, request_id, upstream_origin, software_version) ON capability_audit TO tgcloud_runtime';
  END IF;
  -- The runtime app can append and read its scoped outbox rows, but cannot
  -- rewrite or delete audit evidence. Publishing is a separate worker role.
  IF to_regclass('public.audit_outbox') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON audit_outbox TO tgcloud_runtime';
    EXECUTE 'GRANT INSERT (event_id, org_id, project_id, event_type, payload) ON audit_outbox TO tgcloud_runtime';
  END IF;
  -- Migration metadata is a trust anchor. The runtime may verify it but must
  -- never insert, update, or delete an applied version/checksum.
  IF to_regclass('public.schema_migrations') IS NOT NULL
     AND to_regclass('public.orgs') IS NOT NULL
     AND to_regclass('public.projects') IS NOT NULL
     AND to_regclass('public.capability_audit') IS NOT NULL
     AND to_regclass('public.audit_outbox') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON schema_migrations TO tgcloud_runtime';
    EXECUTE 'GRANT SELECT ON orgs, projects, capability_audit, audit_outbox, schema_migrations TO tgcloud_audit_reader';
  END IF;
  IF to_regclass('public.audit_outbox') IS NOT NULL THEN
    EXECUTE 'GRANT SELECT ON audit_outbox TO tgcloud_audit_worker';
    EXECUTE 'GRANT UPDATE (published_at, attempts, next_attempt_at, claim_token, claim_expires_at) ON audit_outbox TO tgcloud_audit_worker';
  END IF;
  IF to_regclass('public.capability_audit_id_seq') IS NOT NULL THEN
    EXECUTE 'GRANT USAGE, SELECT ON capability_audit_id_seq TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.audit_outbox_id_seq') IS NOT NULL THEN
    EXECUTE 'GRANT USAGE, SELECT ON audit_outbox_id_seq TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.tenant_revocations_id_seq') IS NOT NULL THEN
    EXECUTE 'GRANT USAGE, SELECT ON tenant_revocations_id_seq TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.idempotency_keys_id_seq') IS NOT NULL THEN
    EXECUTE 'GRANT USAGE, SELECT ON idempotency_keys_id_seq TO tgcloud_runtime';
  END IF;
  IF to_regclass('public.secret_versions_id_seq') IS NOT NULL THEN
    EXECUTE 'GRANT USAGE, SELECT ON secret_versions_id_seq TO tgcloud_runtime';
  END IF;
END $$;

COMMIT;

-- The migration command automatically assumes this role when the connected
-- identity is a member. It is also safe to wrap the command explicitly:
--   BEGIN; SET LOCAL ROLE tgcloud_schema_owner; ...migration command...; COMMIT;
-- Keep tgcloud_runtime and tgcloud_audit_reader as separate LOGIN roles when
-- deploying. Use one explicitly scoped audit worker per logical tenant; never
-- make any runtime/reader/worker role a table owner or grant BYPASSRLS. The
-- schema-owner BYPASSRLS attribute is reserved for trusted migrations.
