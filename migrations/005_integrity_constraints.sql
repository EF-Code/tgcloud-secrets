-- Expand the tenant relationship proof without changing the canonical project id
-- format used by the 0.1 storage API. Nullable audit/revocation project IDs are
-- retained so old system events can be upgraded without destructive cleanup.
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_org_id_id ON projects(org_id, id);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capabilities_org_project_fk') THEN
    ALTER TABLE capabilities
      ADD CONSTRAINT capabilities_org_project_fk
      FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capability_audit_org_project_fk') THEN
    ALTER TABLE capability_audit
      ADD CONSTRAINT capability_audit_org_project_fk
      FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_revocations_org_project_fk') THEN
    ALTER TABLE tenant_revocations
      ADD CONSTRAINT tenant_revocations_org_project_fk
      FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idempotency_keys_org_project_fk') THEN
    ALTER TABLE idempotency_keys
      ADD CONSTRAINT idempotency_keys_org_project_fk
      FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id);
  END IF;
END $$;
