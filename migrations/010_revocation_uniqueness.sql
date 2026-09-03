CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_revocations_org_scope
  ON tenant_revocations(org_id)
  WHERE project_id IS NULL;
