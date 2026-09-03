ALTER TABLE orgs ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS not_before TIMESTAMPTZ;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS revoked_reason TEXT;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS use_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS mac_key_id TEXT NOT NULL DEFAULT 'env-v1';
ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE capability_audit AS audit
SET org_id = capability.org_id,
    project_id = capability.project_id
FROM capabilities AS capability
WHERE audit.capability_id = capability.id
  AND (audit.org_id IS NULL OR audit.project_id IS NULL);

ALTER TABLE capability_audit ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'proxy_request';
ALTER TABLE capability_audit ADD COLUMN IF NOT EXISTS outcome TEXT;
ALTER TABLE capability_audit ADD COLUMN IF NOT EXISTS request_id TEXT;
ALTER TABLE capability_audit ADD COLUMN IF NOT EXISTS upstream_origin TEXT;
ALTER TABLE capability_audit ADD COLUMN IF NOT EXISTS software_version TEXT;

ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_org_id_name_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_org_id_name ON projects(org_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_org_id_id ON projects(org_id, id);

ALTER TABLE capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE capabilities FORCE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE orgs FORCE ROW LEVEL SECURITY;
ALTER TABLE capability_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE capability_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS orgs_tenant_isolation ON orgs;
CREATE POLICY orgs_tenant_isolation ON orgs
  USING (id = current_setting('app.org_id', true))
  WITH CHECK (id = current_setting('app.org_id', true));

DROP POLICY IF EXISTS projects_tenant_isolation ON projects;
CREATE POLICY projects_tenant_isolation ON projects
  USING (org_id = current_setting('app.org_id', true)
         AND id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
             AND id = current_setting('app.project_id', true));

DROP POLICY IF EXISTS secrets_tenant_isolation ON secrets;
CREATE POLICY secrets_tenant_isolation ON secrets
  USING (project_id = current_setting('app.project_id', true))
  WITH CHECK (project_id = current_setting('app.project_id', true));

DROP POLICY IF EXISTS capabilities_tenant_isolation ON capabilities;
CREATE POLICY capabilities_tenant_isolation ON capabilities
  USING (org_id = current_setting('app.org_id', true)
         AND project_id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
             AND project_id = current_setting('app.project_id', true));

DROP POLICY IF EXISTS capability_audit_tenant_isolation ON capability_audit;
CREATE POLICY capability_audit_tenant_isolation ON capability_audit
  USING (org_id = current_setting('app.org_id', true)
         AND project_id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
             AND project_id = current_setting('app.project_id', true));
