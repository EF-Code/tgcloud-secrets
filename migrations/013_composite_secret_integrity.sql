-- Complete the tenant relationship proof for encrypted records. Existing
-- installations are backfilled from the canonical project relationship before
-- the new columns become mandatory.
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE secrets AS secret
SET org_id = project.org_id
FROM projects AS project
WHERE project.id = secret.project_id
  AND secret.org_id IS NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM secrets WHERE org_id IS NULL) THEN
    RAISE EXCEPTION 'secrets.org_id could not be backfilled';
  END IF;
END $$;

ALTER TABLE secrets ALTER COLUMN org_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_org_project_id ON secrets(org_id, project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_org_project_name ON secrets(org_id, project_id, name);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secrets_org_fk') THEN
    ALTER TABLE secrets ADD CONSTRAINT secrets_org_fk FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secrets_org_project_fk') THEN
    ALTER TABLE secrets ADD CONSTRAINT secrets_org_project_fk FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE;
  END IF;
END $$;

ALTER TABLE secret_versions ADD COLUMN IF NOT EXISTS org_id TEXT;
UPDATE secret_versions AS version
SET org_id = secret.org_id
FROM secrets AS secret
WHERE secret.id = version.secret_id
  AND version.org_id IS NULL;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM secret_versions WHERE org_id IS NULL) THEN
    RAISE EXCEPTION 'secret_versions.org_id could not be backfilled';
  END IF;
END $$;

ALTER TABLE secret_versions ALTER COLUMN org_id SET NOT NULL;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secret_versions_org_fk') THEN
    ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_org_fk FOREIGN KEY (org_id) REFERENCES orgs(id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secret_versions_org_project_fk') THEN
    ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_org_project_fk FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secret_versions_secret_org_project_fk') THEN
    ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_secret_org_project_fk
      FOREIGN KEY (org_id, project_id, secret_id) REFERENCES secrets(org_id, project_id, id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secret_versions_name_org_project_fk') THEN
    ALTER TABLE secret_versions ADD CONSTRAINT secret_versions_name_org_project_fk
      FOREIGN KEY (org_id, project_id, name) REFERENCES secrets(org_id, project_id, name) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capabilities_secret_org_project_fk') THEN
    ALTER TABLE capabilities ADD CONSTRAINT capabilities_secret_org_project_fk
      FOREIGN KEY (org_id, project_id, secret_id) REFERENCES secrets(org_id, project_id, id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'capabilities_secret_name_org_project_fk') THEN
    ALTER TABLE capabilities ADD CONSTRAINT capabilities_secret_name_org_project_fk
      FOREIGN KEY (org_id, project_id, secret_name) REFERENCES secrets(org_id, project_id, name) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'audit_outbox_org_project_fk') THEN
    ALTER TABLE audit_outbox ADD CONSTRAINT audit_outbox_org_project_fk
      FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_revocations_org_project_fk_v2') THEN
    ALTER TABLE tenant_revocations ADD CONSTRAINT tenant_revocations_org_project_fk_v2
      FOREIGN KEY (org_id, project_id) REFERENCES projects(org_id, id) ON DELETE CASCADE;
  END IF;
END $$;

DROP POLICY IF EXISTS secrets_tenant_isolation ON secrets;
CREATE POLICY secrets_tenant_isolation ON secrets
  USING (org_id = current_setting('app.org_id', true)
         AND project_id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
              AND project_id = current_setting('app.project_id', true));

DROP POLICY IF EXISTS secret_versions_tenant_isolation ON secret_versions;
CREATE POLICY secret_versions_tenant_isolation ON secret_versions
  USING (org_id = current_setting('app.org_id', true)
         AND project_id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
              AND project_id = current_setting('app.project_id', true));
