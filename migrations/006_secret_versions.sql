ALTER TABLE secrets ADD COLUMN IF NOT EXISTS current_version INT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS secret_versions (
  id BIGSERIAL PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  version INT NOT NULL,
  encrypted_blob JSONB NOT NULL,
  dek_ciphertext TEXT,
  key_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(secret_id, version)
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_project_name
  ON secret_versions(project_id, name, version DESC);

ALTER TABLE secret_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_versions_tenant_isolation ON secret_versions;
CREATE POLICY secret_versions_tenant_isolation ON secret_versions
  USING (project_id = current_setting('app.project_id', true))
  WITH CHECK (project_id = current_setting('app.project_id', true));
