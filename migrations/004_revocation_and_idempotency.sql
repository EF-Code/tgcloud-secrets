CREATE TABLE IF NOT EXISTS tenant_revocations (
  id BIGSERIAL PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  UNIQUE(org_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_revocations_active
  ON tenant_revocations(org_id, project_id)
  WHERE active;

CREATE TABLE IF NOT EXISTS idempotency_keys (
  id BIGSERIAL PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(org_id, project_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency_keys(expires_at);

ALTER TABLE tenant_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_revocations_isolation ON tenant_revocations;
CREATE POLICY tenant_revocations_isolation ON tenant_revocations
  USING (org_id = current_setting('app.org_id', true)
         AND (project_id IS NULL OR project_id = current_setting('app.project_id', true)))
  WITH CHECK (org_id = current_setting('app.org_id', true)
              AND (project_id IS NULL OR project_id = current_setting('app.project_id', true)));

ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS idempotency_keys_isolation ON idempotency_keys;
CREATE POLICY idempotency_keys_isolation ON idempotency_keys
  USING (org_id = current_setting('app.org_id', true)
         AND project_id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
              AND project_id = current_setting('app.project_id', true));
