CREATE TABLE IF NOT EXISTS audit_outbox (
  id BIGSERIAL PRIMARY KEY,
  event_id UUID NOT NULL UNIQUE,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at TIMESTAMPTZ,
  attempts INT NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_outbox_pending
  ON audit_outbox(next_attempt_at, id)
  WHERE published_at IS NULL;

ALTER TABLE audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_outbox_tenant_isolation ON audit_outbox;
CREATE POLICY audit_outbox_tenant_isolation ON audit_outbox
  USING (org_id = current_setting('app.org_id', true)
         AND project_id = current_setting('app.project_id', true))
  WITH CHECK (org_id = current_setting('app.org_id', true)
             AND project_id = current_setting('app.project_id', true));
