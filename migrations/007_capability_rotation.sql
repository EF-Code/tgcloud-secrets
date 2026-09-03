ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS scheduled_revoke_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_capabilities_scheduled_revoke
  ON capabilities(scheduled_revoke_at)
  WHERE scheduled_revoke_at IS NOT NULL AND revoked_at IS NULL;
