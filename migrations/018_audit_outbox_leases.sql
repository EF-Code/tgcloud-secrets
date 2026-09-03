-- Claim rows with a short lease before publishing so a slow or unavailable
-- audit destination cannot hold database row locks for the whole batch.
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS claim_token UUID;
ALTER TABLE audit_outbox ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_audit_outbox_claim_expiry
  ON audit_outbox(claim_expires_at, next_attempt_at, id)
  WHERE published_at IS NULL;
