ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS response_envelope JSONB;
