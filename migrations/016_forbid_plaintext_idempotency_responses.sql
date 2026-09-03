-- No application path should retain a plaintext idempotency response. The
-- earlier scrub removed legacy rows that had no encrypted envelope; this
-- forward migration also clears any row left with both representations and
-- prevents a future runtime write from recreating the plaintext copy.
UPDATE idempotency_keys
SET response = NULL
WHERE response IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'idempotency_response_must_be_null'
  ) THEN
    ALTER TABLE idempotency_keys
      ADD CONSTRAINT idempotency_response_must_be_null
      CHECK (response IS NULL);
  END IF;
END $$;
