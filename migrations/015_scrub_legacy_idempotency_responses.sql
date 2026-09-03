-- Completed responses created before encrypted response envelopes were added
-- may contain bearer capability tokens. They cannot be safely re-encrypted by a
-- schema migration because migrations must not receive KMS plaintext. Remove
-- them so the legacy JSON column is no longer a plaintext credential store.
UPDATE idempotency_keys
SET response = NULL
WHERE response IS NOT NULL AND response_envelope IS NULL;
