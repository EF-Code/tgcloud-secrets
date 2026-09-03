-- KMS rotation is scoped to one project. Keep the authoritative wrapping-key
-- identifier on that project so rotating one project cannot invalidate sibling
-- projects in the same organization.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS kms_key_id TEXT;

UPDATE projects AS project
SET kms_key_id = organization.kms_key_id
FROM orgs AS organization
WHERE project.org_id = organization.id
  AND project.kms_key_id IS NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM projects
    WHERE kms_key_id IS NULL
       OR length(kms_key_id) = 0
       OR length(kms_key_id) > 512
       OR btrim(kms_key_id) <> kms_key_id
       OR kms_key_id = 'unknown'
       OR kms_key_id ~ '[[:cntrl:]]'
  ) THEN
    RAISE EXCEPTION 'projects.kms_key_id contains an invalid or missing key id';
  END IF;
END $$;

ALTER TABLE projects ALTER COLUMN kms_key_id SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'projects_kms_key_id_check'
  ) THEN
    ALTER TABLE projects ADD CONSTRAINT projects_kms_key_id_check
      CHECK (length(kms_key_id) BETWEEN 1 AND 512
             AND btrim(kms_key_id) = kms_key_id
             AND kms_key_id <> 'unknown'
             AND kms_key_id !~ '[[:cntrl:]]');
  END IF;
END $$;
