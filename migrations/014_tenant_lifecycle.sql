ALTER TABLE orgs ADD COLUMN IF NOT EXISTS lifecycle_state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS lifecycle_reason TEXT;
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS lifecycle_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS offboarding_completed_at TIMESTAMPTZ;

ALTER TABLE projects ADD COLUMN IF NOT EXISTS lifecycle_state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS lifecycle_reason TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS lifecycle_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE projects ADD COLUMN IF NOT EXISTS offboarding_completed_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orgs_lifecycle_state_check') THEN
    ALTER TABLE orgs ADD CONSTRAINT orgs_lifecycle_state_check
      CHECK (lifecycle_state IN ('active', 'disabling', 'revoking', 'erasing', 'completed'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'projects_lifecycle_state_check') THEN
    ALTER TABLE projects ADD CONSTRAINT projects_lifecycle_state_check
      CHECK (lifecycle_state IN ('active', 'disabling', 'revoking', 'erasing', 'completed'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_orgs_lifecycle_state ON orgs(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_projects_lifecycle_state ON projects(org_id, lifecycle_state);
