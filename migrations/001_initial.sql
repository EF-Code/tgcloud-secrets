CREATE TABLE IF NOT EXISTS orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kms_key_id TEXT NOT NULL DEFAULT 'local',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(org_id, name)
);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  encrypted_blob JSONB NOT NULL,
  dek_ciphertext TEXT,
  key_id TEXT NOT NULL DEFAULT 'local',
  version INT NOT NULL DEFAULT 3,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id, name)
);

CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  secret_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  base_url TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  methods JSONB NOT NULL,
  inject_header TEXT NOT NULL,
  inject_prefix TEXT NOT NULL,
  allow_http BOOLEAN NOT NULL DEFAULT false,
  expires_at TIMESTAMPTZ,
  metadata_mac TEXT NOT NULL,
  key_id TEXT NOT NULL DEFAULT 'local',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_capabilities_token_hash ON capabilities(token_hash);
CREATE INDEX IF NOT EXISTS idx_capabilities_org_project ON capabilities(org_id, project_id);
CREATE INDEX IF NOT EXISTS idx_secrets_project_name ON secrets(project_id, name);
CREATE INDEX IF NOT EXISTS idx_capabilities_project ON capabilities(project_id);

CREATE TABLE IF NOT EXISTS capability_audit (
  id BIGSERIAL PRIMARY KEY,
  capability_id TEXT REFERENCES capabilities(id) ON DELETE SET NULL,
  org_id TEXT,
  project_id TEXT,
  peer TEXT,
  path TEXT,
  method TEXT,
  status INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_capability_time ON capability_audit(capability_id, created_at);
