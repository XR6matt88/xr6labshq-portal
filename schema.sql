CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 0,
  display_name TEXT NOT NULL,
  institution TEXT,
  research_field TEXT,
  orcid_id TEXT,
  orcid_verified INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'member',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_members_orcid ON members (orcid_id);

CREATE TABLE IF NOT EXISTS auth_tokens (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL DEFAULT 'login',
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_email_exp ON auth_tokens (email, expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  user_agent TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS zenodo_records (
  zenodo_id TEXT PRIMARY KEY,
  concept_doi TEXT,
  version_doi TEXT,
  community_slug TEXT NOT NULL,
  community_title TEXT,
  title TEXT NOT NULL,
  abstract TEXT,
  resource_type TEXT,
  publication_date TEXT,
  license_id TEXT,
  access_right TEXT,
  zenodo_url TEXT,
  authors_json TEXT,
  synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_zenodo_comm_date ON zenodo_records (community_slug, publication_date DESC);

CREATE TABLE IF NOT EXISTS member_publications (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  zenodo_id TEXT NOT NULL,
  match_method TEXT NOT NULL DEFAULT 'orcid_auto',
  verified_by_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (member_id, zenodo_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_action_target ON audit_logs (action, target_id, created_at);

CREATE TABLE IF NOT EXISTS sync_logs (
  id TEXT PRIMARY KEY,
  community_slug TEXT NOT NULL,
  records_fetched INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  error_message TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Aktiviti',
  description TEXT NOT NULL DEFAULT '',
  media_type TEXT NOT NULL DEFAULT 'none',
  media_key TEXT,
  media_filename TEXT,
  media_mime TEXT,
  activity_date TEXT NOT NULL,
  created_by TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_announcements_active_date
  ON announcements (is_active, activity_date DESC, created_at DESC);
