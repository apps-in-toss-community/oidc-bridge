-- 001_initial.sqlite.sql — zero-code mode Phase 1 schema for SQLite.
-- TEXT[] → TEXT (JSON), BYTEA → BLOB, TIMESTAMPTZ → TEXT (ISO-8601 UTC).
-- The driver layer enforces the JSON shape and timestamp parsing.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS api_tokens_user_id_idx ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS workspaces_owner_idx ON workspaces(owner_user_id);

CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  app_id_toss TEXT NOT NULL,
  display_title TEXT NOT NULL,
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hashes TEXT NOT NULL DEFAULT '[]',
  mtls_cert_enc BLOB NOT NULL,
  mtls_key_enc BLOB NOT NULL,
  sealing_key_version INTEGER NOT NULL,
  allowed_origins TEXT NOT NULL DEFAULT '[]',
  ownership_status TEXT NOT NULL CHECK (ownership_status IN ('pending','verified','lapsed')),
  ownership_grace_until TEXT,
  raw_tokens_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, app_id_toss)
);
CREATE INDEX IF NOT EXISTS apps_workspace_idx ON apps(workspace_id);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS master_keys (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  retired_at TEXT,
  provider_ref TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);
