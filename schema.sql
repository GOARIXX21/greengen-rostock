-- GreenGenRostock V28 – D1 Schema
-- Bestehender verschlüsselter App-State + unveränderbares Audit-Journal

CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_app_state_updated
  ON app_state(updated_at);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY NOT NULL,
  occurred_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred
  ON audit_events(occurred_at);
