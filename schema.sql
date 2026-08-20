-- GreenGenRostock V27 – D1 Schema (minimal-invasiv)
-- Speichert ausschließlich bereits clientseitig verschlüsselte Blobs.
-- Keine Klartextdaten auf dem Server.

CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_app_state_updated ON app_state(updated_at);
