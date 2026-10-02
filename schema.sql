-- ============================================================
-- GreenGen Rostock – D1 Schema
-- V38 Compliance / Append-only Audit & Zutrittsprotokoll
-- ============================================================

-- Zentrale App-State-Tabelle
-- Enthält ausschließlich die bereits clientseitig
-- verschlüsselten Datenblobs der Anwendung.
CREATE TABLE IF NOT EXISTS app_state (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_app_state_updated
ON app_state(updated_at);


-- ============================================================
-- Audit-Protokoll
-- ============================================================
-- Append-only:
-- Es gibt bewusst KEINEN UPDATE- oder DELETE-Endpunkt
-- für diese Tabelle.
--
-- payload:
--   clientseitig verschlüsselter Audit-Eintrag
--
-- payload_sha256:
--   Integritätsnachweis des gespeicherten Payloads
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY NOT NULL,
  occurred_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred
ON audit_events(occurred_at);


-- ============================================================
-- Zutrittsprotokoll
-- ============================================================
-- Ebenfalls append-only.
--
-- Die bisherige künstliche Begrenzung auf 5.000 Einträge
-- wird damit nicht mehr im Datenmodell benötigt.
--
-- Alte Einträge werden nicht durch einen normalen
-- Benutzer-/Admin-Delete gelöscht.
-- ============================================================

CREATE TABLE IF NOT EXISTS access_events (
  id TEXT PRIMARY KEY NOT NULL,
  occurred_at TEXT NOT NULL,
  payload TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_access_events_occurred
ON access_events(occurred_at);
