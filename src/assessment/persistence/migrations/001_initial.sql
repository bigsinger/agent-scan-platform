-- Core persistence tables. The store creates the remaining typed record tables
-- after migrations so older databases can be upgraded before normal startup.
CREATE TABLE IF NOT EXISTS app_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_setting (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    managed_by TEXT NOT NULL DEFAULT 'local',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT,
    job_id TEXT,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
