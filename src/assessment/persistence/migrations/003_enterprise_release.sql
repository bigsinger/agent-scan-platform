-- v4.2.10 release-specific generic records used by incremental scans and
-- review governance. Remaining generic tables are idempotently created by the
-- store schema builder after this migration completes.
CREATE TABLE IF NOT EXISTS scan_file_cache (
    id TEXT PRIMARY KEY,
    status TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS finding_instance (
    id TEXT PRIMARY KEY,
    status TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS finding_suppression (
    id TEXT PRIMARY KEY,
    status TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT
);
