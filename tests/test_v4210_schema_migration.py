import sqlite3

import pytest

import assessment.store as store_module
from assessment.store import AssessmentStore


def test_v4210_schema_migrations_are_versioned_idempotent_and_backed_up(tmp_path):
    db = tmp_path / "db" / "app.db"
    db.parent.mkdir(parents=True)
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE legacy_record(id TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO legacy_record VALUES ('keep-me', 'before-upgrade')")
        conn.commit()

    store = AssessmentStore(db)
    store.initialize()
    store.initialize()

    with store.connect() as conn:
        migrations = conn.execute(
            "SELECT version, checksum_sha256 FROM schema_migration ORDER BY version"
        ).fetchall()
        schema_version = conn.execute(
            "SELECT value FROM app_metadata WHERE key='schema_version'"
        ).fetchone()["value"]
        legacy = conn.execute("SELECT value FROM legacy_record WHERE id='keep-me'").fetchone()["value"]
    assert [row["version"] for row in migrations] == ["001", "002", "003"]
    assert all(len(row["checksum_sha256"]) == 64 for row in migrations)
    assert schema_version == "4.2.10"
    assert legacy == "before-upgrade"
    backups = list((db.parent / "migration-backups").glob("before-001_initial-*.db"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("SELECT value FROM legacy_record WHERE id='keep-me'").fetchone()[0] == "before-upgrade"


def test_v4210_failed_migration_rolls_back_its_transaction(monkeypatch, tmp_path):
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "001_valid.sql").write_text("CREATE TABLE stable(id TEXT PRIMARY KEY);", encoding="utf-8")
    (migrations / "002_invalid.sql").write_text(
        "CREATE TABLE must_rollback(id TEXT PRIMARY KEY); THIS IS INVALID SQL;",
        encoding="utf-8",
    )
    monkeypatch.setattr(store_module, "MIGRATION_DIR", migrations)
    db = tmp_path / "failed.db"

    with pytest.raises(sqlite3.DatabaseError):
        AssessmentStore(db).initialize()

    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        applied = [row[0] for row in conn.execute("SELECT version FROM schema_migration ORDER BY version")]
    assert "stable" in tables
    assert "must_rollback" not in tables
    assert applied == ["001"]
