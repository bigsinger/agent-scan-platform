from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

from .contracts import completeness_rows
from .security import SensitiveDataError, SensitiveDataGuard


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("ASSESSMENT_STATE_ROOT") or (REPO_ROOT / "data"))
ARTIFACT_ROOT = Path(os.environ.get("ASSESSMENT_ARTIFACT_ROOT") or (DATA_DIR / "artifacts"))
DB_DIR = DATA_DIR / "db"
DB_PATH = Path(os.environ.get("ASSESSMENT_DB_PATH") or (DB_DIR / "app.db"))
SEED_PATH = PACKAGE_ROOT / "static" / "assessment" / "seed.json"
MIGRATION_DIR = PACKAGE_ROOT / "persistence" / "migrations"
AUDIT_CORRELATION_ID: ContextVar[str] = ContextVar("assessment_audit_correlation_id", default="")


def set_audit_correlation_id(value: str) -> None:
    AUDIT_CORRELATION_ID.set(str(value or ""))


RUNTIME_SEED_LIST_KEYS = {
    "agents",
    "agentAssets",
    "discoveryHits",
    "discoveryErrors",
    "discoveryLog",
    "mcpServers",
    "consents",
    "tools",
    "skills",
    "tasks",
    "jobs",
    "processes",
    "taskEvents",
    "findings",
    "evidenceItems",
    "reports",
    "components",
    "redteamRuns",
    "attackPaths",
    "policyDrafts",
    "defenseRecommendations",
    "retests",
    "backupRecords",
    "heatmap",
    "caseLibrary",
    "redCases",
    "profiles",
    "ruleRows",
    "scanners",
    "schedules",
    "integrations",
    "licenses",
    "dbTables",
    "taskStages",
}

RUNTIME_SEED_OBJECT_KEYS = {
    "selectedAsset",
    "selectedTask",
    "selectedMcp",
    "selectedTool",
    "selectedConsent",
    "selectedSkill",
    "selectedCase",
    "selectedRedteamRun",
    "selectedFinding",
    "selectedEvidence",
    "selectedAttackPath",
    "selectedPolicyDraft",
    "selectedReport",
    "selectedRule",
    "selectedProfile",
    "selectedRetest",
}

PROTOTYPE_RUNTIME_TABLES = [
    "assessment_target",
    "discovery_run",
    "discovery_hit",
    "agent_instance",
    "config_snapshot",
    "component",
    "component_relation",
    "assessment",
    "assessment_scope",
    "task",
    "task_stage",
    "task_event",
    "scan_stage",
    "scan_file_cache",
    "scan_job",
    "mcp_consent",
    "consent_request",
    "process_execution",
    "mcp_server",
    "mcp_tool",
    "mcp_prompt",
    "mcp_resource",
    "mcp_signature",
    "tool_label",
    "toxic_flow",
    "skill",
    "skill_file",
    "scanner_run",
    "test_run",
    "redteam_run",
    "redteam_message",
    "finding",
    "finding_instance",
    "finding_suppression",
    "evidence",
    "artifact",
    "attack_path",
    "attack_path_node",
    "attack_path_edge",
    "policy_draft",
    "report",
    "retest",
    "retest_run",
    "guard_event",
    "defense_recommendation",
]

PROTOTYPE_SEED_IDS = {
    "agt_cc_001",
    "agt_cx_001",
    "agt_oc_001",
    "agt_he_001",
    "asm_v4_001",
    "asm_v4_002",
    "asm_v4_003",
    "asm_v4_004",
    "asm_v4_005",
    "mcp_001",
    "mcp_002",
    "mcp_003",
    "mcp_004",
    "mcp_005",
    "skill_001",
    "skill_002",
    "skill_003",
    "skill_004",
    "skill_005",
    "fnd_001",
    "fnd_002",
    "fnd_003",
    "fnd_004",
    "ev_001",
    "ev_002",
    "ev_003",
    "ev_004",
    "rpt_001",
    "rpt_002",
    "rpt_003",
    "rpt_004",
    "rt_001",
    "rt_002",
    "rt_003",
    "job_001",
    "job_002",
    "job_003",
    "job_004",
    "job_005",
    "job_006",
    "job_007",
    "exec_001",
    "exec_002",
    "exec_003",
    "exec_004",
}

PROTOTYPE_SEED_MARKERS = (
    "claude-code-repo-demo",
    "codex-project-a",
    "openclaw-gateway-lab",
    "hermes-profile-dev",
    "/workspace/demo",
    "/workspace/claude-demo",
    "unknown.example",
)


GENERIC_TABLES = [
    "assessment_target",
    "discovery_run",
    "discovery_hit",
    "agent_instance",
    "config_snapshot",
    "component",
    "component_relation",
    "adapter",
    "adapter_capability",
    "assessment_profile",
    "profile_rule",
    "profile_casepack",
    "assessment",
    "assessment_scope",
    "task",
    "task_stage",
    "task_event",
    "scan_stage",
    "scan_file_cache",
    "scan_job",
    "mcp_consent",
    "consent_request",
    "process_execution",
    "sandbox_policy",
    "sandbox_profile",
    "policy_decision",
    "mcp_server",
    "mcp_tool",
    "mcp_prompt",
    "mcp_resource",
    "mcp_signature",
    "tool_label",
    "toxic_flow",
    "skill",
    "skill_file",
    "scanner_plugin",
    "scanner_run",
    "rule",
    "rule_version",
    "case_pack",
    "test_case",
    "test_run",
    "redteam_case",
    "redteam_run",
    "redteam_message",
    "judge_rule",
    "payload_template",
    "finding",
    "finding_instance",
    "finding_suppression",
    "evidence",
    "artifact",
    "attack_path",
    "attack_path_node",
    "attack_path_edge",
    "policy_draft",
    "report",
    "retest",
    "retest_run",
    "scanner",
    "scanner_health",
    "schedule",
    "integration",
    "integration_config",
    "integration_event",
    "diagnostic_event",
    "database_backup",
    "backup_record",
    "third_party_component",
    "agent_scan_compat",
    "issue_mapping",
    "compatibility_test",
    "feature_requirement",
    "guard_event",
    "defense_recommendation",
    "module_setting",
    "system_health_check",
    # v4.2 探针与行为分析表
    "probe_adapter",
    "probe_install_plan",
    "behavior_chain",
    "behavior_anomaly",
]

ALLOWED_TABLES = set(GENERIC_TABLES)


class AssessmentStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self._lock = Lock()

    def initialize(self) -> None:
        for directory in [
            DB_DIR,
            self.db_path.parent,
            ARTIFACT_ROOT,
            DATA_DIR / "work",
            DATA_DIR / "reports",
            DATA_DIR / "backups",
        ]:
            directory.mkdir(parents=True, exist_ok=True)
        database_preexisted = self.db_path.is_file() and self.db_path.stat().st_size > 0
        with self.connect() as conn:
            self._apply_schema_migrations(conn, backup_existing=database_preexisted)
            self._create_schema(conn)
            self._purge_prototype_runtime_records(conn)
            self._seed_if_needed(conn)

    def _apply_schema_migrations(self, conn: sqlite3.Connection, *, backup_existing: bool) -> None:
        migration_files = sorted(MIGRATION_DIR.glob("[0-9][0-9][0-9]_*.sql"))
        if not migration_files:
            raise RuntimeError(f"schema migrations are missing: {MIGRATION_DIR}")
        migration_table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migration'"
        ).fetchone()
        applied = {}
        if migration_table_exists:
            applied = {
                str(row["version"]): str(row["checksum_sha256"])
                for row in conn.execute("SELECT version, checksum_sha256 FROM schema_migration").fetchall()
            }
        pending: list[tuple[Path, str, str]] = []
        for path in migration_files:
            version = path.stem.split("_", 1)[0]
            script = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
            if version in applied:
                if applied[version] != checksum:
                    raise RuntimeError(f"applied migration checksum changed: {path.name}")
                continue
            pending.append((path, checksum, script))
        backup_path: Path | None = None
        if pending and backup_existing:
            backup_dir = self.db_path.parent / "migration-backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = backup_dir / f"before-{pending[0][0].stem}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.db"
            with sqlite3.connect(backup_path) as target:
                conn.backup(target)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migration (
                version TEXT PRIMARY KEY,
                checksum_sha256 TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        for path, checksum, script in pending:
            try:
                conn.execute("BEGIN IMMEDIATE")
                for statement in script.split(";"):
                    statement = statement.strip()
                    if statement:
                        conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migration(version, checksum_sha256, applied_at) VALUES (?, ?, ?)",
                    (path.stem.split("_", 1)[0], checksum, utc_now()),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        app_metadata_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_metadata'"
        ).fetchone()
        if pending and app_metadata_exists:
            conn.execute(
                "INSERT OR REPLACE INTO app_metadata(key, value, updated_at) VALUES (?, ?, ?)",
                ("schema_version", "4.2.10", utc_now()),
            )
            if backup_path:
                conn.execute(
                    "INSERT OR REPLACE INTO app_metadata(key, value, updated_at) VALUES (?, ?, ?)",
                    ("last_migration_backup", str(backup_path), utc_now()),
                )
            conn.commit()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_setting (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                managed_by TEXT NOT NULL DEFAULT 'local',
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_event (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT,
                job_id TEXT,
                type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_event (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        for table in GENERIC_TABLES:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    id TEXT PRIMARY KEY,
                    status TEXT,
                    data_json TEXT NOT NULL DEFAULT '{{}}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
                """
            )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_scan_event_assessment_seq ON scan_event(assessment_id, seq)")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_audit_event_object ON audit_event(object_type, object_id, seq)")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_feature_requirement_status ON feature_requirement(status, created_at)")
        # v4.2 探针与 OTel 结构化表
        self._migrate_observability(conn)
        conn.commit()

    def _seed_if_needed(self, conn: sqlite3.Connection) -> None:
        now = utc_now()
        conn.execute(
            "INSERT OR REPLACE INTO app_metadata(key, value, updated_at) VALUES (?, ?, ?)",
            ("app_version", "4.2.10", now),
        )
        existing = conn.execute("SELECT value_json FROM app_setting WHERE key='ui_state'").fetchone()
        if existing:
            self._sanitize_ui_state(conn, json.loads(existing["value_json"]))
            self._sync_contract_seed(conn)
            return
        state = runtime_empty_seed_state(load_seed_state())
        state["completeness"] = completeness_rows()
        conn.execute(
            "INSERT INTO app_setting(key, value_json, managed_by, updated_at) VALUES (?, ?, ?, ?)",
            ("ui_state", json.dumps(state, ensure_ascii=False), "local", now),
        )
        self._sync_contract_seed(conn, state)
        self.audit(conn, "system.seed", "app", "ui_state", {"source": "runtime-empty seed"})
        conn.commit()

    def _sanitize_ui_state(self, conn: sqlite3.Connection, state: dict) -> None:
        sanitized = runtime_empty_seed_state(state)
        if sanitized == state:
            return
        conn.execute(
            """
            INSERT INTO app_setting(key, value_json, managed_by, updated_at)
            VALUES ('ui_state', ?, 'local', ?)
            ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
            """,
            (json.dumps(sanitized, ensure_ascii=False), utc_now()),
        )

    def _purge_prototype_runtime_records(self, conn: sqlite3.Connection) -> None:
        deleted: dict[str, int] = {}
        for table in PROTOTYPE_RUNTIME_TABLES:
            rows = conn.execute(f"SELECT id, data_json FROM {table}").fetchall()
            delete_ids = [
                row["id"]
                for row in rows
                if row["id"] in PROTOTYPE_SEED_IDS or any(marker in row["data_json"] for marker in PROTOTYPE_SEED_MARKERS)
            ]
            for record_id in delete_ids:
                conn.execute(f"DELETE FROM {table} WHERE id=?", (record_id,))
            if delete_ids:
                deleted[table] = len(delete_ids)
        if deleted:
            now = utc_now()
            total = sum(deleted.values())
            conn.execute(
                "INSERT OR REPLACE INTO app_metadata(key, value, updated_at) VALUES (?, ?, ?)",
                ("prototype_seed_purged_at", now, now),
            )
            self.audit(conn, "system.purge_prototype_seed", "app", "runtime_records", {"deleted": total, "tables": deleted})

    def _sync_contract_seed(self, conn: sqlite3.Connection, state: dict | None = None) -> None:
        rows = completeness_rows()
        now = utc_now()
        if state is None:
            existing = conn.execute("SELECT value_json FROM app_setting WHERE key='ui_state'").fetchone()
            state = json.loads(existing["value_json"]) if existing else runtime_empty_seed_state(load_seed_state())
        existing_ids = {row.get("id") for row in state.get("completeness", []) if isinstance(row, dict)}
        if existing_ids != {row["id"] for row in rows}:
            state["completeness"] = rows
            conn.execute(
                """
                INSERT INTO app_setting(key, value_json, managed_by, updated_at)
                VALUES ('ui_state', ?, 'local', ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (json.dumps(state, ensure_ascii=False), now),
            )
        for row in rows:
            conn.execute(
                """
                INSERT OR REPLACE INTO feature_requirement(id, status, data_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (row["id"], "已验收", json.dumps(row, ensure_ascii=False), now, now),
            )

    def _migrate_observability(self, conn: sqlite3.Connection) -> None:
        """v4.2 探针与 OTel 结构化表迁移."""
        from .observability.storage import OBSERVABILITY_DDL
        for statement in OBSERVABILITY_DDL.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.execute(stmt)

    def get_state(self) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT value_json FROM app_setting WHERE key='ui_state'").fetchone()
        if not row:
            return runtime_empty_seed_state(load_seed_state())
        return json.loads(row["value_json"])

    def save_state(self, state: dict) -> None:
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO app_setting(key, value_json, managed_by, updated_at)
                VALUES ('ui_state', ?, 'local', ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (json.dumps(state, ensure_ascii=False), utc_now()),
            )
            conn.commit()

    def upsert_record(self, table: str, record: dict, status: str | None = None) -> dict:
        self._ensure_table(table)
        if not record.get("id"):
            record = {**record, "id": new_id(table[:3])}
        now = utc_now()
        row_status = status or str(record.get("status") or "ACTIVE")
        row = SensitiveDataGuard.sanitize_for_persist(dict(record))
        row.setdefault("status", row_status)
        with self._lock, self.connect() as conn:
            existing = conn.execute(f"SELECT created_at FROM {table} WHERE id=?", (row["id"],)).fetchone()
            created_at = existing["created_at"] if existing else row.get("created_at", now)
            row.setdefault("created_at", created_at)
            row["updated_at"] = now
            conn.execute(
                f"""
                INSERT INTO {table}(id, status, data_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    data_json=excluded.data_json,
                    updated_at=excluded.updated_at
                """,
                (row["id"], row_status, json.dumps(row, ensure_ascii=False), created_at, now),
            )
            conn.commit()
        return row

    def upsert_records(self, table: str, records: list[dict], status: str | None = None) -> list[dict]:
        if not records:
            return []
        self._ensure_table(table)
        now = utc_now()
        prepared: list[tuple[dict, str]] = []
        for record in records:
            current = dict(record)
            if not current.get("id"):
                current["id"] = new_id(table[:3])
            row = SensitiveDataGuard.sanitize_for_persist(current)
            row_status = status or str(row.get("status") or "ACTIVE")
            row["status"] = row_status
            prepared.append((row, row_status))
        ids = [str(row["id"]) for row, _ in prepared]
        existing: dict[str, str] = {}
        with self._lock, self.connect() as conn:
            for offset in range(0, len(ids), 500):
                chunk = ids[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                for found in conn.execute(
                    f"SELECT id, created_at FROM {table} WHERE id IN ({placeholders})",
                    tuple(chunk),
                ).fetchall():
                    existing[str(found["id"])] = str(found["created_at"])
            values = []
            for row, row_status in prepared:
                existing_created_at = existing.get(str(row["id"]))
                if existing_created_at:
                    row["created_at"] = existing_created_at
                else:
                    row.setdefault("created_at", now)
                row["updated_at"] = now
                values.append(
                    (
                        row["id"],
                        row_status,
                        json.dumps(row, ensure_ascii=False),
                        row["created_at"],
                        now,
                    )
                )
            conn.executemany(
                f"""
                INSERT INTO {table}(id, status, data_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    data_json=excluded.data_json,
                    updated_at=excluded.updated_at
                """,
                values,
            )
            conn.commit()
        return [row for row, _ in prepared]

    def get_record(self, table: str, record_id: str) -> dict | None:
        self._ensure_table(table)
        with self.connect() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (record_id,)).fetchone()
        return decode_record(row) if row else None

    def list_records(self, table: str, status: str | None = None, limit: int = 500) -> list[dict]:
        self._ensure_table(table)
        limit = max(1, min(limit, 5000))
        query = f"SELECT * FROM {table}"
        params: tuple[Any, ...] = ()
        if status is not None:
            query += " WHERE status=?"
            params = (status,)
        query += " ORDER BY created_at DESC LIMIT ?"
        params = (*params, limit)
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [decode_record(row) for row in rows]

    def list_scan_events(self, assessment_id: str, limit: int = 500) -> list[dict]:
        limit = max(1, min(limit, 5000))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT seq, assessment_id, job_id, type, payload_json, created_at
                FROM scan_event
                WHERE assessment_id=?
                ORDER BY seq ASC
                LIMIT ?
                """,
                (assessment_id, limit),
            ).fetchall()
        events = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            events.append(
                {
                    "seq": row["seq"],
                    "assessment_id": row["assessment_id"],
                    "job_id": row["job_id"],
                    "type": row["type"],
                    "payload": payload,
                    "time": row["created_at"],
                    "text": payload.get("message") or payload.get("text") or row["type"],
                }
            )
        return events

    def list_audit_events(self, object_type: str | None = None, object_id: str | None = None, limit: int = 500) -> list[dict]:
        limit = max(1, min(limit, 5000))
        query = "SELECT seq, actor, action, object_type, object_id, payload_json, created_at FROM audit_event"
        clauses = []
        params: list[Any] = []
        if object_type:
            clauses.append("object_type=?")
            params.append(object_type)
        if object_id:
            clauses.append("object_id=?")
            params.append(object_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY seq ASC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        events = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            events.append(
                {
                    "seq": row["seq"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "object_type": row["object_type"],
                    "object_id": row["object_id"],
                    "payload": payload,
                    "created_at": row["created_at"],
                }
            )
        return events

    def write_artifact(
        self,
        kind: str,
        content: str | bytes,
        suffix: str = "json",
        directory: str = "artifacts",
        metadata: dict | None = None,
    ) -> dict:
        safe_suffix = suffix.strip(".") or "bin"
        artifact_id = new_id("art")
        today = datetime.now(timezone.utc)
        base_dir = ARTIFACT_ROOT / directory / today.strftime("%Y") / today.strftime("%m")
        base_dir.mkdir(parents=True, exist_ok=True)
        path = base_dir / f"{artifact_id}.{safe_suffix}"
        safe_content = SensitiveDataGuard.sanitize_for_persist(content)
        if isinstance(safe_content, bytes):
            path.write_bytes(safe_content)
        else:
            path.write_text(str(safe_content), encoding="utf-8")
        relative_path = str(path.relative_to(DATA_DIR)).replace("\\", "/") if DATA_DIR in path.parents else str((Path("artifacts") / directory / today.strftime("%Y") / today.strftime("%m") / path.name)).replace("\\", "/")
        mirror_path = DATA_DIR / relative_path
        if mirror_path.resolve() != path.resolve():
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(safe_content, bytes):
                mirror_path.write_bytes(safe_content)
            else:
                mirror_path.write_text(str(safe_content), encoding="utf-8")
        record = {
            "id": artifact_id,
            "kind": kind,
            "relative_path": relative_path,
            "absolute_path": str(path),
            "sha256": file_sha256(path),
            "size": path.stat().st_size,
            "content_type": content_type_for_suffix(safe_suffix),
            "metadata": SensitiveDataGuard.sanitize_for_persist(metadata or {}),
            "created_at": utc_now(),
        }
        return self.upsert_record("artifact", record, status="READY")

    def audit_event(self, action: str, object_type: str, object_id: str, payload: dict | None = None) -> dict:
        with self._lock, self.connect() as conn:
            event = self.audit(conn, action, object_type, object_id, payload or {})
            conn.commit()
        return event

    def audit(
        self,
        conn: sqlite3.Connection,
        action: str,
        object_type: str,
        object_id: str,
        payload: dict,
    ) -> dict:
        created_at = utc_now()
        safe_payload = dict(payload)
        correlation_id = AUDIT_CORRELATION_ID.get()
        if correlation_id:
            safe_payload.setdefault("correlation_id", correlation_id)
        conn.execute(
            """
            INSERT INTO audit_event(actor, action, object_type, object_id, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("local-user", action, object_type, object_id, json.dumps(SensitiveDataGuard.sanitize_for_persist(safe_payload), ensure_ascii=False), created_at),
        )
        seq = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {
            "seq": seq,
            "actor": "local-user",
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "created_at": created_at,
        }

    def scan_event(self, assessment_id: str, event_type: str, payload: dict, job_id: str | None = None) -> dict:
        created_at = utc_now()
        safe_payload = SensitiveDataGuard.sanitize_for_persist(payload)
        SensitiveDataGuard.assert_safe_to_persist(safe_payload)
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_event(assessment_id, job_id, type, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (assessment_id, job_id, event_type, json.dumps(safe_payload, ensure_ascii=False), created_at),
            )
            seq = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
        return {"seq": seq, "assessment_id": assessment_id, "job_id": job_id, "type": event_type, "payload": safe_payload, "created_at": created_at}

    def database_status(self) -> dict:
        with self.connect() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            table_stats = []
            for row in tables:
                name = row["name"]
                count = conn.execute(f"SELECT COUNT(*) AS c FROM {name}").fetchone()["c"]
                table_stats.append({"name": name, "rows": count})
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()[0]
            busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            wal_checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "path": "data/db/app.db",
            "mode": str(journal_mode).upper(),
            "pragma": {
                "journal_mode": journal_mode,
                "foreign_keys": bool(foreign_keys),
                "busy_timeout": busy_timeout,
                "synchronous": "NORMAL",
            },
            "page_count": page_count,
            "page_size": page_size,
            "sqlite_bytes": page_count * page_size,
            "file_bytes": db_size,
            "wal_checkpoint": list(wal_checkpoint) if wal_checkpoint else [],
            "tables": table_stats,
            "state": "健康",
        }

    def backup_database(self) -> dict:
        backup_dir = DATA_DIR / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        destination = backup_dir / f"app-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.db"
        with self.connect() as source, sqlite3.connect(destination) as target:
            source.backup(target)
        sha256 = file_sha256(destination)
        record = {
            "id": new_id("bak"),
            "relative_path": str(destination.relative_to(DATA_DIR)).replace("\\", "/"),
            "sha256": sha256,
            "size": destination.stat().st_size,
            "schema_version": "4.2.10",
            "created_at": utc_now(),
        }
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO backup_record(id, status, data_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (record["id"], "VERIFIED", json.dumps(record, ensure_ascii=False), record["created_at"], record["created_at"]),
            )
            self.audit(conn, "database.backup", "backup_record", record["id"], record)
            conn.commit()
        return record

    def integrity_check(self) -> dict:
        with self.connect() as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        self.audit_event("database.integrity_check", "database", "app.db", {"result": result})
        return {"result": result, "status": "PASS" if result == "ok" else "FAIL"}

    def checkpoint(self) -> dict:
        with self.connect() as conn:
            result = list(conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())
        self.audit_event("database.checkpoint", "database", "app.db", {"result": result})
        return {"result": result, "status": "DONE"}

    def vacuum(self) -> dict:
        with self.connect() as conn:
            conn.execute("VACUUM")
        self.audit_event("database.vacuum", "database", "app.db", {})
        return {"status": "DONE"}

    def _ensure_table(self, table: str) -> None:
        if table not in ALLOWED_TABLES:
            raise ValueError(f"Unsupported table: {table}")


def load_seed_state() -> dict:
    return json.loads(SEED_PATH.read_text(encoding="utf-8"))


def runtime_empty_seed_state(state: dict) -> dict:
    sanitized = dict(state)
    for key in RUNTIME_SEED_LIST_KEYS:
        sanitized[key] = []
    for key in RUNTIME_SEED_OBJECT_KEYS:
        sanitized[key] = {}
    sanitized["form"] = {
        "adapter": "自动识别",
        "targetPath": "",
        "discoveryPaths": "",
        "snapshotContent": "",
        "assessmentName": "",
        "businessNote": "",
        "redteamTarget": "local-agent-dry-run",
        "redteamCaseId": "",
        "redteamMode": "dry-run",
    }
    sanitized["quickModes"] = [
        mode for mode in state.get("quickModes", []) if isinstance(mode, dict) and mode.get("id") != "fixture"
    ]
    sanitized["completeness"] = completeness_rows()
    sanitized["apiError"] = ""
    sanitized["runtimeMode"] = "api"
    sanitized["planJson"] = json.dumps(
        {
            "adapter": "auto-detect",
            "target": "local-machine",
            "profile": "standard-complete@4.2.10",
            "safe_mode": "local-readonly",
            "remote_analysis": False,
            "mutates_installed_agents": False,
            "stdio_mcp": "per-server-consent",
        },
        ensure_ascii=False,
        indent=2,
    )
    sanitized["ruleYaml"] = "尚未选择规则。请先从规则库创建或加载本地规则。"
    sanitized["scannerManifest"] = "\n".join(
        [
            "apiVersion: assessment.security/v1",
            "kind: ScannerManifest",
            "metadata:",
            "  status: runtime-catalog",
            "spec:",
            "  source: runtime built-ins + SQLite scanner_plugin",
            "  safe_mode: local-readonly",
        ]
    )
    return sanitized


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid4().hex[:8]}"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_record(row: sqlite3.Row) -> dict:
    payload = json.loads(row["data_json"])
    payload.setdefault("id", row["id"])
    payload.setdefault("status", row["status"])
    payload.setdefault("created_at", row["created_at"])
    payload.setdefault("updated_at", row["updated_at"])
    return payload


def content_type_for_suffix(suffix: str) -> str:
    mapping = {
        "html": "text/html; charset=utf-8",
        "json": "application/json; charset=utf-8",
        "csv": "text/csv; charset=utf-8",
        "txt": "text/plain; charset=utf-8",
        "sarif": "application/sarif+json; charset=utf-8",
    }
    return mapping.get(suffix.lower(), "application/octet-stream")


_STORE = AssessmentStore()


def get_store() -> AssessmentStore:
    return _STORE
