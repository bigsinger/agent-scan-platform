from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .security import SensitiveDataGuard
from .store import GENERIC_TABLES, AssessmentStore, decode_record, file_sha256, utc_now


DEFAULT_RETENTION_DAYS = {
    "tasks": 180,
    "events": 90,
    "findings": 365,
    "evidence": 365,
    "reports": 365,
    "observability": 30,
    "artifacts": 365,
}

RETENTION_TABLES = {
    "tasks": (
        "assessment", "assessment_scope", "task", "task_stage", "scan_stage",
        "scan_job", "process_execution", "scanner_run", "test_run", "retest", "retest_run",
    ),
    "events": ("task_event", "scan_event"),
    "findings": (
        "finding", "finding_instance", "finding_suppression", "attack_path",
        "attack_path_node", "attack_path_edge", "policy_draft",
    ),
    "evidence": ("evidence",),
    "reports": ("report",),
    "observability": (
        "probe_event", "otel_span", "otel_log", "otel_metric_point", "behavior_edge",
        "behavior_chain", "behavior_anomaly",
    ),
}

STRUCTURED_KEYS = {
    "scan_event": "seq",
    "probe_event": "event_id",
    "otel_span": "span_id",
    "otel_log": "id",
    "otel_metric_point": "id",
    "behavior_edge": "id",
}


def _state_root(store: AssessmentStore) -> Path:
    configured = os.environ.get("ASSESSMENT_STATE_ROOT")
    if configured:
        return Path(configured).resolve()
    return (store.db_path.parent.parent if store.db_path.parent.name.lower() == "db" else store.db_path.parent).resolve()


def _artifact_root(store: AssessmentStore) -> Path:
    configured = os.environ.get("ASSESSMENT_ARTIFACT_ROOT")
    return Path(configured).resolve() if configured else (_state_root(store) / "artifacts").resolve()


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _retention_candidates(
    store: AssessmentStore, policies: dict[str, int]
) -> tuple[dict[str, list[str | int]], dict[str, dict[str, Any]]]:
    now = datetime.now(timezone.utc)
    candidates: dict[str, list[str | int]] = {}
    summary: dict[str, dict[str, Any]] = {}
    with store.connect() as conn:
        for category, tables in RETENTION_TABLES.items():
            cutoff = now - timedelta(days=policies[category])
            category_count = 0
            table_counts: dict[str, int] = {}
            for table in tables:
                if not _table_exists(conn, table):
                    continue
                key = STRUCTURED_KEYS.get(table, "id")
                if table in GENERIC_TABLES:
                    rows = conn.execute(
                        f'SELECT "{key}" AS record_key, COALESCE(updated_at, created_at) AS record_time FROM "{table}"'
                    ).fetchall()
                else:
                    rows = conn.execute(
                        f'SELECT "{key}" AS record_key, created_at AS record_time FROM "{table}"'
                    ).fetchall()
                old = [row["record_key"] for row in rows if (_parse_time(row["record_time"]) or now) < cutoff]
                if old:
                    candidates[table] = old
                    table_counts[table] = len(old)
                    category_count += len(old)
            summary[category] = {
                "retention_days": policies[category],
                "candidate_count": category_count,
                "tables": table_counts,
            }
    return candidates, summary


def _normalized_policies(values: dict[str, Any] | None) -> dict[str, int]:
    values = values or {}
    policies: dict[str, int] = {}
    for category, default in DEFAULT_RETENTION_DAYS.items():
        try:
            days = int(values.get(category, default))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"retention value for {category} must be an integer") from exc
        if days < 1 or days > 3650:
            raise ValueError(f"retention value for {category} must be between 1 and 3650")
        policies[category] = days
    return policies


def retention_plan(store: AssessmentStore, values: dict[str, Any] | None = None) -> dict[str, Any]:
    policies = _normalized_policies(values)
    candidates, summary = _retention_candidates(store, policies)
    canonical = json.dumps(
        {"policies": policies, "candidates": candidates},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "schema": "agent-security-retention-plan@4.2.10",
        "plan_id": "ret_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24],
        "generated_at": utc_now(),
        "mode": "DRY_RUN",
        "policies": policies,
        "summary": summary,
        "candidate_count": sum(len(items) for items in candidates.values()),
        "candidate_tables": {table: len(items) for table, items in candidates.items()},
        "mutates_installed_agents": False,
        "stdio_mcp_started": False,
    }


def _backup_database(store: AssessmentStore, operation: str) -> Path:
    root = _state_root(store)
    backup_dir = root / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    destination = backup_dir / f"{operation}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.db"
    with store.connect() as source, sqlite3.connect(destination) as target:
        source.backup(target)
    return destination


def _purge_state_records(store: AssessmentStore, deleted_ids: set[str]) -> None:
    if not deleted_ids:
        return
    state = store.get_state()
    changed = False
    for key, value in list(state.items()):
        if isinstance(value, list):
            filtered = [item for item in value if not (isinstance(item, dict) and str(item.get("id")) in deleted_ids)]
            if len(filtered) != len(value):
                state[key] = filtered
                changed = True
        elif isinstance(value, dict) and str(value.get("id")) in deleted_ids:
            state[key] = {}
            changed = True
    if changed:
        store.save_state(state)


def apply_retention(
    store: AssessmentStore, values: dict[str, Any] | None, plan_id: str
) -> dict[str, Any]:
    plan = retention_plan(store, values)
    if not plan_id or plan_id != plan["plan_id"]:
        raise ValueError("retention plan changed; generate a new dry-run plan before apply")
    policies = plan["policies"]
    candidates, _ = _retention_candidates(store, policies)
    backup = _backup_database(store, "retention")
    deleted_ids: set[str] = set()
    with store.connect() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            for table, ids in candidates.items():
                key = STRUCTURED_KEYS.get(table, "id")
                for offset in range(0, len(ids), 500):
                    chunk = ids[offset : offset + 500]
                    placeholders = ",".join("?" for _ in chunk)
                    conn.execute(f'DELETE FROM "{table}" WHERE "{key}" IN ({placeholders})', tuple(chunk))
                deleted_ids.update(str(value) for value in ids)
            store.audit(
                conn,
                "maintenance.retention.apply",
                "database",
                plan["plan_id"],
                {"candidate_tables": plan["candidate_tables"], "backup_sha256": file_sha256(backup)},
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    _purge_state_records(store, deleted_ids)
    gc = artifact_gc_plan(store, min_age_days=policies["artifacts"])
    gc_result = apply_artifact_gc(store, gc["plan_id"], policies["artifacts"], backup_database=False)
    return {
        **plan,
        "mode": "APPLY",
        "status": "COMPLETED",
        "deleted_count": len(deleted_ids),
        "backup": f"<state>/backups/{backup.name}",
        "backup_sha256": file_sha256(backup),
        "artifact_gc": gc_result,
    }


def _artifact_records(store: AssessmentStore) -> list[dict[str, Any]]:
    with store.connect() as conn:
        rows = conn.execute("SELECT * FROM artifact ORDER BY created_at DESC").fetchall()
    return [decode_record(row) for row in rows]


def _collect_artifact_references(store: AssessmentStore, artifact_ids: set[str]) -> set[str]:
    references: set[str] = set()

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, str(child_key))
        elif isinstance(value, list):
            for child in value:
                walk(child, key)
        elif isinstance(value, str) and "artifact" in key.lower() and value in artifact_ids:
            references.add(value)

    with store.connect() as conn:
        for table in GENERIC_TABLES:
            if table == "artifact" or not _table_exists(conn, table):
                continue
            for row in conn.execute(f'SELECT data_json FROM "{table}"').fetchall():
                try:
                    walk(json.loads(row["data_json"]))
                except (TypeError, ValueError):
                    continue
    return references


def _artifact_paths(store: AssessmentStore, record: dict[str, Any]) -> list[Path]:
    root = _artifact_root(store)
    state_root = _state_root(store)
    paths: list[Path] = []
    relative = str(record.get("relative_path") or "").replace("\\", "/").lstrip("/")
    if relative:
        candidate = (state_root / relative).resolve()
        if candidate == root or root in candidate.parents:
            paths.append(candidate)
    absolute = record.get("absolute_path")
    if absolute:
        candidate = Path(str(absolute)).resolve()
        if (candidate == root or root in candidate.parents) and candidate not in paths:
            paths.append(candidate)
    return paths


def artifact_integrity(store: AssessmentStore) -> dict[str, Any]:
    records = _artifact_records(store)
    missing: list[str] = []
    mismatched: list[str] = []
    verified = 0
    for record in records:
        paths = _artifact_paths(store, record)
        existing = next((path for path in paths if path.is_file()), None)
        if not existing:
            missing.append(str(record.get("id")))
            continue
        expected = str(record.get("sha256") or "").lower()
        if not expected or file_sha256(existing) != expected:
            mismatched.append(str(record.get("id")))
            continue
        verified += 1
    status = "PASS" if not missing and not mismatched else "FAIL"
    return {
        "schema": "agent-security-artifact-integrity@4.2.10",
        "status": status,
        "records": len(records),
        "verified": verified,
        "missing_count": len(missing),
        "mismatch_count": len(mismatched),
        "missing_ids": missing[:50],
        "mismatch_ids": mismatched[:50],
        "mutates_installed_agents": False,
    }


def artifact_gc_plan(store: AssessmentStore, min_age_days: int = 30) -> dict[str, Any]:
    if min_age_days < 1 or min_age_days > 3650:
        raise ValueError("artifact GC age must be between 1 and 3650 days")
    records = _artifact_records(store)
    artifact_ids = {str(record.get("id")) for record in records}
    references = _collect_artifact_references(store, artifact_ids)
    cutoff = datetime.now(timezone.utc) - timedelta(days=min_age_days)
    candidates = sorted(
        str(record.get("id"))
        for record in records
        if str(record.get("id")) not in references
        and (_parse_time(record.get("created_at")) or datetime.now(timezone.utc)) < cutoff
    )
    canonical = json.dumps(
        {"min_age_days": min_age_days, "candidate_ids": candidates}, separators=(",", ":"), sort_keys=True
    )
    return {
        "schema": "agent-security-artifact-gc-plan@4.2.10",
        "plan_id": "agc_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24],
        "mode": "DRY_RUN",
        "min_age_days": min_age_days,
        "records": len(records),
        "referenced": len(references),
        "candidate_count": len(candidates),
        "candidate_ids": candidates[:100],
        "mutates_installed_agents": False,
    }


def apply_artifact_gc(
    store: AssessmentStore,
    plan_id: str,
    min_age_days: int = 30,
    *,
    backup_database: bool = True,
) -> dict[str, Any]:
    plan = artifact_gc_plan(store, min_age_days)
    if not plan_id or plan_id != plan["plan_id"]:
        raise ValueError("artifact GC plan changed; generate a new dry-run plan before apply")
    candidate_ids = set(plan["candidate_ids"])
    # The public plan caps displayed IDs; recompute the full set for apply.
    records = _artifact_records(store)
    references = _collect_artifact_references(store, {str(record.get("id")) for record in records})
    cutoff = datetime.now(timezone.utc) - timedelta(days=min_age_days)
    candidates = [
        record for record in records
        if str(record.get("id")) not in references
        and (_parse_time(record.get("created_at")) or datetime.now(timezone.utc)) < cutoff
    ]
    candidate_ids = {str(record.get("id")) for record in candidates}
    backup = _backup_database(store, "artifact-gc") if backup_database else None
    quarantine = _state_root(store) / "backups" / f"artifact-gc-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    moved: list[tuple[Path, Path]] = []
    manifest: list[dict[str, Any]] = []
    try:
        for record in candidates:
            for source in _artifact_paths(store, record):
                if not source.is_file():
                    continue
                destination = quarantine / str(record.get("id")) / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source), str(destination))
                moved.append((source, destination))
                manifest.append({
                    "artifact_id": record.get("id"),
                    "file": source.name,
                    "sha256": file_sha256(destination),
                    "size": destination.stat().st_size,
                })
        with store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for artifact_id in candidate_ids:
                conn.execute("DELETE FROM artifact WHERE id=?", (artifact_id,))
            store.audit(
                conn,
                "maintenance.artifact_gc.apply",
                "artifact",
                plan["plan_id"],
                {"deleted_records": len(candidate_ids), "quarantined_files": len(moved)},
            )
            conn.commit()
    except Exception:
        for source, destination in reversed(moved):
            if destination.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(destination), str(source))
        raise
    if manifest:
        quarantine.mkdir(parents=True, exist_ok=True)
        safe_manifest = SensitiveDataGuard.sanitize_for_persist({"files": manifest})
        (quarantine / "manifest.json").write_text(json.dumps(safe_manifest, indent=2), encoding="utf-8")
    return {
        **plan,
        "mode": "APPLY",
        "status": "COMPLETED",
        "deleted_records": len(candidate_ids),
        "quarantined_files": len(moved),
        "backup": f"<state>/backups/{backup.name}" if backup else None,
        "quarantine": f"<state>/backups/{quarantine.name}" if manifest else None,
    }
