"""Agent Security v4.2 — 探针与 OTel 数据持久化层.

结构化表 (不走通用 data_json 模式):
  - probe_event
  - otel_span
  - otel_log
  - otel_metric_point
  - behavior_edge

通用表 (复用 store.upsert_record):
  - probe_adapter
  - probe_install_plan
  - behavior_chain
  - behavior_anomaly
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..security import SensitiveDataGuard

from ..store import AssessmentStore, get_store, new_id, utc_now
from .normalizer import attributes_to_dict
from .redaction import redact_payload


# ── 结构化表 DDL (由 store._create_schema 通过 _OBSERVABILITY_DDL 注入) ──

OBSERVABILITY_DDL = """
CREATE TABLE IF NOT EXISTS probe_event (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    trace_id TEXT,
    span_id TEXT,
    parent_span_id TEXT,
    source_agent TEXT NOT NULL,
    adapter_id TEXT,
    session_id TEXT,
    run_id TEXT,
    turn_id TEXT,
    tool_call_id TEXT,
    tool_name TEXT,
    tool_type TEXT,
    mcp_server TEXT,
    mcp_tool TEXT,
    mcp_transport TEXT,
    phase TEXT,
    status TEXT,
    duration_ms INTEGER,
    input_size INTEGER,
    output_size INTEGER,
    input_hash TEXT,
    output_hash TEXT,
    redaction_status TEXT NOT NULL DEFAULT 'not_required',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_labels_json TEXT NOT NULL DEFAULT '[]',
    error_type TEXT,
    error_message_redacted TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    hash_chain_prev TEXT,
    hash_chain TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS otel_span (
    span_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_span_id TEXT,
    name TEXT NOT NULL,
    kind TEXT,
    start_time TEXT,
    end_time TEXT,
    duration_ms INTEGER,
    status_code TEXT,
    status_message TEXT,
    resource_json TEXT NOT NULL DEFAULT '{}',
    scope_json TEXT NOT NULL DEFAULT '{}',
    attrs_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS otel_log (
    id TEXT PRIMARY KEY,
    trace_id TEXT,
    span_id TEXT,
    timestamp TEXT NOT NULL,
    severity_text TEXT,
    body_redacted TEXT,
    resource_json TEXT NOT NULL DEFAULT '{}',
    attrs_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS otel_metric_point (
    id TEXT PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    value REAL,
    unit TEXT,
    resource_json TEXT NOT NULL DEFAULT '{}',
    attrs_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS behavior_edge (
    id TEXT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    from_event_id TEXT NOT NULL,
    to_event_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    latency_ms INTEGER,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_probe_event_time ON probe_event(timestamp);
CREATE INDEX IF NOT EXISTS idx_probe_event_trace ON probe_event(trace_id);
CREATE INDEX IF NOT EXISTS idx_probe_event_session ON probe_event(session_id);
CREATE INDEX IF NOT EXISTS idx_probe_event_tool ON probe_event(tool_name);
CREATE INDEX IF NOT EXISTS idx_probe_event_risk ON probe_event(risk_score);
CREATE INDEX IF NOT EXISTS idx_otel_span_trace ON otel_span(trace_id);
CREATE INDEX IF NOT EXISTS idx_otel_span_created ON otel_span(created_at);
CREATE INDEX IF NOT EXISTS idx_otel_log_trace ON otel_log(trace_id);
CREATE INDEX IF NOT EXISTS idx_otel_log_created ON otel_log(created_at);
CREATE INDEX IF NOT EXISTS idx_otel_metric_created ON otel_metric_point(created_at);
CREATE INDEX IF NOT EXISTS idx_behavior_edge_chain ON behavior_edge(chain_id);
"""


def migrate_observability(store: AssessmentStore) -> None:
    """在现有数据库上执行 v4.2 结构化表迁移."""
    with store.connect() as conn:
        for statement in OBSERVABILITY_DDL.split(";"):
            stmt = statement.strip()
            if stmt:
                conn.execute(stmt)
        conn.commit()


# ── Probe Event CRUD ──────────────────────────────────────────

def _otel_nano_to_iso(value: Any) -> str | None:
    try:
        nano = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(nano / 1_000_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _json_loads_or_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _dedup_id(prefix: str, value: dict[str, Any]) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}_{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:24]}"


def _redacted_json(value: Any) -> str:
    return json.dumps(SensitiveDataGuard.sanitize_for_persist(value), ensure_ascii=False)


# ── Probe Event CRUD ──────────────────────────────────────────

_PROBE_EVENT_COLUMNS = (
    "event_id", "event_type", "timestamp", "trace_id", "span_id", "parent_span_id",
    "source_agent", "adapter_id", "session_id", "run_id", "turn_id", "tool_call_id",
    "tool_name", "tool_type", "mcp_server", "mcp_tool", "mcp_transport", "phase", "status",
    "duration_ms", "input_size", "output_size", "input_hash", "output_hash", "redaction_status",
    "risk_score", "risk_labels_json", "error_type", "error_message_redacted", "payload_json",
    "hash_chain_prev", "hash_chain", "created_at",
)
_PROBE_EVENT_INSERT_SQL = f"""INSERT OR REPLACE INTO probe_event(
    {', '.join(_PROBE_EVENT_COLUMNS)}
) VALUES ({','.join('?' for _ in _PROBE_EVENT_COLUMNS)})"""


def _prepare_probe_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize and redact an event before it crosses the persistence boundary."""
    event = SensitiveDataGuard.sanitize_for_persist(event)
    if not isinstance(event, dict):
        raise TypeError("probe event must be an object")
    now = utc_now()
    return {
        "event_id": event.get("event_id", _dedup_id("evt", event)),
        "event_type": event.get("event_type", "unknown"),
        "timestamp": event.get("timestamp", now),
        "trace_id": event.get("trace_id"),
        "span_id": event.get("span_id"),
        "parent_span_id": event.get("parent_span_id"),
        "source_agent": event.get("source_agent", "unknown"),
        "adapter_id": event.get("adapter_id"),
        "session_id": event.get("session_id"),
        "run_id": event.get("run_id"),
        "turn_id": event.get("turn_id"),
        "tool_call_id": event.get("tool_call_id"),
        "tool_name": event.get("tool_name"),
        "tool_type": event.get("tool_type"),
        "mcp_server": event.get("mcp_server"),
        "mcp_tool": event.get("mcp_tool"),
        "mcp_transport": event.get("mcp_transport"),
        "phase": event.get("phase"),
        "status": event.get("status"),
        "duration_ms": event.get("duration_ms"),
        "input_size": event.get("input_size"),
        "output_size": event.get("output_size"),
        "input_hash": event.get("input_hash"),
        "output_hash": event.get("output_hash"),
        "redaction_status": event.get("redaction_status", "not_required"),
        "risk_score": event.get("risk_score", 0),
        "risk_labels_json": _redacted_json(event.get("risk_labels", [])),
        "error_type": event.get("error_type"),
        "error_message_redacted": SensitiveDataGuard.redact_text(str(event.get("error_message_redacted") or "")),
        "payload_json": _redacted_json(event.get("payload", {})),
        "hash_chain_prev": event.get("hash_chain_prev"),
        "hash_chain": event.get("hash_chain"),
        "created_at": now,
    }


def insert_probe_event(store: AssessmentStore, event: dict[str, Any]) -> dict[str, Any]:
    """写入一条规范化 probe_event."""
    row = _prepare_probe_event(event)
    with store.connect() as conn:
        conn.execute(_PROBE_EVENT_INSERT_SQL, tuple(row[column] for column in _PROBE_EVENT_COLUMNS))
        conn.commit()
    return row


def insert_events_batch(store: AssessmentStore, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Redact and persist a receiver batch in one SQLite transaction."""
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, event in enumerate(events):
        try:
            rows.append(_prepare_probe_event(event))
        except Exception as exc:
            errors.append(f"event[{index}]: {type(exc).__name__}")
    if rows:
        with store.connect() as conn:
            conn.executemany(
                _PROBE_EVENT_INSERT_SQL,
                (tuple(row[column] for column in _PROBE_EVENT_COLUMNS) for row in rows),
            )
            conn.commit()
    return {"accepted": len(rows), "rejected": len(errors), "errors": errors}


def list_probe_events(
    store: AssessmentStore,
    *,
    source_agent: str | None = None,
    session_id: str | None = None,
    event_type: str | None = None,
    trace_id: str | None = None,
    risk_min: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """查询 probe_event, 支持多条件过滤."""
    clauses: list[str] = ["1=1"]
    params: list[Any] = []
    if source_agent:
        clauses.append("source_agent=?")
        params.append(source_agent)
    if session_id:
        clauses.append("session_id=?")
        params.append(session_id)
    if event_type:
        clauses.append("event_type=?")
        params.append(event_type)
    if trace_id:
        clauses.append("trace_id=?")
        params.append(trace_id)
    if risk_min is not None:
        clauses.append("risk_score>=?")
        params.append(risk_min)
    limit = max(1, min(limit, 500))
    query = f"SELECT * FROM probe_event WHERE {' AND '.join(clauses)} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    with store.connect() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [_decode_probe_event(r) for r in rows]


def get_probe_event(store: AssessmentStore, event_id: str) -> dict[str, Any] | None:
    """按 event_id 获取单条事件."""
    with store.connect() as conn:
        row = conn.execute("SELECT * FROM probe_event WHERE event_id=?", (event_id,)).fetchone()
    return _decode_probe_event(row) if row else None


def _decode_probe_event(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["risk_labels"] = json.loads(d.get("risk_labels_json") or "[]")
    except Exception:
        d["risk_labels"] = []
    try:
        d["payload"] = json.loads(d.get("payload_json") or "{}")
    except Exception:
        d["payload"] = {}
    d.pop("risk_labels_json", None)
    d.pop("payload_json", None)
    return d


# ── OTel Span CRUD ────────────────────────────────────────────

_OTEL_SPAN_COLUMNS = (
    "span_id", "trace_id", "parent_span_id", "name", "kind", "start_time", "end_time",
    "duration_ms", "status_code", "status_message", "resource_json", "scope_json",
    "attrs_json", "created_at",
)
_OTEL_SPAN_INSERT_SQL = f"""INSERT OR REPLACE INTO otel_span(
    {', '.join(_OTEL_SPAN_COLUMNS)}
) VALUES ({','.join('?' for _ in _OTEL_SPAN_COLUMNS)})"""


def _prepare_otel_span(span: dict[str, Any]) -> dict[str, Any]:
    span = SensitiveDataGuard.sanitize_for_persist(span)
    if not isinstance(span, dict):
        raise TypeError("OTel span must be an object")
    attrs = attributes_to_dict(span.get("attributes"))
    resource = span.get("resource", {})
    scope = span.get("scope", {})
    now = utc_now()
    return {
        "span_id": span.get("spanId") or span.get("span_id") or _dedup_id("span", span),
        "trace_id": span.get("traceId") or span.get("trace_id", ""),
        "parent_span_id": span.get("parentSpanId") or span.get("parent_span_id"),
        "name": SensitiveDataGuard.redact_text(str(span.get("name") or "unknown")),
        "kind": span.get("kind"),
        "start_time": span.get("startTime") or span.get("start_time") or _otel_nano_to_iso(span.get("startTimeUnixNano")),
        "end_time": span.get("endTime") or span.get("end_time") or _otel_nano_to_iso(span.get("endTimeUnixNano")),
        "duration_ms": span.get("duration_ms") or span.get("durationMs"),
        "status_code": span.get("status", {}).get("code") if isinstance(span.get("status"), dict) else span.get("status_code"),
        "status_message": SensitiveDataGuard.redact_text(str(span.get("status", {}).get("message") if isinstance(span.get("status"), dict) else span.get("status_message") or "")),
        "resource_json": _redacted_json(resource),
        "scope_json": _redacted_json(scope),
        "attrs_json": _redacted_json(attrs),
        "created_at": now,
    }


def insert_otel_span(store: AssessmentStore, span: dict[str, Any]) -> dict[str, Any]:
    row = _prepare_otel_span(span)
    with store.connect() as conn:
        conn.execute(_OTEL_SPAN_INSERT_SQL, tuple(row[column] for column in _OTEL_SPAN_COLUMNS))
        conn.commit()
    return row


def insert_otel_spans_batch(store: AssessmentStore, spans: list[dict[str, Any]]) -> int:
    rows = [_prepare_otel_span(span) for span in spans]
    if rows:
        with store.connect() as conn:
            conn.executemany(
                _OTEL_SPAN_INSERT_SQL,
                (tuple(row[column] for column in _OTEL_SPAN_COLUMNS) for row in rows),
            )
            conn.commit()
    return len(rows)


# ── Behavior Chain ────────────────────────────────────────────

_OTEL_LOG_COLUMNS = (
    "id", "trace_id", "span_id", "timestamp", "severity_text", "body_redacted",
    "resource_json", "attrs_json", "created_at",
)
_OTEL_LOG_INSERT_SQL = f"""INSERT OR REPLACE INTO otel_log(
    {', '.join(_OTEL_LOG_COLUMNS)}
) VALUES ({','.join('?' for _ in _OTEL_LOG_COLUMNS)})"""


def _prepare_otel_log(log: dict[str, Any]) -> dict[str, Any]:
    log = SensitiveDataGuard.sanitize_for_persist(log)
    if not isinstance(log, dict):
        raise TypeError("OTel log must be an object")
    attrs = attributes_to_dict(log.get("attributes"))
    now = utc_now()
    return {
        "id": log.get("id") or _dedup_id("log", log),
        "trace_id": log.get("traceId") or log.get("trace_id"),
        "span_id": log.get("spanId") or log.get("span_id"),
        "timestamp": _otel_nano_to_iso(log.get("timeUnixNano")) or log.get("timestamp") or now,
        "severity_text": log.get("severityText") or log.get("severity_text"),
        "body_redacted": SensitiveDataGuard.redact_text(str(log.get("body_redacted") or redact_payload({"body": log.get("body")}).get("body") or "")),
        "resource_json": _redacted_json(log.get("resource", {})),
        "attrs_json": _redacted_json(attrs),
        "created_at": now,
    }


def insert_otel_log(store: AssessmentStore, log: dict[str, Any]) -> dict[str, Any]:
    row = _prepare_otel_log(log)
    with store.connect() as conn:
        conn.execute(_OTEL_LOG_INSERT_SQL, tuple(row[column] for column in _OTEL_LOG_COLUMNS))
        conn.commit()
    return row


def insert_otel_logs_batch(store: AssessmentStore, logs: list[dict[str, Any]]) -> int:
    rows = [_prepare_otel_log(log) for log in logs]
    if rows:
        with store.connect() as conn:
            conn.executemany(
                _OTEL_LOG_INSERT_SQL,
                (tuple(row[column] for column in _OTEL_LOG_COLUMNS) for row in rows),
            )
            conn.commit()
    return len(rows)


_OTEL_METRIC_COLUMNS = (
    "id", "metric_name", "metric_type", "timestamp", "value", "unit", "resource_json",
    "attrs_json", "created_at",
)
_OTEL_METRIC_INSERT_SQL = f"""INSERT OR REPLACE INTO otel_metric_point(
    {', '.join(_OTEL_METRIC_COLUMNS)}
) VALUES ({','.join('?' for _ in _OTEL_METRIC_COLUMNS)})"""


def _prepare_otel_metric_point(point: dict[str, Any]) -> dict[str, Any]:
    point = SensitiveDataGuard.sanitize_for_persist(point)
    if not isinstance(point, dict):
        raise TypeError("OTel metric point must be an object")
    attrs = attributes_to_dict(point.get("attributes"))
    now = utc_now()
    return {
        "id": point.get("id") or _dedup_id("metric", point),
        "metric_name": SensitiveDataGuard.redact_text(str(point.get("metric_name") or point.get("name") or "unknown")),
        "metric_type": point.get("metric_type") or point.get("type") or "gauge",
        "timestamp": _otel_nano_to_iso(point.get("timeUnixNano")) or _otel_nano_to_iso(point.get("timestamp")) or point.get("timestamp") or now,
        "value": point.get("value"),
        "unit": point.get("unit"),
        "resource_json": _redacted_json(point.get("resource", {})),
        "attrs_json": _redacted_json(attrs),
        "created_at": now,
    }


def insert_otel_metric_point(store: AssessmentStore, point: dict[str, Any]) -> dict[str, Any]:
    row = _prepare_otel_metric_point(point)
    with store.connect() as conn:
        conn.execute(_OTEL_METRIC_INSERT_SQL, tuple(row[column] for column in _OTEL_METRIC_COLUMNS))
        conn.commit()
    return row


def insert_otel_metric_points_batch(store: AssessmentStore, points: list[dict[str, Any]]) -> int:
    rows = [_prepare_otel_metric_point(point) for point in points]
    if rows:
        with store.connect() as conn:
            conn.executemany(
                _OTEL_METRIC_INSERT_SQL,
                (tuple(row[column] for column in _OTEL_METRIC_COLUMNS) for row in rows),
            )
            conn.commit()
    return len(rows)


# ── Behavior Chain ────────────────────────────────────────────

def create_behavior_chain(store: AssessmentStore, chain: dict[str, Any]) -> dict[str, Any]:
    """创建一条行为链 (通用表)."""
    return store.upsert_record("behavior_chain", {
        **chain,
        "chain_id": chain.get("chain_id", new_id("bch")),
        "status": chain.get("status", "open"),
    }, status=chain.get("status", "open"))


def create_behavior_anomaly(store: AssessmentStore, anomaly: dict[str, Any]) -> dict[str, Any]:
    """创建一条异常记录 (通用表)."""
    return store.upsert_record("behavior_anomaly", {
        **anomaly,
        "id": anomaly.get("id", new_id("ano")),
        "status": anomaly.get("status", "open"),
    }, status=anomaly.get("status", "open"))


# ── 统计 / 摘要 ────────────────────────────────────────────────

def probe_event_stats(store: AssessmentStore) -> dict[str, Any]:
    """获取事件统计: 总数、按类型/agent 分组、最近时间."""
    with store.connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM probe_event").fetchone()["c"]
        by_type = {
            r["event_type"]: r["c"]
            for r in conn.execute("SELECT event_type, COUNT(*) AS c FROM probe_event GROUP BY event_type ORDER BY c DESC LIMIT 20").fetchall()
        }
        by_agent = {
            r["source_agent"]: r["c"]
            for r in conn.execute("SELECT source_agent, COUNT(*) AS c FROM probe_event GROUP BY source_agent ORDER BY c DESC").fetchall()
        }
        by_risk = {
            "high": conn.execute("SELECT COUNT(*) AS c FROM probe_event WHERE risk_score>=70").fetchone()["c"],
            "medium": conn.execute("SELECT COUNT(*) AS c FROM probe_event WHERE risk_score>=40 AND risk_score<70").fetchone()["c"],
            "low": conn.execute("SELECT COUNT(*) AS c FROM probe_event WHERE risk_score<40").fetchone()["c"],
        }
        recent = conn.execute("SELECT timestamp FROM probe_event ORDER BY timestamp DESC LIMIT 1").fetchone()
    return {
        "total_events": total,
        "by_event_type": by_type,
        "by_agent": by_agent,
        "by_risk": by_risk,
        "last_event_at": recent["timestamp"] if recent else None,
    }


def probe_adapter_health(store: AssessmentStore) -> list[dict[str, Any]]:
    """获取探针健康状态列表."""
    adapters = store.list_records("probe_adapter")
    result = []
    for a in adapters:
        result.append({
            "adapter_id": a.get("id"),
            "agent_type": a.get("agent_type"),
            "enabled": bool(a.get("enabled", False)),
            "last_heartbeat_at": a.get("last_heartbeat_at"),
            "dropped_events": a.get("dropped_events", 0),
            "status": a.get("status", "unknown"),
        })
    return result
