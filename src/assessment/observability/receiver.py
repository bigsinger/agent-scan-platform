"""Agent Security v4.2.10 OTLP/HTTP JSON side-channel receiver.

独立启动: python -m assessment.observability.receiver --host 127.0.0.1 --port 4318
集成启动: 通过 uvicorn 挂载 FastAPI 子应用.

Only OTLP/HTTP JSON is supported. Protobuf and OTLP/gRPC are intentionally not
advertised. Prompt/result bodies are redacted before persistence.
"""

from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import re
import threading
import time
import zlib
from datetime import datetime, timezone
from typing import Any

import uvicorn

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
except ImportError:
    FastAPI = None  # type: ignore

from ..store import get_store
from .storage import (
    insert_events_batch,
    insert_otel_logs_batch,
    insert_otel_metric_points_batch,
    insert_otel_spans_batch,
    migrate_observability,
    probe_event_stats,
    probe_adapter_health,
)
from .normalizer import attributes_to_dict, span_to_probe_event, log_to_probe_event
from .redaction import redact_payload

logger = logging.getLogger(__name__)

MAX_REQUEST_BYTES = 1 * 1024 * 1024
MAX_BATCH_ITEMS = 10_000
MAX_EVENT_BYTES = 64 * 1024
MAX_REQUESTS_PER_MINUTE = 120
MAX_INFLIGHT_REQUESTS = 8
OTLP_JSON_CONTENT_TYPES = {"application/json", "application/x-json"}
_TRACE_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")

_rate_lock = threading.Lock()
_rate_windows: dict[str, list[float]] = {}
_inflight = threading.BoundedSemaphore(MAX_INFLIGHT_REQUESTS)


class ReceiverError(ValueError):
    def __init__(self, status_code: int, code: str, message: str, rejected_field: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.rejected_field = rejected_field


def _receiver_error(status_code: int, code: str, message: str, rejected_field: str) -> JSONResponse:
    _receiver_state["rejected"] += 1
    return JSONResponse(
        {
            "partialSuccess": {rejected_field: 0},
            "error": {"code": code, "message": message},
        },
        status_code=status_code,
    )


def _is_loopback(host: str | None) -> bool:
    value = (host or "").strip().lower()
    return value in {"127.0.0.1", "::1", "localhost", "testclient", "testserver"}


def _require_loopback_or_token(request: Request) -> None:
    if _is_loopback(request.client.host if request.client else None):
        return
    expected = os.environ.get("ASSESSMENT_OTEL_TOKEN", "")
    supplied = request.headers.get("X-OTel-Token", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        raise ReceiverError(401, "OTEL_AUTH_REQUIRED", "receiver requires a token for non-loopback clients", "rejected")


def _check_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _rate_lock:
        window = [then for then in _rate_windows.get(client, []) if now - then < 60]
        if len(window) >= MAX_REQUESTS_PER_MINUTE:
            _rate_windows[client] = window
            raise ReceiverError(429, "OTEL_RATE_LIMITED", "receiver rate limit exceeded", "rejected")
        window.append(now)
        _rate_windows[client] = window


async def _read_otlp_json(request: Request) -> dict[str, Any]:
    _require_loopback_or_token(request)
    _check_rate_limit(request)
    if not _inflight.acquire(blocking=False):
        raise ReceiverError(429, "OTEL_BACKPRESSURE", "receiver is at capacity; retry later", "rejected")
    try:
        content_type = request.headers.get("content-type", "application/json").split(";", 1)[0].strip().lower()
        if content_type not in OTLP_JSON_CONTENT_TYPES:
            raise ReceiverError(415, "OTEL_UNSUPPORTED_CONTENT_TYPE", "only OTLP/HTTP JSON is supported", "rejected")
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                parsed_length = int(content_length)
            except ValueError as exc:
                raise ReceiverError(400, "OTEL_INVALID_CONTENT_LENGTH", "invalid content length", "rejected") from exc
            if parsed_length > MAX_REQUEST_BYTES:
                raise ReceiverError(413, "OTEL_REQUEST_TOO_LARGE", "request body exceeds receiver limit", "rejected")
        raw = await request.body()
        if len(raw) > MAX_REQUEST_BYTES:
            raise ReceiverError(413, "OTEL_REQUEST_TOO_LARGE", "request body exceeds receiver limit", "rejected")
        if request.headers.get("content-encoding", "").lower() == "gzip":
            try:
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                expanded = decompressor.decompress(raw, MAX_REQUEST_BYTES + 1)
                if len(expanded) > MAX_REQUEST_BYTES or decompressor.unconsumed_tail:
                    raise ReceiverError(413, "OTEL_REQUEST_TOO_LARGE", "decompressed request body exceeds receiver limit", "rejected")
                expanded += decompressor.flush(MAX_REQUEST_BYTES + 1 - len(expanded))
                if len(expanded) > MAX_REQUEST_BYTES:
                    raise ReceiverError(413, "OTEL_REQUEST_TOO_LARGE", "decompressed request body exceeds receiver limit", "rejected")
                raw = expanded
            except zlib.error as exc:
                raise ReceiverError(400, "OTEL_INVALID_GZIP", "invalid gzip request body", "rejected") from exc
        if len(raw) > MAX_REQUEST_BYTES:
            raise ReceiverError(413, "OTEL_REQUEST_TOO_LARGE", "request body exceeds receiver limit", "rejected")
        try:
            body = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ReceiverError(400, "OTEL_INVALID_JSON", "invalid OTLP JSON payload", "rejected") from exc
        if not isinstance(body, dict):
            raise ReceiverError(400, "OTEL_INVALID_PAYLOAD", "OTLP JSON payload must be an object", "rejected")
        return body
    finally:
        _inflight.release()


def _validate_identifiers(items: list[dict[str, Any]], kind: str) -> None:
    for item in items:
        if kind in {"trace", "log"}:
            trace_id = item.get("traceId") or item.get("trace_id")
            if trace_id and not _TRACE_ID_RE.fullmatch(str(trace_id)):
                raise ReceiverError(400, "OTEL_INVALID_TRACE_ID", "trace ID must be 32 hexadecimal characters", f"rejected{kind.title()}s")
        span_id = item.get("spanId") or item.get("span_id")
        if span_id and not _SPAN_ID_RE.fullmatch(str(span_id)):
            raise ReceiverError(400, "OTEL_INVALID_SPAN_ID", "span ID must be 16 hexadecimal characters", f"rejected{kind.title()}s")
        for field in ("startTimeUnixNano", "endTimeUnixNano", "timeUnixNano", "observedTimeUnixNano"):
            value = item.get(field)
            if value in {None, ""}:
                continue
            try:
                if int(value) < 0:
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ReceiverError(400, "OTEL_INVALID_TIMESTAMP", f"{field} must be a non-negative integer", f"rejected{kind.title()}s") from exc


def _validate_batch(items: list[dict[str, Any]], kind: str) -> None:
    if len(items) > MAX_BATCH_ITEMS:
        raise ReceiverError(413, "OTEL_BATCH_TOO_LARGE", "OTLP batch exceeds item limit", f"rejected{kind.title()}s")
    for item in items:
        if len(json.dumps(item, ensure_ascii=False, default=str).encode("utf-8")) > MAX_EVENT_BYTES:
            raise ReceiverError(413, "OTEL_EVENT_TOO_LARGE", "OTLP event exceeds item size limit", f"rejected{kind.title()}s")
    _validate_identifiers(items, kind)


# ── 运行状态 ──────────────────────────────────────────────────
_receiver_state: dict[str, Any] = {
    "started_at": None,
    "accepted_traces": 0,
    "accepted_logs": 0,
    "accepted_metrics": 0,
    "rejected": 0,
    "last_event_at": None,
}


def create_receiver_app() -> FastAPI | None:
    """创建 OTel HTTP Receiver FastAPI 子应用."""
    if FastAPI is None:
        return None
    app = FastAPI(title="Agent Security OTel Receiver", version="4.2.10")
    migrate_observability(get_store())

    @app.get("/healthz")
    async def healthz():
        stats = probe_event_stats(get_store())
        return {
            "status": "ok",
            "listen": os.environ.get("ASSESSMENT_OTEL_LISTEN", "127.0.0.1:4318"),
            "protocols": ["otlp_http_json"],
            "unsupported_protocols": ["otlp_http_protobuf", "otlp_grpc"],
            "receiver": {
                "started_at": _receiver_state.get("started_at"),
                "accepted_traces": _receiver_state["accepted_traces"],
                "accepted_logs": _receiver_state["accepted_logs"],
                "accepted_metrics": _receiver_state["accepted_metrics"],
                "rejected": _receiver_state["rejected"],
                "last_event_at": _receiver_state.get("last_event_at"),
            },
            "database": {"total_events": stats["total_events"], "last_event_at": stats["last_event_at"]},
            "probes": probe_adapter_health(get_store()),
        }

    @app.post("/v1/traces")
    async def post_traces(request: Request):
        """Receive OTLP/HTTP JSON traces; protobuf is intentionally unsupported."""
        try:
            body = await _read_otlp_json(request)
            spans = _extract_spans_from_otlp(body)
            _validate_batch(spans, "trace")
            store = get_store()
            events = []
            for span in spans:
                event = span_to_probe_event(span, span.get("resource"), span.get("scope"))
                if event:
                    events.append(event)
            insert_otel_spans_batch(store, spans)
            generated_events = insert_events_batch(store, events)["accepted"]
            _receiver_state["accepted_traces"] += len(spans)
            _receiver_state["last_event_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            return JSONResponse({"partialSuccess": {}, "accepted": len(spans), "generated_events": generated_events}, status_code=200)
        except ReceiverError as exc:
            return _receiver_error(exc.status_code, exc.code, str(exc), exc.rejected_field)
        except Exception:
            logger.warning("OTLP traces ingestion failed", exc_info=True)
            return _receiver_error(400, "OTEL_INVALID_TRACE_PAYLOAD", "invalid OTLP trace payload", "rejectedSpans")

    @app.post("/v1/logs")
    async def post_logs(request: Request):
        """Receive OTLP/HTTP JSON logs; raw message data is redacted before persistence."""
        try:
            body = await _read_otlp_json(request)
            logs = _extract_logs_from_otlp(body)
            _validate_batch(logs, "log")
            store = get_store()
            events = []
            for log in logs:
                body_obj = log.get("body")
                log["body_redacted"] = str(redact_payload({"body": body_obj}).get("body"))
                event = log_to_probe_event(log, log.get("resource"), log.get("scope"))
                if event:
                    events.append(event)
            insert_otel_logs_batch(store, logs)
            insert_events_batch(store, events)
            _receiver_state["accepted_logs"] += len(logs)
            _receiver_state["last_event_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            return JSONResponse({"partialSuccess": {}, "accepted": len(logs)}, status_code=200)
        except ReceiverError as exc:
            return _receiver_error(exc.status_code, exc.code, str(exc), exc.rejected_field)
        except Exception:
            logger.warning("OTLP logs ingestion failed", exc_info=True)
            return _receiver_error(400, "OTEL_INVALID_LOG_PAYLOAD", "invalid OTLP log payload", "rejectedLogRecords")

    @app.post("/v1/metrics")
    async def post_metrics(request: Request):
        """Receive OTLP/HTTP JSON metrics."""
        try:
            body = await _read_otlp_json(request)
            points = _extract_metric_points_from_otlp(body)
            _validate_batch(points, "metric")
            store = get_store()
            insert_otel_metric_points_batch(store, points)
            _receiver_state["accepted_metrics"] += len(points)
            _receiver_state["last_event_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            return JSONResponse({"partialSuccess": {}, "accepted": len(points)}, status_code=200)
        except ReceiverError as exc:
            return _receiver_error(exc.status_code, exc.code, str(exc), exc.rejected_field)
        except Exception:
            logger.warning("OTLP metrics ingestion failed", exc_info=True)
            return _receiver_error(400, "OTEL_INVALID_METRIC_PAYLOAD", "invalid OTLP metric payload", "rejectedDataPoints")

    @app.post("/retention")
    async def retention(request: Request):
        try:
            _require_loopback_or_token(request)
            body = await request.json()
            days = int(body.get("days", 30))
            if days < 1 or days > 3650:
                raise ReceiverError(422, "OTEL_INVALID_RETENTION", "retention days must be between 1 and 3650", "rejected")
            apply = bool(body.get("apply", False))
        except ReceiverError as exc:
            return _receiver_error(exc.status_code, exc.code, str(exc), exc.rejected_field)
        cutoff = time.time() - days * 86400
        store = get_store()
        counts = {"probe_event": 0, "otel_span": 0, "otel_log": 0, "otel_metric_point": 0}
        with store.connect() as conn:
            for table in counts:
                try:
                    rows = conn.execute(f"SELECT rowid, created_at FROM {table}").fetchall()
                except Exception:
                    continue
                delete_ids = []
                for row in rows:
                    created = row["created_at"] if hasattr(row, "keys") else row[1]
                    try:
                        dt = datetime.fromisoformat(str(created).replace("Z", "+00:00")).timestamp()
                    except Exception:
                        dt = time.time()
                    if dt < cutoff:
                        delete_ids.append(row["rowid"] if hasattr(row, "keys") else row[0])
                counts[table] = len(delete_ids)
                if apply and delete_ids:
                    conn.executemany(f"DELETE FROM {table} WHERE rowid=?", [(rid,) for rid in delete_ids])
            if apply:
                conn.commit()
        return {"dry_run": not apply, "days": days, "counts": counts, "mutates_installed_agents": False}

    _receiver_state["started_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return app


def _extract_spans_from_otlp(body: dict[str, Any]) -> list[dict[str, Any]]:
    """从 OTLP JSON body 中提取 span 列表."""
    spans: list[dict[str, Any]] = []
    try:
        resource_spans = body.get("resourceSpans", [])
        for rs in resource_spans:
            resource = rs.get("resource", {})
            scope_spans = rs.get("scopeSpans", [])
            for ss in scope_spans:
                scope = ss.get("scope", {})
                for raw_span in ss.get("spans", []):
                    span = dict(raw_span)
                    span["resource"] = resource
                    span["scope"] = scope
                    spans.append(span)
    except Exception:
        pass
    return spans


def _extract_logs_from_otlp(body: dict[str, Any]) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = []
    for rl in body.get("resourceLogs", []):
        resource = rl.get("resource", {})
        for sl in rl.get("scopeLogs", []):
            scope = sl.get("scope", {})
            for raw_record in sl.get("logRecords", []):
                record = dict(raw_record)
                record["resource"] = resource
                record["scope"] = scope
                logs.append(record)
    return logs


def _extract_metric_points_from_otlp(body: dict[str, Any]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for rm in body.get("resourceMetrics", []):
        resource = rm.get("resource", {})
        for sm in rm.get("scopeMetrics", []):
            scope = sm.get("scope", {})
            for metric in sm.get("metrics", []):
                name = metric.get("name", "unknown")
                unit = metric.get("unit")
                for mtype in ("gauge", "sum", "histogram"):
                    if mtype not in metric:
                        continue
                    data = metric.get(mtype) or {}
                    for dp in data.get("dataPoints", []):
                        value = dp.get("asDouble") if dp.get("asDouble") is not None else dp.get("asInt")
                        points.append({
                            "name": name,
                            "metric_name": name,
                            "metric_type": mtype,
                            "unit": unit,
                            "value": value,
                            "timestamp": dp.get("timeUnixNano") or dp.get("startTimeUnixNano"),
                            "attributes": attributes_to_dict(dp.get("attributes")),
                            "resource": resource,
                            "scope": scope,
                        })
    return points


# ── CLI 入口 ──────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Security OTel Receiver")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4318, help="监听端口 (默认 4318)")
    args = parser.parse_args()
    if not _is_loopback(args.host) and not os.environ.get("ASSESSMENT_OTEL_TOKEN"):
        parser.error("non-loopback receiver binding requires ASSESSMENT_OTEL_TOKEN")
    os.environ["ASSESSMENT_OTEL_LISTEN"] = f"{args.host}:{args.port}"
    app = create_receiver_app()
    if app is None:
        print("ERROR: fastapi not installed")
        return
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
