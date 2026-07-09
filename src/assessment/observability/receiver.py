"""Agent Security v4.2 — OTel HTTP Receiver 骨架.

独立启动: python -m assessment.observability.receiver --host 127.0.0.1 --port 4318
集成启动: 通过 uvicorn 挂载 FastAPI 子应用.
"""

from __future__ import annotations

import argparse
import json
import logging
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
    insert_otel_span,
    insert_otel_log,
    insert_otel_metric_point,
    insert_probe_event,
    migrate_observability,
    probe_event_stats,
    probe_adapter_health,
)
from .normalizer import attributes_to_dict, span_to_probe_event, log_to_probe_event
from .redaction import redact_payload

logger = logging.getLogger(__name__)

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
    app = FastAPI(title="Agent Security OTel Receiver", version="4.2.0")
    migrate_observability(get_store())

    @app.get("/healthz")
    async def healthz():
        stats = probe_event_stats(get_store())
        return {
            "status": "ok",
            "listen": "127.0.0.1:4318",
            "protocols": ["otlp_http_json", "normalized_json"],
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
        """接收 OTLP/HTTP JSON traces."""
        try:
            body = await request.json()
            spans = _extract_spans_from_otlp(body)
            store = get_store()
            generated_events = 0
            for span in spans:
                insert_otel_span(store, span)
                event = span_to_probe_event(span, span.get("resource"), span.get("scope"))
                if event:
                    insert_probe_event(store, event)
                    generated_events += 1
            _receiver_state["accepted_traces"] += len(spans)
            _receiver_state["last_event_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "Z"
            return JSONResponse({"partialSuccess": {}, "error": "", "accepted": len(spans), "generated_events": generated_events}, status_code=200)
        except Exception as exc:
            _receiver_state["rejected"] += 1
            logger.warning("OTLP traces parse error: %s", exc)
            return JSONResponse({"partialSuccess": {"rejectedSpans": []}, "error": str(exc)}, status_code=400)

    @app.post("/v1/logs")
    async def post_logs(request: Request):
        """接收 OTLP/HTTP JSON logs."""
        try:
            body = await request.json()
            logs = _extract_logs_from_otlp(body)
            store = get_store()
            for log in logs:
                body_obj = log.get("body")
                log["body_redacted"] = str(redact_payload({"body": body_obj}).get("body"))
                insert_otel_log(store, log)
                event = log_to_probe_event(log, log.get("resource"), log.get("scope"))
                if event:
                    insert_probe_event(store, event)
            _receiver_state["accepted_logs"] += len(logs)
            _receiver_state["last_event_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "Z"
            return JSONResponse({"partialSuccess": {}, "error": "", "accepted": len(logs)}, status_code=200)
        except Exception as exc:
            _receiver_state["rejected"] += 1
            return JSONResponse({"partialSuccess": {"rejectedLogRecords": []}, "error": str(exc)}, status_code=400)

    @app.post("/v1/metrics")
    async def post_metrics(request: Request):
        """接收 OTLP/HTTP JSON metrics."""
        try:
            body = await request.json()
            points = _extract_metric_points_from_otlp(body)
            store = get_store()
            for point in points:
                insert_otel_metric_point(store, point)
            _receiver_state["accepted_metrics"] += len(points)
            _receiver_state["last_event_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "Z"
            return JSONResponse({"partialSuccess": {}, "error": "", "accepted": len(points)}, status_code=200)
        except Exception as exc:
            _receiver_state["rejected"] += 1
            return JSONResponse({"partialSuccess": {"rejectedDataPoints": []}, "error": str(exc)}, status_code=400)

    _receiver_state["started_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "Z"
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
                for span in ss.get("spans", []):
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
            for rec in sl.get("logRecords", []):
                rec["resource"] = resource
                rec["scope"] = scope
                logs.append(rec)
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
    app = create_receiver_app()
    if app is None:
        print("ERROR: fastapi not installed")
        return
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
