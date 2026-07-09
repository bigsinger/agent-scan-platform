"""Agent Security v4.2.5 — OTel span/log/metric -> probe_event 规范化转换器."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from .redaction import redact_payload, stable_hash
from ..store import utc_now


def attributes_to_dict(attributes: list[dict[str, Any]] | dict[str, Any] | None) -> dict[str, Any]:
    """将 OTLP JSON attributes 数组/字典转换为普通 dict.

    支持 OTLP JSON 格式:
      {"key":"agent.session_id", "value":{"stringValue":"..."}}
    """
    if not attributes:
        return {}
    if isinstance(attributes, dict):
        return dict(attributes)
    result: dict[str, Any] = {}
    for item in attributes:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if not key:
            continue
        result[str(key)] = _otel_value(item.get("value"))
    return result


def _otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if k in value:
            return value[k]
    if "arrayValue" in value:
        vals = value.get("arrayValue", {}).get("values", [])
        return [_otel_value(v) for v in vals]
    if "kvlistValue" in value:
        return attributes_to_dict(value.get("kvlistValue", {}).get("values", []))
    return value


def normalize_agent_name(value: Any) -> str:
    text = str(value or "").lower()
    if "codex" in text:
        return "codex"
    if "hermes" in text:
        return "hermes"
    if "openclaw" in text:
        return "openclaw"
    if "claude" in text:
        return "claude-code"
    return "unknown"


def span_to_probe_event(span: dict[str, Any], resource: dict[str, Any] | None = None, scope: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """将 OTel span 规范化为 probe_event; 无 Agent 属性时仍保留 span 事件."""
    attrs = attributes_to_dict(span.get("attributes"))
    res_attrs = attributes_to_dict((resource or {}).get("attributes") if isinstance(resource, dict) else resource)
    event_type = attrs.get("agent.event_type") or attrs.get("event.name") or _event_type_from_span_name(span.get("name"))
    if not event_type:
        return None
    source_agent = normalize_agent_name(attrs.get("agent.name") or attrs.get("gen_ai.system") or res_attrs.get("service.name"))
    tool_name = attrs.get("agent.tool_name") or attrs.get("tool.name") or attrs.get("gen_ai.tool.name")
    command = attrs.get("agent.command") or attrs.get("process.command_line") or attrs.get("shell.command")
    payload = redact_payload({
        "span_name": span.get("name"),
        "command": command,
        "attributes": attrs,
    })
    return {
        "event_id": f"otel_span_{span.get('spanId') or span.get('span_id') or stable_hash(str(span))[:12]}",
        "event_type": str(event_type),
        "timestamp": _span_time(span) or utc_now(),
        "trace_id": span.get("traceId") or span.get("trace_id"),
        "span_id": span.get("spanId") or span.get("span_id"),
        "parent_span_id": span.get("parentSpanId") or span.get("parent_span_id"),
        "source_agent": source_agent,
        "adapter_id": "otel-receiver",
        "session_id": attrs.get("agent.session_id") or attrs.get("session.id"),
        "run_id": attrs.get("agent.run_id"),
        "turn_id": attrs.get("agent.turn_id"),
        "tool_call_id": attrs.get("agent.tool_call_id") or attrs.get("tool.call.id"),
        "tool_name": tool_name,
        "tool_type": attrs.get("agent.tool_type") or ("shell" if str(tool_name).lower() in {"bash", "shell", "powershell"} else None),
        "mcp_server": attrs.get("mcp.server"),
        "mcp_tool": attrs.get("mcp.tool"),
        "mcp_transport": attrs.get("mcp.transport"),
        "phase": attrs.get("agent.phase") or _phase_from_event_type(str(event_type)),
        "status": _status_from_span(span),
        "duration_ms": _duration_ms(span),
        "input_hash": stable_hash(str(command or attrs.get("agent.input") or "")),
        "redaction_status": "redacted",
        "payload": payload,
    }


def log_to_probe_event(log: dict[str, Any], resource: dict[str, Any] | None = None, scope: dict[str, Any] | None = None) -> dict[str, Any] | None:
    attrs = attributes_to_dict(log.get("attributes"))
    res_attrs = attributes_to_dict((resource or {}).get("attributes") if isinstance(resource, dict) else resource)
    event_type = attrs.get("agent.event_type") or attrs.get("event.name")
    if not event_type:
        return None
    body = _otel_value(log.get("body"))
    payload = redact_payload({"body": body, "attributes": attrs})
    source_agent = normalize_agent_name(attrs.get("agent.name") or res_attrs.get("service.name"))
    log_id_seed = f"{log.get('traceId','')}:{log.get('spanId','')}:{log.get('timeUnixNano','')}:{event_type}"
    return {
        "event_id": f"otel_log_{stable_hash(log_id_seed)[:16]}",
        "event_type": str(event_type),
        "timestamp": _unix_nano_to_iso(log.get("timeUnixNano")) or utc_now(),
        "trace_id": log.get("traceId") or attrs.get("trace_id"),
        "span_id": log.get("spanId") or attrs.get("span_id"),
        "source_agent": source_agent,
        "adapter_id": "otel-receiver",
        "session_id": attrs.get("agent.session_id") or attrs.get("session.id"),
        "turn_id": attrs.get("agent.turn_id"),
        "tool_call_id": attrs.get("agent.tool_call_id"),
        "tool_name": attrs.get("agent.tool_name") or attrs.get("tool.name"),
        "tool_type": attrs.get("agent.tool_type"),
        "phase": attrs.get("agent.phase") or _phase_from_event_type(str(event_type)),
        "status": str(attrs.get("agent.status") or "ok"),
        "redaction_status": "redacted",
        "payload": payload,
    }


def _event_type_from_span_name(name: Any) -> str | None:
    text = str(name or "").lower()
    if "tool.call" in text or text == "tool.call":
        return "tool.call.started"
    if "mcp" in text:
        return "mcp.rpc.started"
    if "llm" in text or "gen_ai" in text:
        return "llm.call.started"
    return "otel.span"


def _phase_from_event_type(event_type: str) -> str:
    if event_type.endswith(".started"):
        return "start"
    if event_type.endswith(".completed"):
        return "complete"
    if event_type.endswith(".error"):
        return "error"
    return "event"


def _status_from_span(span: dict[str, Any]) -> str:
    status = span.get("status")
    if isinstance(status, dict):
        code = str(status.get("code") or "").lower()
        return "error" if "error" in code or code == "2" else "ok"
    return "ok"


def _span_time(span: dict[str, Any]) -> str | None:
    return span.get("startTime") or span.get("start_time") or _unix_nano_to_iso(span.get("startTimeUnixNano"))


def _duration_ms(span: dict[str, Any]) -> int | None:
    if span.get("duration_ms") is not None:
        return int(span["duration_ms"])
    start = _nano_int(span.get("startTimeUnixNano"))
    end = _nano_int(span.get("endTimeUnixNano"))
    if start is not None and end is not None and end >= start:
        return int((end - start) / 1_000_000)
    return None


def _nano_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _unix_nano_to_iso(value: Any) -> str | None:
    nano = _nano_int(value)
    if nano is None:
        return None
    return datetime.fromtimestamp(nano / 1_000_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
