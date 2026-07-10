"""Probe 公共模块: 事件发射器、缓冲区、fail-open."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from ...security import SensitiveDataGuard


DEFAULT_COLLECTOR_URL = os.environ.get("ASSESSMENT_PROBE_OTLP_ENDPOINT", "http://127.0.0.1:4318/v1/logs")
DEFAULT_BUFFER_PATH = Path.home() / ".agent-scan" / "probe_emit_buffer.jsonl"
DEFAULT_BUFFER_MAX_BYTES = 1024 * 1024
DEFAULT_BUFFER_FILES = 3


def _otel_log_payload(event: dict[str, Any]) -> dict[str, Any]:
    attrs = []
    mapping = {
        "agent.event_type": event.get("event_type") or "probe.event",
        "agent.name": event.get("source_agent") or "unknown",
        "agent.session_id": event.get("session_id") or "",
        "agent.turn_id": event.get("turn_id") or "",
        "agent.tool_call_id": event.get("tool_call_id") or "",
        "agent.tool_name": event.get("tool_name") or "",
        "agent.tool_type": event.get("tool_type") or "",
        "agent.phase": event.get("phase") or "event",
        "agent.status": event.get("status") or "ok",
    }
    for key, value in mapping.items():
        attrs.append({"key": key, "value": {"stringValue": str(value)}})
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": f"agent-security-probe-{mapping['agent.name']}"}}]},
                "scopeLogs": [
                    {
                        "scope": {"name": "agent-security-observer", "version": "4.2.10"},
                        "logRecords": [
                            {
                                "timeUnixNano": str(time.time_ns()),
                                "severityText": "INFO",
                                "body": {"stringValue": json.dumps(event, ensure_ascii=False, separators=(",", ":"))},
                                "attributes": attrs,
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _rotate_buffer(path: Path, max_bytes: int, generations: int) -> None:
    if not path.exists() or path.stat().st_size < max_bytes:
        return
    oldest = path.with_name(f"{path.name}.{generations}")
    oldest.unlink(missing_ok=True)
    for index in range(generations - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        if source.exists():
            source.replace(path.with_name(f"{path.name}.{index + 1}"))
    path.replace(path.with_name(f"{path.name}.1"))


def emit_normalized_event(
    event: dict[str, Any],
    collector_url: str = DEFAULT_COLLECTOR_URL,
    timeout_sec: float = 0.5,
    buffer_path: str | Path = DEFAULT_BUFFER_PATH,
) -> bool:
    """发送规范化探针事件到 Collector.

    fail-open: Collector 不可达时写入本地 JSONL buffer 并返回 False.

    Returns:
        True 表示成功发送, False 表示写入 buffer.
    """
    try:
        safe_event = SensitiveDataGuard.sanitize_for_persist(event)
    except Exception:
        return False
    try:
        wire_payload = _otel_log_payload(safe_event) if collector_url.rstrip("/").endswith("/v1/logs") else {"events": [safe_event]}
        payload = json.dumps(wire_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        req = Request(
            collector_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(req, timeout=timeout_sec)
        return True
    except (URLError, HTTPError, OSError):
        # fail-open: 写本地 buffer
        try:
            buffer = Path(str(buffer_path))
            buffer.parent.mkdir(parents=True, exist_ok=True)
            _rotate_buffer(
                buffer,
                max(4096, int(os.environ.get("ASSESSMENT_PROBE_BUFFER_MAX_BYTES", str(DEFAULT_BUFFER_MAX_BYTES)))),
                max(1, min(int(os.environ.get("ASSESSMENT_PROBE_BUFFER_FILES", str(DEFAULT_BUFFER_FILES))), 10)),
            )
            with buffer.open("a", encoding="utf-8") as f:
                f.write(json.dumps(safe_event, ensure_ascii=False, separators=(",", ":")) + "\n")
            try:
                os.chmod(buffer, 0o600)
            except OSError:
                pass
        except Exception:
            pass
        return False
