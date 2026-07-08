"""Probe 公共模块: 事件发射器、缓冲区、fail-open."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DEFAULT_COLLECTOR_URL = "http://127.0.0.1:8000/api/v1/probes/events"
DEFAULT_BUFFER_PATH = Path.home() / ".agent-scan" / "probe_emit_buffer.jsonl"


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
        payload = json.dumps({"events": [event]}).encode("utf-8")
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
            with buffer.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass
        return False
