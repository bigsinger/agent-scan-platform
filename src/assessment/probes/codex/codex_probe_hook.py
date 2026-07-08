"""Agent Security v4.2 — Codex 探针 Hook 脚本生成与解析.

Codex Hooks 是基于 TOML 配置的生命周期回调。
每个 hook event 映射到一个脚本命令，脚本接收 JSON payload 并输出事件。

本模块生成 probe hook 脚本并解析 Codex hook 事件 payload。
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..common.emitter import emit_normalized_event
from ...store import new_id, utc_now


# ── Hook 事件映射 ───────────────────────────────────────────

CODEX_HOOK_EVENTS: dict[str, str] = {
    "SessionStart": "agent.session.started",
    "UserPromptSubmit": "agent.user_input.received",
    "PreToolUse": "tool.call.started",
    "PermissionRequest": "policy.decision.shadow",
    "PostToolUse": "tool.call.completed",
    "Stop": "agent.turn.completed",
    "SubagentStop": "agent.turn.completed",
    "PreCompact": "agent.turn.started",
    "PostCompact": "agent.turn.completed",
}

DEFAULT_COLLECTOR_URL = "http://127.0.0.1:8000/api/v1/probes/events"
FALLBACK_BUFFER_PATH = Path.home() / ".codex" / "probe_buffer.jsonl"


# ── Hook 脚本生成 ───────────────────────────────────────────

def generate_hook_script(
    collector_url: str = DEFAULT_COLLECTOR_URL,
    timeout_ms: int = 200,
) -> str:
    """生成 Codex probe hook Python 脚本内容.

    脚本由 Codex 在每个 hook event 触发时调用,
    负责解析 stdin JSON payload, 脱敏, 上报规范化事件.
    """
    return f'''#!/usr/bin/env python3
"""Codex Security Probe Hook — 自动生成, 只读上报, fail-open."""
import json, sys, os, hashlib, urllib.request, urllib.error
from pathlib import Path

COLLECTOR_URL = {json.dumps(collector_url)}
TIMEOUT = {timeout_ms} / 1000.0
ADAPTER_ID = "codex-hooks-local"
ADAPTER_VERSION = "0.1.0"

def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def redact_value(value):
    if isinstance(value, str):
        for pat in ["sk-", "Bearer ", "password", "secret", "api_key"]:
            if pat in value.lower():
                return "[REDACTED]"
        return value
    return str(value)

def build_event(hook_event: str, payload: dict) -> dict:
    session_id = payload.get("sessionId") or payload.get("session_id", "")
    tool_call_id = payload.get("toolCallId") or payload.get("tool_id", "")
    tool_name = payload.get("toolName") or payload.get("name", "")
    input_text = payload.get("input") or payload.get("text") or payload.get("command") or ""
    output_text = payload.get("output") or payload.get("result") or ""
    error_text = payload.get("error") or ""

    event_type = {json.dumps(CODEX_HOOK_EVENTS)}.get(hook_event, hook_event)
    phase = "start" if "Pre" in hook_event or "SessionStart" in hook_event or "UserPrompt" in hook_event else \\
            "complete" if "Post" in hook_event or "Complete" in hook_event else \\
            "error" if "Error" in hook_event else "unknown"

    return {{
        "event_id": "codex_" + hashlib.md5((hook_event + str(id(payload))).encode()).hexdigest()[:12],
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "Z",
        "source_agent": "codex",
        "adapter_id": ADAPTER_ID,
        "session_id": session_id,
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "tool_type": "shell" if tool_name in {{"Bash", "PowerShell", "Shell"}} else "builtin" if not tool_name else "extension",
        "phase": phase,
        "status": "error" if error_text else "ok",
        "input_hash": stable_hash(input_text),
        "output_hash": stable_hash(output_text),
        "redaction_status": "redacted",
        "payload": {{
            "hook_event": hook_event,
            "input_preview": redact_value(input_text[:200]),
            "output_preview": redact_value(output_text[:200]),
            "error": redact_value(error_text[:200]) if error_text else None,
        }},
    }}

def main():
    if len(sys.argv) < 2:
        return 0
    hook_event = sys.argv[1]
    try:
        payload = json.loads(sys.stdin.read()) if not sys.stdin.isatty() else {{}}
    except Exception:
        payload = {{}}
    try:
        event = build_event(hook_event, payload)
        data = json.dumps({{"events": [event]}}).encode()
        req = urllib.request.Request(
            COLLECTOR_URL,
            data=data,
            headers={{"Content-Type": "application/json"}},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=TIMEOUT)
    except Exception:
        # fail-open: 写入本地 buffer
        try:
            with open({json.dumps(str(FALLBACK_BUFFER_PATH))}, "a") as f:
                f.write(json.dumps(event) + "\\n")
        except Exception:
            pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''


# ── Install Plan 生成 ────────────────────────────────────────

def generate_install_plan(dry_run: bool = True) -> dict[str, Any]:
    """生成 Codex 探针安装计划 (dry-run 模式)."""
    codex_config = _find_codex_config()
    steps: list[dict[str, Any]] = []
    rollback: list[dict[str, Any]] = []

    if not codex_config:
        return {
            "agent_type": "codex",
            "install_status": "not_found",
            "note": "未发现 Codex 配置文件 (~/.codex/config.toml)",
            "steps": [],
            "rollback": [],
        }

    # 备份步骤
    backup_path = codex_config.parent / "config.toml.probe_backup"
    steps.append({
        "action": "backup",
        "description": f"备份当前配置到 {backup_path}",
        "source": str(codex_config),
        "target": str(backup_path),
    })
    rollback.insert(0, {
        "action": "restore",
        "description": f"从 {backup_path} 恢复配置",
        "source": str(backup_path),
        "target": str(codex_config),
    })

    # 检查是否已有 hooks 配置
    hooks_exist = _check_hooks_exist(codex_config)

    if not hooks_exist:
        hook_script = generate_hook_script()
        hook_path = codex_config.parent / "probe_hook.py"
        before_hash = _file_hash(codex_config)

        steps.append({
            "action": "write_hook",
            "description": f"写入探针 hook 脚本到 {hook_path}",
            "target": str(hook_path),
            "content_preview": hook_script[:200] + "...",
        })
        rollback.insert(0, {
            "action": "delete_file",
            "description": f"删除 hook 脚本 {hook_path}",
            "target": str(hook_path),
        })

        steps.append({
            "action": "modify_config",
            "description": "在 config.toml 中注册 hook 命令",
            "target": str(codex_config),
            "diff_preview": "添加 [hooks] 章节, 注册 UserPromptSubmit/PreToolUse/PostToolUse 等事件",
        })
        rollback.insert(0, {
            "action": "restore_config",
            "description": "从备份还原 config.toml",
            "target": str(codex_config),
            "before_hash": before_hash,
        })

    return {
        "agent_type": "codex",
        "install_status": "installed" if hooks_exist else "ready_to_install",
        "target_config_path": str(codex_config),
        "backup_path": str(backup_path),
        "before_hash": _file_hash(codex_config),
        "steps": steps,
        "rollback": rollback,
        "hooks_exist": hooks_exist,
    }


def parse_hook_event(hook_event: str, raw_payload: str) -> dict[str, Any]:
    """解析 Codex hook 事件 payload 为规范化探针事件.

    Args:
        hook_event: Codex hook 事件名 (如 UserPromptSubmit)
        raw_payload: stdin JSON 字符串

    Returns:
        规范化 probe_event dict
    """
    event_type = CODEX_HOOK_EVENTS.get(hook_event, hook_event)
    try:
        payload = json.loads(raw_payload) if raw_payload else {}
    except json.JSONDecodeError:
        payload = {"raw": raw_payload[:500]}

    session_id = payload.get("sessionId") or payload.get("session_id", "")
    tool_call_id = payload.get("toolCallId") or payload.get("tool_id", "")
    tool_name = payload.get("toolName") or payload.get("name", "")
    input_text = payload.get("input") or payload.get("text") or payload.get("command") or ""
    output_text = payload.get("output") or payload.get("result") or ""
    error_text = payload.get("error") or ""

    phase = "start" if "Pre" in hook_event or "SessionStart" in hook_event or "UserPrompt" in hook_event else \
            "complete" if "Post" in hook_event or "Complete" in hook_event else \
            "error" if "Error" in hook_event else "unknown"

    return {
        "event_id": f"codex_{uuid4().hex[:12]}",
        "event_type": event_type,
        "timestamp": utc_now(),
        "source_agent": "codex",
        "adapter_id": "codex-hooks-local",
        "session_id": session_id,
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "tool_type": "shell" if tool_name in {"Bash", "PowerShell", "Shell"} else "builtin" if not tool_name else "extension",
        "phase": phase,
        "status": "error" if error_text else "ok",
        "input_hash": hashlib.sha256(input_text.encode()).hexdigest() if hasattr(__import__("hashlib"), "sha256") else "",
        "redaction_status": "redacted",
        "payload": {
            "hook_event": hook_event,
            "input_preview": input_text[:200],
            "output_preview": output_text[:200],
            "error": error_text[:200] if error_text else None,
        },
    }


# ── 辅助函数 ────────────────────────────────────────────────

def _find_codex_config() -> Path | None:
    """查找 Codex 配置文件."""
    candidates = [
        Path.home() / ".codex" / "config.toml",
        Path.home() / "AppData" / "Local" / "Codex" / "config.toml",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def _check_hooks_exist(config_path: Path) -> bool:
    """检查 config.toml 是否已有 hooks 配置."""
    try:
        text = config_path.read_text(encoding="utf-8")
        return "[hooks]" in text.lower()
    except Exception:
        return False


def _file_hash(path: Path) -> str:
    """计算文件 SHA-256."""
    try:
        import hashlib
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return ""
