"""Agent Security v4.2 — Hermes 探针 Plugin/ Hook 适配器.

Hermes 探针通过 Hermes 的 hook 生命周期回调接入:
  - pre_llm_call -> agent.turn.started / agent.user_input.received
  - post_llm_call -> agent.turn.completed
  - pre_tool_call -> tool.call.started
  - post_tool_call -> tool.call.completed / tool.call.error
  - subagent_start / subagent_stop -> subagent 链路
  - pre_gateway_dispatch -> gateway 消息记录

工具名处理:
  - mcp_<server>_<tool> 格式解析为 mcp_server + mcp_tool
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..common.emitter import emit_normalized_event
from ...store import new_id, utc_now


# ── Hermes 生命周期事件映射 ─────────────────────────────────

HERMES_HOOK_EVENTS: dict[str, str] = {
    "pre_llm_call": "agent.turn.started",
    "post_llm_call": "agent.turn.completed",
    "pre_tool_call": "tool.call.started",
    "post_tool_call": "tool.call.completed",
    "subagent_start": "agent.turn.started",
    "subagent_stop": "agent.turn.completed",
    "pre_gateway_dispatch": "agent.turn.started",
}

# MCP 工具名正则: mcp_<server>_<tool>
MCP_TOOL_NAME_RE = re.compile(r"^mcp_(.+?)_(.+)$")


# ── 工具名解析 ──────────────────────────────────────────────

def parse_tool_name(tool_name: str) -> dict[str, str]:
    """解析 Hermes 工具名, 提取 tool_type 和 mcp_server/mcp_tool.

    Args:
        tool_name: 原始工具名, 如 "Read", "Bash", "mcp_fetch_fetch"

    Returns:
        包含 tool_type, mcp_server, mcp_tool 的字典
    """
    m = MCP_TOOL_NAME_RE.match(tool_name)
    if m:
        return {
            "tool_type": "mcp",
            "mcp_server": m.group(1),
            "mcp_tool": m.group(2),
        }
    if tool_name.lower() in {"bash", "powershell", "shell", "cmd"}:
        return {"tool_type": "shell", "mcp_server": "", "mcp_tool": ""}
    return {"tool_type": "builtin", "mcp_server": "", "mcp_tool": ""}


# ── Hermes Hook 事件解析 ────────────────────────────────────

def parse_hook_event(hook_name: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """将 Hermes hook payload 解析为规范化探针事件.

    Args:
        hook_name: Hermes hook 名 (如 "pre_tool_call")
        payload: hook 回调传入的字典

    Returns:
        规范化 probe_event dict, 或 None (如果忽略此事件)
    """
    event_type = HERMES_HOOK_EVENTS.get(hook_name)
    if not event_type:
        return None

    tool_name = str(payload.get("tool_name") or payload.get("tool", payload.get("name", "")))
    tool_info = parse_tool_name(tool_name)
    session_id = payload.get("session_id") or payload.get("session", "")
    turn_id = payload.get("turn_id") or payload.get("turn", payload.get("conversation_id", ""))
    tool_call_id = payload.get("tool_call_id") or payload.get("call_id", "")
    input_text = str(payload.get("input") or payload.get("args") or payload.get("user_input", ""))
    output_text = str(payload.get("output") or payload.get("result") or payload.get("response", ""))
    error_text = str(payload.get("error") or payload.get("exception", ""))
    duration = payload.get("duration_ms") or payload.get("duration")

    phase = "start" if hook_name.startswith("pre_") else \
            "complete" if hook_name.startswith("post_") and not error_text else \
            "error" if error_text else "unknown"

    event: dict[str, Any] = {
        "event_id": f"hermes_{uuid4().hex[:12]}",
        "event_type": event_type,
        "timestamp": utc_now(),
        "source_agent": "hermes",
        "adapter_id": "hermes-plugin-local",
        "session_id": session_id,
        "turn_id": turn_id,
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "tool_type": tool_info["tool_type"],
        "mcp_server": tool_info["mcp_server"],
        "mcp_tool": tool_info["mcp_tool"],
        "mcp_transport": "stdio" if tool_info["tool_type"] == "mcp" else "",
        "phase": phase,
        "status": "error" if error_text else "ok",
        "duration_ms": int(duration) if duration else None,
        "input_hash": hashlib.sha256(input_text.encode()).hexdigest(),
        "output_hash": hashlib.sha256(output_text.encode()).hexdigest(),
        "redaction_status": "redacted",
        "payload": {
            "hook": hook_name,
            "input_preview": input_text[:200],
            "output_preview": output_text[:200],
            "error": error_text[:200] if error_text else None,
        },
    }

    return event


# ── Hermes plugin 脚本生成 ───────────────────────────────────

def generate_hermes_plugin_code() -> str:
    """生成 Hermes 探针 plugin Python 代码.

    该 plugin 注册到 Hermes 的 hook 生命周期,
    采集事件后通过 emitter 上报到 Collector.
    """
    return '''"""
Hermes Security Probe Plugin — 自动生成, 只读上报, fail-open.

在 Hermes 配置中注册:
  hooks:
    probe_plugin:
      module: "hermes_probe_plugin"
      enabled: true
"""

import hashlib, json, os
from uuid import uuid4
from datetime import datetime, timezone

try:
    from hermes_sdk import register_hook
except ImportError:
    register_hook = None

COLLECTOR_URL = "http://127.0.0.1:8000/api/v1/probes/events"

def _emit(event: dict) -> None:
    """发送事件到 Collector, fail-open."""
    try:
        import urllib.request
        data = json.dumps({"events": [event]}).encode()
        req = urllib.request.Request(
            COLLECTOR_URL, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=0.5)
    except Exception:
        try:
            buffer = Path.home() / ".hermes" / "probe_buffer.jsonl"
            buffer.parent.mkdir(parents=True, exist_ok=True)
            with open(buffer, "a") as f:
                f.write(json.dumps(event) + "\\n")
        except Exception:
            pass

def _build_event(hook_name: str, payload: dict) -> dict:
    tool_name = str(payload.get("tool_name", payload.get("tool", "")))
    event = {
        "event_id": "probe_" + uuid4().hex[:12],
        "event_type": f"agent.{hook_name.replace('_', '.')}",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "Z",
        "source_agent": "hermes",
        "adapter_id": "hermes-plugin-local",
        "session_id": payload.get("session_id", ""),
        "turn_id": payload.get("turn_id", ""),
        "tool_name": tool_name,
        "tool_type": "mcp" if tool_name.startswith("mcp_") else "shell" if tool_name.lower() in {"bash","shell"} else "builtin",
        "phase": "start" if hook_name.startswith("pre_") else "complete",
        "status": "ok",
        "redaction_status": "redacted",
        "payload": {"hook": hook_name},
    }
    if tool_name.startswith("mcp_"):
        parts = tool_name.split("_", 2)
        if len(parts) >= 3:
            event["mcp_server"] = parts[1]
            event["mcp_tool"] = parts[2]
    return event

if register_hook:
    @register_hook("pre_llm_call")
    def on_pre_llm(ctx):
        _emit(_build_event("pre_llm_call", ctx or {}))
        return ctx

    @register_hook("post_llm_call")
    def on_post_llm(ctx):
        _emit(_build_event("post_llm_call", ctx or {}))
        return ctx

    @register_hook("pre_tool_call")
    def on_pre_tool(ctx):
        _emit(_build_event("pre_tool_call", ctx or {}))
        return ctx

    @register_hook("post_tool_call")
    def on_post_tool(ctx):
        _emit(_build_event("post_tool_call", ctx or {}))
        return ctx
'''


# ── Install Plan 生成 ────────────────────────────────────────

def generate_install_plan(dry_run: bool = True) -> dict[str, Any]:
    """生成 Hermes 探针安装计划 (dry-run 模式)."""
    hermes_config = _find_hermes_config()
    steps: list[dict[str, Any]] = []
    rollback: list[dict[str, Any]] = []

    if not hermes_config:
        return {
            "agent_type": "hermes",
            "install_status": "not_found",
            "note": "未发现 Hermes 配置文件 (~/.hermes/config.yaml 或 config.yml)",
            "steps": [],
            "rollback": [],
        }

    backup_path = hermes_config.parent / "config.yaml.probe_backup"
    before_hash = _file_hash(hermes_config)
    hooks_exist = _check_hooks_exist(hermes_config)

    steps.append({
        "action": "backup",
        "description": f"备份当前配置到 {backup_path}",
        "source": str(hermes_config),
        "target": str(backup_path),
    })
    rollback.insert(0, {
        "action": "restore",
        "description": f"从 {backup_path} 恢复配置",
        "source": str(backup_path),
        "target": str(hermes_config),
    })

    if not hooks_exist:
        steps.append({
            "action": "modify_config",
            "description": "在 Hermes 配置中添加 hooks/probe_plugin 段落",
            "target": str(hermes_config),
            "before_hash": before_hash,
            "diff_preview": "添加 hooks.probe_plugin 章节, 注册 pre_llm_call/ post_llm_call/ pre_tool_call/ post_tool_call",
        })
        rollback.insert(0, {
            "action": "restore_config",
            "description": "从备份还原 Hermes 配置",
            "target": str(hermes_config),
            "before_hash": before_hash,
        })

    return {
        "agent_type": "hermes",
        "install_status": "installed" if hooks_exist else "ready_to_install",
        "target_config_path": str(hermes_config),
        "backup_path": str(backup_path),
        "before_hash": before_hash,
        "steps": steps,
        "rollback": rollback,
        "hooks_exist": hooks_exist,
    }


# ── 辅助函数 ────────────────────────────────────────────────

def _find_hermes_config() -> Path | None:
    """查找 Hermes 配置文件."""
    candidates = [
        Path.home() / ".hermes" / "config.yaml",
        Path.home() / ".hermes" / "config.yml",
        Path.home() / "AppData" / "Local" / "hermes" / "config.yaml",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def _check_hooks_exist(config_path: Path) -> bool:
    """检查配置是否已有 hooks 段落."""
    try:
        text = config_path.read_text(encoding="utf-8")
        return "hooks:" in text.lower() or "probe" in text.lower()
    except Exception:
        return False


def _file_hash(path: Path) -> str:
    try:
        import hashlib
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return ""
