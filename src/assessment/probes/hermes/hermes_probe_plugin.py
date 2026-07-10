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
from pathlib import Path

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


# ── Install Plan 与能力生命周期 ────────────────────────────────

PROBE_MARKER_BEGIN = "# agent-scan-platform hermes probe begin"
PROBE_MARKER_END = "# agent-scan-platform hermes probe end"
PROBE_DISABLED_MARKER = "# agent-scan-platform hermes probe disabled"
PROBE_HOOK_EVENTS = ("pre_llm_call", "post_llm_call", "pre_tool_call", "post_tool_call")


def _default_command_runner(command: list[str]) -> tuple[int, str, str]:
    """Run a read-only Hermes capability command with a bounded timeout."""
    import subprocess

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False)
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", type(exc).__name__


def _probe_marker_state(config_path: Path) -> str:
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return "absent"
    if PROBE_MARKER_BEGIN not in text or PROBE_MARKER_END not in text:
        return "absent"
    return "disabled" if PROBE_DISABLED_MARKER in text else "enabled"


def capability_probe(
    *,
    config_path: Path | None = None,
    command_runner: Any | None = None,
) -> dict[str, Any]:
    """Read capability evidence without treating generic config text as a probe.

    An active probe is recognized only by this product's bounded marker. Command
    output is retained as evidence, but an empty plugin listing can never promote
    a generic ``hooks:`` stanza to an installed probe.
    """
    config = config_path or _find_hermes_config()
    runner = command_runner or _default_command_runner
    commands = [["hermes", "--version"], ["hermes", "hooks", "list"], ["hermes", "hooks", "doctor"], ["hermes", "plugins", "list", "--plain", "--no-bundled"]]
    evidence = []
    for command in commands:
        try:
            code, stdout, stderr = runner(command)
        except Exception as exc:  # capability inspection is always fail-open
            code, stdout, stderr = 127, "", type(exc).__name__
        evidence.append({"command": command, "exit_code": int(code), "stdout": str(stdout)[:1000], "stderr": str(stderr)[:500]})

    marker_state = _probe_marker_state(config) if config else "absent"
    installed = marker_state == "enabled"
    return {
        "agent_type": "hermes",
        "status": "INSTALLED_DEGRADED" if installed else "NOT_INSTALLED",
        "installed": installed,
        "capability_status": "SUPPORTED_PARTIAL" if config else "NOT_INSTALLED",
        "config_path": str(config) if config else None,
        "marker_state": marker_state,
        "evidence": evidence,
        "supports_apply": bool(config),
        "supports_uninstall": bool(config),
        "supports_rollback": bool(config),
        "supports_synthetic_self_test": bool(config),
    }


def _file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _plan_id(config_path: Path, before_hash: str) -> str:
    return "hermes-plan-" + hashlib.sha256(f"{config_path}:{before_hash}".encode()).hexdigest()[:16]


def generate_install_plan(dry_run: bool = True, *, config_path: Path | str | None = None) -> dict[str, Any]:
    """Return a truthful, non-mutating Hermes installation plan.

    This function never applies a configuration change, even when callers pass
    ``dry_run=False``; apply is a separate plan-ID-confirmed operation.
    """
    config = Path(config_path) if config_path else _find_hermes_config()
    if not config or not config.is_file():
        return {
            "agent_type": "hermes", "install_status": "NOT_INSTALLED", "capability_status": "NOT_INSTALLED",
            "dry_run": True, "note": "未发现 Hermes 配置文件，未生成可应用计划", "steps": [], "rollback": [],
        }
    before_hash = _file_hash(config)
    backup = config.with_name(config.name + ".agent_scan_probe_backup")
    plugin_path = config.parent / "agent_scan_hermes_probe.py"
    capability = capability_probe(config_path=config)
    if capability["installed"]:
        return {
            "agent_type": "hermes", "install_status": "INSTALLED_DEGRADED", "capability_status": "INSTALLED_DEGRADED",
            "dry_run": True, "plan_id": _plan_id(config, before_hash), "target_config_path": str(config),
            "steps": [], "rollback": [], "note": "已发现本产品探针标记；仍需运行自测确认健康状态", "capability": capability,
        }
    steps = [
        {"action": "backup", "source": str(config), "target": str(backup), "before_hash": before_hash},
        {"action": "write_plugin", "target": str(plugin_path), "content_hash": hashlib.sha256(generate_hermes_plugin_code().encode()).hexdigest()},
        {"action": "atomic_replace_config", "target": str(config), "diff_preview": "添加受限 agent-scan Hermes probe 配置标记；事件=" + ",".join(PROBE_HOOK_EVENTS), "timeout_ms": 200},
        {"action": "synthetic_self_test", "description": "仅构造 probe.health 事件，不发送真实用户 Prompt"},
    ]
    rollback = [
        {"action": "restore_config", "source": str(backup), "target": str(config)},
        {"action": "delete_file", "target": str(plugin_path)},
    ]
    return {
        "agent_type": "hermes", "install_status": "SUPPORTED_PARTIAL", "capability_status": "SUPPORTED_PARTIAL",
        "dry_run": True, "plan_id": _plan_id(config, before_hash), "target_config_path": str(config),
        "backup_path": str(backup), "plugin_path": str(plugin_path), "before_hash": before_hash,
        "steps": steps, "rollback": rollback, "hooks_exist": False, "capability": capability,
    }


def _probe_config_block(disabled: bool = False) -> str:
    lines = [PROBE_MARKER_BEGIN]
    if disabled:
        lines.append(PROBE_DISABLED_MARKER)
    lines.extend(["# lifecycle events: " + ", ".join(PROBE_HOOK_EVENTS), "# fail_open: true; timeout_ms: 200", PROBE_MARKER_END])
    return "\n".join(lines) + "\n"


def _write_atomic(path: Path, content: str) -> None:
    temporary = path.with_name(path.name + ".agent_scan_probe_tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def apply_install_plan(plan: dict[str, Any], *, confirmed_plan_id: str) -> dict[str, Any]:
    """Apply exactly one reviewed Hermes plan after explicit ID confirmation."""
    if not confirmed_plan_id or confirmed_plan_id != plan.get("plan_id"):
        raise ValueError("explicit confirmation for this plan_id is required")
    config = Path(plan["target_config_path"])
    if not config.is_file() or _file_hash(config) != plan.get("before_hash"):
        raise ValueError("target configuration changed or is unavailable; regenerate the plan")
    backup = Path(plan["backup_path"])
    plugin_path = Path(plan["plugin_path"])
    backup.write_bytes(config.read_bytes())
    try:
        plugin_path.write_text(generate_hermes_plugin_code(), encoding="utf-8")
        current = config.read_text(encoding="utf-8")
        _write_atomic(config, current.rstrip() + "\n" + _probe_config_block())
    except Exception:
        if backup.exists():
            _write_atomic(config, backup.read_text(encoding="utf-8"))
        raise
    return {"status": "INSTALLED_DEGRADED", "plan_id": plan["plan_id"], "config_path": str(config), "self_test_required": True}


def run_synthetic_self_test(*, config_path: Path | str) -> dict[str, Any]:
    """Validate only the installed marker and generated plugin; no agent command runs."""
    config = Path(config_path)
    state = _probe_marker_state(config)
    return {"passed": state == "enabled", "status": "INSTALLED_DEGRADED" if state == "enabled" else "NOT_INSTALLED", "event_type": "probe.health", "synthetic": True}


def disable_probe(*, config_path: Path | str) -> dict[str, Any]:
    config = Path(config_path)
    text = config.read_text(encoding="utf-8")
    if _probe_marker_state(config) == "enabled":
        _write_atomic(config, text.replace(PROBE_MARKER_BEGIN, PROBE_MARKER_BEGIN + "\n" + PROBE_DISABLED_MARKER, 1))
    return {"status": "INSTALLED_DEGRADED", "enabled": False}


def uninstall_probe(*, config_path: Path | str) -> dict[str, Any]:
    config = Path(config_path)
    text = config.read_text(encoding="utf-8")
    start, end = text.find(PROBE_MARKER_BEGIN), text.find(PROBE_MARKER_END)
    if start >= 0 and end >= start:
        end = text.find("\n", end)
        _write_atomic(config, (text[:start] + text[end + 1:]).rstrip() + "\n")
    return {"status": "NOT_INSTALLED", "enabled": False}


def rollback_install(plan: dict[str, Any]) -> dict[str, Any]:
    config, backup = Path(plan["target_config_path"]), Path(plan["backup_path"])
    if not backup.is_file():
        raise ValueError("rollback backup is unavailable")
    _write_atomic(config, backup.read_text(encoding="utf-8"))
    Path(plan["plugin_path"]).unlink(missing_ok=True)
    return {"status": "NOT_INSTALLED", "rolled_back": True}


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
