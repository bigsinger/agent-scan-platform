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
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..common.emitter import emit_normalized_event
from ...security import SensitiveDataGuard
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
            "input_preview": SensitiveDataGuard.redact_text(input_text, max_len=200),
            "output_preview": SensitiveDataGuard.redact_text(output_text, max_len=200),
            "error": SensitiveDataGuard.redact_text(error_text, max_len=200) if error_text else None,
        },
    }

    return event


# ── Hermes plugin 脚本生成 ───────────────────────────────────

def generate_hermes_plugin_code() -> str:
    """Generate a real Hermes user plugin using the v0.18 register(ctx) API."""
    return r'''"""Agent Security observer for Hermes. Generated, observe-only and fail-open."""
from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from uuid import uuid4

def _collector_endpoint():
    configured = os.environ.get("AGENT_SCAN_OTLP_ENDPOINT", "").strip()
    if configured:
        return configured
    try:
        state = json.loads(Path(__file__).with_name("install-state.json").read_text(encoding="utf-8"))
        configured = str(state.get("collector_url") or "").strip()
    except Exception:
        configured = ""
    return configured or "http://127.0.0.1:4318/v1/logs"


ENDPOINT = _collector_endpoint()
BUFFER = Path(os.environ.get("AGENT_SCAN_PROBE_BUFFER", str(Path.home() / ".agent-scan" / "hermes-probe-buffer.jsonl")))
MAX_BUFFER_BYTES = max(4096, int(os.environ.get("AGENT_SCAN_PROBE_BUFFER_BYTES", "1048576")))
EVENTS = (
    "on_session_start", "on_session_end", "pre_llm_call", "post_llm_call",
    "pre_tool_call", "post_tool_call", "subagent_start", "subagent_stop",
)
_EVENT_TYPES = {
    "on_session_start": "agent.session.started", "on_session_end": "agent.session.completed",
    "pre_llm_call": "agent.user_input.received", "post_llm_call": "agent.turn.completed",
    "pre_tool_call": "tool.call.started", "post_tool_call": "tool.call.completed",
    "subagent_start": "agent.subagent.started", "subagent_stop": "agent.subagent.completed",
}
_SECRET_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_-]{8,}"), re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._-]{12,}"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|cookie|session)\b\s*[:=]\s*[^\s,;]{6,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{16,}"), re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
)
_queue = queue.Queue(maxsize=2048)
_start_lock = threading.Lock()
_worker_started = False


def _redact(value):
    text = str(value or "").replace("\x00", "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("<REDACTED>", text)
    return text[:200]


def _text(value):
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":"))
    except Exception:
        return type(value).__name__


def _build_event(hook_name, kwargs):
    tool_name = str(kwargs.get("tool_name") or kwargs.get("name") or "")
    raw_input = _text(kwargs.get("user_message") or kwargs.get("tool_input") or kwargs.get("request") or "")
    raw_output = _text(kwargs.get("result") or kwargs.get("response") or kwargs.get("error") or "")
    return {
        "event_id": "hermes_" + uuid4().hex[:20],
        "event_type": _EVENT_TYPES.get(hook_name, "agent.event"),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_agent": "hermes",
        "adapter_id": "hermes-user-plugin-v4.2.10",
        "session_id": str(kwargs.get("session_id") or ""),
        "turn_id": str(kwargs.get("turn_id") or ""),
        "tool_call_id": str(kwargs.get("tool_call_id") or ""),
        "tool_name": tool_name,
        "tool_type": "mcp" if tool_name.startswith("mcp_") else "shell" if tool_name.lower() in {"terminal", "bash", "shell", "powershell"} else "builtin",
        "phase": "start" if hook_name.startswith(("pre_", "on_session_start", "subagent_start")) else "complete",
        "status": "error" if kwargs.get("error") else "ok",
        "input_size": len(raw_input),
        "output_size": len(raw_output),
        "input_hash": hashlib.sha256(raw_input.encode("utf-8", errors="replace")).hexdigest(),
        "output_hash": hashlib.sha256(raw_output.encode("utf-8", errors="replace")).hexdigest(),
        "redaction_status": "redacted-preview",
        "payload": {"hook": hook_name, "input_preview": _redact(raw_input), "output_preview": _redact(raw_output)},
    }


def _otlp_payload(event):
    attrs = []
    for key, value in {
        "agent.event_type": event["event_type"], "agent.name": "hermes",
        "agent.session_id": event["session_id"], "agent.turn_id": event["turn_id"],
        "agent.tool_call_id": event["tool_call_id"], "agent.tool_name": event["tool_name"],
        "agent.tool_type": event["tool_type"], "agent.phase": event["phase"], "agent.status": event["status"],
    }.items():
        attrs.append({"key": key, "value": {"stringValue": str(value)}})
    return {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "hermes-agent"}}]}, "scopeLogs": [{"scope": {"name": "agent-security-observer", "version": "4.2.10"}, "logRecords": [{"timeUnixNano": str(time.time_ns()), "severityText": "INFO", "body": {"stringValue": json.dumps(event, ensure_ascii=False, separators=(",", ":"))}, "attributes": attrs}]}]}]}


def _buffer(event):
    try:
        BUFFER.parent.mkdir(parents=True, exist_ok=True)
        if BUFFER.exists() and BUFFER.stat().st_size >= MAX_BUFFER_BYTES:
            rotated = BUFFER.with_name(BUFFER.name + ".1")
            rotated.unlink(missing_ok=True)
            BUFFER.replace(rotated)
        with BUFFER.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        try:
            os.chmod(BUFFER, 0o600)
        except OSError:
            pass
    except Exception:
        pass


def _worker():
    while True:
        event = _queue.get()
        try:
            data = json.dumps(_otlp_payload(event), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            request = Request(ENDPOINT, data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=0.2):
                pass
        except Exception:
            _buffer(event)
        finally:
            _queue.task_done()


def _ensure_worker():
    global _worker_started
    if _worker_started:
        return
    with _start_lock:
        if not _worker_started:
            threading.Thread(target=_worker, name="agent-security-hermes-observer", daemon=True).start()
            _worker_started = True


def _observe(hook_name, kwargs):
    try:
        _ensure_worker()
        _queue.put_nowait(_build_event(hook_name, kwargs))
    except Exception:
        pass
    return None


def register(ctx):
    for event_name in EVENTS:
        def callback(_event_name=event_name, **kwargs):
            return _observe(_event_name, kwargs)
        callback.__name__ = "observe_" + event_name
        ctx.register_hook(event_name, callback)
'''


def generate_hermes_plugin_manifest() -> str:
    return """name: agent-scan-observer
version: \"4.2.10\"
description: \"Observe-only OTLP/HTTP JSON telemetry for Agent Security Assessment.\"
author: agent-scan-platform
hooks:
  - on_session_start
  - on_session_end
  - pre_llm_call
  - post_llm_call
  - pre_tool_call
  - post_tool_call
  - subagent_start
  - subagent_stop
"""


# ── Install Plan 与能力生命周期 ────────────────────────────────

PROBE_MARKER_BEGIN = "# agent-scan-platform hermes probe begin"
PROBE_MARKER_END = "# agent-scan-platform hermes probe end"
PROBE_DISABLED_MARKER = "# agent-scan-platform hermes probe disabled"
PROBE_PLUGIN_NAME = "agent-scan-observer"
PROBE_HOOK_EVENTS = (
    "on_session_start",
    "on_session_end",
    "pre_llm_call",
    "post_llm_call",
    "pre_tool_call",
    "post_tool_call",
    "subagent_start",
    "subagent_stop",
)


def _default_command_runner(command: list[str]) -> tuple[int, str, str]:
    """Run a read-only Hermes capability command with a bounded timeout."""
    import subprocess

    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=2, check=False)
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


def _plugin_paths(config_path: Path) -> dict[str, Path]:
    plugin_dir = config_path.parent / "plugins" / PROBE_PLUGIN_NAME
    return {
        "dir": plugin_dir,
        "code": plugin_dir / "__init__.py",
        "manifest": plugin_dir / "plugin.yaml",
        "state": plugin_dir / "install-state.json",
    }


def _load_install_state(config_path: Path) -> dict[str, Any]:
    path = _plugin_paths(config_path)["state"]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _config_enables_plugin(config_path: Path) -> bool:
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(re.search(r"(?s)\bplugins\s*:.*?\benabled\s*:.*?agent-scan-observer", text))


def _run_hermes_plugin_command(config_path: Path, action: str) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["HERMES_HOME"] = str(config_path.parent)
    env["HERMES_CONFIG"] = str(config_path)
    command = ["hermes", "plugins", action, PROBE_PLUGIN_NAME]
    if action == "enable":
        command.append("--no-allow-tool-override")
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, check=False, env=env)
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", type(exc).__name__


def _strip_probe_marker(text: str) -> str:
    start, end = text.find(PROBE_MARKER_BEGIN), text.find(PROBE_MARKER_END)
    if start < 0 or end < start:
        return text
    end = text.find("\n", end)
    return (text[:start] + (text[end + 1 :] if end >= 0 else "")).rstrip() + "\n"


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
    paths = _plugin_paths(config) if config else {}
    plugin_files = bool(paths and paths["code"].is_file() and paths["manifest"].is_file())
    configured = bool(config and _config_enables_plugin(config))
    state = _load_install_state(config) if config else {}
    drifted = bool(state.get("managed_config_hash") and config and _file_hash(config) != state.get("managed_config_hash"))
    installed = marker_state == "enabled" and plugin_files and configured
    present = marker_state != "absent" or plugin_files
    status = "INSTALLED_HEALTHY" if installed and not drifted else "INSTALLED_DEGRADED" if present else "NOT_INSTALLED"
    return {
        "agent_type": "hermes",
        "status": status,
        "installed": installed,
        "capability_status": status if present else "SUPPORTED_FULL" if config else "NOT_INSTALLED",
        "config_path": str(config) if config else None,
        "marker_state": marker_state,
        "plugin_files_present": plugin_files,
        "plugin_enabled": configured,
        "drifted": drifted,
        "plugin_dir": str(paths.get("dir")) if paths else None,
        "evidence": evidence,
        "supports_apply": bool(config),
        "supports_uninstall": bool(config),
        "supports_rollback": bool(config),
        "supports_synthetic_self_test": bool(config),
        "transport": "otlp_http_json",
        "observe_only": True,
        "fail_open": True,
    }


def _file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _plan_id(config_path: Path, before_hash: str) -> str:
    return "hermes-plan-" + hashlib.sha256(f"{config_path}:{before_hash}".encode()).hexdigest()[:16]


def generate_install_plan(
    dry_run: bool = True,
    *,
    config_path: Path | str | None = None,
    command_runner: Any | None = None,
) -> dict[str, Any]:
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
    paths = _plugin_paths(config)
    capability = capability_probe(config_path=config, command_runner=command_runner)
    if capability["installed"]:
        return {
            "agent_type": "hermes", "install_status": capability["status"], "capability_status": capability["status"],
            "dry_run": True, "plan_id": _plan_id(config, before_hash), "target_config_path": str(config),
            "steps": [], "rollback": [], "note": "已发现本产品探针标记；仍需运行自测确认健康状态", "capability": capability,
        }
    steps = [
        {"action": "backup", "source": str(config), "target": str(backup), "before_hash": before_hash},
        {"action": "write_plugin", "target": str(paths["code"]), "content_hash": hashlib.sha256(generate_hermes_plugin_code().encode()).hexdigest()},
        {"action": "write_manifest", "target": str(paths["manifest"]), "content_hash": hashlib.sha256(generate_hermes_plugin_manifest().encode()).hexdigest()},
        {"action": "hermes_plugin_enable", "command": ["hermes", "plugins", "enable", PROBE_PLUGIN_NAME, "--no-allow-tool-override"], "target": str(config), "timeout_seconds": 15},
        {"action": "synthetic_self_test", "description": "编译插件并校验 manifest/注册事件；不发送真实用户 Prompt"},
    ]
    rollback = [
        {"action": "restore_config", "source": str(backup), "target": str(config)},
        {"action": "delete_directory", "target": str(paths["dir"])},
    ]
    return {
        "agent_type": "hermes", "install_status": "SUPPORTED_FULL", "capability_status": "SUPPORTED_FULL",
        "dry_run": True, "plan_id": _plan_id(config, before_hash), "target_config_path": str(config),
        "backup_path": str(backup), "plugin_path": str(paths["code"]), "plugin_dir": str(paths["dir"]), "manifest_path": str(paths["manifest"]), "before_hash": before_hash,
        "steps": steps, "rollback": rollback, "hooks_exist": False, "capability": capability,
        "observe_only": True, "fail_open": True, "callback_budget_ms": 50, "network_timeout_ms": 200,
    }


def _probe_config_block(disabled: bool = False) -> str:
    lines = [PROBE_MARKER_BEGIN]
    if disabled:
        lines.append(PROBE_DISABLED_MARKER)
    lines.extend(["# plugin: " + PROBE_PLUGIN_NAME, "# lifecycle events: " + ", ".join(PROBE_HOOK_EVENTS), "# observe_only: true; fail_open: true; network_timeout_ms: 200", PROBE_MARKER_END])
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
    plugin_dir = Path(plan["plugin_dir"])
    plugin_path = Path(plan["plugin_path"])
    manifest_path = Path(plan["manifest_path"])
    backup.write_bytes(config.read_bytes())
    try:
        plugin_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(plugin_path, generate_hermes_plugin_code())
        _write_atomic(manifest_path, generate_hermes_plugin_manifest())
        code, _stdout, _stderr = _run_hermes_plugin_command(config, "enable")
        if code != 0 or not _config_enables_plugin(config):
            raise RuntimeError(f"Hermes plugin enable failed with exit code {code}")
        current = _strip_probe_marker(config.read_text(encoding="utf-8"))
        _write_atomic(config, current.rstrip() + "\n" + _probe_config_block())
        install_state = {
            "schema": "agent-security-hermes-probe-install@4.2.10",
            "plan_id": plan["plan_id"],
            "before_hash": plan.get("before_hash"),
            "backup_path": str(backup),
            "collector_url": plan.get("collector_url") or "http://127.0.0.1:4318/v1/logs",
            "enabled": True,
            "installed_at": utc_now(),
        }
        install_state["managed_config_hash"] = _file_hash(config)
        _write_atomic(_plugin_paths(config)["state"], json.dumps(install_state, ensure_ascii=False, indent=2))
        self_test = run_synthetic_self_test(config_path=config)
        if not self_test["passed"]:
            raise RuntimeError("Hermes plugin synthetic self-test failed")
    except Exception:
        if backup.exists():
            _write_atomic(config, backup.read_text(encoding="utf-8"))
        shutil.rmtree(plugin_dir, ignore_errors=True)
        raise
    return {"status": "INSTALLED_HEALTHY", "plan_id": plan["plan_id"], "config_path": str(config), "plugin_dir": str(plugin_dir), "self_test": self_test, "observe_only": True}


def run_synthetic_self_test(*, config_path: Path | str) -> dict[str, Any]:
    """Compile the installed plugin and verify registration metadata without Agent data."""
    config = Path(config_path)
    state = _probe_marker_state(config)
    paths = _plugin_paths(config)
    checks = {
        "marker_enabled": state == "enabled",
        "plugin_enabled": _config_enables_plugin(config),
        "code_present": paths["code"].is_file(),
        "manifest_present": paths["manifest"].is_file(),
        "all_events_declared": False,
        "python_compiles": False,
    }
    try:
        code = paths["code"].read_text(encoding="utf-8")
        compile(code, str(paths["code"]), "exec")
        checks["python_compiles"] = True
        manifest = paths["manifest"].read_text(encoding="utf-8")
        checks["all_events_declared"] = all(event in manifest and event in code for event in PROBE_HOOK_EVENTS)
    except (OSError, SyntaxError):
        pass
    passed = all(checks.values())
    return {"passed": passed, "status": "INSTALLED_HEALTHY" if passed else "INSTALLED_DEGRADED", "event_type": "probe.health", "synthetic": True, "checks": checks, "network_sent": False, "user_prompt_used": False}


def disable_probe(*, config_path: Path | str) -> dict[str, Any]:
    config = Path(config_path)
    code, _stdout, _stderr = _run_hermes_plugin_command(config, "disable")
    if code != 0:
        raise RuntimeError(f"Hermes plugin disable failed with exit code {code}")
    text = _strip_probe_marker(config.read_text(encoding="utf-8"))
    _write_atomic(config, text.rstrip() + "\n" + _probe_config_block(disabled=True))
    state = _load_install_state(config)
    state.update({"enabled": False, "disabled_at": utc_now(), "managed_config_hash": _file_hash(config)})
    _write_atomic(_plugin_paths(config)["state"], json.dumps(state, ensure_ascii=False, indent=2))
    return {"status": "INSTALLED_DEGRADED", "enabled": False, "observe_only": True}


def uninstall_probe(*, config_path: Path | str) -> dict[str, Any]:
    config = Path(config_path)
    paths = _plugin_paths(config)
    state = _load_install_state(config)
    backup = Path(str(state.get("backup_path") or config.with_name(config.name + ".agent_scan_probe_backup")))
    managed = str(state.get("managed_config_hash") or "")
    exact_restore = bool(backup.is_file() and managed and _file_hash(config) == managed)
    if exact_restore:
        _write_atomic(config, backup.read_text(encoding="utf-8"))
    else:
        _run_hermes_plugin_command(config, "disable")
        _write_atomic(config, _strip_probe_marker(config.read_text(encoding="utf-8")))
    shutil.rmtree(paths["dir"], ignore_errors=True)
    return {"status": "NOT_INSTALLED", "enabled": False, "exact_config_restored": exact_restore, "drift_preserved": not exact_restore}


def rollback_install(plan: dict[str, Any]) -> dict[str, Any]:
    config, backup = Path(plan["target_config_path"]), Path(plan["backup_path"])
    if not backup.is_file():
        raise ValueError("rollback backup is unavailable")
    _write_atomic(config, backup.read_text(encoding="utf-8"))
    shutil.rmtree(Path(plan["plugin_dir"]), ignore_errors=True)
    return {"status": "NOT_INSTALLED", "rolled_back": True, "exact_config_restored": True}


def repair_probe(*, config_path: Path | str) -> dict[str, Any]:
    config = Path(config_path)
    paths = _plugin_paths(config)
    if not paths["code"].is_file() or not paths["manifest"].is_file():
        raise ValueError("installed Hermes probe files are unavailable; generate a new plan")
    code, _stdout, _stderr = _run_hermes_plugin_command(config, "enable")
    if code != 0:
        raise RuntimeError(f"Hermes plugin repair failed with exit code {code}")
    text = _strip_probe_marker(config.read_text(encoding="utf-8"))
    _write_atomic(config, text.rstrip() + "\n" + _probe_config_block())
    state = _load_install_state(config)
    state.update({"enabled": True, "repaired_at": utc_now(), "managed_config_hash": _file_hash(config)})
    _write_atomic(paths["state"], json.dumps(state, ensure_ascii=False, indent=2))
    result = run_synthetic_self_test(config_path=config)
    if not result["passed"]:
        raise RuntimeError("Hermes plugin repair self-test failed")
    return result


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
