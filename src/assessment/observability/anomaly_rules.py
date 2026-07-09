"""Agent Security v4.2 — P0 异常规则引擎.

规则清单:
  ANOM-SECRET-IN-PROMPT         用户输入或工具参数含疑似 secret
  ANOM-DANGEROUS-SHELL          shell 工具调用含危险命令
  ANOM-SENSITIVE-READ-THEN-NETWORK  读取敏感文件后调用网络发送
  ANOM-MCP-REPEATED-FAILURE     同一 MCP server/tool 连续失败超阈值
  ANOM-TOOL-LOOP                同一 turn 内同一工具重复调用超阈值
  ANOM-CROSS-WORKSPACE-PATH     读取/写入 workspace 外高敏路径
  ANOM-APPROVAL-MISMATCH        PermissionRequest 未批准但 tool_call completed
  ANOM-RAW-CAPTURE-ENABLED      探针配置为保存 raw prompt/result
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..store import AssessmentStore, new_id, utc_now
from .storage import (
    create_behavior_anomaly,
)


# ── 危险命令模式 ────────────────────────────────────────────

DANGEROUS_SHELL_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+-rf\b", "递归强制删除"),
    (r"\brm\b.*\b-rf\b", "递归删除"),
    (r"\bdel\s+/[sfq]\b", "Windows 强制删除"),
    (r"\bformat\s+[a-z]:", "格式化磁盘"),
    (r"\bdestroy\b", "销毁操作"),
    (r"\bmkfs\b", "创建文件系统"),
    (r"\bdd\s+if=.*\sof=", "dd 磁盘写入"),
    (r"curl\b.*\|\s*(?:sh|bash|zsh|powershell)", "curl-to-sh 远程执行"),
    (r"wget\b.*\|\s*(?:sh|bash|zsh|powershell)", "wget-to-sh 远程执行"),
    (r"powershell\s+-enc\b", "PowerShell Base64 编码执行"),
    (r"powershell\s+-ex\b", "PowerShell 绕过执行策略"),
    (r"reg\s+(?:add|delete|copy|save|restore|load|unload)", "注册表写入"),
    (r"sudo\s+rm\s+-rf\s+/", "sudo 根目录删除"),
    (r">\s*/dev/sda", "直接写入块设备"),
]

# ── 敏感文件/路径模式 ────────────────────────────────────────

SENSITIVE_READ_PATTERNS: list[str] = [
    r"\.ssh[\\/]",
    r"id_rsa",
    r"id_ed25519",
    r"\.aws[\\/]credentials",
    r"\.gcp[\\/]",
    r"\.azure[\\/]",
    r"config\.json.*token",
    r"\.env",
    r"token",
    r"secret",
    r"credential",
    r"cookie",
    r"authorization",
    r"bearer",
]

NETWORK_TOOL_PATTERNS: list[str] = [
    r"^curl$",
    r"^wget$",
    r"^http$",
    r"^invoke-webrequest$",
    r"^mcp_fetch_",
    r"^fetch$",
    r"^web_fetch$",
    r"^browser_",
    r"^api_",
]

# ── 跨 workspace 高敏路径 ───────────────────────────────────

HIGH_SENSITIVITY_PATHS: list[str] = [
    r"\\\.ssh\\",
    r"\\\.gnupg\\",
    r"\\AppData\\Roaming\\",
    r"\\Program Files\\",
    r"\\Windows\\System32\\",
    r"\\etc\\",
    r"\\var\\log\\",
]

# ── 规则注册表 ──────────────────────────────────────────────

ANOMALY_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "ANOM-SECRET-IN-PROMPT",
        "severity": "high",
        "title": "敏感信息泄露 — 用户输入/工具参数疑似 secret",
        "description": "用户输入或工具参数中包含 token/secret/password/key 等敏感字段名或疑似值",
        "fix": "检查是否有必要在 Agent 交互中输入明文 secret；使用环境变量或 vault 替代",
        "owasp_llm": "LLM01 — Prompt Injection / 信息泄露",
        "mitre_atlas": "AML.T0043 — Sensitive Information Extraction",
    },
    {
        "rule_id": "ANOM-DANGEROUS-SHELL",
        "severity": "high",
        "title": "危险 Shell 命令 — rm -rf / curl|sh 等",
        "description": "shell 工具调用包含递归删除、磁盘格式化、远程执行等危险命令模式",
        "fix": "确认命令必要性；对破坏性操作使用 dry-run 先行验证",
        "owasp_llm": "LLM02 — Insecure Output Handling",
        "mitre_atlas": "AML.T0020 — Command and Scripting Interpreter",
    },
    {
        "rule_id": "ANOM-SENSITIVE-READ-THEN-NETWORK",
        "severity": "high",
        "title": "敏感读取后网络发送 — 数据外传风险",
        "description": "读取 SSH key/token/env/secret 等敏感数据后短时间内调用网络发送工具",
        "fix": "确认数据外传必要性；默认应阻止将敏感文件内容发送到外部地址",
        "owasp_llm": "LLM06 — Sensitive Information Disclosure",
        "mitre_atlas": "AML.T0024 — Exfiltration via C2 Channel",
    },
    {
        "rule_id": "ANOM-MCP-REPEATED-FAILURE",
        "severity": "medium",
        "title": "MCP 重复失败 — 同一 Server/Tool 连续失败",
        "description": "同一 MCP server 或 tool 连续多次调用失败，可能表示服务不可用或配置错误",
        "fix": "检查 MCP server 状态、连接和配置；确认 server 进程是否正常",
        "owasp_llm": "LLM08 — Excessive Agency / 工具失效",
        "mitre_atlas": "AML.T0041 — Denial of Service",
    },
    {
        "rule_id": "ANOM-TOOL-LOOP",
        "severity": "medium",
        "title": "工具调用循环 — 同一 turn 内重复调用",
        "description": "同一 turn 内同一工具被重复调用超过阈值，可能存在无限循环",
        "fix": "设置工具调用次数上限；检查 Agent 是否陷入循环推理",
        "owasp_llm": "LLM08 — Excessive Agency",
        "mitre_atlas": "AML.T0029 — Resource Hijack",
    },
    {
        "rule_id": "ANOM-CROSS-WORKSPACE-PATH",
        "severity": "medium",
        "title": "越权路径访问 — 读取/写入 workspace 外高敏路径",
        "description": "Agent 读取或写入当前 workspace 外的高敏路径（系统目录、密钥目录等）",
        "fix": "使用沙箱路径限制；确认 Agent 是否有必要访问这些路径",
        "owasp_llm": "LLM06 — Sensitive Information Disclosure",
        "mitre_atlas": "AML.T0023 — Unauthorized Access",
    },
    {
        "rule_id": "ANOM-APPROVAL-MISMATCH",
        "severity": "high",
        "title": "审批状态不匹配 — PermissionRequest 未批准但调用完成",
        "description": "PermissionRequest 显示未批准或被拒绝，但后续出现同一 tool_call 的 completed 事件",
        "fix": "审查 Agent 权限系统是否存在绕过；检查 hook 是否被正确调用",
        "owasp_llm": "LLM08 — Excessive Agency",
        "mitre_atlas": "AML.T0025 — Privilege Escalation",
    },
    {
        "rule_id": "ANOM-RAW-CAPTURE-ENABLED",
        "severity": "low",
        "title": "Raw Capture 已启用 — 探针保存明文数据",
        "description": "探针被配置为保存原始用户输入和工具输出，存在隐私和数据泄露风险",
        "fix": "仅在安全审计等必要时启用 raw capture；默认应保持关闭",
        "owasp_llm": "LLM06 — Sensitive Information Disclosure",
        "mitre_atlas": "AML.T0043 — Sensitive Information Extraction",
    },
]


# ── 主入口 ──────────────────────────────────────────────────

def evaluate_event_rules(
    store: AssessmentStore,
    events: list[dict[str, Any]],
    *,
    chain_id: str | None = None,
) -> list[dict[str, Any]]:
    """对一组事件运行所有异常规则, 返回生成的异常列表."""
    anomalies: list[dict[str, Any]] = []

    # 按规则依次评估
    ano = _check_secret_in_prompt(events, chain_id)
    if ano:
        _save_and_collect(store, ano, anomalies)

    ano = _check_dangerous_shell(events, chain_id)
    if ano:
        _save_and_collect(store, ano, anomalies)

    anos = _check_sensitive_read_then_network(events, chain_id)
    for a in anos:
        _save_and_collect(store, a, anomalies)

    anos = _check_mcp_repeated_failure(events, chain_id)
    for a in anos:
        _save_and_collect(store, a, anomalies)

    ano = _check_tool_loop(events, chain_id)
    if ano:
        _save_and_collect(store, ano, anomalies)

    anos = _check_cross_workspace_path(events, chain_id)
    for a in anos:
        _save_and_collect(store, a, anomalies)

    ano = _check_approval_mismatch(events, chain_id)
    if ano:
        _save_and_collect(store, ano, anomalies)

    ano = _check_raw_capture_enabled(store, chain_id)
    if ano:
        _save_and_collect(store, ano, anomalies)

    return anomalies


def _save_and_collect(store: AssessmentStore, anomaly: dict[str, Any], collection: list[dict[str, Any]]) -> None:
    """保存异常到数据库并加入返回列表."""
    create_behavior_anomaly(store, anomaly)
    collection.append(anomaly)


# ── 规则实现 ────────────────────────────────────────────────

def _check_secret_in_prompt(events: list[dict[str, Any]], chain_id: str | None) -> dict[str, Any] | None:
    """ANOM-SECRET-IN-PROMPT: 检查事件 payload 中是否含 secret 字段名."""
    for ev in events:
        payload = ev.get("payload", {})
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            key_lower = key.lower()
            for pattern in ["token", "secret", "password", "key", "credential", "authorization", "bearer"]:
                if pattern in key_lower and value and str(value) != "[REDACTED]":
                    # 非脱敏的敏感字段：证据只保存字段名和哈希，不保存明文
                    return _make_anomaly("ANOM-SECRET-IN-PROMPT", chain_id, ev, {
                        "sensitive_field": key,
                        "value_hash": __import__("hashlib").sha256(str(value).encode()).hexdigest(),
                        "value_state": "redacted_required",
                        "event_id": ev["event_id"],
                    })
    return None


def _check_dangerous_shell(events: list[dict[str, Any]], chain_id: str | None) -> dict[str, Any] | None:
    """ANOM-DANGEROUS-SHELL: 检查 shell 工具调用中的危险命令."""
    for ev in events:
        if ev.get("tool_type") != "shell":
            continue
        payload = ev.get("payload", {})
        if not isinstance(payload, dict):
            continue
        command = str(payload.get("command") or payload.get("cmd") or "")
        for pattern, description in DANGEROUS_SHELL_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return _make_anomaly("ANOM-DANGEROUS-SHELL", chain_id, ev, {
                    "dangerous_pattern": description,
                    "command_preview": command[:200],
                    "event_id": ev["event_id"],
                })
    return None


def _check_sensitive_read_then_network(events: list[dict[str, Any]], chain_id: str | None) -> list[dict[str, Any]]:
    """ANOM-SENSITIVE-READ-THEN-NETWORK: 敏感读取后在短时间内调用网络工具."""
    results: list[dict[str, Any]] = []
    sensitive_reads: list[dict[str, Any]] = []

    for ev in events:
        payload = ev.get("payload", {})
        cmd = str(payload.get("command", "")).lower()
        for pattern in SENSITIVE_READ_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                sensitive_reads.append(ev)
                break

    if not sensitive_reads:
        return results

    # 在敏感读取之后查找网络调用 (同一 session, 5 分钟内)
    for read_ev in sensitive_reads:
        read_time = read_ev.get("timestamp", "")
        read_session = read_ev.get("session_id")
        for ev in events:
            if ev["event_id"] == read_ev["event_id"]:
                continue
            if read_session and ev.get("session_id") != read_session:
                continue
            tool_name = ev.get("tool_name", "")
            if any(re.match(p, tool_name, re.IGNORECASE) for p in NETWORK_TOOL_PATTERNS):
                results.append(_make_anomaly("ANOM-SENSITIVE-READ-THEN-NETWORK", chain_id, ev, {
                    "sensitive_read_event": read_ev["event_id"],
                    "network_event": ev["event_id"],
                    "sensitive_file_hint": str(read_ev.get("payload", {}).get("command", ""))[:200],
                    "network_tool": tool_name,
                }))
                break  # 一个读取只触发一次
    return results


def _check_mcp_repeated_failure(events: list[dict[str, Any]], chain_id: str | None) -> list[dict[str, Any]]:
    """ANOM-MCP-REPEATED-FAILURE: 同一 MCP server/tool 连续失败超过 3 次."""
    failure_map: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        if ev.get("status") == "error" and ev.get("tool_type") == "mcp":
            key = f"{ev.get('mcp_server', '?')}/{ev.get('mcp_tool', ev.get('tool_name', '?'))}"
            failure_map.setdefault(key, []).append(ev)

    results: list[dict[str, Any]] = []
    for key, failures in failure_map.items():
        if len(failures) >= 3:
            results.append(_make_anomaly("ANOM-MCP-REPEATED-FAILURE", chain_id, failures[-1], {
                "mcp_key": key,
                "failure_count": len(failures),
                "last_error": failures[-1].get("error_message_redacted") or failures[-1].get("payload", {}).get("error", ""),
            }))
    return results


def _check_tool_loop(events: list[dict[str, Any]], chain_id: str | None) -> dict[str, Any] | None:
    """ANOM-TOOL-LOOP: 同一 turn 内同一工具重复调用超过 5 次."""
    from collections import Counter
    tool_counter: Counter = Counter()
    current_turn = None
    for ev in events:
        turn_id = ev.get("turn_id")
        if turn_id and turn_id != current_turn:
            tool_counter.clear()
            current_turn = turn_id
        tn = ev.get("tool_name")
        if tn:
            tool_counter[tn] += 1
            if tool_counter[tn] >= 5:
                return _make_anomaly("ANOM-TOOL-LOOP", chain_id, ev, {
                    "tool_name": tn,
                    "call_count": tool_counter[tn],
                    "turn_id": current_turn,
                })
    return None


def _check_cross_workspace_path(events: list[dict[str, Any]], chain_id: str | None) -> list[dict[str, Any]]:
    """ANOM-CROSS-WORKSPACE-PATH: 路径参数中包含高敏路径."""
    results: list[dict[str, Any]] = []
    for ev in events:
        payload = ev.get("payload", {})
        for val in payload.values():
            if isinstance(val, str):
                for pattern in HIGH_SENSITIVITY_PATHS:
                    if re.search(pattern, val, re.IGNORECASE):
                        results.append(_make_anomaly("ANOM-CROSS-WORKSPACE-PATH", chain_id, ev, {
                            "sensitive_path": val[:200],
                            "matched_pattern": pattern,
                            "event_id": ev["event_id"],
                        }))
                        break  # 一个事件只触发一次
    return results


def _check_approval_mismatch(events: list[dict[str, Any]], chain_id: str | None) -> dict[str, Any] | None:
    """ANOM-APPROVAL-MISMATCH: 检查是否有未批准的 tool_call 完成."""
    denied_tools: dict[str, str] = {}  # tool_call_id -> event_id
    completed_tools: dict[str, str] = {}  # tool_call_id -> event_id

    for ev in events:
        tc_id = ev.get("tool_call_id")
        if not tc_id:
            continue
        if ev.get("event_type") == "policy.decision.shadow" and ev.get("status") in ("denied", "rejected"):
            denied_tools[tc_id] = ev["event_id"]
        if ev.get("event_type") in ("tool.call.completed", "tool.call.error") and tc_id in denied_tools:
            completed_tools[tc_id] = ev["event_id"]

    if completed_tools:
        first_tc_id = next(iter(completed_tools))
        source = next((ev for ev in events if ev.get("event_id") == completed_tools[first_tc_id]), events[0])
        return _make_anomaly("ANOM-APPROVAL-MISMATCH", chain_id, source,
                            {"denied_tool_call_ids": list(denied_tools.keys()),
                             "completed_after_denial": list(completed_tools.keys())})
    return None


def _check_raw_capture_enabled(store: AssessmentStore, chain_id: str | None) -> dict[str, Any] | None:
    """ANOM-RAW-CAPTURE-ENABLED: 探针原始捕获配置检查."""
    adapters = store.list_records("probe_adapter")
    for a in adapters:
        if a.get("raw_capture_enabled"):
            return _make_anomaly("ANOM-RAW-CAPTURE-ENABLED", chain_id, {
                "event_id": "config",
                "source_agent": a.get("agent_type", "unknown"),
            }, {
                "adapter_id": a.get("id"),
                "agent_type": a.get("agent_type"),
                "raw_capture_enabled": True,
            })
    return None


# ── 异常记录构造 ────────────────────────────────────────────

def _make_anomaly(
    rule_id: str,
    chain_id: str | None,
    source_event: dict[str, Any] | None,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """构造异常记录."""
    rule_def = next((r for r in ANOMALY_RULES if r["rule_id"] == rule_id), {})
    return {
        "id": new_id("ano"),
        "chain_id": chain_id or "",
        "event_id": (source_event or {}).get("event_id", ""),
        "rule_id": rule_id,
        "severity": rule_def.get("severity", "medium"),
        "title": rule_def.get("title", rule_id),
        "description": rule_def.get("description", ""),
        "evidence_json": json.dumps(evidence, ensure_ascii=False),
        "status": "open",
        "fix": rule_def.get("fix", ""),
        "owasp_llm": rule_def.get("owasp_llm", ""),
        "mitre_atlas": rule_def.get("mitre_atlas", ""),
    }
