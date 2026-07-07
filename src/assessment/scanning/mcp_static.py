from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlparse

from ..store import utc_now
from .redaction import redact_text, stable_hash


def mcp_static_risks(server: dict[str, Any]) -> list[dict[str, Any]]:
    command = str(server.get("command") or "")
    args = [str(arg) for arg in server.get("args") or []]
    url = str(server.get("url") or "")
    env_keys = [str(key) for key in server.get("env_keys") or server.get("envKeys") or []]
    text = " ".join([command, *args, url]).lower()
    risks: list[dict[str, Any]] = []

    def add(
        rule: str,
        title: str,
        severity: str,
        risk_class: str,
        confidence: float,
        evidence: str,
        fix: str,
        labels: list[str],
    ) -> None:
        if rule in {item["rule"] for item in risks}:
            return
        risks.append(
            {
                "rule": rule,
                "title": title,
                "severity": severity,
                "class": risk_class,
                "confidence": confidence,
                "summary": title,
                "evidence": redact_text(evidence),
                "fix": fix,
                "labels": labels,
            }
        )

    parsed = urlparse(url) if url else None
    host = parsed.hostname if parsed else ""
    scheme = (parsed.scheme or "").lower() if parsed else ""

    if str(server.get("transport")) == "stdio":
        add(
            "MCP-STDIO-CONSENT-001",
            "stdio MCP Server 需要人工审批，检查阶段不得自动启动",
            "中危 P2",
            "medium",
            0.86,
            command or str(server.get("name")),
            "保持默认拒绝；只有人工确认命令、配置哈希和任务上下文后才允许一次性启动。",
            ["stdio", "consent_required"],
        )
    if any(token in text for token in ["powershell", "cmd.exe", " bash", " sh ", "iex", "invoke-expression", " iwr ", "curl ", "|"]):
        add(
            "MCP-CMD-001",
            "MCP stdio Server 使用高风险命令外壳或管道执行",
            "高危 P1",
            "high",
            0.92,
            " ".join([command, *args])[:260],
            "固定可审计的可执行文件路径，禁止 shell 管道、远程脚本和隐式解释器启动。",
            ["shell_exec", "process_spawn"],
        )
    if any(token in text for token in ["npx", "uvx", "pipx", "npm ", "pnpm dlx", " -y "]):
        add(
            "MCP-SUPPLYCHAIN-001",
            "MCP 启动命令可能动态下载并执行外部包",
            "高危 P1",
            "high",
            0.88,
            " ".join([command, *args])[:260],
            "固定包版本、校验哈希，并在隔离环境中预安装，不允许运行时下载执行。",
            ["package_download", "process_spawn"],
        )
    if any(token in text for token in ["http://", "https://", "webhook", "upload", "send_report"]):
        add(
            "MCP-NET-001",
            "MCP 配置或参数包含外部网络目标",
            "高危 P1" if "http://" in text else "中危 P2",
            "high" if "http://" in text else "medium",
            0.84,
            " ".join([url, *args])[:260],
            "Remote MCP 必须使用 HTTPS allowlist；stdio 参数不得直接包含未批准外传地址。",
            ["network_send"],
        )
    if scheme == "http":
        add(
            "MCP-REMOTE-HTTP-001",
            "Remote MCP 使用明文 HTTP",
            "高危 P1",
            "high",
            0.9,
            url,
            "Remote MCP 必须使用 HTTPS，并绑定企业 allowlist 与认证策略。",
            ["network_send", "remote_mcp"],
        )
    if host and is_private_mcp_host(host):
        add(
            "MCP-REMOTE-PRIVATE-001",
            "Remote MCP 指向本机或私网地址",
            "高危 P1",
            "high",
            0.88,
            host,
            "对 localhost、链路本地、私网和内网域名启用显式审批，避免 SSRF 与边界绕过。",
            ["network_send", "ssrf"],
        )
    if (parsed and (parsed.username or parsed.password)) or server.get("url_has_credentials"):
        add(
            "MCP-REMOTE-CREDENTIAL-001",
            "Remote MCP URL 内嵌认证信息",
            "中危 P2",
            "medium",
            0.86,
            url,
            "URL 中不要嵌入账号或 Token；改用 Secret Reference 和短期凭据。",
            ["secret_env", "remote_mcp"],
        )
    if any(any(marker in key.upper() for marker in ["TOKEN", "SECRET", "PASSWORD", "KEY"]) for key in env_keys):
        add(
            "MCP-ENV-SECRET-001",
            "MCP Server 环境变量包含敏感键名",
            "高危 P1",
            "high",
            0.9,
            ",".join(env_keys),
            "最小化传入环境变量；敏感 Token 使用短期凭据并在证据与日志中脱敏。",
            ["secret_env"],
        )
    if any(token in text for token in ["filesystem", "read_file", "write_file", "workspace", ":\\", "/workspace", "~/."]):
        add(
            "MCP-FS-BOUNDARY-001",
            "MCP Server 具备文件系统或工作区访问能力",
            "中危 P2",
            "medium",
            0.8,
            " ".join([command, *args])[:260],
            "限制根目录到测评工作区；对写入和敏感路径读取启用二次确认。",
            ["file_read", "file_write"],
        )
    if not risks:
        add(
            "MCP-STATIC-PASS-001",
            "MCP 配置静态检查未发现高风险启动特征",
            "低危 P3",
            "low",
            0.68,
            str(server.get("name") or server.get("id")),
            "保持周期性复检；配置哈希变化后重新审批。",
            ["config_only"],
        )
    return risks


def is_private_mcp_host(host: str) -> bool:
    normalized = host.strip("[]").lower()
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    if normalized.endswith(".local") or normalized.endswith(".internal") or normalized.endswith(".lan"):
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def highest_mcp_risk(risks: list[dict[str, Any]]) -> dict[str, str]:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "gray": 0}
    labels = {"critical": "严重", "high": "高", "medium": "需审批", "low": "低", "gray": "未知"}
    risk_class = max((risk.get("class", "gray") for risk in risks), key=lambda value: order.get(str(value), 0), default="gray")
    return {"class": str(risk_class), "label": labels.get(str(risk_class), "未知")}


def derive_mcp_tools(server: dict[str, Any], risks: list[dict[str, Any]], checked_at: str) -> list[dict[str, Any]]:
    labels = sorted({label for risk in risks for label in risk.get("labels", [])})
    name = str(server.get("name") or server.get("id") or "mcp")
    server_id = str(server.get("id") or name)
    specs: list[tuple[str, str, list[str], str, str]] = []
    if "file_read" in labels or "file_write" in labels:
        specs.append(("read_workspace", "读取或枚举工作区文件。", ["file_read", "private_data"], "高", "high"))
    if "shell_exec" in labels or "process_spawn" in labels:
        specs.append(("spawn_process", "启动本地命令或解释器。", ["shell_exec", "process_spawn"], "高", "high"))
    if "network_send" in labels:
        specs.append(("network_request", "访问外部网络或上传数据。", ["network_send", "external_sink"], "高", "high"))
    if "secret_env" in labels:
        specs.append(("read_environment", "读取传入 MCP Server 的环境变量键。", ["secret_env"], "高", "high"))
    if "package_download" in labels:
        specs.append(("runtime_package", "运行时下载并执行包入口。", ["package_download", "supply_chain"], "高", "high"))
    if "ssrf" in labels:
        specs.append(("ssrf_boundary", "访问本机、私网或内网 Remote MCP 目标。", ["network_send", "ssrf"], "高", "high"))
    if not specs:
        specs.append(("inspect_config", "静态解析 MCP 配置和签名。", ["config_only"], "低", "low"))

    tools: list[dict[str, Any]] = []
    for suffix, desc, tool_labels, risk, risk_class in specs:
        tool_name = f"{name}.{suffix}"
        tools.append(
            {
                "id": "tool_" + stable_hash(f"{server_id}:{suffix}", 20),
                "name": tool_name,
                "server": name,
                "server_id": server_id,
                "desc": desc,
                "labels": tool_labels,
                "risk": risk,
                "riskClass": risk_class,
                "status": "STATIC_ONLY",
                "source": "mcp-static-inspect",
                "signature": "static:" + stable_hash(json.dumps({"server": server_id, "tool": suffix, "labels": tool_labels}, sort_keys=True), 12),
                "safe_mode": "local-readonly",
                "created_at": checked_at,
            }
        )
    return tools


def sanitize_mcp_server(server: dict[str, Any]) -> dict[str, Any]:
    clean = dict(server)
    if "command" in clean:
        clean["command"] = redact_text(str(clean.get("command") or ""))
    if "args" in clean:
        clean["args"] = [redact_text(str(arg)) for arg in clean.get("args") or []]
    if "url" in clean:
        clean["url"] = redact_text(str(clean.get("url") or ""))
    clean.pop("env", None)
    return clean


def tool_flows(item: dict[str, Any], server: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    name = item.get("name") or item.get("id") or "tool"
    tool_id = str(item.get("id") or "tool_" + stable_hash(str(name), 20))
    server_id = str(item.get("server_id") or (server or {}).get("id") or "")
    server_name = str(item.get("server") or (server or {}).get("name") or "")
    labels = set(item.get("labels") or [])
    created_at = item.get("created_at") or (server or {}).get("inspected_at") or utc_now()
    flows: list[dict[str, Any]] = []

    def add_flow(
        kind: str,
        display: str,
        risk: str,
        risk_class: str,
        status: str,
        source: str,
        sink: str,
        control: str,
        policy: str,
        matched_labels: list[str],
    ) -> None:
        flows.append(
            {
                "id": "flow_" + stable_hash(f"{tool_id}:{kind}", 20),
                "tool_id": tool_id,
                "tool": name,
                "server_id": server_id,
                "server": server_name,
                "kind": kind,
                "name": display,
                "risk": risk,
                "riskClass": risk_class,
                "status": status,
                "source": source,
                "sink": sink,
                "control": control,
                "policy": policy,
                "labels": matched_labels,
                "safe_mode": "local-readonly",
                "mutates_installed_agents": False,
                "mcp_started": False,
                "external_process_started": False,
                "source_detector": "mcp-static-inspect",
                "created_at": created_at,
            }
        )

    if labels & {"file_read", "private_data"}:
        add_flow("private_read", f"{name} -> workspace/private data", "高", "high", "需审批", "workspace", "agent context", "path allowlist", "deny-sensitive-paths", sorted(labels & {"file_read", "private_data"}))
    if labels & {"network_send", "external_sink"}:
        add_flow("external_send", f"{name} -> external network sink", "高", "high", "默认阻断", "agent context", "external", "domain allowlist", "https-allowlist-required", sorted(labels & {"network_send", "external_sink"}))
    if labels & {"shell_exec", "process_spawn"}:
        add_flow("process_exec", f"{name} -> local process", "高", "high", "默认阻断", "tool call", "subprocess", "human consent", "subprocess-deny-by-default", sorted(labels & {"shell_exec", "process_spawn"}))
    if labels & {"secret_env"}:
        add_flow("secret_env", f"{name} -> secret environment", "高", "high", "脱敏", "env", "mcp server", "env deny patterns", "redact-before-persist", ["secret_env"])
    if labels & {"package_download", "supply_chain"}:
        add_flow("runtime_package", f"{name} -> runtime package execution", "高", "high", "默认阻断", "package registry", "local process", "pinned package allowlist", "no-runtime-download", sorted(labels & {"package_download", "supply_chain"}))
    if labels & {"ssrf"}:
        add_flow("remote_private", f"{name} -> private remote endpoint", "高", "high", "默认阻断", "remote url", "private network", "ssrf allowlist", "deny-private-remote-mcp", ["ssrf"])
    if not flows:
        add_flow("config_only", f"{name} static config flow", "低", "low", "允许", "config", "signature", "readonly", "local-readonly", ["config_only"])
    return flows
