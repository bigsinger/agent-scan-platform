from __future__ import annotations

import json
from html import escape
from typing import Any

from ..store import AssessmentStore, new_id, utc_now


class ReportRenderer:
    def __init__(self, store: AssessmentStore) -> None:
        self.store = store

    def create_report(
        self,
        assessment: dict[str, Any],
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        discovery: dict[str, Any] | None = None,
        report_type: str = "Standard",
    ) -> dict[str, Any]:
        report_id = new_id("rpt")
        snapshot = {
            "report_id": report_id,
            "assessment": assessment,
            "findings": findings,
            "evidence": evidence,
            "discovery": discovery or {},
            "generated_at": utc_now(),
            "report_type": report_type,
            "summary": summarize(findings),
        }
        json_text = json.dumps(snapshot, ensure_ascii=False, indent=2)
        json_artifact = self.store.write_artifact(
            "report-json",
            json_text,
            suffix="json",
            directory="reports",
            metadata={"assessment_id": assessment["id"], "report_id": report_id},
        )
        html_text = render_html(snapshot)
        html_artifact = self.store.write_artifact(
            "report-html",
            html_text,
            suffix="html",
            directory="reports",
            metadata={"assessment_id": assessment["id"], "report_id": report_id},
        )
        record = {
            "id": report_id,
            "name": f"{assessment.get('name', '本地测评')} 报告",
            "task": assessment["id"],
            "assessment_id": assessment["id"],
            "type": report_type,
            "template": "local-standard@4.1",
            "formats": "HTML/JSON",
            "html_artifact_id": html_artifact["id"],
            "json_artifact_id": json_artifact["id"],
            "html_path": html_artifact["relative_path"],
            "json_path": json_artifact["relative_path"],
            "size": html_artifact["size"] + json_artifact["size"],
            "time": snapshot["generated_at"],
            "status": "READY",
            "finding_count": len(findings),
            "summary": snapshot["summary"],
        }
        return self.store.upsert_record("report", record, status="READY")


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"p0": 0, "p1": 0, "p2": 0, "other": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "")
        if "P0" in severity or "严重" in severity:
            summary["p0"] += 1
        elif "P1" in severity or "高危" in severity:
            summary["p1"] += 1
        elif "P2" in severity or "中危" in severity:
            summary["p2"] += 1
        else:
            summary["other"] += 1
    return summary


def render_html(snapshot: dict[str, Any]) -> str:
    assessment = snapshot["assessment"]
    findings = snapshot["findings"]
    evidence = snapshot["evidence"]
    summary = snapshot["summary"]
    scan_options = assessment.get("scan_options") or {}
    boundary_rows = render_boundary_rows(assessment, scan_options)
    rows = "\n".join(render_finding_row(f) for f in findings) or (
        "<tr><td colspan=\"7\">未发现自动化规则命中项；请继续执行人工检查表和红队用例。</td></tr>"
    )
    evidence_rows = "\n".join(render_evidence_row(e) for e in evidence[:200]) or (
        "<tr><td colspan=\"5\">本次扫描未生成证据。</td></tr>"
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>{escape(str(assessment.get("name", "Agent 安全测评报告")))}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #1f2937; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .muted {{ color: #667085; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 20px 0; }}
    .metric {{ border: 1px solid #d0d5dd; border-radius: 8px; padding: 14px; }}
    .metric b {{ display: block; font-size: 28px; margin-top: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 14px 0 28px; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; }}
    code {{ background: #f2f4f7; padding: 2px 5px; border-radius: 4px; }}
    .risk {{ font-weight: 700; }}
    .footer {{ margin-top: 32px; font-size: 13px; color: #667085; }}
  </style>
</head>
<body>
  <h1>{escape(str(assessment.get("name", "Agent 安全测评报告")))}</h1>
  <p class="muted">报告 ID：{escape(str(snapshot["report_id"]))} · 任务 ID：{escape(str(assessment.get("id")))} · 生成时间：{escape(str(snapshot["generated_at"]))}</p>
  <div class="grid">
    <div class="metric">P0 严重<b>{summary["p0"]}</b></div>
    <div class="metric">P1 高危<b>{summary["p1"]}</b></div>
    <div class="metric">P2 中危<b>{summary["p2"]}</b></div>
    <div class="metric">证据数<b>{len(evidence)}</b></div>
  </div>
  <h2>执行边界</h2>
  <p>本报告由本地只读扫描生成。扫描过程不会启动 stdio MCP Server，不上传文件内容；证据片段已做敏感信息脱敏。</p>
  <table>
    <thead><tr><th>边界项</th><th>取值</th></tr></thead>
    <tbody>{boundary_rows}</tbody>
  </table>
  <h2>发现项</h2>
  <table>
    <thead><tr><th>ID</th><th>严重度</th><th>规则</th><th>标题</th><th>组件/路径</th><th>置信度</th><th>整改建议</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <h2>证据快照</h2>
  <table>
    <thead><tr><th>ID</th><th>类型</th><th>位置</th><th>SHA-256</th><th>脱敏片段</th></tr></thead>
    <tbody>{evidence_rows}</tbody>
  </table>
  <div class="footer">Agent 安全测评能力模块 V4.2.10 · SQLite 本地存储 · HTML/JSON 离线报告 · 兼容标记：Agent 安全测评能力模块 V4.1</div>
</body>
</html>"""


def render_boundary_rows(assessment: dict[str, Any], scan_options: dict[str, Any]) -> str:
    fields = [
        ("请求用户范围", assessment.get("user_scope_requested") or scan_options.get("user_scope_requested") or "current-user"),
        ("实际用户范围", assessment.get("effective_user_scope") or scan_options.get("effective_user_scope") or "current-user"),
        ("执行模式", assessment.get("execution_mode") or scan_options.get("execution_mode") or "readonly"),
        ("实际执行", assessment.get("effective_execution_mode") or scan_options.get("effective_execution_mode") or "local-readonly"),
        ("MCP 策略", assessment.get("mcp_policy") or scan_options.get("mcp_policy") or "never-start-stdio"),
        ("stdio MCP 已启动", scan_options.get("stdio_mcp_started", assessment.get("stdio_mcp_started", False))),
        ("Agent 运行时已启动", scan_options.get("agent_runtime_started", assessment.get("agent_runtime_started", False))),
        ("远程分析", scan_options.get("remote_analysis", assessment.get("remote_analysis", False))),
        ("外部 SCA 已执行", scan_options.get("external_sca_executed", assessment.get("external_sca_executed", False))),
        ("Dry-run 红队已执行", scan_options.get("dry_run_redteam_executed", assessment.get("dry_run_redteam_executed", False))),
        ("修改已安装 Agent", scan_options.get("mutates_installed_agents", assessment.get("mutates_installed_agents", False))),
    ]
    return "\n".join(
        f"<tr><td>{escape(str(label))}</td><td><code>{escape(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value))}</code></td></tr>"
        for label, value in fields
    )


def render_finding_row(finding: dict[str, Any]) -> str:
    return (
        "<tr>"
        f"<td><code>{escape(str(finding.get('id', '')))}</code></td>"
        f"<td class=\"risk\">{escape(str(finding.get('severity', '')))}</td>"
        f"<td><code>{escape(str(finding.get('rule', finding.get('rule_id', ''))))}</code></td>"
        f"<td>{escape(str(finding.get('title', '')))}</td>"
        f"<td>{escape(str(finding.get('component', finding.get('agent', ''))))}</td>"
        f"<td>{escape(str(finding.get('confidence', '')))}</td>"
        f"<td>{escape(str(finding.get('fix', finding.get('remediation', ''))))}</td>"
        "</tr>"
    )


def render_evidence_row(evidence: dict[str, Any]) -> str:
    return (
        "<tr>"
        f"<td><code>{escape(str(evidence.get('id', '')))}</code></td>"
        f"<td>{escape(str(evidence.get('type', '')))}</td>"
        f"<td>{escape(str(evidence.get('location', evidence.get('path', ''))))}</td>"
        f"<td><code>{escape(str(evidence.get('sha256', ''))[:16])}</code></td>"
        f"<td>{escape(str(evidence.get('content', evidence.get('text', ''))))}</td>"
        "</tr>"
    )
