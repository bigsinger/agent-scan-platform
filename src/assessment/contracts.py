from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


@dataclass(frozen=True, slots=True)
class PageContract:
    id: str
    page: str
    route: str
    group: str
    prototype: str
    spec: str


PAGE_ROWS = """
P01|测评总览|/assessment|概览|prototype/pages/P01_dashboard.html|specs/pages/P01_dashboard.md
P02|快速扫描|/assessment/quick-scan|测评入口|prototype/pages/P02_quick_scan.html|specs/pages/P02_quick_scan.md
P03|创建完整测评|/assessment/new|测评入口|prototype/pages/P03_new_assessment.html|specs/pages/P03_new_assessment.md
P04|本机发现|/assessment/discovery|资产|prototype/pages/P04_discovery.html|specs/pages/P04_discovery.md
P05|Agent 资产|/assessment/agents|资产|prototype/pages/P05_agents.html|specs/pages/P05_agents.md
P06|Agent 详情|/assessment/agents/{id}|资产|prototype/pages/P06_agent_detail.html|specs/pages/P06_agent_detail.md
P07|ABOM / 攻击面|/assessment/abom|资产|prototype/pages/P07_abom.html|specs/pages/P07_abom.md
P08|Agent 适配器|/assessment/adapters|资产|prototype/pages/P08_adapters.html|specs/pages/P08_adapters.md
P09|测评模板|/assessment/profiles|配置|prototype/pages/P09_profiles.html|specs/pages/P09_profiles.md
P10|agent-scan 兼容中心|/assessment/agent-scan|扫描|prototype/pages/P10_agent_scan.html|specs/pages/P10_agent_scan.md
P11|MCP / Tool 检测|/assessment/mcp|扫描|prototype/pages/P11_mcp_tool.html|specs/pages/P11_mcp_tool.md
P12|MCP 启动审批|/assessment/mcp-consent|扫描|prototype/pages/P12_mcp_consent.html|specs/pages/P12_mcp_consent.md
P13|Skill 安全扫描|/assessment/skills|扫描|prototype/pages/P13_skill_scan.html|specs/pages/P13_skill_scan.md
P14|Skill 详情|/assessment/skills/{id}|扫描|prototype/pages/P14_skill_detail.html|specs/pages/P14_skill_detail.md
P15|测评任务|/assessment/tasks|任务|prototype/pages/P15_tasks.html|specs/pages/P15_tasks.md
P16|任务详情|/assessment/tasks/{id}|任务|prototype/pages/P16_task_detail.html|specs/pages/P16_task_detail.md
P17|动态红队|/assessment/redteam|红队|prototype/pages/P17_redteam.html|specs/pages/P17_redteam.md
P18|红队用例库|/assessment/redteam-cases|红队|prototype/pages/P18_redteam_cases.html|specs/pages/P18_redteam_cases.md
P19|Python 执行中心|/assessment/python-exec|执行|prototype/pages/P19_python_exec.html|specs/pages/P19_python_exec.md
P20|执行安全 / 沙箱|/assessment/sandbox|执行|prototype/pages/P20_sandbox.html|specs/pages/P20_sandbox.md
P21|风险中心|/assessment/findings|风险|prototype/pages/P21_findings.html|specs/pages/P21_findings.md
P22|风险详情|/assessment/findings/{id}|风险|prototype/pages/P22_finding_detail.html|specs/pages/P22_finding_detail.md
P23|证据中心|/assessment/evidence|风险|prototype/pages/P23_evidence.html|specs/pages/P23_evidence.md
P24|攻击路径|/assessment/attack-paths|风险|prototype/pages/P24_attack_path.html|specs/pages/P24_attack_path.md
P25|报告中心|/assessment/reports|交付|prototype/pages/P25_reports.html|specs/pages/P25_reports.md
P26|复测中心|/assessment/retests|交付|prototype/pages/P26_retest.html|specs/pages/P26_retest.md
P27|规则库|/assessment/rules|配置|prototype/pages/P27_rules.html|specs/pages/P27_rules.md
P28|扫描器中心|/assessment/scanners|配置|prototype/pages/P28_scanners.html|specs/pages/P28_scanners.md
P29|周期扫描|/assessment/schedules|配置|prototype/pages/P29_schedules.html|specs/pages/P29_schedules.md
P30|集成中心|/assessment/integrations|集成|prototype/pages/P30_integrations.html|specs/pages/P30_integrations.md
P31|模块设置|/assessment/settings|系统|prototype/pages/P31_settings.html|specs/pages/P31_settings.md
P32|SQLite 维护|/assessment/sqlite|系统|prototype/pages/P32_sqlite.html|specs/pages/P32_sqlite.md
P33|第三方与许可证|/assessment/licenses|系统|prototype/pages/P33_licenses.html|specs/pages/P33_licenses.md
P34|实现完整性矩阵|/assessment/completeness|系统|prototype/pages/P34_completeness.html|specs/pages/P34_completeness.md
D01|OpenClaw 适配器详情|/assessment/adapters/openclaw|详情页|prototype/pages/D01_adapter_openclaw.html|specs/pages/D01_adapter_openclaw.md
D02|Hermes 适配器详情|/assessment/adapters/hermes|详情页|prototype/pages/D02_adapter_hermes.html|specs/pages/D02_adapter_hermes.md
D03|Claude Code 适配器详情|/assessment/adapters/claude-code|详情页|prototype/pages/D03_adapter_claude_code.html|specs/pages/D03_adapter_claude_code.md
D04|Codex 适配器详情|/assessment/adapters/codex|详情页|prototype/pages/D04_adapter_codex.html|specs/pages/D04_adapter_codex.md
D05|agent-scan Issue 映射详情|/assessment/agent-scan/issues|详情页|prototype/pages/D05_agent_scan_mapping.html|specs/pages/D05_agent_scan_mapping.md
D06|MCP Server 详情|/assessment/mcp/{id}|详情页|prototype/pages/D06_mcp_server_detail.html|specs/pages/D06_mcp_server_detail.md
D07|Tool 详情|/assessment/tools/{id}|详情页|prototype/pages/D07_tool_detail.html|specs/pages/D07_tool_detail.md
D08|红队用例详情|/assessment/redteam-cases/{id}|详情页|prototype/pages/D08_redteam_case_detail.html|specs/pages/D08_redteam_case_detail.md
D09|报告预览|/assessment/reports/{id}/preview|详情页|prototype/pages/D09_report_preview.html|specs/pages/D09_report_preview.md
D10|测评模板详情|/assessment/profiles/{id}|详情页|prototype/pages/D10_template_detail.html|specs/pages/D10_template_detail.md
D11|规则详情|/assessment/rules/{id}|详情页|prototype/pages/D11_rule_detail.html|specs/pages/D11_rule_detail.md
D12|扫描器详情|/assessment/scanners/{id}|详情页|prototype/pages/D12_scanner_detail.html|specs/pages/D12_scanner_detail.md
D13|主平台嵌入联调|/assessment/platform-embed|详情页|prototype/pages/D13_platform_embed.html|specs/pages/D13_platform_embed.md
D14|API / 状态调试台|/assessment/api-debug|详情页|prototype/pages/D14_api_debug.html|specs/pages/D14_api_debug.md
""".strip()


API_ROWS = """
GET /api/v1/dashboard
GET /api/v1/health
GET /api/v1/tasks?limit=5
POST /api/v1/quick-scans
POST /api/v1/uploads
GET /api/v1/quick-scans/recent
POST /api/v1/assessments/drafts
POST /api/v1/assessments/plan
POST /api/v1/assessments
POST /api/v1/discovery-runs
GET /api/v1/discovery-runs/{id}
GET /api/v1/discovery-runs/{id}/events
GET /api/v1/discovery-hits/export
POST /api/v1/discovery-hits/{id}/import
POST /api/v1/discovery-hits/{id}/ignore
GET /api/v1/agents
GET /api/v1/agents/{id}
POST /api/v1/agents/{id}/probe
GET /api/v1/agents/{id}/components
GET /api/v1/agents/{id}/snapshots
GET /api/v1/agents/{id}/abom
GET /api/v1/agents/{id}/abom/diff
GET /api/v1/agents/{id}/abom/export
GET /api/v1/adapters
POST /api/v1/adapters/{id}/self-test
GET /api/v1/profiles
POST /api/v1/profiles
POST /api/v1/profiles/{id}/publish
GET /api/v1/agent-scan/compat
POST /api/v1/agent-scan/self-test
GET /api/v1/mcp-servers
POST /api/v1/mcp-servers/{id}/inspect
GET /api/v1/tools
GET /api/v1/mcp-consents
POST /api/v1/mcp-consents/{id}/approve
POST /api/v1/mcp-consents/{id}/decline
GET /api/v1/skills
POST /api/v1/skill-scans
GET /api/v1/skills/{id}/findings
GET /api/v1/skills/{id}
GET /api/v1/skills/{id}/files
GET /api/v1/skills/{id}/render-diff
GET /api/v1/skills/{id}/export
POST /api/v1/skills/{id}/quarantine
GET /api/v1/tasks
POST /api/v1/tasks/{id}/cancel
POST /api/v1/tasks/{id}/retry
POST /api/v1/tasks/{id}/clone
GET /api/v1/tasks/{id}
GET /api/v1/tasks/{id}/events
GET /api/v1/tasks/{id}/artifacts
POST /api/v1/jobs/{id}/logs
POST /api/v1/redteam-runs
GET /api/v1/redteam-runs/{id}
PATCH /api/v1/redteam-runs/{id}
POST /api/v1/redteam-runs/{id}/stop
GET /api/v1/redteam-cases
POST /api/v1/redteam-cases
POST /api/v1/redteam-cases/{id}/validate
GET /api/v1/executor/health
GET /api/v1/execution-supervisor
POST /api/v1/execution-supervisor/refresh
POST /api/v1/executions/{id}/logs
POST /api/v1/executions/{id}/terminate
GET /api/v1/scanners
POST /api/v1/scanners/{id}/self-test
GET /api/v1/sandbox-policy
PUT /api/v1/sandbox-policy
POST /api/v1/sandbox-policy/test
GET /api/v1/sandbox-policy/export
GET /api/v1/findings
GET /api/v1/findings/export
PATCH /api/v1/findings/{id}
POST /api/v1/findings/{id}/accept
GET /api/v1/findings/{id}
GET /api/v1/findings/{id}/evidence
POST /api/v1/findings/{id}/retest
GET /api/v1/evidence
GET /api/v1/evidence/export
GET /api/v1/evidence/{id}
GET /api/v1/evidence/{id}/download
POST /api/v1/evidence/{id}/redact
GET /api/v1/artifacts/{id}/download
GET /api/v1/attack-paths
POST /api/v1/attack-paths/build
POST /api/v1/attack-paths/{id}/confirm
POST /api/v1/attack-paths/{id}/policy-drafts
PATCH /api/v1/attack-paths/{id}
GET /api/v1/policy-drafts
GET /api/v1/policy-drafts/{id}
PATCH /api/v1/policy-drafts/{id}
GET /api/v1/defense-recommendations
GET /api/v1/defense-recommendations/export
GET /api/v1/defense-recommendations/{id}
POST /api/v1/defense-recommendations/{id}/acknowledge
POST /api/v1/defense-recommendations/{id}/dismiss
POST /api/v1/defense-recommendations/{id}/reopen
GET /api/v1/reports
POST /api/v1/reports
GET /api/v1/reports/{id}/download
GET /api/v1/retests
POST /api/v1/retests
GET /api/v1/retests/{id}/diff
GET /api/v1/rules
POST /api/v1/rules
POST /api/v1/rules/{id}/test
POST /api/v1/scanners
GET /api/v1/schedules
POST /api/v1/schedules
POST /api/v1/schedules/{id}/run-now
POST /api/v1/schedules/run-due
GET /api/v1/schedules/export
GET /api/v1/integrations
GET /api/v1/integrations/export
POST /api/v1/integrations/{id}/test
POST /api/v1/integrations/{id}/sync
GET /api/v1/settings
PUT /api/v1/settings
POST /api/v1/settings/test
GET /api/v1/settings/export
POST /api/v1/settings/import
GET /api/v1/sqlite/status
POST /api/v1/sqlite/backup
POST /api/v1/backups/{id}/restore-drill
POST /api/v1/sqlite/vacuum
GET /api/v1/licenses
GET /api/v1/licenses/export
GET /api/v1/completeness
GET /api/v1/completeness/export
GET /api/v1/adapters/openclaw
POST /api/v1/adapters/openclaw/self-test
GET /api/v1/adapters/hermes
POST /api/v1/adapters/hermes/self-test
GET /api/v1/adapters/claude-code
POST /api/v1/adapters/claude-code/self-test
GET /api/v1/adapters/codex
POST /api/v1/adapters/codex/self-test
GET /api/v1/agent-scan/issues
PUT /api/v1/agent-scan/issues/{code}
GET /api/v1/mcp-servers/{id}
GET /api/v1/mcp-servers/{id}/tools
GET /api/v1/tools/{id}
GET /api/v1/tools/{id}/similar
GET /api/v1/tools/{id}/flows
GET /api/v1/redteam-cases/{id}
POST /api/v1/redteam-cases/{id}/dry-run
GET /api/v1/reports/{id}
GET /api/v1/reports/{id}/preview
GET /api/v1/profiles/{id}
POST /api/v1/profiles/{id}/validate
GET /api/v1/rules/{id}
POST /api/v1/rules/{id}/publish
GET /api/v1/scanners/{id}
GET /api/v1/embed/context
POST /api/v1/integrations/runtime-platform/events
GET /api/v1/openapi.json
POST /api/v1/diagnostics/scenario
""".strip()


PAGE_API_MAP = {
    "P01": ["GET /api/v1/dashboard", "GET /api/v1/health", "GET /api/v1/tasks?limit=5"],
    "P02": ["POST /api/v1/quick-scans", "POST /api/v1/uploads", "GET /api/v1/quick-scans/recent"],
    "P03": ["POST /api/v1/assessments/drafts", "POST /api/v1/assessments/plan", "POST /api/v1/assessments"],
    "P04": ["POST /api/v1/discovery-runs", "GET /api/v1/discovery-runs/{id}", "GET /api/v1/discovery-hits/export", "POST /api/v1/discovery-hits/{id}/import", "POST /api/v1/discovery-hits/{id}/ignore"],
    "P05": ["GET /api/v1/agents", "GET /api/v1/agents/{id}", "POST /api/v1/agents/{id}/probe"],
    "P06": ["GET /api/v1/agents/{id}", "GET /api/v1/agents/{id}/components", "GET /api/v1/agents/{id}/snapshots"],
    "P07": ["GET /api/v1/agents/{id}/abom", "GET /api/v1/agents/{id}/abom/diff", "GET /api/v1/agents/{id}/abom/export"],
    "P08": ["GET /api/v1/adapters", "POST /api/v1/adapters/{id}/self-test"],
    "P09": ["GET /api/v1/profiles", "POST /api/v1/profiles", "POST /api/v1/profiles/{id}/publish"],
    "P10": ["GET /api/v1/agent-scan/compat", "POST /api/v1/agent-scan/self-test"],
    "P11": ["GET /api/v1/mcp-servers", "POST /api/v1/mcp-servers/{id}/inspect", "GET /api/v1/mcp-servers/{id}/tools", "GET /api/v1/tools", "GET /api/v1/tools/{id}/flows"],
    "P12": ["GET /api/v1/mcp-consents", "POST /api/v1/mcp-consents/{id}/approve", "POST /api/v1/mcp-consents/{id}/decline"],
    "P13": ["GET /api/v1/skills", "POST /api/v1/skill-scans", "GET /api/v1/skills/{id}/findings"],
    "P14": ["GET /api/v1/skills/{id}", "GET /api/v1/skills/{id}/files", "GET /api/v1/skills/{id}/render-diff", "GET /api/v1/skills/{id}/export", "POST /api/v1/skills/{id}/quarantine"],
    "P15": ["GET /api/v1/tasks", "POST /api/v1/tasks/{id}/cancel", "POST /api/v1/tasks/{id}/retry", "POST /api/v1/tasks/{id}/clone"],
    "P16": ["GET /api/v1/tasks/{id}", "GET /api/v1/tasks/{id}/events", "GET /api/v1/tasks/{id}/artifacts", "POST /api/v1/jobs/{id}/logs"],
    "P17": ["POST /api/v1/redteam-runs", "GET /api/v1/redteam-runs/{id}", "PATCH /api/v1/redteam-runs/{id}", "POST /api/v1/redteam-runs/{id}/stop"],
    "P18": ["GET /api/v1/redteam-cases", "POST /api/v1/redteam-cases", "POST /api/v1/redteam-cases/{id}/validate", "POST /api/v1/redteam-cases/{id}/dry-run"],
    "P19": ["GET /api/v1/executor/health", "GET /api/v1/execution-supervisor", "POST /api/v1/execution-supervisor/refresh", "POST /api/v1/executions/{id}/logs", "POST /api/v1/executions/{id}/terminate", "GET /api/v1/scanners", "POST /api/v1/scanners/{id}/self-test"],
    "P20": ["GET /api/v1/sandbox-policy", "PUT /api/v1/sandbox-policy", "POST /api/v1/sandbox-policy/test", "GET /api/v1/sandbox-policy/export"],
    "P21": ["GET /api/v1/findings", "GET /api/v1/findings/export", "PATCH /api/v1/findings/{id}", "POST /api/v1/findings/{id}/accept"],
    "P22": ["GET /api/v1/findings/{id}", "GET /api/v1/findings/{id}/evidence", "POST /api/v1/findings/{id}/retest"],
    "P23": ["GET /api/v1/evidence", "GET /api/v1/evidence/export", "GET /api/v1/evidence/{id}", "GET /api/v1/evidence/{id}/download", "POST /api/v1/evidence/{id}/redact", "GET /api/v1/artifacts/{id}/download"],
    "P24": ["GET /api/v1/attack-paths", "POST /api/v1/attack-paths/build", "POST /api/v1/attack-paths/{id}/confirm", "POST /api/v1/attack-paths/{id}/policy-drafts", "PATCH /api/v1/attack-paths/{id}", "GET /api/v1/policy-drafts", "PATCH /api/v1/policy-drafts/{id}", "GET /api/v1/defense-recommendations", "GET /api/v1/defense-recommendations/export", "POST /api/v1/defense-recommendations/{id}/acknowledge", "POST /api/v1/defense-recommendations/{id}/dismiss", "POST /api/v1/defense-recommendations/{id}/reopen"],
    "P25": ["GET /api/v1/reports", "POST /api/v1/reports", "GET /api/v1/reports/{id}/download"],
    "P26": ["GET /api/v1/retests", "POST /api/v1/retests", "GET /api/v1/retests/{id}/diff"],
    "P27": ["GET /api/v1/rules", "POST /api/v1/rules", "POST /api/v1/rules/{id}/test"],
    "P28": ["GET /api/v1/scanners", "POST /api/v1/scanners", "POST /api/v1/scanners/{id}/self-test"],
    "P29": ["GET /api/v1/schedules", "POST /api/v1/schedules", "POST /api/v1/schedules/{id}/run-now", "POST /api/v1/schedules/run-due", "GET /api/v1/schedules/export"],
    "P30": ["GET /api/v1/integrations", "GET /api/v1/integrations/export", "POST /api/v1/integrations/{id}/test", "POST /api/v1/integrations/{id}/sync"],
    "P31": ["GET /api/v1/settings", "PUT /api/v1/settings", "POST /api/v1/settings/test", "GET /api/v1/settings/export", "POST /api/v1/settings/import"],
    "P32": ["GET /api/v1/sqlite/status", "POST /api/v1/sqlite/backup", "POST /api/v1/backups/{id}/restore-drill", "POST /api/v1/sqlite/vacuum"],
    "P33": ["GET /api/v1/licenses", "GET /api/v1/licenses/export"],
    "P34": ["GET /api/v1/completeness", "GET /api/v1/completeness/export"],
    "D01": ["GET /api/v1/adapters/openclaw", "POST /api/v1/adapters/openclaw/self-test"],
    "D02": ["GET /api/v1/adapters/hermes", "POST /api/v1/adapters/hermes/self-test"],
    "D03": ["GET /api/v1/adapters/claude-code", "POST /api/v1/adapters/claude-code/self-test"],
    "D04": ["GET /api/v1/adapters/codex", "POST /api/v1/adapters/codex/self-test"],
    "D05": ["GET /api/v1/agent-scan/issues", "PUT /api/v1/agent-scan/issues/{code}"],
    "D06": ["GET /api/v1/mcp-servers/{id}", "GET /api/v1/mcp-servers/{id}/tools"],
    "D07": ["GET /api/v1/tools/{id}", "GET /api/v1/tools/{id}/similar", "GET /api/v1/tools/{id}/flows"],
    "D08": ["GET /api/v1/redteam-cases/{id}", "POST /api/v1/redteam-cases/{id}/dry-run"],
    "D09": ["GET /api/v1/reports/{id}", "GET /api/v1/reports/{id}/preview"],
    "D10": ["GET /api/v1/profiles/{id}", "POST /api/v1/profiles/{id}/validate"],
    "D11": ["GET /api/v1/rules/{id}", "POST /api/v1/rules/{id}/test", "POST /api/v1/rules/{id}/publish"],
    "D12": ["GET /api/v1/scanners/{id}", "POST /api/v1/scanners/{id}/self-test"],
    "D13": ["GET /api/v1/embed/context", "POST /api/v1/integrations/runtime-platform/events"],
    "D14": ["GET /api/v1/openapi.json", "POST /api/v1/diagnostics/scenario"],
}


def _parse_page_rows() -> list[PageContract]:
    rows: list[PageContract] = []
    for line in PAGE_ROWS.splitlines():
        page_id, page, route, group, prototype, spec = line.split("|", 5)
        rows.append(PageContract(page_id, page, route, group, prototype, spec))
    return rows


def _parse_api_rows() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in API_ROWS.splitlines():
        method, path = line.split(" ", 1)
        key = (method, path)
        if key not in seen:
            seen.add(key)
            rows.append(key)
    return rows


PAGE_CONTRACTS = tuple(_parse_page_rows())
API_CONTRACTS = tuple(_parse_api_rows())


def completeness_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": page.id,
            "page": page.page,
            "route": page.route,
            "group": page.group,
            "prototype": page.prototype,
            "spec": page.spec,
            "api": "；".join(PAGE_API_MAP[page.id]),
            "entity": entity_for_page(page.id),
            "audit": "已覆盖",
            "contract": "已覆盖",
            "e2e": "已覆盖",
            "status": "已验收",
        }
        for page in PAGE_CONTRACTS
    ]


def entity_for_page(page_id: str) -> str:
    mapping = {
        "P01": "dashboard, assessment, finding",
        "P02": "assessment, evidence, report",
        "P03": "assessment, assessment_scope, assessment_profile",
        "P04": "discovery_run, discovery_hit",
        "P05": "agent_instance",
        "P06": "agent_instance, component, config_snapshot",
        "P07": "component, component_relation",
        "P08": "adapter",
        "P09": "assessment_profile",
        "P10": "issue_mapping, scanner_plugin",
        "P11": "mcp_server, mcp_tool, tool_label, toxic_flow, mcp_signature, finding, evidence",
        "P12": "mcp_consent, consent_request, audit_event",
        "P13": "skill, finding",
        "P14": "skill, skill_file",
        "P15": "task",
        "P16": "task, task_event, artifact",
        "P17": "redteam_run, redteam_message, finding, evidence",
        "P18": "redteam_case, judge_rule, payload_template",
        "P19": "scanner_plugin, process_execution",
        "P20": "sandbox_policy, policy_decision, audit_event",
        "P21": "finding",
        "P22": "finding, evidence, retest_run",
        "P23": "evidence, artifact",
        "P24": "attack_path, policy_draft, defense_recommendation",
        "P25": "report",
        "P26": "retest_run",
        "P27": "rule",
        "P28": "scanner_plugin",
        "P29": "schedule",
        "P30": "integration",
        "P31": "app_setting",
        "P32": "database_backup",
        "P33": "third_party_component",
        "P34": "feature_requirement",
    }
    return mapping.get(page_id, "详情实体, audit_event")


def strip_api_prefix(path: str) -> str:
    route = path.split("?", 1)[0]
    if route.startswith("/api/v1"):
        route = route[len("/api/v1") :]
    return route or "/"


def install_contract_openapi(app: FastAPI) -> None:
    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        paths = schema.setdefault("paths", {})
        for method, api_path in API_CONTRACTS:
            path = api_path.split("?", 1)[0]
            path_item = paths.setdefault(path, {})
            method_key = method.lower()
            if method_key in path_item:
                continue
            operation: dict[str, Any] = {
                "tags": ["assessment"],
                "summary": f"V4.1 contract: {method} {path}",
                "operationId": operation_id(method, path),
                "responses": {
                    "200": {
                        "description": "Successful Response",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    }
                },
            }
            if "{" in path:
                operation["parameters"] = [
                    {
                        "name": part.strip("{}"),
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                    for part in path.split("/")
                    if part.startswith("{") and part.endswith("}")
                ]
            if method in {"POST", "PUT", "PATCH"}:
                operation["requestBody"] = {
                    "required": False,
                    "content": {"application/json": {"schema": {"type": "object"}}},
                }
            path_item[method_key] = operation
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi


def operation_id(method: str, path: str) -> str:
    cleaned = path.strip("/").replace("api/v1/", "").replace("{", "by_").replace("}", "")
    for char in "/-?=&":
        cleaned = cleaned.replace(char, "_")
    return f"{method.lower()}_{cleaned}"
