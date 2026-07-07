# 页面索引与交付清单

本包共生成 **48 个页面/详情页**，每个页面均有独立 HTML 原型与独立 SPEC。

| 编号 | 页面 | 原型 | SPEC | Route | 分组 |
|---|---|---|---|---|---|
| P01 | 测评总览 | `prototype/pages/P01_dashboard.html` | `specs/pages/P01_dashboard.md` | `/assessment` | 概览 |
| P02 | 快速扫描 | `prototype/pages/P02_quick_scan.html` | `specs/pages/P02_quick_scan.md` | `/assessment/quick-scan` | 测评入口 |
| P03 | 创建完整测评 | `prototype/pages/P03_new_assessment.html` | `specs/pages/P03_new_assessment.md` | `/assessment/new` | 测评入口 |
| P04 | 本机发现 | `prototype/pages/P04_discovery.html` | `specs/pages/P04_discovery.md` | `/assessment/discovery` | 资产 |
| P05 | Agent 资产 | `prototype/pages/P05_agents.html` | `specs/pages/P05_agents.md` | `/assessment/agents` | 资产 |
| P06 | Agent 详情 | `prototype/pages/P06_agent_detail.html` | `specs/pages/P06_agent_detail.md` | `/assessment/agents/{id}` | 资产 |
| P07 | ABOM / 攻击面 | `prototype/pages/P07_abom.html` | `specs/pages/P07_abom.md` | `/assessment/abom` | 资产 |
| P08 | Agent 适配器 | `prototype/pages/P08_adapters.html` | `specs/pages/P08_adapters.md` | `/assessment/adapters` | 资产 |
| P09 | 测评模板 | `prototype/pages/P09_profiles.html` | `specs/pages/P09_profiles.md` | `/assessment/profiles` | 配置 |
| P10 | agent-scan 兼容中心 | `prototype/pages/P10_agent_scan.html` | `specs/pages/P10_agent_scan.md` | `/assessment/agent-scan` | 扫描 |
| P11 | MCP / Tool 检测 | `prototype/pages/P11_mcp_tool.html` | `specs/pages/P11_mcp_tool.md` | `/assessment/mcp` | 扫描 |
| P12 | MCP 启动审批 | `prototype/pages/P12_mcp_consent.html` | `specs/pages/P12_mcp_consent.md` | `/assessment/mcp-consent` | 扫描 |
| P13 | Skill 安全扫描 | `prototype/pages/P13_skill_scan.html` | `specs/pages/P13_skill_scan.md` | `/assessment/skills` | 扫描 |
| P14 | Skill 详情 | `prototype/pages/P14_skill_detail.html` | `specs/pages/P14_skill_detail.md` | `/assessment/skills/{id}` | 扫描 |
| P15 | 测评任务 | `prototype/pages/P15_tasks.html` | `specs/pages/P15_tasks.md` | `/assessment/tasks` | 任务 |
| P16 | 任务详情 | `prototype/pages/P16_task_detail.html` | `specs/pages/P16_task_detail.md` | `/assessment/tasks/{id}` | 任务 |
| P17 | 动态红队 | `prototype/pages/P17_redteam.html` | `specs/pages/P17_redteam.md` | `/assessment/redteam` | 红队 |
| P18 | 红队用例库 | `prototype/pages/P18_redteam_cases.html` | `specs/pages/P18_redteam_cases.md` | `/assessment/redteam-cases` | 红队 |
| P19 | Python 执行中心 | `prototype/pages/P19_python_exec.html` | `specs/pages/P19_python_exec.md` | `/assessment/python-exec` | 执行 |
| P20 | 执行安全 / 沙箱 | `prototype/pages/P20_sandbox.html` | `specs/pages/P20_sandbox.md` | `/assessment/sandbox` | 执行 |
| P21 | 风险中心 | `prototype/pages/P21_findings.html` | `specs/pages/P21_findings.md` | `/assessment/findings` | 风险 |
| P22 | 风险详情 | `prototype/pages/P22_finding_detail.html` | `specs/pages/P22_finding_detail.md` | `/assessment/findings/{id}` | 风险 |
| P23 | 证据中心 | `prototype/pages/P23_evidence.html` | `specs/pages/P23_evidence.md` | `/assessment/evidence` | 风险 |
| P24 | 攻击路径 | `prototype/pages/P24_attack_path.html` | `specs/pages/P24_attack_path.md` | `/assessment/attack-paths` | 风险 |
| P25 | 报告中心 | `prototype/pages/P25_reports.html` | `specs/pages/P25_reports.md` | `/assessment/reports` | 交付 |
| P26 | 复测中心 | `prototype/pages/P26_retest.html` | `specs/pages/P26_retest.md` | `/assessment/retests` | 交付 |
| P27 | 规则库 | `prototype/pages/P27_rules.html` | `specs/pages/P27_rules.md` | `/assessment/rules` | 配置 |
| P28 | 扫描器中心 | `prototype/pages/P28_scanners.html` | `specs/pages/P28_scanners.md` | `/assessment/scanners` | 配置 |
| P29 | 周期扫描 | `prototype/pages/P29_schedules.html` | `specs/pages/P29_schedules.md` | `/assessment/schedules` | 配置 |
| P30 | 集成中心 | `prototype/pages/P30_integrations.html` | `specs/pages/P30_integrations.md` | `/assessment/integrations` | 集成 |
| P31 | 模块设置 | `prototype/pages/P31_settings.html` | `specs/pages/P31_settings.md` | `/assessment/settings` | 系统 |
| P32 | SQLite 维护 | `prototype/pages/P32_sqlite.html` | `specs/pages/P32_sqlite.md` | `/assessment/sqlite` | 系统 |
| P33 | 第三方与许可证 | `prototype/pages/P33_licenses.html` | `specs/pages/P33_licenses.md` | `/assessment/licenses` | 系统 |
| P34 | 实现完整性矩阵 | `prototype/pages/P34_completeness.html` | `specs/pages/P34_completeness.md` | `/assessment/completeness` | 系统 |
| D01 | OpenClaw 适配器详情 | `prototype/pages/D01_adapter_openclaw.html` | `specs/pages/D01_adapter_openclaw.md` | `/assessment/adapters/openclaw` | 详情页 |
| D02 | Hermes 适配器详情 | `prototype/pages/D02_adapter_hermes.html` | `specs/pages/D02_adapter_hermes.md` | `/assessment/adapters/hermes` | 详情页 |
| D03 | Claude Code 适配器详情 | `prototype/pages/D03_adapter_claude_code.html` | `specs/pages/D03_adapter_claude_code.md` | `/assessment/adapters/claude-code` | 详情页 |
| D04 | Codex 适配器详情 | `prototype/pages/D04_adapter_codex.html` | `specs/pages/D04_adapter_codex.md` | `/assessment/adapters/codex` | 详情页 |
| D05 | agent-scan Issue 映射详情 | `prototype/pages/D05_agent_scan_mapping.html` | `specs/pages/D05_agent_scan_mapping.md` | `/assessment/agent-scan/issues` | 详情页 |
| D06 | MCP Server 详情 | `prototype/pages/D06_mcp_server_detail.html` | `specs/pages/D06_mcp_server_detail.md` | `/assessment/mcp/{id}` | 详情页 |
| D07 | Tool 详情 | `prototype/pages/D07_tool_detail.html` | `specs/pages/D07_tool_detail.md` | `/assessment/tools/{id}` | 详情页 |
| D08 | 红队用例详情 | `prototype/pages/D08_redteam_case_detail.html` | `specs/pages/D08_redteam_case_detail.md` | `/assessment/redteam-cases/{id}` | 详情页 |
| D09 | 报告预览 | `prototype/pages/D09_report_preview.html` | `specs/pages/D09_report_preview.md` | `/assessment/reports/{id}/preview` | 详情页 |
| D10 | 测评模板详情 | `prototype/pages/D10_template_detail.html` | `specs/pages/D10_template_detail.md` | `/assessment/profiles/{id}` | 详情页 |
| D11 | 规则详情 | `prototype/pages/D11_rule_detail.html` | `specs/pages/D11_rule_detail.md` | `/assessment/rules/{id}` | 详情页 |
| D12 | 扫描器详情 | `prototype/pages/D12_scanner_detail.html` | `specs/pages/D12_scanner_detail.md` | `/assessment/scanners/{id}` | 详情页 |
| D13 | 主平台嵌入联调 | `prototype/pages/D13_platform_embed.html` | `specs/pages/D13_platform_embed.md` | `/assessment/platform-embed` | 详情页 |
| D14 | API / 状态调试台 | `prototype/pages/D14_api_debug.html` | `specs/pages/D14_api_debug.md` | `/assessment/api-debug` | 详情页 |
