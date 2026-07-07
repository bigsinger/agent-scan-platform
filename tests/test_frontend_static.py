import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "assessment" / "static"
REMOTE_PATTERN = re.compile(r"https?://|//unpkg|//cdn|//cdnjs|fonts\.googleapis", re.IGNORECASE)


def test_frontend_assets_are_local_and_boot_guarded():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    assert 'id="boot-status"' in html
    assert 'id="boot-error"' in html
    assert "v-cloak" in html
    assert "/static/vendor/vue.global.prod.js" in html
    for path in [
        STATIC / "assessment" / "index.html",
        STATIC / "assessment" / "app.js",
        STATIC / "assessment" / "seed.js",
        STATIC / "assessment" / "style.css",
    ]:
        assert not REMOTE_PATTERN.search(path.read_text(encoding="utf-8")), path


def test_vendor_manifest_matches_vue_runtime():
    manifest = json.loads((STATIC / "vendor" / "vendor-manifest.json").read_text(encoding="utf-8"))
    vue = STATIC / "vendor" / "vue.global.prod.js"
    assert hashlib.sha256(vue.read_bytes()).hexdigest() == manifest["vue.global.prod.js"]["sha256"]


def test_frontend_seed_fallback_does_not_ship_prototype_runtime_data():
    seed = json.loads((STATIC / "assessment" / "seed.json").read_text(encoding="utf-8"))
    seed_js = (STATIC / "assessment" / "seed.js").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    empty_runtime_keys = [
        "agents",
        "agentAssets",
        "discoveryHits",
        "discoveryErrors",
        "discoveryLog",
        "mcpServers",
        "consents",
        "tools",
        "skills",
        "tasks",
        "jobs",
        "processes",
        "taskEvents",
        "findings",
        "evidenceItems",
        "reports",
        "components",
        "redteamRuns",
        "attackPaths",
        "policyDrafts",
        "retests",
        "backupRecords",
        "heatmap",
        "caseLibrary",
        "redCases",
        "profiles",
        "ruleRows",
        "scanners",
        "schedules",
        "integrations",
        "licenses",
        "dbTables",
        "taskStages",
    ]
    for key in empty_runtime_keys:
        assert seed[key] == [], key
    for key in [
        "selectedAsset",
        "selectedTask",
        "selectedMcp",
        "selectedTool",
        "selectedConsent",
        "selectedSkill",
        "selectedCase",
        "selectedRedteamRun",
        "selectedFinding",
        "selectedEvidence",
        "selectedAttackPath",
        "selectedPolicyDraft",
        "selectedReport",
        "selectedRule",
        "selectedProfile",
        "selectedRetest",
    ]:
        assert seed[key] == {}, key
    assert [mode["id"] for mode in seed["quickModes"]] == ["machine", "path", "mcp"]
    assert len(seed["completeness"]) == 48
    assert "后端 API 暂不可用，当前显示本地种子数据。" not in app_js
    assert "当前显示本地空态配置" in app_js
    combined = json.dumps(seed, ensure_ascii=False) + seed_js
    for token in [
        "claude-code-repo-demo",
        "agt_cc_001",
        "asm_v4_",
        "/workspace/demo",
        "64/64",
        "84+",
        "openclaw-gateway-lab",
        "hermes-profile-dev",
        "codex-project-a",
    ]:
        assert token not in combined


def test_adapter_self_test_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "已开始全部适配器自测" not in html
    assert "回归自测通过" not in html
    assert "<tr><td>OpenClaw</td><td>✓" not in html
    assert "<tr><td>Codex</td><td>✓" not in html
    assert "a.fixtures" not in html
    assert "@click=\"selfTestAllAdapters\"" in html
    assert "@click=\"selfTestAdapter(a)\"" in html
    assert "adapterSelfTestResult" in html
    assert "v-for=\"row in adapterCoverageRows\"" in html
    assert "v-for=\"cell in row.cells\"" in html
    assert "async selfTestAdapter" in app_js
    assert "async selfTestAllAdapters" in app_js
    assert "adapterCoverageRows()" in app_js
    assert "adapterCoverageHeaders()" in app_js
    assert "/api/v1/adapters/" in app_js


def test_adapter_detail_deep_links_are_runtime_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")

    assert "current==='adapter-detail'" in html
    assert "if(path.startsWith('/assessment/adapters/')) return 'adapter-detail';" in app_js
    assert "'adapter-detail':adapterDetailPath" in app_js
    assert "async loadAdapterDetail" in app_js
    assert "async runAdapterDetailSelfTest" in app_js
    assert "downloadAdapterDetailSelfTest" in app_js
    assert "adapterDetailSelfTest" in html
    assert "`/api/v1/adapters/{id}`" in html
    assert "运行只读自测" in html
    assert "不会显示原型样例数据" in html


def test_agent_scan_compat_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "上游源码哈希验证通过" not in html
    assert "兼容自测完成：64/64 通过" not in html
    assert "64/64" not in html
    assert "专用 Discoverer" not in html
    assert "Cursor/VSCode/Windsurf/Kiro" not in html
    assert "<td>✓</td>" not in html
    assert "<td>E001</td><td>MCP-PI-001</td><td>Tool Description Injection</td>" not in html
    assert "<td>E002</td><td>MCP-TS-001</td><td>Cross-server Reference</td>" not in html
    assert "W015~W020" not in html
    assert "映射 E001/E004/W019/DM-05" not in html
    assert '"agent": "claude_code"' not in html
    assert '"servers": 3' not in html
    assert '"skills": 8' not in html
    assert 'data-testid="agent-scan-self-test"' in html
    assert "@click=\"refreshAgentScanCompat()\"" in html
    assert "@click=\"runAgentScanSelfTest\"" in html
    assert "agentScanSelfTestResult" in html
    assert "agentScanLocalRuleRows()" in app_js
    assert "agentScanIssueCodesText()" in app_js
    assert "agentScanCloudPreview()" in app_js
    assert "agentScanCloudPreviewJson()" in app_js
    assert "agentScanIssues=issues.items || []" in app_js
    assert "v-for=\"row in agentScanDiscoveryRows\"" in html
    assert "v-for=\"col in agentScanDiscoveryColumns\"" in html
    assert "v-for=\"row in agentScanLocalRuleRows\"" in html
    assert "{{agentScanCloudPreviewJson}}" in html
    assert "async refreshAgentScanCompat" in app_js
    assert "async runAgentScanSelfTest" in app_js
    assert "agentScanDiscoveryRows()" in app_js
    assert "agentScanDiscoveryColumns()" in app_js
    assert "discovery_coverage" in app_js
    assert "/api/v1/agent-scan/self-test" in app_js
    assert "/api/v1/agent-scan/issues?page_size=200" in app_js


def test_license_update_check_ui_is_runtime_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "github.com/snyk/agent-scan</div><div>Version" not in html
    assert "<span class=\"badge blue\">人工检查</span>" not in html
    assert "<span class=\"badge gray\">禁用</span>" not in html
    assert "升级前必须通过本地兼容自测" not in html
    assert "需人工复核上游许可证" not in html
    assert "agentScanOwnershipRows()" in app_js
    assert "licenseUpdateCheckRows()" in app_js
    assert "async refreshLicenseContext" in app_js
    assert "/api/v1/licenses?page_size=200" in app_js
    assert "/api/v1/agent-scan/compat" in app_js
    assert "@click=\"refreshLicenseContext()\"" in html
    assert "v-for=\"row in agentScanOwnershipRows\"" in html
    assert "v-for=\"row in licenseUpdateCheckRows\"" in html


def test_quick_scan_ui_requires_api_assessment_record():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "mode:this.quickMode" in app_js
    assert 'v-model="form.scanSkills"' in html
    assert 'v-model="form.runLocalAnalyzers"' in html
    assert 'v-model="form.useExistingSca"' in html
    assert 'v-model="form.remoteAnalysis"' in html
    assert 'v-model="form.quickUserScope"' in html
    assert 'v-model="form.quickExecutionMode"' in html
    assert 'v-model="form.discoveryUserScope"' in html
    assert 'value="readable-users"' in html
    assert 'value="dry-run-redteam"' in html
    assert 'v-model="form.assessmentRemoteAnalysis"' in html
    assert 'quickUserScope:\'current-user\'' in app_js
    assert 'quickExecutionMode:\'readonly\'' in app_js
    assert 'discoveryUserScope:\'current-user\'' in app_js
    assert '<input type="checkbox" checked> 扫描 Skills' not in html
    assert '<input type="checkbox" checked> 运行本地分析器' not in html
    assert '<select><option>只读检查（推荐）</option><option>检查 + MCP 逐项审批</option><option>完整 Dry-run 红队</option></select>' not in html
    assert "scanOptionPayload(scope)" in app_js
    assert "assessmentPayload(extra)" in app_js
    assert "this.form=Object.assign({}, defaultFormState, this.form || {})" in app_js
    assert "remote_analysis_requested:remoteRequested" in app_js
    assert "remote_analysis:false" in app_js
    assert "run_local_analyzers:!!this.form.runLocalAnalyzers" in app_js
    assert "user_scope:this.form.quickUserScope || 'current-user'" in app_js
    assert "execution_mode:executionMode" in app_js
    assert "dry_run_redteam_requested:executionMode==='dry-run-redteam'" in app_js
    assert "scope:this.form.discoveryUserScope || 'current-user'" in app_js
    assert "if(res.redteam_run){ this.mergeRecords('redteamRuns', [res.redteam_run]); this.selectedRedteamRun=res.redteam_run; }" in app_js
    assert "asm_quick_" not in app_js
    assert "快速扫描未返回真实任务记录" in app_js
    assert "v-for=\"t in quickHistory\"" in html
    assert "tasks.slice(0,4)" not in html
    assert "refreshQuickHistory()" in html
    assert "exportQuickHistory" in html
    assert "async refreshQuickHistory" in app_js
    assert "async exportQuickHistory" in app_js
    assert "/api/v1/quick-scans/recent?page_size=20" in app_js
    assert "/api/v1/quick-scans/recent/export" in app_js


def test_quick_scan_snapshot_upload_merges_scan_results():
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "async uploadSnapshot" in app_js
    assert "kind:'quick-scan-snapshot'" in app_js
    assert "this.mergeRecords('tasks', [res.assessment])" in app_js
    assert "this.mergeRecords('findings', res.findings)" in app_js
    assert "this.mergeRecords('evidenceItems', res.evidence)" in app_js
    assert "快照已保存并扫描" in app_js


def test_assessment_wizard_generates_plan_from_api():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "async nextWizardStep" in app_js
    assert "async refreshAssessmentPlan" in app_js
    assert "/api/v1/assessments/plan" in app_js
    assert "this.planJson=JSON.stringify(plan, null, 2)" in app_js
    assert "this.assessmentPlanSnapshot=res.snapshot || null" in app_js
    assert "@click=\"nextWizardStep\"" in html
    assert "@click=\"previousWizardStep\"" in html
    assert "wizard++" not in html
    assert "wizard--" not in html
    assert "正在生成 Assessment Plan" in html
    assert "计划快照已写入 artifact" in html


def test_discovery_run_ui_exposes_current_evidence_download():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "下载本次证据" in html
    assert "discoveryInventoryExport" in html
    assert "最近导出：{{discoveryInventoryExport.schema}}" in html
    assert 'v-if="discoveryRunEvidence"' in html
    assert ':href="discoveryRunEvidence"' in html
    assert "discoveryRunEvidence" in app_js
    assert "discoveryInventoryExport" in app_js
    assert "this.discoveryRunEvidence=res.download || (res.run&&res.run.download) || ''" in app_js
    assert "this.mergeRecords('discoveryRuns', [res.run])" in app_js
    assert "evidence='+this.discoveryRunEvidence" in app_js
    assert "async exportDiscovery" in app_js
    assert "/api/v1/discovery-hits/export" in app_js
    assert "发现验收包已导出" in app_js
    assert "window.open(res.download" in app_js
    assert 'v-model="form.discoveryAgentConfigs"' in html
    assert 'v-model="form.discoverySkills"' in html
    assert 'v-model="form.discoveryMcp"' in html
    assert 'v-model="form.discoveryChangesOnly"' in html
    assert '<input type="checkbox" checked> Agent 配置' not in html
    assert '<input type="checkbox" checked> Skills' not in html
    assert '<input type="checkbox" checked> MCP 配置' not in html
    assert "include_agent_configs:!!this.form.discoveryAgentConfigs" in app_js
    assert "include_skills:!!this.form.discoverySkills" in app_js
    assert "include_mcp:!!this.form.discoveryMcp" in app_js
    assert "changes_only:!!this.form.discoveryChangesOnly" in app_js
    assert "x.change_status||'UNKNOWN'" in html
    assert "版本 / 方法" in html
    assert "x.version||'-'" in html
    assert "x.probe_method||'-'" in html
    assert "a.probe_source||a.install_status" in html
    assert "selectedAsset.probe_method||'-'" in html


def test_skill_scan_ui_has_real_sync_and_changes_only_actions():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert '@click="runSkillScan"' in html
    assert '@click="runChangedSkillScan"' in html
    assert "async runChangedSkillScan()" in app_js
    assert "discover:true, include_agent_configs:false, include_mcp:false, include_skills:true" in app_js
    assert "changes_only:true" in app_js
    assert "skillScanResult.scan_mode" in html
    assert "skillScanResult.change_summary" in html


def test_sandbox_policy_ui_has_editable_controls_and_runtime_decisions():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "策略编辑" in html
    assert 'v-model="sandboxPolicy.network.default"' in html
    assert 'v-model="sandboxPolicy.process.subprocess"' in html
    assert 'v-model="sandboxPolicy.process.stdio_mcp"' in html
    assert 'v-model.number="sandboxPolicy.process.max_parallel"' in html
    assert 'v-model.number="sandboxPolicy.limits.timeout_sec"' in html
    assert "setSandboxList(['paths','read']" in html
    assert "setSandboxList(['paths','write']" in html
    assert "setSandboxList(['paths','deny']" in html
    assert "setSandboxList(['network','allow']" in html
    assert "setSandboxList(['env','deny_patterns']" in html
    assert "v-for=\"d in sandboxPolicyDecisions\"" in html
    assert "sandboxPolicyExport&&sandboxPolicyExport.download" in html
    assert "listToLines(value)" in app_js
    assert "setSandboxList(path, raw)" in app_js
    assert "this.sandboxPolicyDecisions=res.recent_decisions || []" in app_js
    assert "this.sandboxPolicyDecisions=this.sandboxTestResult.tests || []" in app_js
    assert "this.sandboxPolicyExport=res" in app_js


def test_mcp_toxic_flow_ui_uses_persisted_flows():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "toxicFlows" in app_js
    assert "mcpToxicFlowRows(){" in app_js
    assert "this.mergeRecords('toxicFlows', res.flows)" in app_js
    assert "this.mergeRecords('toxicFlows', flows.items)" in app_js
    assert "{{mcpToxicFlowRows.length}}" in html
    assert "v-for=\"f in mcpToxicFlowRows.slice(0,6)\"" in html
    assert "已持久化为本地 Toxic Flow 记录" in html


def test_mcp_and_tool_detail_deep_links_are_runtime_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    style = (STATIC / "assessment" / "style.css").read_text(encoding="utf-8")

    assert "current==='mcp-detail'" in html
    assert "current==='tool-detail'" in html
    assert "if(path.startsWith('/assessment/mcp/')) return 'mcp-detail';" in app_js
    assert "if(path.startsWith('/assessment/tools/')) return 'tool-detail';" in app_js
    assert "'mcp-detail':mcpDetailPath" in app_js
    assert "'tool-detail':toolDetailPath" in app_js
    assert "async loadMcpDetail" in app_js
    assert "async loadToolDetail" in app_js
    assert "/api/v1/mcp-servers/'+encodeURIComponent(id)" in app_js
    assert "/api/v1/tools/'+encodeURIComponent(tool.id)+'/similar" in app_js
    assert "/api/v1/tools/'+encodeURIComponent(tool.id)+'/flows" in app_js
    assert "不启动 stdio MCP" in html
    assert "持久化 Toxic Flow" in html
    assert 'table class="compact-table"' in html
    assert 'class="action-cell"' in html
    assert "table.compact-table{min-width:0" in style


def test_attack_path_visualization_uses_runtime_nodes():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "attackPathNodeRows(){" in app_js
    assert "selectedAttackPathPolicyDrafts(){" in app_js
    assert "v-for=\"node in attackPathNodeRows\"" in html
    assert "v-if=\"attackPathNodeRows.length\"" in html
    assert "{{node.label}}" in html
    assert "{{node.findingId||'未关联 Finding'}}" in html
    assert "v-for=\"p in selectedAttackPathPolicyDrafts\"" in html
    assert "{{selectedAttackPathPolicyDrafts.length}} drafts" in html
    assert "@click=\"preflightPolicyDraft(p)\"" in html
    assert "policyDraftPreflight" in html
    assert "最近预检：{{policyDraftPreflight.schema}}" in html
    assert "p.preflight_status||p.status" in html
    assert "@click=\"exportPolicyDraftPackage\"" in html
    assert "policyDraftExport" in html
    assert "外部文档<br><span" not in html
    assert "Agent Planner<br><span" not in html
    assert "async exportPolicyDraftPackage" in app_js
    assert "async preflightPolicyDraft" in app_js
    assert "'/api/v1/policy-drafts/'+encodeURIComponent(target.id)+'/preflight'" in app_js
    assert "this.policyDraftPreflight=res.preflight || null" in app_js
    assert "/api/v1/policy-drafts/export" in app_js


def test_consent_bulk_decline_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "async denyAllConsents" in app_js
    assert "/api/v1/consents/bulk-decision" in app_js
    assert "for(const consent of pending) await this.denyConsent(consent)" not in app_js
    assert "expiredConsentCount" in app_js
    assert "isPendingConsent(c)" in app_js
    assert "canDecideConsent(c)" in app_js
    assert "this.consents.filter(c=>this.isPendingConsent(c))" in app_js
    assert "已过期" in html
    assert "approved_config_sha256" in html
    assert "approval_fingerprint" in html
    assert ':disabled="!canDecideConsent(c)"' in html


def test_dashboard_health_self_test_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "健康检查通过" not in html
    assert "1 process" not in html
    assert "2/2 slots" not in html
    assert "schema 4" not in html
    assert "<span class=\"badge low\">健康</span>" not in html
    assert "agent-scan 0.5.12</button>" not in html
    assert "v-for=\"row in dashboardHealthRows\"" in html
    assert "runDashboardHealthAction(row)" in html
    assert "healthSelfTestResult" in html
    assert "dashboardHealthRows()" in app_js
    assert "runDashboardHealthAction(row)" in app_js
    assert "async runHealthSelfTest" in app_js
    assert "/api/v1/health/self-test" in app_js


def test_dashboard_guard_check_exports_evidence():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "@click=\"runGuardCheck\"" in html
    assert "@click=\"evaluateGuardPreflight\"" in html
    assert "只判定不执行" in html
    assert "guardPreflight.action" in html
    assert "guardPreflight.target" in html
    assert "guardPreflightResult" in html
    assert "guardPreflightDownload" in html
    assert "@click=\"downloadGuardEvidence\"" in html
    assert "defenseRecommendationRows.slice(0,8)" in html
    assert "@click=\"acknowledgeDefenseRecommendation(rec)\"" in html
    assert "@click=\"dismissDefenseRecommendation(rec)\"" in html
    assert "@click=\"exportDefenseRecommendations\"" in html
    assert "guardLastDownload" in app_js
    assert "downloadGuardEvidence()" in app_js
    assert "defenseRecommendations" in app_js
    assert "async refreshDefenseRecommendations" in app_js
    assert "async acknowledgeDefenseRecommendation" in app_js
    assert "async dismissDefenseRecommendation" in app_js
    assert "async evaluateGuardPreflight" in app_js
    assert "/api/v1/guard/evaluate" in app_js
    assert "hermes --version" in app_js
    assert "this.sandboxPolicyDecisions=[res.policy_decision]" in app_js
    assert "async exportDefenseRecommendations" in app_js
    assert "/api/v1/guard/check" in app_js
    assert "/api/v1/defense-recommendations" in app_js


def test_profile_template_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "已创建模板草稿" not in html
    assert "模板详情已打开" not in html
    assert "@click=\"createProfileDraft\"" in html
    assert "@click=\"cloneProfile(p)\"" in html
    assert "@click=\"openProfile(p)\"" in html
    assert "@click=\"validateProfile(p)\"" in html
    assert "@click=\"publishProfile(selectedProfile)\"" in html
    assert "async createProfileDraft" in app_js
    assert "async cloneProfile" in app_js
    assert "async openProfile" in app_js
    assert "async validateProfile" in app_js
    assert "async publishProfile" in app_js
    assert "/api/v1/profiles" in app_js


def test_assessment_plan_ui_uses_runtime_packages():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "84 项基线" not in html
    assert "84 + product rules" not in html
    assert "baseline: 84" not in html
    assert "dry_run</div><div>远程分析" not in html
    assert "Claude Code 专项" not in html
    assert "直接注入" not in html
    assert "长时漂移" not in html
    assert "assessmentRulePackages" in html
    assert "dynamicCasePackages" in html
    assert "taskPlanSummaryRows" in html
    assert "selectedProfilePlanYaml" in html
    assert "assessmentRulePackages()" in app_js
    assert "dynamicCasePackages()" in app_js
    assert "taskPlanSummaryRows()" in app_js
    assert "selectedProfilePlanYaml()" in app_js
    assert "parsedProfileRuleCount()" in app_js
    assert "rules:this.ruleStats.total" in app_js
    assert "|| 84" not in app_js


def test_findings_export_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "风险清单 CSV 已导出" not in html
    assert "@click=\"exportFindings\"" in html
    assert "async exportFindings" in app_js
    assert "/api/v1/findings/export" in app_js


def test_finding_false_positive_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "误报审批需人工理由，本轮未自动关闭风险" not in html
    assert "@click=\"markFindingFalsePositive(selectedFinding)\"" in html
    assert "async markFindingFalsePositive" in app_js
    assert "'/api/v1/findings/'+encodeURIComponent(finding.id)+'/false-positive'" in app_js
    assert "误报候选已写入 SQLite" in app_js


def test_finding_history_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "selectedFindingHistory" in app_js
    assert "async loadFindingHistory" in app_js
    assert "selectFindingTab(tab)" in app_js
    assert "'/api/v1/findings/'+encodeURIComponent(target.id)+'/history'" in app_js
    assert "v-for=\"h in selectedFindingHistory\"" in html
    assert "@click=\"selectFindingTab(x)\"" in html
    assert "@click=\"loadFindingHistory(selectedFinding)\"" in html
    assert "历史只读取本系统 SQLite finding/evidence/retest/audit_event" in html
    assert "状态来自本系统 Finding 记录。" not in html


def test_redteam_case_variables_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "<tr><td>language</td><td>zh-CN/en</td></tr>" not in html
    assert "<tr><td>encoding</td><td>plain/base64/zero-width</td></tr>" not in html
    assert "<tr><td>turn</td><td>1~8</td></tr>" not in html
    assert "selectedRedteamCaseVariables()" in app_js
    assert "c.variable_schema" in app_js
    assert "c.payload_schema && c.payload_schema.variables" in app_js
    assert "input-template" in app_js
    assert "v-if=\"selectedRedteamCaseVariables.length\"" in html
    assert "v-for=\"v in selectedRedteamCaseVariables\"" in html
    assert "{{v.value}}" in html


def test_sqlite_backup_restore_drill_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "恢复演练需在维护窗口手动选择备份" not in html
    assert "@click=\"runBackupRestoreDrill(b)\"" in html
    assert "@click=\"runLatestBackupRestoreDrill\"" in html
    assert "backupDrillResult" in html
    assert "async runBackupRestoreDrill" in app_js
    assert "'/api/v1/backups/'+encodeURIComponent(backup.id)+'/restore-drill'" in app_js
    assert "current_database_mutated" not in html


def test_execution_log_and_stop_request_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "已打开 Job 日志" not in html
    assert "已打开脱敏日志" not in html
    assert "已发送终止信号，10 秒后强制 Kill" not in html
    assert "@click=\"openJobLog(j)\"" in html
    assert "@click=\"openExecutionLog(p)\"" in html
    assert "@click=\"requestExecutionTerminate(p)\"" in html
    assert "executionLog" in html
    assert "executionTermination" in html
    assert "executionTermination.mode" in html
    assert "async openExecutionLog" in app_js
    assert "async openJobLog" in app_js
    assert "async requestExecutionTerminate" in app_js
    assert "'/api/v1/executions/'+encodeURIComponent(id)+'/logs'" in app_js
    assert "'/api/v1/jobs/'+encodeURIComponent(id)+'/logs'" in app_js
    assert "'/api/v1/executions/'+encodeURIComponent(process.id)+'/terminate'" in app_js
    assert "未发送外部进程信号" in app_js


def test_task_retry_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "Job 已重新排队" not in html
    assert "@click=\"retryTask(t)\"" in html
    assert "@click=\"retryTask(selectedTask)\"" in html
    assert "canRetryTask(t)" in html
    assert "async retryTask" in app_js
    assert "'/api/v1/tasks/'+encodeURIComponent(task.id)+'/retry'" in app_js


def test_task_queue_status_is_runtime_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "服务上次正常关闭。0 个 Job 需要恢复，1 个报告渲染任务可重试。" not in html
    assert '<span class="muted small">运行</span><div class="kpi">2</div>' not in html
    assert '<span class="muted small">等待</span><div class="kpi">3</div>' not in html
    assert '<span class="muted small">可用槽</span><div class="kpi">0/2</div>' not in html
    assert "{{taskQueueSummary.running}}" in html
    assert "{{taskQueueSummary.waiting}}" in html
    assert "{{taskQueueSummary.waitingApproval}}" in html
    assert "{{taskQueueSummary.slotText}}" in html
    assert "taskQueueSummary(){" in app_js
    assert "taskRecoverySummary(){" in app_js
    assert "当前无待恢复 Job、失败进程或可重试报告" in app_js


def test_task_detail_findings_and_evidence_tabs_are_data_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "v-else-if=\"taskTab==='风险'\"" in html
    assert "v-for=\"f in selectedTaskFindings\"" in html
    assert "v-else-if=\"taskTab==='证据'\"" in html
    assert "v-for=\"e in selectedTaskEvidence\"" in html
    assert "async retryTask" in app_js
    assert "selectedTaskFindings()" in app_js
    assert "selectedTaskEvidence()" in app_js
    assert "assessment_id" in app_js
    assert "evidence_ids" in app_js


def test_task_detail_jobs_events_and_approval_are_runtime_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "job_006" not in html
    assert "Last-Event-ID: 1841" not in html
    assert "id: 1842" not in html
    assert "当前 2 个 stdio MCP Server 等待审批" not in html
    assert "{{selectedTaskJobs.length}} / {{taskStages.length}}" in html
    assert "v-for=\"j in selectedTaskJobs\"" in html
    assert "v-if=\"!selectedTaskJobs.length\"" in html
    assert "{{selectedTaskEventSourceSnippet}}" in html
    assert "selectedTaskPendingConsents.length" in html
    assert "selectedTaskJobs()" in app_js
    assert "selectedTaskPendingConsents()" in app_js
    assert "selectedTaskEventSourceSnippet()" in app_js
    assert "path.match(/^\\/assessment\\/tasks\\/([^/]+)/)" in app_js
    assert "this.pushRoute('task-detail')" in app_js
    assert "refreshTaskEvents(t, true)" in app_js


def test_task_detail_error_cleanup_tab_is_runtime_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "关联内容已设计；实现时使用任务 ID 加载" not in html
    assert "v-else-if=\"taskTab==='错误与清理'\"" in html
    assert "selectedTaskCleanupSummaryRows" in html
    assert "selectedTaskCleanupMessage" in html
    assert "selectedTaskErrorEvents.slice(0,8)" in html
    assert "selectedTaskCleanupArtifacts" in html
    assert "selectedTaskProcesses.length" in html
    assert "selectedTaskReports.length" in html
    assert "selectedTaskProcesses()" in app_js
    assert "selectedTaskReports()" in app_js
    assert "selectedTaskErrorEvents()" in app_js
    assert "selectedTaskCleanupArtifacts()" in app_js
    assert "selectedTaskCleanupSummaryRows()" in app_js
    assert "不 kill、不启动、不修改 Codex/Hermes/MCP" in app_js


def test_finding_detail_uses_real_finding_and_evidence_data():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "ev_01 · source" not in html
    assert "casepack: claude-code-core@4.0" not in html
    assert "2026-06-26" not in html
    assert "selectedFindingEvidence.length" in html
    assert "v-for=\"e in selectedFindingEvidence\"" in html
    assert "findingReproductionSteps(selectedFinding)" in html
    assert "selectedFindingEvidence()" in app_js
    assert "findingReproductionSteps(finding)" in app_js


def test_retest_diff_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "复测对比读取当前记录" not in html
    assert "隐藏指令执行" not in html
    assert "越界 Tool Call" not in html
    assert "剩余风险" not in html
    assert "@click.stop=\"loadRetestDiff(r)\"" in html
    assert "v-for=\"row in (retestDiff&&retestDiff.rows)||[]\"" in html
    assert "retestDiff.safe_mode" in html
    assert "selectedRetest" in app_js
    assert "async loadRetestDiff" in app_js
    assert "'/api/v1/retests/'+encodeURIComponent(retest.id)+'/diff'" in app_js


def test_report_readiness_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "Jinja2" not in html
    assert "Chromium" not in html
    assert "最近失败" not in html
    assert "standard@4.0.0" not in html
    assert "范围/授权</td><td><span class=\"badge low\">✓" not in html
    assert "v-for=\"row in reportReadinessRows\"" in html
    assert "@click.stop=\"exportReportPackage(r)\"" in html
    assert "reportPackageExport" in html
    assert "最近交付包：{{reportPackageExport.schema}}" in html
    assert "reportRenderingStatus.engine" in html
    assert "refreshReportPreview(selectedReport)" in html
    assert "reportReadinessRows()" in app_js
    assert "reportRenderingStatus()" in app_js
    assert "async refreshReportPreview" in app_js
    assert "async exportReportPackage" in app_js
    assert "async syncReport" in app_js
    assert "reportSyncLastDownload" in app_js
    assert "/package" in app_js
    assert "报告交付包已生成" in app_js
    assert "this.mergeRecords('reports', [res.report])" in app_js
    assert "报告回写包已生成" in app_js


def test_rule_management_ui_uses_real_rule_state():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "<div class=\"metric-label\">基线</div><div class=\"metric-value\">84" not in html
    assert "<div class=\"metric-label\">本地专项</div><div class=\"metric-value\">31" not in html
    assert "<div class=\"metric-label\">产品专项</div><div class=\"metric-value\">67" not in html
    assert "<div class=\"metric-label\">人工检查</div><div class=\"metric-value\">18" not in html
    assert "人工签署</td><td><span class=\"badge medium\">待 1 人" not in html
    assert "v-for=\"row in ruleGateRows\"" in html
    assert "selectedRuleDefinition" in html
    assert "ruleStats.total" in html
    assert "selectRule(r)" in html
    assert "ruleStats()" in app_js
    assert "ruleGateRows()" in app_js
    assert "selectRule(rule)" in app_js


def test_scanner_center_surfaces_runtime_self_test_artifact():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "scannerTestResult.download" in html
    assert "下载证据" in html
    assert "(scannerTestResult.checks||[]).length" in html
    assert "'/api/v1/scanners/'+encodeURIComponent(scanner.id)+'/self-test'" in app_js
    assert "this.mergeRecords('scanners', [res.scanner])" in app_js
    assert "扫描器自测已写入 scanner_health" in app_js


def test_schedule_due_runner_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "@click=\"runDueSchedules\"" in html
    assert "执行到期计划" in html
    assert "scheduleDueRun" in html
    assert "到期批次：{{scheduleDueRun.counts&&scheduleDueRun.counts.executed}}" in html
    assert "async runDueSchedules" in app_js
    assert "/api/v1/schedules/run-due" in app_js
    assert "到期计划执行完成" in app_js
    assert "max_runs:10" in app_js


def test_integration_sync_ui_surfaces_local_package_artifact():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "integrationSyncResult" in app_js
    assert "integrationSyncLastDownload" in app_js
    assert "downloadIntegrationSync()" in app_js
    assert "'/api/v1/integrations/'+encodeURIComponent(integration.id)+'/sync'" in app_js
    assert "this.integrationSyncResult=res.sync || null" in app_js
    assert "同步包已生成" in app_js
    assert "最近同步包：{{integrationSyncResult.schema" in html
    assert "@click=\"downloadIntegrationSync\"" in html
    assert "下载证据" in html


def test_platform_embed_page_uses_runtime_context_and_event_artifact():
    seed = json.loads((STATIC / "assessment" / "seed.json").read_text(encoding="utf-8"))
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")

    nav_items = [item for group in seed["navGroups"] for item in group["items"]]
    assert any(item["key"] == "platform-embed" and item["name"] == "主平台嵌入联调" for item in nav_items)
    assert "current==='platform-embed'" in html
    assert "'platform-embed':'/assessment/platform-embed'" in app_js
    assert "/assessment/platform-embed':'platform-embed" in app_js
    assert "/assessment/platform-embed':'integrations" not in app_js
    assert "refreshPlatformEmbedContext" in app_js
    assert "submitPlatformEmbedEvent" in app_js
    assert "downloadPlatformEmbedEvent" in app_js
    assert "/api/v1/embed/context" in app_js
    assert "/api/v1/integrations/runtime-platform/events" in app_js
    assert "@click=\"refreshPlatformEmbedContext()\"" in html
    assert "@click=\"submitPlatformEmbedEvent\"" in html
    assert "@click=\"downloadPlatformEmbedEvent\"" in html
    assert "runtime-platform-event" in html
    assert "模拟回写" not in html
    assert "embed-demo" not in app_js


def test_completeness_matrix_ui_uses_runtime_summary():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert '<div class="metric-label">页面/详情</div><div class="metric-value">48' not in html
    assert '<div class="metric-label">API</div><div class="metric-value">141' not in html
    assert '<div class="metric-label">SQLite 表</div><div class="metric-value">49' not in html
    assert '<div class="metric-label">缺口</div><div class="metric-value">0' not in html
    assert "<td><span class=\"check\">✓</span></td><td><span class=\"check\">✓</span></td><td><span class=\"check\">✓</span></td>" not in html
    assert "completenessStats.pages" in html
    assert "completenessStats.sqlite_tables" in html
    assert "statusClass(x.audit)" in html
    assert "statusClass(x.contract)" in html
    assert "statusClass(x.e2e)" in html
    assert "completenessStats()" in app_js
    assert "async refreshCompleteness" in app_js
    assert "/api/v1/completeness?page_size=200" in app_js


def test_api_debug_page_uses_runtime_openapi_and_diagnostics():
    seed = json.loads((STATIC / "assessment" / "seed.json").read_text(encoding="utf-8"))
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")

    nav_items = [item for group in seed["navGroups"] for item in group["items"]]
    assert any(item["key"] == "api-debug" and item["name"] == "API / 状态调试台" for item in nav_items)
    assert "current==='api-debug'" in html
    assert "/assessment/api-debug':'api-debug" in app_js
    assert "completeness','/assessment/api-debug':'completeness" not in app_js
    assert "refreshApiDebugOpenapi" in app_js
    assert "runApiDiagnosticScenario" in app_js
    assert "exportOpenapiContract" in app_js
    assert "downloadApiDiagnostic" in app_js
    assert "/api/v1/openapi.json" in app_js
    assert "/api/v1/diagnostics/scenario" in app_js
    assert "@click=\"refreshApiDebugOpenapi()\"" in html
    assert "@click=\"runApiDiagnosticScenario\"" in html
    assert "@click=\"downloadApiDiagnostic\"" in html
    assert "Mock 数据" not in html
    assert "错误注入" not in html
