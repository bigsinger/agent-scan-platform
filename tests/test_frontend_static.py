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


def test_agent_scan_compat_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "上游源码哈希验证通过" not in html
    assert "兼容自测完成：64/64 通过" not in html
    assert "64/64" not in html
    assert "专用 Discoverer" not in html
    assert "Cursor/VSCode/Windsurf/Kiro" not in html
    assert "<td>✓</td>" not in html
    assert 'data-testid="agent-scan-self-test"' in html
    assert "@click=\"refreshAgentScanCompat()\"" in html
    assert "@click=\"runAgentScanSelfTest\"" in html
    assert "agentScanSelfTestResult" in html
    assert "v-for=\"row in agentScanDiscoveryRows\"" in html
    assert "v-for=\"col in agentScanDiscoveryColumns\"" in html
    assert "async refreshAgentScanCompat" in app_js
    assert "async runAgentScanSelfTest" in app_js
    assert "agentScanDiscoveryRows()" in app_js
    assert "agentScanDiscoveryColumns()" in app_js
    assert "discovery_coverage" in app_js
    assert "/api/v1/agent-scan/self-test" in app_js


def test_quick_scan_ui_requires_api_assessment_record():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "mode:this.quickMode" in app_js
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


def test_discovery_run_ui_exposes_current_evidence_download():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "下载本次证据" in html
    assert 'v-if="discoveryRunEvidence"' in html
    assert ':href="discoveryRunEvidence"' in html
    assert "discoveryRunEvidence" in app_js
    assert "this.discoveryRunEvidence=res.download || (res.run&&res.run.download) || ''" in app_js
    assert "this.mergeRecords('discoveryRuns', [res.run])" in app_js
    assert "evidence='+this.discoveryRunEvidence" in app_js


def test_consent_bulk_decline_ui_is_api_backed():
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "async denyAllConsents" in app_js
    assert "/api/v1/consents/bulk-decision" in app_js
    assert "for(const consent of pending) await this.denyConsent(consent)" not in app_js


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
    assert "@click=\"downloadGuardEvidence\"" in html
    assert "guardLastDownload" in app_js
    assert "downloadGuardEvidence()" in app_js
    assert "/api/v1/guard/check" in app_js


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
    assert "reportRenderingStatus.engine" in html
    assert "refreshReportPreview(selectedReport)" in html
    assert "reportReadinessRows()" in app_js
    assert "reportRenderingStatus()" in app_js
    assert "async refreshReportPreview" in app_js
    assert "async syncReport" in app_js
    assert "reportSyncLastDownload" in app_js
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
