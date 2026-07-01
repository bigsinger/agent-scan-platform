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
    assert 'data-testid="agent-scan-self-test"' in html
    assert "@click=\"refreshAgentScanCompat()\"" in html
    assert "@click=\"runAgentScanSelfTest\"" in html
    assert "agentScanSelfTestResult" in html
    assert "async refreshAgentScanCompat" in app_js
    assert "async runAgentScanSelfTest" in app_js
    assert "/api/v1/agent-scan/self-test" in app_js


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


def test_findings_export_ui_is_api_backed():
    html = (STATIC / "assessment" / "index.html").read_text(encoding="utf-8")
    app_js = (STATIC / "assessment" / "app.js").read_text(encoding="utf-8")
    assert "风险清单 CSV 已导出" not in html
    assert "@click=\"exportFindings\"" in html
    assert "async exportFindings" in app_js
    assert "/api/v1/findings/export" in app_js


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
