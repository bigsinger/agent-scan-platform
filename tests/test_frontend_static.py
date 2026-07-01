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
    assert "@click=\"selfTestAllAdapters\"" in html
    assert "@click=\"selfTestAdapter(a)\"" in html
    assert "adapterSelfTestResult" in html
    assert "async selfTestAdapter" in app_js
    assert "async selfTestAllAdapters" in app_js
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
    assert "@click=\"runHealthSelfTest\"" in html
    assert "healthSelfTestResult" in html
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
