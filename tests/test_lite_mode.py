from pathlib import Path

from fastapi.testclient import TestClient

from assessment.main import app


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "assessment" / "static" / "assessment"


def test_lite_workspace_is_default_and_advanced_workspace_is_preserved():
    client = TestClient(app)

    lite = client.get("/assessment")
    advanced = client.get("/assessment/advanced")
    professional_route = client.get("/assessment/quick-scan")

    assert lite.status_code == 200
    assert 'id="lite-app"' in lite.text
    assert "检查本机 Agent 安全风险" in lite.text
    assert "/static/assessment/lite.js?v=4.2.10" in lite.text
    assert 'id="app"' not in lite.text

    assert advanced.status_code == 200
    assert 'id="app"' in advanced.text
    assert "Agent 安全测评能力模块" in advanced.text
    assert professional_route.status_code == 200
    assert 'id="app"' in professional_route.text


def test_lite_workspace_loads_only_the_minimum_real_api_flow():
    html = (STATIC / "lite.html").read_text(encoding="utf-8")
    javascript = (STATIC / "lite.js").read_text(encoding="utf-8")
    stylesheet = (STATIC / "lite.css").read_text(encoding="utf-8")

    assert "/static/vendor/vue.global.prod.js" not in html
    assert "/static/assessment/seed.js" not in html
    assert "/api/v1/bootstrap" not in javascript
    assert "/api/v1/version" in javascript
    assert "/api/v1/discovery-runs" in javascript
    assert "/api/v1/quick-scans" in javascript
    assert "/api/v1/tasks/" in javascript
    assert "/api/v1/findings?page_size=200" in javascript
    assert "/api/v1/reports/" in javascript
    assert "/api/v1/quick-scans/recent?page_size=5" in javascript
    assert "mutates_installed_agents: false" in javascript
    assert "execution_mode: 'readonly'" in javascript
    assert "remote_analysis: false" in javascript
    assert "max_files: 150" in javascript
    assert "静态检查完成" in javascript
    assert "本机只读" in html
    assert "专业模式" in html
    assert "@media(max-width:760px)" in stylesheet


def test_powershell_start_script_supports_single_process_lite_mode():
    script = (ROOT / "start_services.ps1").read_text(encoding="utf-8")

    assert "[switch]$Lite" in script
    assert "if (-not $Lite) { $requiredPorts += $OtelPort }" in script
    assert 'mode = $(if ($Lite) { "lite" } else { "full" })' in script
    assert 'OTel receiver: skipped (lite mode)' in script
    assert 'if (-not $Lite) {' in script
