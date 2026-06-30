from fastapi.testclient import TestClient

from assessment.contracts import API_CONTRACTS
from assessment.main import app


client = TestClient(app)


def test_core_health_and_dashboard():
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    client.post("/api/v1/discovery-runs", json={"path": "tests/fixtures/sample_agent_project", "scope": "fixture"})
    dashboard = client.get("/api/v1/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["metrics"]["agents"] >= 1
    assert "guard" in dashboard.json()


def test_all_spec_pages_have_completeness_rows():
    response = client.get("/api/v1/completeness?page_size=100")
    assert response.status_code == 200
    rows = response.json()["items"]
    assert len(rows) == 48
    assert rows[0]["id"] == "P01"
    assert rows[-1]["id"] == "D14"
    assert {row["route"] for row in rows} >= {"/assessment/mcp-consent", "/assessment/python-exec", "/assessment/api-debug"}


def test_openapi_contains_v4_1_contract_endpoints():
    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    for _, api_path in API_CONTRACTS:
        path = api_path.split("?", 1)[0]
        assert path in paths, path


def test_write_api_updates_state_and_audit():
    response = client.post("/api/v1/quick-scans", json={"mode": "fixture", "max_files": 50})
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["assessment"]["status"] in {"已完成", "部分完成"}
    assert payload["report"]["status"] == "READY"
    assert payload["audit_event"]["action"] == "post.quick-scans"


def test_database_maintenance_endpoints():
    assert client.get("/api/v1/database/status").status_code == 200
    assert client.post("/api/v1/database/integrity-check").json()["integrity"]["status"] == "PASS"
    assert client.post("/api/v1/sqlite/integrity-check").json()["integrity"]["status"] == "PASS"
    assert client.post("/api/v1/sqlite/checkpoint").json()["checkpoint"]["status"] == "DONE"
    backup = client.post("/api/v1/database/backup")
    assert backup.status_code == 200
    assert backup.json()["backup"]["sha256"]
    backups = client.get("/api/v1/backups")
    assert backups.status_code == 200
    assert backups.json()["total"] >= 1


def test_report_evidence_and_risk_closure_actions():
    scan = client.post("/api/v1/quick-scans", json={"mode": "fixture", "max_files": 50}).json()
    report = client.post("/api/v1/reports", json={"assessment_id": scan["assessment"]["id"], "type": "Standard"}).json()["report"]
    assert report["status"] == "READY"
    preview = client.get(f"/api/v1/reports/{report['id']}")
    assert preview.status_code == 200
    assert preview.json()["preview"]["download"].endswith("/download")
    download = client.get(f"/api/v1/reports/{report['id']}/download")
    assert download.status_code == 200
    assert "Agent 安全测评能力模块 V4.1" in download.text

    evidence = scan["evidence"][0]
    redacted = client.post(f"/api/v1/evidence/{evidence['id']}/redact", json={})
    assert redacted.status_code == 200
    assert redacted.json()["evidence"]["redaction"] == "已脱敏"

    finding = scan["findings"][0]
    accepted = client.post(f"/api/v1/findings/{finding['id']}/accept", json={"reason": "contract test"})
    assert accepted.json()["finding"]["status"] == "已接受风险"
    retest = client.post(f"/api/v1/findings/{finding['id']}/retest", json={"scope": "固化输入"})
    assert retest.json()["retest"]["status"] == "QUEUED"


def test_representative_spec_endpoints():
    endpoints = [
        "/api/v1/agents",
        "/api/v1/agents/agt_cc_001",
        "/api/v1/agents/agt_cc_001/components",
        "/api/v1/agents/agt_cc_001/abom",
        "/api/v1/adapters",
        "/api/v1/agent-scan/status",
        "/api/v1/agent-scan/compat",
        "/api/v1/agent-scan/issues",
        "/api/v1/mcp/servers",
        "/api/v1/mcp-servers",
        "/api/v1/mcp-consents",
        "/api/v1/skills",
        "/api/v1/assessments",
        "/api/v1/assessments/asm_v4_001/events",
        "/api/v1/tasks/asm_v4_001/events",
        "/api/v1/execution-supervisor",
        "/api/v1/executor/health",
        "/api/v1/sandbox-policy",
        "/api/v1/guard/status",
        "/api/v1/findings",
        "/api/v1/evidence",
        "/api/v1/reports",
        "/api/v1/sqlite/status",
        "/api/v1/licenses/export",
        "/api/v1/third-party",
    ]
    for endpoint in endpoints:
        response = client.get(endpoint)
        assert response.status_code == 200, endpoint
