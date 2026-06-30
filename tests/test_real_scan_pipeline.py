from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from assessment.main import app
from assessment.scanning import discovery as discovery_module
from assessment.scanning.discovery import DiscoveryEngine
from assessment.scanning.guard import PassiveGuard
from assessment.scanning.models import DiscoveryResult
from assessment.store import AssessmentStore


client = TestClient(app)
FIXTURE = Path(__file__).parent / "fixtures" / "sample_agent_project"


def test_quick_scan_generates_findings_evidence_and_report():
    response = client.post(
        "/api/v1/quick-scans",
        json={"mode": "path", "target_path": str(FIXTURE), "adapter": "Codex", "max_files": 200},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["assessment"]["status"] in {"已完成", "部分完成"}
    assert payload["files_scanned"] >= 4
    assert payload["findings"]
    assert payload["evidence"]
    assert payload["report"]["status"] == "READY"

    rule_ids = {finding["rule_id"] for finding in payload["findings"]}
    assert "SECRET-KEY-001" in rule_ids
    assert "MCP-CMD-001" in rule_ids
    assert "SKILL-PI-001" in rule_ids
    assert "FLOW-DESTRUCTIVE-001" in rule_ids
    assert "CODEX-CONFIG-001" in rule_ids

    evidence_text = "\n".join(item["content"] for item in payload["evidence"])
    assert "sk-test000000000000000000000000" not in evidence_text
    assert "<REDACTED" in evidence_text

    report_id = payload["report"]["id"]
    report = client.get(f"/api/v1/reports/{report_id}/download")
    assert report.status_code == 200
    assert "Agent 安全测评" in report.text
    assert "sk-test000000000000000000000000" not in report.text


def test_discovery_creates_mcp_consent_without_starting_stdio():
    response = client.post("/api/v1/discovery-runs", json={"path": str(FIXTURE), "scope": "fixture"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["status"] == "COMPLETED"
    assert payload["mcp_servers"]
    assert payload["consents"]
    assert payload["consents"][0]["status"] == "待审批"
    assert payload["consents"][0]["env"]["OPENAI_API_KEY"] == "<REDACTED>"


def test_mcp_static_inspect_derives_tools_and_evidence_without_starting_stdio():
    discovery = client.post("/api/v1/discovery-runs", json={"path": str(FIXTURE), "scope": "fixture"})
    assert discovery.status_code == 200
    server = discovery.json()["mcp_servers"][0]

    response = client.post(f"/api/v1/mcp-servers/{server['id']}/inspect", json={})

    assert response.status_code == 200
    payload = response.json()
    assert payload["safe_mode"] == "local-readonly"
    assert payload["external_process_started"] is False
    assert payload["mcp_started"] is False
    assert payload["inspection"]["status"] == "COMPLETED"
    assert payload["inspection"]["tool_count"] >= 1
    assert "MCP-CMD-001" in payload["inspection"]["risk_rules"]
    assert payload["server"]["status"] == "待审批"
    assert payload["server"]["signature"].startswith("static:")
    assert payload["tools"]
    assert any("shell_exec" in tool["labels"] for tool in payload["tools"])
    assert payload["findings"]
    assert payload["evidence"]["artifact_path"]

    tools = client.get(f"/api/v1/mcp-servers/{server['id']}/tools")
    assert tools.status_code == 200
    assert tools.json()["items"]

    flow_tool = next(tool for tool in payload["tools"] if "shell_exec" in tool["labels"])
    flows = client.get(f"/api/v1/tools/{flow_tool['id']}/flows")
    assert flows.status_code == 200
    assert any(item["status"] == "默认阻断" for item in flows.json()["items"])

    artifact = client.get(payload["inspection"]["download"])
    assert artifact.status_code == 200
    assert "未启动 stdio MCP Server" in artifact.text
    assert "sk-test000000000000000000000000" not in artifact.text


def test_discovery_probes_installed_hermes_and_codex(monkeypatch, tmp_path):
    hermes_project = tmp_path / "hermes" / "hermes-agent"
    hermes_project.mkdir(parents=True)
    codex_exe = tmp_path / "OpenAI.Codex_26.616.10790.0_x64__2p2nqsd0c76g0" / "app" / "Codex.exe"
    codex_exe.parent.mkdir(parents=True)
    codex_exe.write_text("", encoding="utf-8")

    def fake_which(command: str) -> str | None:
        return "C:/tools/hermes.exe" if command == "hermes" else None

    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=f"Hermes Agent v0.17.0 (2026.6.19)\nProject: {hermes_project}\nPython: 3.11.15\n",
        )

    monkeypatch.setattr(discovery_module.shutil, "which", fake_which)
    monkeypatch.setattr(discovery_module.subprocess, "run", fake_run)
    monkeypatch.setattr(discovery_module, "CODEX_EXE_CANDIDATES", (codex_exe,))
    monkeypatch.setattr(DiscoveryEngine, "_candidate_roots", lambda self, explicit_paths: [])

    result = DiscoveryEngine().discover(None)

    agents = {agent["adapter"]: agent for agent in result.agents}
    assert agents["Hermes"]["version"] == "Hermes Agent v0.17.0"
    assert agents["Codex"]["version"] == "26.616.10790.0"
    assert agents["Codex"]["install_status"] == "已安装"


def test_passive_guard_baselines_and_detects_hash_changes(tmp_path):
    store = AssessmentStore(tmp_path / "guard.db")
    store.initialize()
    guard = PassiveGuard(store)

    first = DiscoveryResult(
        run={"id": "disc_1", "status": "COMPLETED"},
        hits=[
            {
                "id": "hit_cfg",
                "type": "MCP",
                "agent": "Codex",
                "path": "~/.codex/config.toml",
                "path_hash": "abc123",
                "sha256": "old",
                "source": "test",
                "scope": "User",
            }
        ],
        agents=[{"id": "agt_codex", "adapter": "Codex"}],
        mcp_servers=[{"id": "mcp_1", "name": "local", "transport": "stdio"}],
    )
    guard.discovery.discover = lambda *args, **kwargs: first
    first_result = guard.check()
    assert first_result["event"]["new_baselines"] == 1
    assert first_result["event"]["changed"] == 0

    second = DiscoveryResult(
        run={"id": "disc_2", "status": "COMPLETED"},
        hits=[{**first.hits[0], "sha256": "new"}],
        agents=first.agents,
        mcp_servers=first.mcp_servers,
    )
    guard.discovery.discover = lambda *args, **kwargs: second
    second_result = guard.check()

    assert second_result["event"]["changed"] == 1
    assert second_result["changes"][0]["severity"] == "高危 P1"
    assert store.list_records("defense_recommendation")
