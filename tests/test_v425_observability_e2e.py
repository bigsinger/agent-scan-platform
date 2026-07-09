from __future__ import annotations

import py_compile
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from assessment.main import app
from assessment.observability.normalizer import attributes_to_dict, span_to_probe_event, log_to_probe_event
from assessment.probes.codex.codex_probe_hook import generate_hook_script
from assessment.probes.hermes.hermes_probe_plugin import generate_hermes_plugin_code
from assessment.scanning.discovery import DiscoveryEngine
from assessment.scanning.scope import self_project_scope
from assessment.store import REPO_ROOT

client = TestClient(app)


def test_v425_behavior_chain_build_is_idempotent():
    payload = {
        "events": [
            {"event_id": "evt-v425-test-001", "event_type": "agent.user_input.received", "timestamp": "2026-07-09T10:00:00Z", "source_agent": "codex", "session_id": "sess-v425-test", "payload": {"input": "hello", "password": "should-not-appear"}},
            {"event_id": "evt-v425-test-002", "event_type": "tool.call.started", "timestamp": "2026-07-09T10:00:01Z", "source_agent": "codex", "session_id": "sess-v425-test", "tool_call_id": "tool-v425-test-001", "tool_name": "Bash", "tool_type": "shell", "payload": {"command": "echo hello"}},
            {"event_id": "evt-v425-test-003", "event_type": "tool.call.completed", "timestamp": "2026-07-09T10:00:02Z", "source_agent": "codex", "session_id": "sess-v425-test", "tool_call_id": "tool-v425-test-001", "tool_name": "Bash", "tool_type": "shell", "status": "ok", "payload": {"output": "hello"}},
        ]
    }
    assert client.post("/api/v1/probes/events", json=payload).status_code == 200
    first = client.post("/api/v1/behavior/chains", json={"action": "build", "source_agent": "codex"})
    assert first.status_code == 200
    first_json = first.json()
    assert first_json["status"] == "BUILT"
    assert first_json["chains"]
    chain_id = first_json["chains"][0]["chain_id"]
    second = client.post("/api/v1/behavior/chains", json={"action": "build", "source_agent": "codex"})
    assert second.status_code == 200
    assert second.json()["created"] == 0
    detail = client.get(f"/api/v1/behavior/chains/{chain_id}")
    assert detail.status_code == 200
    assert len(detail.json()["events"]) >= 3
    assert len(detail.json()["edges"]) >= 2
    assert "should-not-appear" not in client.get("/api/v1/probes/events?session_id=sess-v425-test").text


def test_v425_otlp_normalizer_and_query_api():
    attrs = [{"key": "agent.session_id", "value": {"stringValue": "sess"}}]
    assert attributes_to_dict(attrs)["agent.session_id"] == "sess"
    span = {
        "traceId": "11111111111111111111111111111111",
        "spanId": "2222222222222222",
        "name": "tool.call",
        "startTimeUnixNano": "1720000000000000000",
        "attributes": [
            {"key": "agent.event_type", "value": {"stringValue": "tool.call.started"}},
            {"key": "agent.tool_name", "value": {"stringValue": "Bash"}},
            {"key": "agent.command", "value": {"stringValue": "echo hello"}},
        ],
    }
    event = span_to_probe_event(span, {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]}, {})
    assert event and event["source_agent"] == "codex"
    assert event["event_type"] == "tool.call.started"
    log_event = log_to_probe_event({"body": {"stringValue": "ok"}, "attributes": [{"key": "agent.event_type", "value": {"stringValue": "agent.turn.completed"}}]}, {"attributes": [{"key": "service.name", "value": {"stringValue": "hermes"}}]}, {})
    assert log_event and log_event["source_agent"] == "hermes"
    for path in ["/api/v1/otel/spans", "/api/v1/otel/logs", "/api/v1/otel/metrics"]:
        resp = client.get(path)
        assert resp.status_code == 200
        assert "items" in resp.json()


def test_v425_probe_install_plan_and_generated_code_compile():
    for agent_type in ["codex", "hermes"]:
        resp = client.post("/api/v1/probes/install-plan", json={"agent_type": agent_type, "dry_run": True})
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["dry_run"] is True
        assert payload["mutates_installed_agents"] is False
        assert payload["requires_confirmation"] is True
    for name, code in [("codex_hook.py", generate_hook_script()), ("hermes_plugin.py", generate_hermes_plugin_code())]:
        path = Path(tempfile.gettempdir()) / name
        path.write_text(code, encoding="utf-8")
        py_compile.compile(str(path), doraise=True)


def test_v425_self_project_source_and_docs_are_skipped():
    result = DiscoveryEngine().discover([REPO_ROOT], scope="self-project-regression", probe_installed=False)
    paths = "\n".join(str(p).replace("\\", "/") for p in result.scan_paths)
    assert "/src/" not in paths
    assert "/doc/" not in paths
    scope = self_project_scope(REPO_ROOT / "src" / "assessment" / "main.py")
    assert scope["policy"] == "skip-agent-scan-platform-source-and-docs"
    assert scope["source_excluded"] is True
