from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from assessment.observability import api as obs_api
from assessment.observability import receiver as receiver_module
from assessment.observability.receiver import create_receiver_app
from assessment.store import AssessmentStore


def _store(tmp_path):
    store = AssessmentStore(tmp_path / "otel-v426.db")
    store.initialize()
    return store


def _platform_client():
    app = FastAPI()
    app.include_router(obs_api.router)
    return TestClient(app)


def test_v426_receiver_ingests_traces_logs_metrics_and_query_api(monkeypatch, tmp_path):
    store = _store(tmp_path)
    monkeypatch.setattr(receiver_module, "get_store", lambda: store)
    monkeypatch.setattr(obs_api, "get_store", lambda: store)
    receiver = TestClient(create_receiver_app())
    platform = _platform_client()

    trace_id = "11111111111111111111111111111111"
    trace_payload = {
        "resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
            "scopeSpans": [{"scope": {"name": "test"}, "spans": [{
                "traceId": trace_id,
                "spanId": "2222222222222222",
                "name": "agent.tool.call",
                "startTimeUnixNano": "1780000000000000000",
                "endTimeUnixNano": "1780000001000000000",
                "attributes": [
                    {"key": "agent.name", "value": {"stringValue": "codex"}},
                    {"key": "session.id", "value": {"stringValue": "v426-smoke"}},
                    {"key": "tool.name", "value": {"stringValue": "shell"}},
                    {"key": "agent.command", "value": {"stringValue": "echo hello"}},
                ],
            }]}],
        }]
    }
    assert receiver.post("/v1/traces", json=trace_payload).json()["accepted"] == 1

    # Unknown OTel without agent/session is stored as OTel only, not converted to noisy probe_event.
    unknown = {"resourceSpans": [{"scopeSpans": [{"spans": [{"traceId": "9"*32, "spanId": "8"*16, "name": "http.request"}]}]}]}
    assert receiver.post("/v1/traces", json=unknown).status_code == 200

    log_payload = {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "hermes"}}]}, "scopeLogs": [{"logRecords": [{"traceId": trace_id, "spanId": "2222222222222222", "timeUnixNano": "1780000002000000000", "severityText": "INFO", "body": {"stringValue": "api_key=supersecret"}, "attributes": [{"key": "agent.event_type", "value": {"stringValue": "agent.turn.completed"}}, {"key": "session.id", "value": {"stringValue": "v426-smoke"}}]}]}]}]}
    assert receiver.post("/v1/logs", json=log_payload).json()["accepted"] == 1

    metric_payload = {"resourceMetrics": [{"scopeMetrics": [{"metrics": [{"name": "agent.tool.calls", "unit": "1", "gauge": {"dataPoints": [{"timeUnixNano": "1780000003000000000", "asInt": "7", "attributes": [{"key": "agent.name", "value": {"stringValue": "codex"}}]}]}}]}]}]}
    assert receiver.post("/v1/metrics", json=metric_payload).json()["accepted"] == 1

    spans = platform.get("/otel/spans").json()["items"]
    logs = platform.get("/otel/logs").json()["items"]
    metrics = platform.get("/otel/metrics").json()["items"]
    assert any(s["trace_id"] == trace_id and isinstance(s["attrs"], dict) for s in spans)
    assert any(l["trace_id"] == trace_id and "supersecret" not in str(l) for l in logs)
    assert any(m["metric_name"] == "agent.tool.calls" and "T" in m["timestamp"] for m in metrics)

    trace = platform.get(f"/otel/traces/{trace_id}").json()
    assert trace["total"]["spans"] >= 1
    assert trace["total"]["logs"] >= 1
    assert trace["total"]["probe_events"] >= 1
    assert "supersecret" not in str(trace)


def test_v426_observability_health_has_platform_and_receiver_semantics(monkeypatch, tmp_path):
    store = _store(tmp_path)
    monkeypatch.setattr(obs_api, "get_store", lambda: store)
    platform = _platform_client()
    payload = platform.get("/observability/health").json()
    assert payload["platform_api"]["status"] == "ok"
    assert payload["receiver"]["status"] in {"ok", "down", "unknown"}
    assert payload["receiver"]["status"] != "ok" or payload["receiver"]["probed"] is True
    for key in ["total_probe_events", "otel_spans", "otel_logs", "otel_metric_points", "behavior_chains", "behavior_anomalies"]:
        assert key in payload["database"]
