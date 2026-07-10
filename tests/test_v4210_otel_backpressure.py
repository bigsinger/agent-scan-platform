import time

from fastapi.testclient import TestClient

import assessment.observability.api as observability_api
from assessment.main import app
from assessment.observability.storage import insert_events_batch, insert_otel_metric_points_batch
from assessment.store import AssessmentStore


def test_v4210_ten_thousand_events_are_batched_deduplicated_and_redacted(tmp_path):
    store = AssessmentStore(tmp_path / "otel-batch.db")
    store.initialize()
    events = [
        {
            "event_id": f"evt_{index}",
            "event_type": "tool.call",
            "timestamp": "2026-01-01T00:00:00Z",
            "source_agent": "codex",
            "session_id": f"session_{index // 10}",
            "payload": {"api_key": "sk-synthetic-not-real-1234567890"},
        }
        for index in range(10_000)
    ]
    started = time.perf_counter()
    first = insert_events_batch(store, events)
    second = insert_events_batch(store, events)
    elapsed = time.perf_counter() - started

    assert first == {"accepted": 10_000, "rejected": 0, "errors": []}
    assert second["accepted"] == 10_000
    assert elapsed < 15
    with store.connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM probe_event").fetchone()[0]
        unsafe = conn.execute(
            "SELECT COUNT(*) FROM probe_event WHERE payload_json LIKE '%synthetic-not-real%'"
        ).fetchone()[0]
    assert count == 10_000
    assert unsafe == 0


def test_v4210_metric_batch_is_idempotent_and_probe_api_rejects_over_limit(monkeypatch, tmp_path):
    store = AssessmentStore(tmp_path / "otel-limit.db")
    store.initialize()
    points = [
        {"metric_name": "agent.tool.duration", "metric_type": "gauge", "timestamp": "1", "value": index}
        for index in range(10)
    ]
    assert insert_otel_metric_points_batch(store, points) == 10
    assert insert_otel_metric_points_batch(store, points) == 10
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM otel_metric_point").fetchone()[0] == 10

    monkeypatch.setattr(observability_api, "get_store", lambda: store)
    monkeypatch.delenv("ASSESSMENT_ADMIN_TOKEN", raising=False)
    response = TestClient(app).post("/api/v1/probes/events", json={"events": [{}] * 10_001})
    assert response.status_code == 413
    assert "10000" in response.json()["error"]["details"]["message"]
