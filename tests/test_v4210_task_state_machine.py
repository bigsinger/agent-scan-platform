from fastapi.testclient import TestClient

from assessment.api import v1 as api_v1
from assessment.main import app
from assessment.scanning.jobs import run_scan_task
from assessment.store import AssessmentStore


def _isolated_client(monkeypatch, tmp_path):
    store = AssessmentStore(tmp_path / "state-machine.db")
    store.initialize()
    monkeypatch.setattr(api_v1, "get_store", lambda: store)
    monkeypatch.setenv("ASSESSMENT_DISABLE_BACKGROUND_JOBS", "true")
    return TestClient(app), store


def test_v4210_async_quick_scan_runs_real_worker_to_terminal_state(monkeypatch, tmp_path):
    client, store = _isolated_client(monkeypatch, tmp_path)
    response = client.post(
        "/api/v1/quick-scans",
        json={
            "mode": "path",
            "target_path": "tests/fixtures/sample_agent_project",
            "async_scan": True,
            "defer_start": True,
            "max_files": 100,
            "include_mcp": False,
        },
    )
    assert response.status_code == 202
    payload = response.json()
    task_id = payload["task"]["id"]
    assert payload["status_code"] == 202
    assert payload["task"]["state_code"] == "QUEUED"
    assert payload["job"]["status"] == "QUEUED"

    completed = run_scan_task(store, task_id)
    assert completed["state_code"] == "COMPLETED"
    assert completed["progress"] == 100
    assert completed["finding_count"] >= 1
    assert completed["evidence_count"] >= 1
    assert completed["report_id"]
    assert store.get_record("scan_job", f"job_{task_id}")["state_code"] == "COMPLETED"
    assert store.get_record("process_execution", f"exec_{task_id}")["state_code"] == "COMPLETED"
    events = client.get(f"/api/v1/tasks/{task_id}/events").json()["items"]
    event_types = {event["type"] for event in events}
    assert {"task.queued", "task.started", "task.progress", "task.completed"}.issubset(event_types)


def test_v4210_cancel_is_idempotent_and_retry_creates_new_queued_job(monkeypatch, tmp_path):
    client, store = _isolated_client(monkeypatch, tmp_path)
    created = client.post(
        "/api/v1/quick-scans",
        json={"mode": "machine", "async_scan": True, "defer_start": True, "max_files": 25},
    ).json()
    task_id = created["task"]["id"]
    first = client.post(f"/api/v1/tasks/{task_id}/cancel", json={"reason": "test cancellation"})
    second = client.post(f"/api/v1/tasks/{task_id}/cancel", json={"reason": "duplicate cancellation"})
    assert first.status_code == 200 and second.status_code == 200
    assert first.json()["task"]["state_code"] == "CANCELLED"
    assert second.json()["task"]["state_code"] == "CANCELLED"
    assert run_scan_task(store, task_id)["state_code"] == "CANCELLED"

    retried = client.post(f"/api/v1/tasks/{task_id}/retry", json={"defer_start": True})
    assert retried.status_code == 202
    retry_task = retried.json()["task"]
    assert retry_task["id"] != task_id
    assert retry_task["source_task_id"] == task_id
    assert retry_task["state_code"] == "QUEUED"
