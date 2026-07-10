from assessment.scanning.jobs import recover_interrupted_scans, retry_scan
from assessment.store import AssessmentStore


def test_v4210_restart_recovery_marks_interrupted_work_retryable(tmp_path):
    store = AssessmentStore(tmp_path / "recovery.db")
    store.initialize()
    task = {
        "id": "asm-interrupted",
        "state_code": "RUNNING_STATIC",
        "status": "运行中",
        "progress": 42,
        "scan_request": {"mode": "path", "target_path": "tests/fixtures/sample_agent_project", "max_files": 100},
    }
    store.upsert_record("task", task, status="RUNNING_STATIC")
    store.upsert_record("assessment", task, status="RUNNING_STATIC")

    assert recover_interrupted_scans(store) == 1
    recovered = store.get_record("task", task["id"])
    assert recovered["state_code"] == "FAILED"
    assert recovered["progress"] < 100
    assert recovered["error_code"] == "WORKER_RESTARTED"
    assert recovered["retryable"] is True

    retried = retry_scan(store, task["id"], {"defer_start": True})
    assert retried["task"]["state_code"] == "QUEUED"
    assert retried["task"]["source_task_id"] == task["id"]
    assert retried["task"]["id"] != task["id"]
