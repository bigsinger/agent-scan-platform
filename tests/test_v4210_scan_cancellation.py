from assessment.scanning.jobs import cancel_scan, queue_scan, run_scan_task
from assessment.store import AssessmentStore


def test_v4210_cancelled_queue_never_reads_scan_target_and_is_idempotent(tmp_path):
    store = AssessmentStore(tmp_path / "cancel.db")
    store.initialize()
    queued = queue_scan(
        store,
        {"mode": "path", "target_path": str(tmp_path / "target-does-not-need-to-exist"), "max_files": 100},
        auto_start=False,
    )
    task_id = queued["task"]["id"]
    first = cancel_scan(store, task_id, "enterprise cancellation test")
    second = cancel_scan(store, task_id, "duplicate request")
    terminal = run_scan_task(store, task_id)

    assert first["state_code"] == "CANCELLED"
    assert second["state_code"] == "CANCELLED"
    assert terminal["state_code"] == "CANCELLED"
    assert terminal["progress"] < 100
    assert not store.get_record("report", str(terminal.get("report_id") or "missing"))
    events = store.list_scan_events(task_id)
    assert {event["type"] for event in events} >= {"task.queued", "task.cancel_requested"}
