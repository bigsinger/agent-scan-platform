from datetime import datetime, timedelta, timezone

from assessment.maintenance import apply_retention, retention_plan
from assessment.store import AssessmentStore


def _old_timestamp() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()


def test_v4210_retention_requires_bound_preview_and_cleans_state(monkeypatch, tmp_path):
    root = tmp_path / "data"
    monkeypatch.setenv("ASSESSMENT_STATE_ROOT", str(root))
    monkeypatch.setenv("ASSESSMENT_ARTIFACT_ROOT", str(root / "artifacts"))
    store = AssessmentStore(root / "db" / "app.db")
    store.initialize()
    old = _old_timestamp()
    store.upsert_record("task", {"id": "task-old", "name": "expired", "created_at": old})
    store.upsert_record("finding", {"id": "finding-old", "task_id": "task-old", "created_at": old})
    state = store.get_state()
    state["tasks"] = [{"id": "task-old", "name": "expired"}]
    state["findings"] = [{"id": "finding-old", "title": "expired"}]
    state["selectedTask"] = {"id": "task-old"}
    store.save_state(state)
    with store.connect() as conn:
        for table in ("task", "finding"):
            conn.execute(f"UPDATE {table} SET created_at=?, updated_at=?", (old, old))
        conn.commit()

    policies = {key: 1 for key in ("tasks", "events", "findings", "evidence", "reports", "observability", "artifacts")}
    preview = retention_plan(store, policies)
    assert preview["mode"] == "DRY_RUN"
    assert preview["candidate_count"] >= 2
    assert store.get_record("task", "task-old") is not None

    try:
        apply_retention(store, policies, "ret_stale")
        raise AssertionError("a stale plan ID must not be accepted")
    except ValueError:
        pass

    result = apply_retention(store, policies, preview["plan_id"])
    assert result["status"] == "COMPLETED"
    assert result["backup_sha256"]
    assert store.get_record("task", "task-old") is None
    assert store.get_record("finding", "finding-old") is None
    state = store.get_state()
    assert not state["tasks"] and not state["findings"] and state["selectedTask"] == {}
    assert list((root / "backups").glob("retention-*.db"))
