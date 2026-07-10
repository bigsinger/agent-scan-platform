from datetime import datetime, timedelta, timezone

from assessment.maintenance import apply_artifact_gc, artifact_gc_plan, artifact_integrity
from assessment.store import AssessmentStore, file_sha256


def test_v4210_artifact_integrity_and_reference_aware_gc(monkeypatch, tmp_path):
    root = tmp_path / "data"
    artifact_root = root / "artifacts"
    monkeypatch.setenv("ASSESSMENT_STATE_ROOT", str(root))
    monkeypatch.setenv("ASSESSMENT_ARTIFACT_ROOT", str(artifact_root))
    store = AssessmentStore(root / "db" / "app.db")
    store.initialize()
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()

    referenced_path = artifact_root / "evidence" / "referenced.json"
    orphan_path = artifact_root / "evidence" / "orphan.json"
    referenced_path.parent.mkdir(parents=True)
    referenced_path.write_text('{"safe":true}', encoding="utf-8")
    orphan_path.write_text('{"safe":true}', encoding="utf-8")
    for artifact_id, path in (("art-referenced", referenced_path), ("art-orphan", orphan_path)):
        store.upsert_record(
            "artifact",
            {
                "id": artifact_id,
                "kind": "test",
                "relative_path": str(path.relative_to(root)).replace("\\", "/"),
                "absolute_path": str(path),
                "sha256": file_sha256(path),
                "size": path.stat().st_size,
                "created_at": old,
            },
            status="READY",
        )
    store.upsert_record(
        "evidence",
        {"id": "evidence-live", "artifact_id": "art-referenced", "created_at": datetime.now(timezone.utc).isoformat()},
        status="READY",
    )
    with store.connect() as conn:
        conn.execute("UPDATE artifact SET created_at=?, updated_at=?", (old, old))
        conn.commit()

    assert artifact_integrity(store)["status"] == "PASS"
    plan = artifact_gc_plan(store, min_age_days=30)
    assert plan["candidate_count"] == 1
    assert plan["candidate_ids"] == ["art-orphan"]

    result = apply_artifact_gc(store, plan["plan_id"], min_age_days=30)
    assert result["deleted_records"] == 1
    assert store.get_record("artifact", "art-orphan") is None
    assert store.get_record("artifact", "art-referenced") is not None
    assert not orphan_path.exists() and referenced_path.exists()
    assert list((root / "backups").glob("artifact-gc-*.db"))

    referenced_path.write_text("tampered", encoding="utf-8")
    integrity = artifact_integrity(store)
    assert integrity["status"] == "FAIL"
    assert integrity["mismatch_ids"] == ["art-referenced"]
