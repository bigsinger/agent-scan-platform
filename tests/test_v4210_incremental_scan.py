from pathlib import Path

from assessment.scanning.scanner import LocalScanEngine
from assessment.store import AssessmentStore


def test_v4210_unchanged_rescan_reuses_analysis_and_evidence(tmp_path):
    store = AssessmentStore(tmp_path / "incremental.db")
    store.initialize()
    engine = LocalScanEngine(store)
    fixture = Path(__file__).parent / "fixtures" / "sample_agent_project"
    request = {"mode": "path", "target_path": str(fixture), "max_files": 100}
    first = engine.run_quick_scan(request)
    artifacts_after_first = len(store.list_records("artifact", limit=5000))
    second = engine.run_quick_scan(request)
    artifacts_after_second = len(store.list_records("artifact", limit=5000))

    assert first.evidence and len(first.evidence) == len(first.findings)
    assert len(second.evidence) == len(first.evidence)
    assert second.assessment["static_cache_hits"] == second.files_scanned
    assert all(item["artifact_reused"] is True for item in second.evidence)
    assert second.assessment["incremental_reuse"] is True
    assert second.assessment["reused_evidence_count"] == len(second.evidence)
    assert artifacts_after_second - artifacts_after_first <= 2
