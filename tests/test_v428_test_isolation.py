from pathlib import Path

from assessment.store import AssessmentStore, REPO_ROOT


def test_v428_assessment_store_can_use_temp_db_without_formal_db(tmp_path):
    formal_db = REPO_ROOT / 'data' / 'db' / 'app.db'
    before_mtime = formal_db.stat().st_mtime if formal_db.exists() else None
    temp_db = tmp_path / 'isolated.db'
    store = AssessmentStore(temp_db)
    store.initialize()
    store.upsert_record('discovery_hit', {'id':'v428_temp_hit','type':'Skill','agent':'Test','path':'tests/fixtures/x','status':'可导入'}, status='NEW')
    assert temp_db.exists()
    assert store.get_record('discovery_hit', 'v428_temp_hit')
    after_mtime = formal_db.stat().st_mtime if formal_db.exists() else None
    assert after_mtime == before_mtime
