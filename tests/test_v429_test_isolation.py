import os
import sqlite3
import subprocess
from pathlib import Path


def test_v429_verify_uses_isolated_environment(tmp_path):
    run_root = tmp_path / 'run'
    env = os.environ.copy()
    env['PYTHONPATH'] = ''
    env['ASSESSMENT_DB_PATH'] = str(run_root / 'app.db')
    env['ASSESSMENT_ARTIFACT_ROOT'] = str(run_root / 'artifacts')
    env['ASSESSMENT_STATE_ROOT'] = str(run_root / 'state')
    env['ASSESSMENT_DISABLE_BACKGROUND_JOBS'] = 'true'
    cmd = ['uv','run','--with','pytest','--with','httpx2','python','-m','pytest','tests/test_v429_api_alias_contract.py','-q']
    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (run_root / 'app.db').exists()
    formal = Path(__file__).resolve().parents[1] / 'data' / 'db' / 'app.db'
    if formal.exists():
        with sqlite3.connect(formal) as conn:
            exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='generic_record'").fetchone()
            count = 0 if not exists else conn.execute("SELECT COUNT(*) FROM generic_record WHERE id LIKE 'v429_%' OR id LIKE 'test_%' OR id LIKE 'contract_%'").fetchone()[0]
        assert count == 0
