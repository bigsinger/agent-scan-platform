import json
from pathlib import Path

from assessment.api import v1
from assessment.contracts import completeness_rows
from assessment.store import file_sha256


def _png(path: Path):
    path.write_bytes(bytes([137, 80, 78, 71, 13, 10, 26, 10]) + b'\x00' * 64)


def _result(path: Path, commit: str, test_file: str, test_name: str, shot: Path):
    payload = {
        'status': 'PASS',
        'commit': commit,
        'assertion_count': 1,
        'tests': {test_file: {'exit_code': 0, 'passed_tests': [test_name]}},
        'screenshots': [{'path': str(shot), 'sha256': file_sha256(shot)}],
    }
    path.write_text(json.dumps(payload), encoding='utf-8')


def test_v4210_completeness_requires_current_result(monkeypatch, tmp_path):
    result = tmp_path / 'result.json'
    monkeypatch.setenv('ASSESSMENT_E2E_RESULT_PATH', str(result))
    assert v1.completeness_runtime_rows()[0]['e2e'] == 'NOT_ASSERTED'

    evidence = v1.completeness_e2e_manifest()[completeness_rows()[0]['id']]
    shot = tmp_path / 'shot.png'; _png(shot)
    _result(result, v1.current_git_commit(), evidence['test_file'], evidence['test_names'][0], shot)
    assert v1.completeness_runtime_rows()[0]['e2e'] == 'PASS'


def test_v4210_completeness_rejects_stale_commit_and_invalid_png(monkeypatch, tmp_path):
    result = tmp_path / 'result.json'; shot = tmp_path / 'shot.png'; _png(shot)
    monkeypatch.setenv('ASSESSMENT_E2E_RESULT_PATH', str(result))
    evidence = v1.completeness_e2e_manifest()[completeness_rows()[0]['id']]
    _result(result, 'stale-commit', evidence['test_file'], evidence['test_names'][0], shot)
    assert v1.completeness_runtime_rows()[0]['e2e'] == 'STALE'
    _result(result, v1.current_git_commit(), evidence['test_file'], evidence['test_names'][0], shot)
    shot.write_text('not png', encoding='utf-8')
    assert v1.completeness_runtime_rows()[0]['e2e'] == 'STALE'
