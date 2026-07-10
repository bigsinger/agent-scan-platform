from assessment.security import SensitiveDataError, SensitiveDataGuard
from assessment.store import AssessmentStore


def test_v4210_sensitive_data_guard_redacts_required_patterns():
    samples = [
        'sk-live-secret-value-123456789',
        'AKIAABCDEFGHIJKLMNOP',
        'Bearer abcdefghijklmnopqrstuvwxyz',
        'api_key=supersecretvalue',
        'ghp_abcdefghijklmnopqrstuvwxyz123456',
        'xoxb-12345678901234567890',
        'AIzaabcdefghijklmnopqrstuvwxyz123456',
    ]
    for sample in samples:
        output = SensitiveDataGuard.redact_text(sample)
        assert sample not in output
        assert 'REDACTED' in output
        SensitiveDataGuard.assert_safe_to_persist(output)


def test_v4210_persistence_gate_sanitizes_db_and_artifacts(tmp_path):
    store = AssessmentStore(tmp_path / 'app.db')
    store.initialize()
    raw = 'token=super-secret-token-123456789'
    item = store.upsert_record('evidence', {'id': 'ev_guard', 'content': raw}, status='READY')
    assert raw not in str(item)
    assert raw not in str(store.get_record('evidence', 'ev_guard'))
    artifact = store.write_artifact('guard-test', raw, suffix='txt')
    content = open(artifact['absolute_path'], encoding='utf-8').read()
    assert raw not in content
    assert 'REDACTED' in content
