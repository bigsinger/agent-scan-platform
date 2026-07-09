from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v428_agent_scan_mapping_e2e():
    issues = client.get('/api/v1/agent-scan/issues?page_size=5').json()
    assert 'items' in issues
    compat = client.get('/api/v1/agent-scan/compat').json()
    assert compat['cloud_required'] is False
    assert compat['mapping_count'] >= 0
    text = str([issues, compat]).lower()
    assert 'supersecret' not in text
