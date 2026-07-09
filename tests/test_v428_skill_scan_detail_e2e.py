from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v428_skill_scan_detail_e2e():
    result = client.post('/api/v1/skill-scans', json={'target_path':'tests/fixtures/sample_agent_project','limit':50}).json()
    assert result['status'] == 'COMPLETED'
    assert result['mutates_installed_agents'] is False
    assert result['skills']
    assert result['findings']
    assert result['evidence']
    text = str(result).lower()
    assert 'supersecret' not in text
    skill_id = result['skills'][0]['id']
    detail = client.get(f'/api/v1/skills/{skill_id}').json()
    assert detail.get('item')
    assert 'real_path' not in str(detail)
