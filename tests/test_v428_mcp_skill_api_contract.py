from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v428_mcp_skill_api_contract_aliases():
    for url in ['/api/v1/mcp-servers', '/api/v1/mcp-consents', '/api/v1/tools', '/api/v1/skills']:
        res = client.get(url)
        assert res.status_code == 200, url
        assert 'items' in res.json()
    alias = client.get('/api/v1/mcp')
    assert alias.status_code == 200
    assert alias.json().get('alias_for') == '/api/v1/mcp-servers'


def test_v428_mcp_consent_reject_alias_and_skill_scan_alias():
    client.post('/api/v1/discovery-runs', json={'path':'tests/fixtures/sample_agent_project','scope':'v428-contract','probe_installed':False})
    consents = client.get('/api/v1/mcp-consents?page_size=50').json()['items']
    if consents:
        res = client.post(f"/api/v1/mcp-consents/{consents[0]['id']}/reject", json={'reason':'test reject'})
        assert res.status_code == 200
        assert res.json()['status'] == 'DECIDED'
    skills = client.get('/api/v1/skills?page_size=50').json()['items']
    if skills:
        res = client.post(f"/api/v1/skills/{skills[0]['id']}/scan", json={'target_path':'tests/fixtures/sample_agent_project','limit':20})
        assert res.status_code == 200
        assert res.json()['mutates_installed_agents'] is False
