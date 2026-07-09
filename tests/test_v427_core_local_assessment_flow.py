from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v427_core_local_assessment_flow():
    discovery = client.post('/api/v1/discovery-runs', json={'path':'tests/fixtures/sample_agent_project','scope':'v427-core-flow','probe_installed':False})
    assert discovery.status_code == 200, discovery.text
    payload = discovery.json()
    hits = payload['hits']
    assert hits and all((h.get('display') or {}).get('title') for h in hits)
    hit = next((h for h in hits if h.get('type') in {'Agent','Config','MCP','Skill'}), hits[0])
    imported = client.post(f"/api/v1/discovery-hits/{hit['id']}/import", json={}).json()
    assert imported['status'] == 'IMPORTED'
    agent = imported['agent']
    agents = client.get('/api/v1/agents?page_size=50').json()['items']
    assert any(a['id'] == agent['id'] for a in agents)
    detail = client.get(f"/api/v1/agents/{agent['id']}").json()
    assert detail['item']['id'] == agent['id']
    quick = client.post('/api/v1/quick-scans', json={'mode':'path','path':'tests/fixtures/sample_agent_project','target_path':'tests/fixtures/sample_agent_project','profile':'standard'}).json()
    assert quick['mutates_installed_agents'] is False
    assert quick['stdio_mcp_started'] is False
    assert quick['agent_runtime_started'] is False
    assert quick.get('findings') is not None
    assert quick.get('evidence') is not None
    assert quick.get('report') is not None
    findings = client.get('/api/v1/findings?page_size=50').json()['items']
    evidence = client.get('/api/v1/evidence?page_size=50').json()['items']
    reports = client.get('/api/v1/reports?page_size=50').json()['items']
    assert isinstance(findings, list)
    assert isinstance(evidence, list)
    assert isinstance(reports, list)
    report_id = (quick.get('report') or {}).get('id') or (reports[0]['id'] if reports else '')
    if report_id:
        preview = client.get(f'/api/v1/reports/{report_id}/preview').json()
        assert preview.get('safe_mode') == 'local-readonly' or preview.get('report') or preview.get('item')
    text = str([hits, imported, quick]).lower()
    assert 'supersecret' not in text
    assert 'authorization: bearer' not in text
