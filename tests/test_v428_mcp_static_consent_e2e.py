from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v428_mcp_static_consent_e2e():
    discovery = client.post('/api/v1/discovery-runs', json={'path':'tests/fixtures/sample_agent_project','scope':'v428-mcp','probe_installed':False}).json()
    assert discovery['stdio_mcp_started'] is False
    servers = discovery.get('mcp_servers') or client.get('/api/v1/mcp-servers?page_size=50').json()['items']
    if not servers:
        return
    server = servers[0]
    detail = client.get(f"/api/v1/mcp-servers/{server['id']}").json()
    assert 'item' in detail
    inspected = client.post(f"/api/v1/mcp-servers/{server['id']}/inspect", json={}).json()
    assert inspected['mutates_installed_agents'] is False
    assert inspected['stdio_mcp_started'] is False
    tools = inspected.get('tools') or []
    if tools:
        tool = client.get(f"/api/v1/tools/{tools[0]['id']}").json()
        assert tool.get('item')
    consents = client.get('/api/v1/mcp-consents?page_size=50').json()['items']
    if consents:
        approved = client.post(f"/api/v1/mcp-consents/{consents[0]['id']}/approve", json={'reason':'unit test'}).json()
        assert approved['status'] == 'DECIDED'
