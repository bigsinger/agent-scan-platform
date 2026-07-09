from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v428_abom_and_adapter_e2e():
    client.post('/api/v1/discovery-runs', json={'path':'tests/fixtures/sample_agent_project','scope':'v428-abom','probe_installed':False})
    agents = client.get('/api/v1/agents?page_size=50').json()['items']
    assert isinstance(agents, list)
    adapters = client.get('/api/v1/adapters?page_size=50').json()['items']
    assert isinstance(adapters, list)
    if agents:
        abom = client.get(f"/api/v1/agents/{agents[0]['id']}/abom").json()
        assert abom.get('safe_mode') == 'local-readonly' or 'nodes' in abom
    text = str([agents, adapters]).lower()
    assert '<target>/assessment/' not in text
