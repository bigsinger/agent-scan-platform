from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v427_discovery_export_contains_display_summary():
    resp = client.post('/api/v1/discovery-runs', json={'path':'tests/fixtures/sample_agent_project','scope':'v427-export','probe_installed':False})
    assert resp.status_code == 200
    export = client.get('/api/v1/discovery-hits/export').json()
    assert export['counts']['hits'] >= 1
    for key in ['agent_count','skill_count','mcp_count','config_count','changed_count','ignored_count','skipped_count']:
        assert key in export['counts']
    assert export['safe_mode'] == 'local-readonly'
    artifact = client.get(export['download']).json()
    hits = artifact['hits']
    assert hits
    for hit in hits[:20]:
        display = hit.get('display') or {}
        assert display.get('title')
        assert display.get('primary_path')
        assert hit['safety']['mutates_installed_agents'] is False
    text = str(artifact).lower()
    assert 'supersecret' not in text
    assert 'authorization: bearer' not in text
