from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def _seed():
    client.post('/api/v1/discovery-runs', json={'path':'tests/fixtures/sample_agent_project','scope':'v428-query','probe_installed':False})


def test_v428_discovery_server_filters_search_and_paginates():
    _seed()
    skill = client.get('/api/v1/discovery-hits?page_size=20&type=Skill').json()
    assert skill['items']
    assert all(item['type'] == 'Skill' for item in skill['items'])
    assert 'has_next' in skill and skill['total'] >= len(skill['items'])
    search = client.get('/api/v1/discovery-hits?page_size=20&q=skill').json()
    assert search['items']
    assert any('skill' in str(item.get('display', {})).lower() or 'skill' in str(item.get('path','')).lower() for item in search['items'])
    bad = client.get('/api/v1/discovery-hits?page_size=20&type=BadType')
    assert bad.status_code == 422


def test_v428_discovery_sort_and_hidden_policy():
    _seed()
    hidden = {'id':'hit_self_src','type':'MCP','agent':'Generic','path':'<target>/assessment/scanning/mcp_static.py','path_hash':'x','sha256':'y','status':'可导入'}
    client.post('/api/v1/discovery-hits/cleanup-self-project', json={'dry_run': True})
    default = client.get('/api/v1/discovery-hits?page_size=200').json()['items']
    assert not any('<target>/assessment/' in str(item.get('path','')) for item in default)
    shown = client.get('/api/v1/discovery-hits?page_size=200&include_hidden=true&self_project_policy=legacy_stale').json()
    assert 'items' in shown
