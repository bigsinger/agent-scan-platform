from fastapi.testclient import TestClient

from assessment.main import app
from assessment.api.v1 import decorate_discovery_hit
from assessment.store import get_store

client = TestClient(app)


def test_v428_self_project_policy_covers_target_assessment_paths():
    legacy = decorate_discovery_hit({'id':'hit_self_src','type':'MCP','agent':'Generic','path':'<target>/assessment/scanning/mcp_static.py','path_hash':'x','sha256':'y','status':'可导入'})
    fixture = decorate_discovery_hit({'id':'hit_fixture','type':'Skill','agent':'Generic','path':'tests/fixtures/sample_agent_project/.agents/skills/danger-skill/SKILL.md','path_hash':'z','sha256':'w','status':'可导入'})
    assert legacy['self_project_policy'] == 'legacy_stale'
    assert legacy['hidden_by_default'] is True
    assert fixture['self_project_policy'] == 'test_asset'
    assert fixture['hidden_by_default'] is False


def test_v428_cleanup_self_project_dry_run_and_default_hide():
    store = get_store()
    store.upsert_record('discovery_hit', {'id':'hit_self_src_api','type':'MCP','agent':'Generic','path':'<target>/assessment/scanning/mcp_static.py','path_hash':'x','sha256':'y','status':'可导入'}, status='NEW')
    dry = client.post('/api/v1/discovery-hits/cleanup-self-project', json={'dry_run': True}).json()
    assert dry['matched'] >= 1
    assert dry['mutates_installed_agents'] is False
    default = client.get('/api/v1/discovery-hits?page_size=500').json()['items']
    assert not any(item.get('id') == 'hit_self_src_api' for item in default)
    hidden = client.get('/api/v1/discovery-hits?page_size=500&include_hidden=true&self_project_policy=legacy_stale').json()['items']
    assert any(item.get('id') == 'hit_self_src_api' for item in hidden)
