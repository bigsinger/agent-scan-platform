from fastapi.testclient import TestClient

from assessment.api.v1 import normalize_agent_asset, agents_query
from assessment.main import app
from assessment.store import get_store

client = TestClient(app)


def test_v428_normalize_agent_name_removes_mojibake():
    item = normalize_agent_asset({'id':'x','name':'Codex бд Local','adapter':'Codex','path':'p','version':'1'})
    assert item['name'] == 'Codex Local'
    assert 'бд' not in item['name']


def test_v428_agents_query_dedupes_codex_and_hermes():
    store = get_store()
    store.upsert_record('agent_instance', {'id':'agt_codex_a','name':'Codex бд Local','adapter':'Codex','path':'<program-files>/Codex.exe','version':'2','status':'ACTIVE'}, status='ACTIVE')
    store.upsert_record('agent_instance', {'id':'agt_codex_b','name':'Codex бд Local','adapter':'Codex','path':'<program-files>/codex.exe','version':'1','status':'RESIDUAL'}, status='RESIDUAL')
    payload = client.get('/api/v1/agents?page_size=100').json()
    codex = [item for item in payload['items'] if item.get('adapter') == 'Codex']
    assert len(codex) <= 1
    if codex:
        assert codex[0]['duplicate_count'] >= 1
        assert codex[0]['installations']
        assert 'бд' not in str(codex[0])
