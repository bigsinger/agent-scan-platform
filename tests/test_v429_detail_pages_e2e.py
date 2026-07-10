from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v429_detail_pages_route_and_api_contracts():
    routes = [
        '/api/v1/adapters/openclaw','/api/v1/adapters/hermes','/api/v1/adapters/claude-code','/api/v1/adapters/codex',
        '/api/v1/redteam-cases/case_prompt_injection','/api/v1/profiles/standard-complete','/api/v1/rules/SECRET-KEY-001',
        '/api/v1/scanners/scn_local_static','/api/v1/platform-embed/context','/api/v1/api-debug/catalog'
    ]
    for url in routes:
        res = client.get(url)
        assert res.status_code == 200, url
        assert isinstance(res.json(), dict)


def test_v429_detail_pages_have_page_specific_assertions():
    adapter = client.get('/api/v1/adapters/hermes').json()
    assert 'item' in adapter
    rule = client.get('/api/v1/rules/SECRET-KEY-001').json()
    assert 'item' in rule and 'SECRET' in str(rule).upper()
    scanner = client.get('/api/v1/scanners/scn_local_static').json()
    assert 'item' in scanner
    embed = client.get('/api/v1/platform-embed/context').json()
    assert embed.get('boundary') or embed.get('mode') or 'local' in str(embed).lower()
