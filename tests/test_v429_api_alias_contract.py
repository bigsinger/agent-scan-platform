from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v429_natural_api_aliases_are_not_404():
    for url in ['/api/v1/python-exec','/api/v1/process-executions','/api/v1/processes']:
        res = client.get(url)
        assert res.status_code == 200, url
        body = res.json()
        assert 'items' in body


def test_v429_page_api_map_paths_resolve():
    for url in ['/api/v1/tasks','/api/v1/redteam-cases','/api/v1/findings','/api/v1/evidence','/api/v1/reports','/api/v1/retests','/api/v1/rules','/api/v1/scanners','/api/v1/schedules','/api/v1/integrations','/api/v1/licenses','/api/v1/completeness']:
        res = client.get(url)
        assert res.status_code == 200, url
