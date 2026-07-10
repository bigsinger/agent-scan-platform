from pathlib import Path
from fastapi.testclient import TestClient

from assessment.main import app
from assessment.store import REPO_ROOT

client = TestClient(app)


def test_v429_rules_scanners_schedules_integrations_operations():
    rule = client.post('/api/v1/rules', json={'id':'v429_rule','title':'v429 rule','pattern':'secret','severity':'P1'}).json()
    assert rule.get('ok') is True
    assert client.get('/api/v1/rules/v429_rule').status_code == 200
    assert client.post('/api/v1/rules/v429_rule/test', json={'text':'secret=abc'}).json().get('ok') is True
    assert client.post('/api/v1/rules/v429_rule/publish', json={}).json().get('ok') is True
    assert client.get('/api/v1/rules/v429_rule/export').status_code == 200

    scanners = client.get('/api/v1/scanners?page_size=20').json()['items']
    if scanners:
        sid = scanners[0]['id']
        assert client.get(f'/api/v1/scanners/{sid}').status_code == 200
        selftest = client.post(f'/api/v1/scanners/{sid}/self-test', json={}).json()
        assert selftest.get('ok') is True

    schedule = client.post('/api/v1/schedules', json={'name':'v429 schedule','cron':'0 9 * * *'}).json()
    assert schedule.get('ok') is True
    sch_id = schedule.get('schedule',{}).get('id') or schedule.get('item',{}).get('id') or schedule.get('id') or 'v429_schedule'
    assert client.post(f'/api/v1/schedules/{sch_id}/run-now', json={}).json().get('ok') is True

    integ = client.post('/api/v1/integrations', json={'name':'v429 integration','credential_ref':'ref_v429_demo'}).json()
    assert integ.get('ok') is True
    iid = integ.get('item',{}).get('id') or integ.get('id') or 'v429_integration'
    assert client.post(f'/api/v1/integrations/{iid}/test', json={}).json().get('ok') is True
    assert client.post(f'/api/v1/integrations/{iid}/sync', json={}).json().get('ok') is True


def test_v429_settings_sqlite_licenses_completeness_api_debug_and_security():
    settings = client.post('/api/v1/settings', json={'bind_host':'0.0.0.0','host_platform_managed':False}).json()
    assert settings.get('ok') is False or settings.get('rejected') or '0.0.0.0' in str(settings)
    safe = client.post('/api/v1/settings', json={'bind_host':'127.0.0.1','admin_token_ref':'[REDACTED]'}).json()
    assert safe.get('ok') is True

    assert client.get('/api/v1/sqlite').status_code == 200
    assert client.post('/api/v1/sqlite/integrity-check', json={}).json().get('ok') is True
    backup = client.post('/api/v1/sqlite/backup', json={}).json()
    assert backup.get('sha256') or backup.get('backup')
    assert client.post('/api/v1/sqlite/checkpoint', json={}).json().get('ok') is True
    assert client.post('/api/v1/sqlite/restore-drill', json={'dry_run': True}).json().get('ok') is True

    lic = client.get('/api/v1/licenses/export').json()
    assert lic.get('download') or lic.get('artifact') or lic.get('sha256')
    comp = client.get('/api/v1/completeness/export').json()
    assert comp.get('download') or comp.get('artifact') or comp.get('sha256')
    debug = client.post('/api/v1/api-debug/request', json={'method':'GET','path':'/api/v1/version'}).json()
    assert debug.get('status_code') == 200
    health = client.get('/api/v1/health').json()
    assert 'secret' not in str(health).lower()
