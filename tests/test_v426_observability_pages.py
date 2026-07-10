from __future__ import annotations

from fastapi.testclient import TestClient

from assessment.main import app
from assessment.contracts import completeness_rows

client = TestClient(app)

NEW_IDS = {"P49","P50","P51","P52","P53","P54","D19","D20","D21","D22"}


def test_v426_observability_routes_and_page_contracts(monkeypatch, tmp_path):
    monkeypatch.setenv('ASSESSMENT_E2E_RESULT_PATH', str(tmp_path / 'missing-result.json'))
    html = client.get('/assessment/probes').text
    assert 'id="app"' in html
    payload = client.get('/api/v1/completeness?page_size=200').json()
    rows = {r['id']: r for r in payload['items']}
    assert NEW_IDS <= set(rows)
    for pid in NEW_IDS:
        assert rows[pid]['audit'] == 'PASS'
        assert rows[pid]['contract'] == 'PASS'
        assert rows[pid]['e2e'] == 'NOT_ASSERTED'
        assert rows[pid]['e2e_evidence']['test_file_exists'] is True


def test_v426_observability_detail_routes_have_drawer_contract():
    app_js = open('src/assessment/static/assessment/app.js', encoding='utf-8').read()
    html = open('src/assessment/static/assessment/index.html', encoding='utf-8').read()
    for token in ["/assessment/probes/", "/assessment/behavior/chains/", "/assessment/otel/spans/", "/assessment/probes/plans/"]:
        assert token in app_js
    assert 'detailDrawerOpen' in app_js
    assert 'returnTo={{detailDrawerReturnTo}}' in html
    assert 'redaction_status' in html or 'Redaction' in html
