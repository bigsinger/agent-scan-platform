from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def _seed_result_chain():
    scan = client.post('/api/v1/quick-scans', json={'path': 'tests/fixtures/sample_agent_project', 'mode': 'path'}).json()
    finding = (scan.get('findings') or [{}])[0]
    evidence = (scan.get('evidence') or [{}])[0]
    return scan, finding, evidence


def test_v429_finding_evidence_attack_path_chain():
    scan, finding, evidence = _seed_result_chain()
    findings = client.get('/api/v1/findings?page_size=20').json()['items']
    evidence_items = client.get('/api/v1/evidence?page_size=20').json()['items']
    assert findings
    assert evidence_items
    fid = findings[0]['id']
    assert client.get(f'/api/v1/findings/{fid}').status_code == 200
    for action in ['accept-risk', 'false-positive', 'assign', 'retest']:
        res = client.post(f'/api/v1/findings/{fid}/{action}', json={'reason':'v429'}).json()
        assert res.get('ok') is True
    evid = evidence_items[0]
    assert client.get(f"/api/v1/evidence/{evid['id']}").status_code == 200
    export = client.get(f"/api/v1/evidence/{evid['id']}/export").json()
    assert export.get('sha256') or export.get('artifact') or export.get('download')
    path = client.post('/api/v1/attack-paths', json={'finding_id': fid, 'name': 'v429 path'}).json()
    assert path.get('ok') is True
    apid = path.get('item', {}).get('id') or path.get('attack_path', {}).get('id') or path.get('id') or 'v429_path'
    assert client.get(f'/api/v1/attack-paths/{apid}').status_code == 200
    draft = client.post('/api/v1/policy-drafts', json={'attack_path_id': apid}).json()
    assert draft.get('ok') is True


def test_v429_reports_and_retests_delivery_package():
    scan, finding, evidence = _seed_result_chain()
    report = client.post('/api/v1/reports', json={'name':'v429 report','assessment_id': scan.get('assessment',{}).get('id')}).json()
    assert report.get('ok') is True
    rid = report.get('report',{}).get('id') or report.get('item',{}).get('id') or report.get('id') or 'v429_report'
    assert client.get(f'/api/v1/reports/{rid}/preview').status_code == 200
    package = client.get(f'/api/v1/reports/{rid}/delivery-package').json()
    assert package.get('sha256') or package.get('manifest') or package.get('download')
    retest = client.post('/api/v1/retests', json={'finding_id': finding.get('id'), 'mode':'dry-run'}).json()
    assert retest.get('ok') is True
    assert retest.get('mutates_installed_agents') is False
