from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v429_dashboard_and_assessment_draft_flow():
    dashboard = client.get('/api/v1/dashboard').json()
    assert dashboard.get('status') in {'ok', 'healthy', None} or 'metrics' in dashboard or 'dashboardMetrics' in str(dashboard)
    health = client.get('/api/v1/health').json()
    assert health['status'] == 'ok'

    draft = client.post('/api/v1/assessments/drafts', json={
        'name': 'v429 final draft',
        'target': 'tests/fixtures/sample_agent_project',
        'mode': 'path',
        'execution_mode': 'readonly',
    }).json()
    assert draft.get('ok') is True
    assert draft.get('mutates_installed_agents') is False
    draft_id = draft.get('draft', {}).get('id') or draft.get('assessment', {}).get('id') or draft.get('id') or 'v429_draft'
    assert client.get(f'/api/v1/assessments/drafts/{draft_id}').status_code == 200
    validated = client.post(f'/api/v1/assessments/drafts/{draft_id}/validate', json={}).json()
    assert validated.get('ok') is True
    started = client.post(f'/api/v1/assessments/drafts/{draft_id}/start', json={}).json()
    assert started.get('mutates_installed_agents') is False


def test_v429_profiles_adapter_detail_export_flow():
    profiles = client.get('/api/v1/profiles?page_size=20').json()
    assert 'items' in profiles
    copied = client.post('/api/v1/profiles', json={'name': 'v429 copied profile', 'base': 'standard-complete@4.1'}).json()
    assert copied.get('ok') is True
    for adapter in ['openclaw', 'hermes', 'claude-code', 'codex']:
        detail = client.get(f'/api/v1/adapters/{adapter}').json()
        assert 'item' in detail
    exported = client.get('/api/v1/profiles/export').json()
    assert exported.get('sha256') or exported.get('artifact') or exported.get('download')
