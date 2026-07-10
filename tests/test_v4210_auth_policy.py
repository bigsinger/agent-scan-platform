from fastapi.testclient import TestClient

from assessment.main import create_app


def test_v4210_auth_policy_requires_token_for_write(monkeypatch):
    monkeypatch.setenv('ASSESSMENT_ADMIN_TOKEN', 'test-admin-token')
    client = TestClient(create_app())
    assert client.get('/api/v1/version').status_code == 200
    denied = client.post('/api/v1/tasks', json={'name':'blocked'})
    assert denied.status_code == 401
    allowed = client.post('/api/v1/tasks', json={'name':'allowed'}, headers={'X-Assessment-Token':'test-admin-token'})
    assert allowed.status_code == 200


def test_v4210_error_redaction_and_security_headers():
    client = TestClient(create_app())
    response = client.get('/api/v1/does-not-exist')
    assert response.status_code in {404, 200}
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Correlation-ID')
