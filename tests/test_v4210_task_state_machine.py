from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v4210_async_quick_scan_returns_queued_task_fast():
    response = client.post('/api/v1/quick-scans', json={'mode':'machine','async_scan': True, 'max_files': 300})
    assert response.status_code == 200
    payload = response.json()
    assert payload['status_code'] == 202
    assert payload['task']['state_code'] == 'QUEUED'
    assert payload['task']['progress'] < 100
    assert payload['job']['status'] == 'QUEUED'
    events = client.get(f"/api/v1/tasks/{payload['task']['id']}/events").json()['items']
    assert any(e['type'] == 'task.queued' for e in events)
