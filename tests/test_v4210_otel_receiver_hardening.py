from fastapi.testclient import TestClient
import gzip

from assessment.observability.receiver import create_receiver_app
from assessment.store import AssessmentStore
import assessment.observability.receiver as receiver


def _client(monkeypatch, tmp_path):
    store = AssessmentStore(tmp_path / 'otel.db'); store.initialize()
    monkeypatch.setattr(receiver, 'get_store', lambda: store)
    return TestClient(create_receiver_app()), store


def test_v4210_otlp_json_trace_ingestion_deduplicates_and_redacts(monkeypatch, tmp_path):
    client, store = _client(monkeypatch, tmp_path)
    span = {'traceId':'0'*32, 'spanId':'1'*16, 'name':'tool.call', 'attributes':[{'key':'cmd','value':{'stringValue':'token=supersecretvalue'}}]}
    payload = {'resourceSpans':[{'scopeSpans':[{'spans':[span]}]}]}
    r1 = client.post('/v1/traces', json=payload)
    r2 = client.post('/v1/traces', json=payload)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()['accepted'] == 1
    with store.connect() as conn:
        rows = conn.execute('select payload_json from probe_event').fetchall()
    assert 'supersecretvalue' not in str(rows)


def test_v4210_otel_limits_and_invalid_ids(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    too_big = b'{' + b' ' * (1024 * 1024 + 1) + b'}'
    assert client.post('/v1/traces', content=too_big, headers={'content-type':'application/json'}).status_code == 413
    bad = {'resourceSpans':[{'scopeSpans':[{'spans':[{'traceId':'bad','spanId':'1'*16,'name':'bad'}]}]}]}
    assert client.post('/v1/traces', json=bad).status_code == 400
    compressed_bomb = gzip.compress(b'{"padding":"' + b'x' * (1024 * 1024 + 1) + b'"}')
    expanded = client.post(
        '/v1/traces',
        content=compressed_bomb,
        headers={'content-type':'application/json', 'content-encoding':'gzip'},
    )
    assert expanded.status_code == 413


def test_v4210_otel_retention_endpoint(monkeypatch, tmp_path):
    client, store = _client(monkeypatch, tmp_path)
    dry = client.post('/retention', json={'days':1})
    assert dry.status_code == 200
    assert dry.json()['dry_run'] is True
    applied = client.post('/retention', json={'days':1, 'apply': True})
    assert applied.status_code == 200
