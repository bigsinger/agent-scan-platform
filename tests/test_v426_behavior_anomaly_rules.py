from __future__ import annotations

import json

from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def _post_events(events):
    response = client.post('/api/v1/probes/events', json={'events': events})
    assert response.status_code == 200, response.text


def test_v426_behavior_chain_and_anomaly_idempotency():
    events = [
        {'event_id':'evt-v426-secret-1','event_type':'agent.user_input.received','timestamp':'2026-07-09T10:00:00Z','source_agent':'codex','session_id':'sess-v426-anom','payload':{'api_key':'topsecret-value'}},
        {'event_id':'evt-v426-shell-1','event_type':'tool.call.started','timestamp':'2026-07-09T10:00:01Z','source_agent':'codex','session_id':'sess-v426-anom','tool_name':'Bash','tool_type':'shell','payload':{'command':'rm -rf /tmp/demo'}},
        {'event_id':'evt-v426-read-1','event_type':'tool.call.started','timestamp':'2026-07-09T10:00:02Z','source_agent':'codex','session_id':'sess-v426-anom','tool_name':'Read','tool_type':'builtin','payload':{'command':'cat ~/.ssh/id_rsa'}},
        {'event_id':'evt-v426-net-1','event_type':'tool.call.started','timestamp':'2026-07-09T10:00:03Z','source_agent':'codex','session_id':'sess-v426-anom','tool_name':'curl','tool_type':'shell','payload':{'command':'curl https://example.invalid'}},
        {'event_id':'evt-v426-path-1','event_type':'tool.call.started','timestamp':'2026-07-09T10:00:04Z','source_agent':'codex','session_id':'sess-v426-anom','tool_name':'Read','tool_type':'builtin','payload':{'path':'C:\\Windows\\System32\\config'}},
        {'event_id':'evt-v426-deny-1','event_type':'policy.decision.shadow','timestamp':'2026-07-09T10:00:05Z','source_agent':'codex','session_id':'sess-v426-anom','tool_call_id':'tc-deny','status':'denied','payload':{}},
        {'event_id':'evt-v426-deny-2','event_type':'tool.call.completed','timestamp':'2026-07-09T10:00:06Z','source_agent':'codex','session_id':'sess-v426-anom','tool_call_id':'tc-deny','status':'ok','payload':{}},
    ]
    # mcp repeated failures and tool loop
    for i in range(3):
        events.append({'event_id':f'evt-v426-mcp-{i}','event_type':'mcp.rpc.error','timestamp':f'2026-07-09T10:00:1{i}Z','source_agent':'hermes','session_id':'sess-v426-anom','tool_type':'mcp','mcp_server':'srv','mcp_tool':'tool','tool_name':'mcp_srv_tool','status':'error','payload':{'error':'failed'}})
    for i in range(5):
        events.append({'event_id':f'evt-v426-loop-{i}','event_type':'tool.call.started','timestamp':f'2026-07-09T10:00:2{i}Z','source_agent':'codex','session_id':'sess-v426-anom','turn_id':'turn-loop','tool_name':'Bash','tool_type':'shell','payload':{'command':'echo ok'}})
    _post_events(events)
    first = client.post('/api/v1/behavior/chains', json={'action':'build'}).json()
    before = client.get('/api/v1/behavior/anomalies?limit=200').json()['items']
    second = client.post('/api/v1/behavior/chains', json={'action':'build'}).json()
    after = client.get('/api/v1/behavior/anomalies?limit=200').json()['items']
    assert second['status'] == 'BUILT'
    assert len(after) == len(before)
    rule_ids = {a['rule_id'] for a in after}
    assert {'ANOM-SECRET-IN-PROMPT','ANOM-DANGEROUS-SHELL','ANOM-SENSITIVE-READ-THEN-NETWORK','ANOM-MCP-REPEATED-FAILURE','ANOM-TOOL-LOOP','ANOM-CROSS-WORKSPACE-PATH','ANOM-APPROVAL-MISMATCH'} <= rule_ids
    text = json.dumps(after, ensure_ascii=False)
    assert 'topsecret-value' not in text
    for anomaly in after:
        assert anomaly.get('severity')
        assert anomaly.get('recommendation') is not None
        assert anomaly.get('false_positive_guidance') is not None


def test_v426_sensitive_read_network_time_window_and_order():
    _post_events([
        {'event_id':'evt-v426-read-window','event_type':'tool.call.started','timestamp':'2026-07-09T12:00:00Z','source_agent':'codex','session_id':'sess-v426-window','tool_name':'Read','payload':{'command':'cat ~/.aws/credentials'}},
        {'event_id':'evt-v426-net-window','event_type':'tool.call.started','timestamp':'2026-07-09T12:04:00Z','source_agent':'codex','session_id':'sess-v426-window','tool_name':'curl','payload':{'command':'curl https://example.invalid'}},
        {'event_id':'evt-v426-net-old','event_type':'tool.call.started','timestamp':'2026-07-09T11:00:00Z','source_agent':'codex','session_id':'sess-v426-reversed','tool_name':'curl','payload':{'command':'curl https://example.invalid'}},
        {'event_id':'evt-v426-read-late','event_type':'tool.call.started','timestamp':'2026-07-09T11:10:00Z','source_agent':'codex','session_id':'sess-v426-reversed','tool_name':'Read','payload':{'command':'cat ~/.aws/credentials'}},
    ])
    client.post('/api/v1/behavior/chains', json={'action':'build'})
    anomalies = client.get('/api/v1/behavior/anomalies?limit=200').json()['items']
    evidence = json.dumps(anomalies, ensure_ascii=False)
    assert 'evt-v426-net-window' in evidence
    assert 'evt-v426-net-old' not in evidence
