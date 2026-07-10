from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def test_v429_security_boundary_localhost_and_admin_protection():
    health = client.get('/api/v1/health').json()
    assert health['status'] == 'ok'
    assert 'secret' not in str(health).lower()
    rejected = client.post('/api/v1/settings', json={'bind_host': '0.0.0.0', 'host_platform_managed': False}).json()
    assert rejected.get('rejected') is True or rejected.get('ok') is False
    allowed = client.post('/api/v1/settings', json={'bind_host': '127.0.0.1', 'host_platform_managed': False}).json()
    assert allowed.get('ok') is True


def test_v429_security_boundary_no_stdio_mcp_or_skill_execution():
    created = client.post('/api/v1/mcp-servers', json={'id':'mcp_sample','name':'mcp_sample','transport':'stdio','command':'node','args':['server.js']}).json()
    assert created.get('ok') is True
    mcp = client.post('/api/v1/mcp-servers/mcp_sample/inspect', json={}).json()
    assert mcp.get('stdio_mcp_started') is False
    assert mcp.get('mutates_installed_agents') is False
    skill = client.post('/api/v1/skills/skill_demo/scan', json={'dry_run': True}).json()
    assert skill.get('mutates_installed_agents') is False
    assert 'executed' not in str(skill).lower() or 'not executed' in str(skill).lower()
