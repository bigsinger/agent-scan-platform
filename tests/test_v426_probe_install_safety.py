from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from assessment.main import app

client = TestClient(app)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v426_probe_install_plan_dry_run_does_not_modify_fake_agent_files(tmp_path):
    fake_home = tmp_path / 'fake-agent-home'
    codex = fake_home / '.codex' / 'config.toml'
    hermes = fake_home / '.hermes' / 'config.yaml'
    codex.parent.mkdir(parents=True)
    hermes.parent.mkdir(parents=True)
    codex.write_text('[model]\nname="codex-test"\n', encoding='utf-8')
    hermes.write_text('profile: test\n', encoding='utf-8')
    before = {codex: _sha(codex), hermes: _sha(hermes)}
    for agent_type in ['codex', 'hermes']:
        resp = client.post('/api/v1/probes/install-plan', json={'agent_type': agent_type, 'dry_run': True, 'target_config_path': str(codex if agent_type=='codex' else hermes)})
        assert resp.status_code == 200
        payload = resp.json()
        assert payload['dry_run'] is True
        assert payload['mutates_installed_agents'] is False
        assert payload['requires_confirmation'] is True
        assert 'steps_json' in payload and 'rollback_json' in payload
    assert {codex: _sha(codex), hermes: _sha(hermes)} == before
    assert sorted(p.relative_to(fake_home).as_posix() for p in fake_home.rglob('*') if p.is_file()) == ['.codex/config.toml', '.hermes/config.yaml']
