from pathlib import Path

from assessment.scanning.discovery import DiscoveryEngine
from assessment.api.v1 import decorate_discovery_hit


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "sample"
    skill = root / ".hermes" / "skills" / "jwt-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: jwt-skill\ndescription: JWT testing skill\nversion: 0.1.0\n---\n# JWT\n", encoding="utf-8")
    cfg = root / ".codex" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('[mcp_servers.demo]\ncommand="node"\nargs=["server.js"]\n[mcp_servers.demo.env]\nAPI_KEY="redacted"\n', encoding="utf-8")
    exe = root / "codex.exe"
    exe.write_text("binary", encoding="utf-8")
    return root


def test_v427_discovery_display_contract_for_all_types(tmp_path):
    root = _fixture(tmp_path)
    result = DiscoveryEngine().discover([root], scope="v427-fixture", probe_installed=False)
    hits = [decorate_discovery_hit(h) for h in result.hits]
    assert hits
    for hit in hits:
        display = hit.get("display") or {}
        assert display.get("title")
        assert display.get("type_label")
        assert display.get("primary_path")
        assert display.get("fields")
        assert hit["mutates_installed_agents"] is False
        assert hit["stdio_mcp_started"] is False
    skill = next(h for h in hits if h["type"] == "Skill")
    assert skill["display"]["title"] == "jwt-skill"
    assert skill["display"]["subtitle"] == "JWT testing skill"
    assert skill["display"]["version"] == "0.1.0"
    labels = {f["label"] for f in skill["display"]["fields"]}
    assert {"版本", "文件", "脚本", "路径"} <= labels


def test_v427_discovery_self_project_policy_marks_legacy_but_keeps_fixtures():
    legacy = decorate_discovery_hit({"id":"h1","type":"Config","agent":"Generic","path":"<project>/src/assessment/scanning/mcp_static.py","path_hash":"x","sha256":"y"})
    fixture = decorate_discovery_hit({"id":"h2","type":"Config","agent":"Generic","path":"tests/fixtures/sample_agent_project/.mcp.json","path_hash":"x","sha256":"y"})
    assert legacy["hidden_by_default"] is True
    assert legacy["self_project_policy"] == "legacy_stale"
    assert fixture["hidden_by_default"] is False
    assert fixture["self_project_policy"] == "test_asset"
