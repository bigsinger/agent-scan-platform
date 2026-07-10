from __future__ import annotations

from pathlib import Path

import pytest

from assessment.probes.codex.codex_probe_hook import (
    capability_probe as codex_capability_probe,
    generate_install_plan as codex_install_plan,
)
from assessment.probes.hermes.hermes_probe_plugin import (
    apply_install_plan,
    capability_probe as hermes_capability_probe,
    disable_probe,
    generate_install_plan as hermes_install_plan,
    rollback_install,
    run_synthetic_self_test,
    uninstall_probe,
)


def test_v4210_capability_detection_does_not_promote_generic_config_text(tmp_path: Path):
    hermes = tmp_path / ".hermes" / "config.yaml"
    codex = tmp_path / ".codex" / "config.toml"
    hermes.parent.mkdir(parents=True)
    codex.parent.mkdir(parents=True)
    hermes.write_text("hooks:\n  unrelated: true\nprobe: false\n", encoding="utf-8")
    codex.write_text("[hooks]\nexample = 'not-a-probe'\n", encoding="utf-8")

    hermes_result = hermes_capability_probe(config_path=hermes, command_runner=lambda *_: (0, "", ""))
    codex_result = codex_capability_probe(config_path=codex, command_runner=lambda *_: (0, "", ""))

    assert hermes_result["status"] == "NOT_INSTALLED"
    assert hermes_result["installed"] is False
    assert codex_result["status"] == "DRY_RUN_ONLY"
    assert codex_result["installed"] is False


def test_v4210_hermes_fake_home_apply_self_test_disable_uninstall_and_rollback(tmp_path: Path):
    config = tmp_path / ".hermes" / "config.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("profile: test\n", encoding="utf-8")
    before = config.read_bytes()

    plan = hermes_install_plan(config_path=config)
    assert plan["install_status"] == "SUPPORTED_PARTIAL"
    assert plan["dry_run"] is True
    assert config.read_bytes() == before

    applied = apply_install_plan(plan, confirmed_plan_id=plan["plan_id"])
    assert applied["status"] == "INSTALLED_DEGRADED"
    assert run_synthetic_self_test(config_path=config)["passed"] is True
    assert "agent-scan-platform hermes probe" in config.read_text(encoding="utf-8")

    assert disable_probe(config_path=config)["status"] == "INSTALLED_DEGRADED"
    assert uninstall_probe(config_path=config)["status"] == "NOT_INSTALLED"
    assert config.read_bytes() == before

    apply_install_plan(plan, confirmed_plan_id=plan["plan_id"])
    assert rollback_install(plan)["status"] == "NOT_INSTALLED"
    assert config.read_bytes() == before


def test_v4210_codex_is_dry_run_only_and_never_writes_a_guessed_hooks_schema(tmp_path: Path):
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[model]\nname = "test"\n', encoding="utf-8")
    before = config.read_bytes()

    plan = codex_install_plan(config_path=config)

    assert plan["install_status"] == "DRY_RUN_ONLY"
    assert plan["steps"] == []
    assert plan["rollback"] == []
    assert "[hooks]" not in plan.get("diff_preview", "")
    assert config.read_bytes() == before


@pytest.mark.parametrize("module_name", ["assessment.probes.common.emitter"])
def test_v4210_probe_fail_open_returns_within_budget_and_never_raises(monkeypatch, tmp_path: Path, module_name: str):
    module = __import__(module_name, fromlist=["emit_normalized_event"])

    def unavailable(*_args, **_kwargs):
        raise OSError("receiver unavailable")

    monkeypatch.setattr(module, "urlopen", unavailable)
    assert module.emit_normalized_event(
        {"event_id": "evt-v4210", "payload": {"token": "sk-test-secret"}},
        timeout_sec=0.001,
        buffer_path=tmp_path / "buffer.jsonl",
    ) is False
