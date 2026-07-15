"""Commit-bound browser journeys for the enterprise release gate.

These tests use an isolated SQLite/artifact root and never apply a probe or
start an Agent/MCP process. Missing Playwright/Chromium is a hard test failure.
"""
from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

import pytest
from playwright.sync_api import Page, sync_playwright


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample_agent_project"
OUT = Path(os.environ.get("ASSESSMENT_BROWSER_RESULT_ROOT") or (ROOT / "data" / "acceptance" / "browser"))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _hash_if_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _stop_owned_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    proc.wait(timeout=8)


@pytest.fixture(scope="module")
def browser_server(tmp_path_factory):
    port = _free_port()
    run_root = tmp_path_factory.mktemp("browser-run")
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("J*.png"):
        old.unlink()
    protected_configs = [
        Path.home() / ".codex" / "config.toml",
        Path.home() / ".hermes" / "config.yaml",
        Path.home() / ".hermes" / "config.yml",
    ]
    before_hashes = {path: _hash_if_file(path) for path in protected_configs}
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(ROOT / "src"),
            "ASSESSMENT_DB_PATH": str(run_root / "app.db"),
            "ASSESSMENT_STATE_ROOT": str(run_root / "state"),
            "ASSESSMENT_ARTIFACT_ROOT": str(run_root / "artifacts"),
            "ASSESSMENT_DISABLE_BACKGROUND_JOBS": "true",
            "ASSESSMENT_LISTEN_HOST": "127.0.0.1",
        }
    )
    log_path = run_root / "browser-server.log"
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "assessment.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            if proc.poll() is not None:
                break
            try:
                with urlopen(base + "/healthz", timeout=0.5) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.1)
        else:
            _stop_owned_process(proc)
            raise RuntimeError("browser service did not become healthy")
        if proc.poll() is not None:
            raise RuntimeError(f"browser service exited early; see {log_path}")
        try:
            yield base
        finally:
            _stop_owned_process(proc)
    after_hashes = {path: _hash_if_file(path) for path in protected_configs}
    assert after_hashes == before_hashes, "browser journeys modified an installed Agent configuration"


@pytest.fixture()
def page(browser_server, request):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        viewports = {
            "test_j02_": {"width": 1440, "height": 900},
            "test_j03_": {"width": 1920, "height": 1080},
            "test_j08_": {"width": 390, "height": 844},
        }
        viewport = next((value for prefix, value in viewports.items() if request.node.name.startswith(prefix)), {"width": 1366, "height": 768})
        context = browser.new_context(viewport=viewport, accept_downloads=True)
        current = context.new_page()
        errors: list[str] = []
        external: list[str] = []
        current.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        current.on("pageerror", lambda error: errors.append(str(error)))
        current.on(
            "request",
            lambda request: external.append(request.url)
            if not request.url.startswith(browser_server)
            and not request.url.startswith(("data:", "blob:", "about:"))
            else None,
        )
        yield current, browser_server, errors, external
        context.close()
        browser.close()


def _goto(page: Page, base: str, path: str, expected_text: str) -> None:
    response = page.goto(base + path, wait_until="domcontentloaded", timeout=30_000)
    assert response and response.ok
    page.wait_for_function("() => !document.querySelector('#boot-status')", timeout=20_000)
    page.get_by_text(expected_text, exact=False).first.wait_for(state="visible", timeout=20_000)


def _api(page: Page, base: str, method: str, path: str, payload: dict | None = None, timeout: float = 90_000):
    response = page.request.fetch(base + path, method=method, data=payload, timeout=timeout)
    assert response.ok, f"{method} {path}: {response.status} {response.text()[:500]}"
    return response.json()


def _assert_and_shot(page: Page, errors: list[str], external: list[str], name: str) -> None:
    shot = OUT / f"{name}.png"
    page.screenshot(path=shot, full_page=True)
    assert shot.read_bytes()[:8] == bytes([137, 80, 78, 71, 13, 10, 26, 10])
    assert shot.stat().st_size > 1024
    assert page.viewport_size and page.viewport_size["width"] >= 320 and page.viewport_size["height"] >= 240
    overflow = page.evaluate("""() => ({
        fits: document.documentElement.scrollWidth <= window.innerWidth + 1,
        viewport: window.innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        offenders: [...document.querySelectorAll('body *')]
          .map(element => {
            const rect = element.getBoundingClientRect();
            return {tag: element.tagName, className: String(element.className || ''),
                    left: Math.round(rect.left), right: Math.round(rect.right), width: Math.round(rect.width)};
          })
          .filter(item => item.right > window.innerWidth + 1 || item.left < -1 || item.width > window.innerWidth + 1)
          .slice(0, 12)
      })""")
    assert overflow["fits"], f"page has root-level horizontal overflow: {overflow}"
    assert page.evaluate("""() => [...document.querySelectorAll('.field label')].filter(label =>
        !label.htmlFor && !label.querySelector('input,select,textarea,button')).length === 0"""), "visible form contains an unbound label"
    assert not errors, errors
    assert not external, external


def test_j01_first_start_empty_dashboard(page):
    browser, base, errors, external = page
    _goto(browser, base, "/assessment", "检查本机 Agent 安全风险")
    assert _api(browser, base, "GET", "/healthz")["status"] == "ok"
    version = _api(browser, base, "GET", "/api/v1/version")
    assert version["app"] == "4.2.10" and version["spec"] == "V4.2.10"
    assert browser.get_by_text("本机只读", exact=True).is_visible()
    assert browser.get_by_role("link", name="专业模式", exact=True).get_attribute("href") == "/assessment/advanced"
    with browser.expect_response(lambda response: response.url.endswith("/api/v1/discovery-runs") and response.request.method == "POST", timeout=60_000) as discovery:
        browser.get_by_role("button", name="仅发现资产", exact=True).click()
    assert discovery.value.ok
    assert discovery.value.json()["mutates_installed_agents"] is False
    browser.locator("#asset-section").wait_for(state="visible", timeout=30_000)
    assert browser.locator(".agent-item").count() >= 1
    _assert_and_shot(browser, errors, external, "J01_dashboard")


def test_j02_discovery_filter_skill_drawer_and_export(page):
    browser, base, errors, external = page
    _goto(browser, base, "/assessment/discovery", "本机 Agent 发现")
    browser.locator(".field", has_text="附加路径").locator("textarea").fill(str(FIXTURE))
    with browser.expect_response(lambda response: response.url.endswith("/api/v1/discovery-runs") and response.request.method == "POST", timeout=60_000) as pending:
        browser.get_by_role("button", name="开始发现", exact=True).click()
    assert pending.value.ok
    browser.get_by_text("discovery.completed", exact=False).wait_for(timeout=30_000)
    browser.get_by_role("button", name="Skills", exact=True).click()
    browser.locator(".discovery-title").first.wait_for(timeout=20_000)
    browser.locator(".discovery-title").first.click()
    browser.locator(".drawer").get_by_text("类型化字段", exact=True).wait_for(timeout=10_000)
    export = _api(browser, base, "GET", "/api/v1/discovery-hits/export")
    assert export["validation"]["status"] == "PASS" and export["mutates_installed_agents"] is False
    _assert_and_shot(browser, errors, external, "J02_discovery")


def test_j03_path_quick_scan_to_findings_evidence_and_report(page):
    browser, base, errors, external = page
    _goto(browser, base, "/assessment/quick-scan", "快速扫描")
    browser.locator(".field", has_text="扫描模式").locator("select").first.select_option("path")
    browser.get_by_placeholder("machine 留空；path 填本机路径；mcp 填 Remote URL、.mcp.json 路径或 JSON 配置").fill(str(FIXTURE))
    with browser.expect_response(lambda response: response.url.endswith("/api/v1/quick-scans/precheck"), timeout=30_000) as precheck:
        browser.get_by_role("button", name="仅检查", exact=True).click()
    assert precheck.value.ok and precheck.value.json()["precheck"]["status"] == "PASS"
    payload = _api(browser, base, "POST", "/api/v1/quick-scans", {"mode": "path", "target_path": str(FIXTURE), "max_files": 100})
    assert payload["assessment"]["id"] and payload["findings"] and payload["evidence"]
    assert payload["report"]["status"] == "READY"
    _goto(browser, base, f"/assessment/tasks/{payload['assessment']['id']}", payload["assessment"]["id"])
    browser.get_by_role("button", name="风险", exact=True).click()
    assert browser.locator("table tbody tr").count() > 0
    _assert_and_shot(browser, errors, external, "J03_quick_scan")


def test_j04_async_machine_cancel_and_retry_state_machine(page):
    browser, base, errors, external = page
    queued = _api(
        browser,
        base,
        "POST",
        "/api/v1/quick-scans",
        {"mode": "machine", "async_scan": True, "defer_start": True, "max_files": 50},
    )
    task_id = queued["task"]["id"]
    assert queued["status_code"] == 202 and queued["task"]["state_code"] == "QUEUED"
    _goto(browser, base, f"/assessment/tasks/{task_id}", task_id)
    with browser.expect_response(lambda response: response.url.endswith(f"/api/v1/tasks/{task_id}/cancel"), timeout=20_000):
        browser.get_by_role("button", name="取消任务", exact=True).click()
    browser.get_by_text("CANCELLED", exact=False).first.wait_for(timeout=20_000)
    with browser.expect_response(lambda response: response.url.endswith(f"/api/v1/tasks/{task_id}/retry"), timeout=20_000) as retried:
        browser.get_by_role("button", name="重试任务", exact=True).click()
    assert retried.value.status == 202
    retry_id = retried.value.json()["task"]["id"]
    assert retry_id != task_id
    events = _api(browser, base, "GET", f"/api/v1/tasks/{task_id}/events")["items"]
    assert {event["type"] for event in events} >= {"task.queued", "task.cancel_requested"}
    _assert_and_shot(browser, errors, external, "J04_task")


def test_j05_mcp_static_consent_and_reapproval_boundary(page):
    browser, base, errors, external = page
    discovery = _api(browser, base, "POST", "/api/v1/discovery-runs", {"path": str(FIXTURE), "scope": "browser-mcp"})
    assert discovery["stdio_mcp_started"] is False
    consents = _api(browser, base, "GET", "/api/v1/mcp-consents?page_size=50")["items"]
    assert consents
    _goto(browser, base, "/assessment/consents", "MCP 启动审批")
    with browser.expect_response(lambda response: "/api/v1/mcp-consents/" in response.url and response.url.endswith("/approve"), timeout=20_000):
        browser.get_by_role("button", name="允许一次", exact=True).first.click()
    browser.get_by_text("配置 Hash 或命令指纹变化", exact=False).first.wait_for(timeout=10_000)
    approved = _api(browser, base, "GET", "/api/v1/mcp-consents?page_size=50")["items"]
    assert any(item.get("status") not in {"待审批", "PENDING"} for item in approved)
    _assert_and_shot(browser, errors, external, "J05_mcp")


def test_j06_skill_scan_change_detail_and_evidence(page):
    browser, base, errors, external = page
    seeded = _api(browser, base, "POST", "/api/v1/skill-scans", {"target_path": str(FIXTURE), "limit": 50})
    assert seeded["skills"] and seeded["evidence"] and seeded["mutates_installed_agents"] is False
    changed = _api(browser, base, "POST", "/api/v1/skill-scans", {"target_path": str(FIXTURE), "limit": 50, "changes_only": True})
    assert changed["change_summary"]["returned"] >= 0 and changed["mutates_installed_agents"] is False
    _goto(browser, base, "/assessment/skills", "Skill 安全扫描")
    browser.locator("table tbody .link").first.click()
    browser.get_by_role("button", name="证据", exact=True).click()
    browser.get_by_text("尚未生成证据。", exact=False).or_(browser.get_by_text("下载", exact=True)).first.wait_for(timeout=20_000)
    _assert_and_shot(browser, errors, external, "J06_skill")


def test_j07_report_finding_detail_returns_to_report_context(page):
    browser, base, errors, external = page
    scan = _api(browser, base, "POST", "/api/v1/quick-scans", {"mode": "path", "target_path": str(FIXTURE), "max_files": 100})
    report_id = scan["report"]["id"]
    _goto(browser, base, f"/assessment/reports/{report_id}", "报告风险")
    browser.get_by_test_id("report-finding-detail").first.click()
    browser.get_by_text("Finding ID", exact=True).wait_for(timeout=20_000)
    browser.get_by_role("button", name="返回报告", exact=False).click()
    browser.get_by_text("报告风险", exact=True).wait_for(timeout=20_000)
    browser.get_by_role("button", name="预览", exact=True).first.click()
    assert report_id in browser.url
    _assert_and_shot(browser, errors, external, "J07_report")


def test_j08_settings_sqlite_completeness_and_delivery_contract(page):
    browser, base, errors, external = page
    _goto(browser, base, "/assessment/probes/install", "探针生命周期")
    browser.get_by_label("Agent 类型", exact=True).select_option("hermes")
    with browser.expect_response(lambda response: response.url.endswith("/api/v1/probes/install-plan"), timeout=30_000):
        browser.get_by_role("button", name="生成只读安装计划", exact=True).click()
    browser.get_by_text("计划详情", exact=True).wait_for(timeout=20_000)
    assert browser.get_by_role("button", name="应用计划", exact=True).is_disabled()
    _goto(browser, base, "/assessment/settings", "模块设置")
    with browser.expect_response(lambda response: response.url.endswith("/api/v1/settings/test"), timeout=20_000):
        browser.get_by_role("button", name="校验", exact=True).click()
    _goto(browser, base, "/assessment/sqlite", "SQLite 维护")
    with browser.expect_response(lambda response: response.url.endswith("/api/v1/sqlite/integrity-check"), timeout=30_000):
        browser.get_by_role("button", name="完整性检查", exact=True).click()
    _goto(browser, base, "/assessment/completeness", "实现完整性矩阵")
    summary = _api(browser, base, "GET", "/api/v1/completeness?page_size=200")["summary"]
    assert summary["pages"] == 58 and summary["audit_passed"] == 58 and summary["contract_passed"] == 58
    assert (ROOT / "tools" / "export_final_delivery_package.ps1").is_file()
    _assert_and_shot(browser, errors, external, "J08_admin")
