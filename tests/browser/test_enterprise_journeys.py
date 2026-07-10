"""Real browser journeys for the enterprise release gate.

Run with: uv run --with pytest --with playwright python -m pytest tests/browser -q
The verifier installs Chromium first; absence is a release failure, never a skip.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get('ASSESSMENT_BROWSER_RESULT_ROOT') or (ROOT / 'data' / 'acceptance' / 'browser'))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def browser_server(tmp_path_factory):
    port = _free_port()
    run_root = tmp_path_factory.mktemp('browser-run')
    env = os.environ.copy()
    env.update({
        'PYTHONPATH': str(ROOT / 'src'),
        'ASSESSMENT_DB_PATH': str(run_root / 'app.db'),
        'ASSESSMENT_STATE_ROOT': str(run_root / 'state'),
        'ASSESSMENT_ARTIFACT_ROOT': str(run_root / 'artifacts'),
        'ASSESSMENT_DISABLE_BACKGROUND_JOBS': 'true',
    })
    proc = subprocess.Popen(['uv', 'run', '--with', 'fastapi', '--with', 'uvicorn', 'python', '-m', 'uvicorn', 'assessment.main:app', '--host', '127.0.0.1', '--port', str(port), '--log-level', 'warning'], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    import urllib.request
    for _ in range(50):
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=1)
            break
        except Exception:
            time.sleep(.2)
    else:
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=3)
        except Exception:
            output = ''
        raise RuntimeError(f'browser service failed to start: {output[-2000:]}')
    yield f'http://127.0.0.1:{port}'
    proc.terminate(); proc.wait(timeout=10)


@pytest.fixture()
def page(browser_server):
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport={'width': 1366, 'height': 768})
        page = context.new_page()
        errors, external = [], []
        page.on('console', lambda msg: errors.append(msg.text) if msg.type == 'error' else None)
        page.on('pageerror', lambda err: errors.append(str(err)))
        page.on('request', lambda req: external.append(req.url) if not req.url.startswith(browser_server) and not req.url.startswith('data:') else None)
        yield page, browser_server, errors, external
        context.close(); browser.close()


def _assert_and_shot(page, errors, external, name):
    page.screenshot(path=OUT / f'{name}.png', full_page=True)
    shot = OUT / f'{name}.png'
    assert shot.read_bytes()[:8] == bytes([137,80,78,71,13,10,26,10])
    assert shot.stat().st_size > 100
    assert not errors, errors
    assert not external, external


@pytest.mark.parametrize('journey,path', [
    ('J01_dashboard', '/assessment'),
    ('J02_discovery', '/assessment/discovery'),
    ('J03_quick_scan', '/assessment/quick-scan'),
    ('J04_task', '/assessment/tasks'),
    ('J05_mcp', '/assessment/mcp'),
    ('J06_skill', '/assessment/skills'),
    ('J07_report', '/assessment/reports'),
    ('J08_admin', '/assessment/settings'),
])
def test_enterprise_journey_pages(page, journey, path):
    browser, base, errors, external = page
    browser.goto(base + path, wait_until='domcontentloaded', timeout=30000)
    browser.wait_for_selector('body', timeout=10000)
    browser.wait_for_timeout(800)
    assert browser.locator('body').inner_text().strip()
    _assert_and_shot(browser, errors, external, journey)
