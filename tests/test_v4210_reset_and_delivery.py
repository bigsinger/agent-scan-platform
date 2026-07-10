import json
import os
import sqlite3
import subprocess
import hashlib
import datetime
from pathlib import Path


def test_v4210_reset_demo_state_apply_clears_product_tables(tmp_path):
    data = tmp_path / 'data'; db = data / 'db' / 'app.db'; db.parent.mkdir(parents=True)
    con = sqlite3.connect(db); con.execute('create table finding(id text)'); con.execute("insert into finding values ('f1')"); con.commit(); con.close()
    cmd = ['powershell','-ExecutionPolicy','Bypass','-File','tools/reset_demo_state.ps1','-DataRoot',str(data),'-Apply']
    r = subprocess.run(cmd, cwd=Path.cwd(), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
    assert r.returncode == 0, (r.stdout or '') + (r.stderr or '')
    con = sqlite3.connect(db); assert con.execute('select count(*) from finding').fetchone()[0] == 0; con.close()
    assert list((data/'backups').glob('reset-*.db'))


def test_v4210_delivery_package_manifest_contains_hashes(tmp_path, monkeypatch):
    out = tmp_path / 'delivery'
    screenshots = []
    for index in range(8):
        screenshot = tmp_path / f'acceptance-{index}.png'; screenshot.write_bytes(b'\x89PNG\r\n\x1a\n' + bytes(range(256)) * 5); screenshots.append(screenshot)
    junits = []
    for name in ('browser.xml','pytest.xml'):
        junit = tmp_path / name; junit.write_text('<testsuites tests="1"><testsuite tests="1"><testcase classname="tests.example" name="test_example"/></testsuite></testsuites>', encoding='utf-8'); junits.append(junit)
    commit = subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip()
    acceptance = tmp_path / 'acceptance.json'
    acceptance.write_text(json.dumps({
        'schema':'agent-security-enterprise-e2e-result@4.2.10','status':'PASS','commit':commit,'exit_code':0,
        'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'generated_from':'pytest-junit-xml',
        'pytest':{'sources':[{'path':str(junit),'sha256':hashlib.sha256(junit.read_bytes()).hexdigest(),'size':junit.stat().st_size} for junit in junits]},
        'screenshots':[{'path':str(screenshot),'sha256':hashlib.sha256(screenshot.read_bytes()).hexdigest(),'size':screenshot.stat().st_size} for screenshot in screenshots],
        'tests':{},
    }), encoding='utf-8')
    state_root = tmp_path / 'package-state'; audit_dir = state_root / 'acceptance'; audit_dir.mkdir(parents=True)
    (audit_dir / 'sensitive-data-audit.json').write_text(json.dumps({
        'schema':'agent-security-sensitive-audit@4.2.10','count':0,'hits':[],
        'raw_values_emitted':False,'agent_paths_scanned':False,'mutates_installed_agents':False,
    }), encoding='utf-8')
    env = os.environ.copy(); env['ASSESSMENT_E2E_RESULT_PATH'] = str(acceptance); env['ASSESSMENT_STATE_ROOT'] = str(state_root)
    r = subprocess.run(['powershell','-ExecutionPolicy','Bypass','-File','tools/export_final_delivery_package.ps1','-OutputRoot',str(out)], cwd=Path.cwd(), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=240, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = out / 'package' / 'manifest.json'
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding='utf-8-sig'))
    assert data['schema'] == 'agent-security-final-delivery@4.2.10'
    assert any(item['path'].startswith('dist/') and item['sha256'] for item in data['files'])
    assert list(out.glob('agent-security-assessment-v4.2.10-*.zip'))
