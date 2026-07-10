import json
import os
import sqlite3
import subprocess
from pathlib import Path


def test_v4210_reset_demo_state_apply_clears_product_tables(tmp_path):
    data = tmp_path / 'data'; db = data / 'db' / 'app.db'; db.parent.mkdir(parents=True)
    con = sqlite3.connect(db); con.execute('create table finding(id text)'); con.execute("insert into finding values ('f1')"); con.commit(); con.close()
    cmd = ['powershell','-ExecutionPolicy','Bypass','-File','tools/reset_demo_state.ps1','-DataRoot',str(data),'-Apply']
    r = subprocess.run(cmd, cwd=Path.cwd(), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
    assert r.returncode == 0, (r.stdout or '') + (r.stderr or '')
    con = sqlite3.connect(db); assert con.execute('select count(*) from finding').fetchone()[0] == 0; con.close()
    assert list((data/'backups').glob('reset-*.db'))


def test_v4210_delivery_package_manifest_contains_hashes(tmp_path):
    out = tmp_path / 'delivery'
    r = subprocess.run(['powershell','-ExecutionPolicy','Bypass','-File','tools/export_final_delivery_package.ps1','-OutputRoot',str(out)], cwd=Path.cwd(), capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = out / 'package' / 'manifest.json'
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding='utf-8-sig'))
    assert data['schema'] == 'agent-security-final-delivery@4.2.10'
    assert any(item['path'].startswith('dist/') and item['sha256'] for item in data['files'])
    assert list(out.glob('agent-security-assessment-v4.2.10-*.zip'))
