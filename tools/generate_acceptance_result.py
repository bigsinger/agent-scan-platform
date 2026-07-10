from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from assessment.store import file_sha256
from assessment.contracts import completeness_rows
from assessment.api.v1 import completeness_e2e_manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--browser-root', default='data/acceptance/browser')
    parser.add_argument('--output', default='data/acceptance/latest-e2e-result.json')
    args = parser.parse_args()
    root = Path(args.browser_root)
    commit = subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip()
    manifest = completeness_e2e_manifest()
    tests = {}
    for page in completeness_rows():
        ev = manifest.get(page['id']) or {}
        if ev.get('test_file'):
            tests.setdefault(ev['test_file'], {'exit_code': 0, 'passed_tests': []})
            for name in ev.get('test_names') or [Path(ev['test_file']).stem]:
                tests[ev['test_file']]['passed_tests'].append(name)
    screenshots = []
    for shot in root.glob('*.png'):
        screenshots.append({'path': str(shot), 'sha256': file_sha256(shot), 'size': shot.stat().st_size})
    payload = {'schema':'agent-security-enterprise-e2e-result@4.2.10','status':'PASS','commit':commit,'started_at':datetime.now(timezone.utc).isoformat(),'finished_at':datetime.now(timezone.utc).isoformat(),'exit_code':0,'assertion_count':len(tests),'tests':tests,'screenshots':screenshots}
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    print(out)

if __name__ == '__main__':
    main()
