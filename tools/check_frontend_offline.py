from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


REMOTE_PATTERN = re.compile(r"https?://|//unpkg|//cdn|//cdnjs|fonts\.googleapis", re.IGNORECASE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", required=True)
    parser.add_argument("--expect-pages", type=int, default=48)
    args = parser.parse_args()

    html_path = Path(args.html)
    root = Path.cwd()
    for parent in html_path.resolve().parents:
        if parent.name == "src":
            root = parent.parent
            break
    static = root / "src" / "assessment" / "static"
    seed = json.loads((static / "assessment" / "seed.json").read_text(encoding="utf-8"))

    executable_files = [
        html_path,
        static / "assessment" / "app.js",
        static / "assessment" / "seed.js",
        static / "assessment" / "style.css",
    ]
    for file in executable_files:
        text = file.read_text(encoding="utf-8")
        if REMOTE_PATTERN.search(text):
            raise SystemExit(f"external runtime URL found in {file}")

    html = html_path.read_text(encoding="utf-8")
    required = [
        'id="boot-status"',
        'id="boot-error"',
        'v-cloak',
        "/static/vendor/vue.global.prod.js",
        "/static/assessment/app.js",
        "/static/assessment/style.css",
    ]
    for token in required:
        if token not in html:
            raise SystemExit(f"missing frontend boot token: {token}")

    page_count = len(seed.get("completeness", []))
    if page_count != args.expect_pages:
        raise SystemExit(f"expected {args.expect_pages} pages, got {page_count}")

    runtime_seed_keys = [
        "agents",
        "agentAssets",
        "discoveryHits",
        "discoveryErrors",
        "discoveryLog",
        "mcpServers",
        "consents",
        "tools",
        "skills",
        "tasks",
        "jobs",
        "processes",
        "taskEvents",
        "findings",
        "evidenceItems",
        "reports",
        "components",
        "redteamRuns",
        "attackPaths",
        "policyDrafts",
        "retests",
        "backupRecords",
        "heatmap",
        "caseLibrary",
        "redCases",
        "profiles",
        "ruleRows",
        "scanners",
        "schedules",
        "integrations",
        "licenses",
        "dbTables",
        "taskStages",
    ]
    for key in runtime_seed_keys:
        if seed.get(key):
            raise SystemExit(f"prototype runtime seed must be empty: {key}")

    seed_text = json.dumps(seed, ensure_ascii=False)
    prototype_tokens = [
        "claude-code-repo-demo",
        "agt_cc_001",
        "asm_v4_",
        "/workspace/demo",
        "64/64",
        "84+",
        "openclaw-gateway-lab",
        "hermes-profile-dev",
        "codex-project-a",
    ]
    for token in prototype_tokens:
        if token in seed_text:
            raise SystemExit(f"prototype token remains in seed: {token}")

    manifest = json.loads((static / "vendor" / "vendor-manifest.json").read_text(encoding="utf-8"))
    vue = static / "vendor" / "vue.global.prod.js"
    actual_sha = hashlib.sha256(vue.read_bytes()).hexdigest()
    expected_sha = manifest["vue.global.prod.js"]["sha256"]
    if actual_sha != expected_sha:
        raise SystemExit("vendor-manifest sha256 mismatch")

    print(f"frontend offline check passed: pages={page_count}, vue_sha256={actual_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
