from __future__ import annotations

import argparse
import json
import struct
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from assessment.api.v1 import completeness_e2e_manifest
from assessment.store import file_sha256


PNG_SIGNATURE = bytes([137, 80, 78, 71, 13, 10, 26, 10])


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalized_test_name(name: str) -> str:
    return name.split("[", 1)[0]


def _module_name(path: str) -> str:
    return path.replace("\\", "/").removesuffix(".py").replace("/", ".")


def _resolve_test_file(case: ET.Element, known_files: set[str]) -> str:
    explicit = str(case.attrib.get("file") or "").replace("\\", "/")
    if explicit:
        return explicit if explicit.startswith("tests/") else f"tests/{explicit.lstrip('./')}"
    classname = str(case.attrib.get("classname") or "")
    matches = [path for path in known_files if classname == _module_name(path) or classname.startswith(_module_name(path) + ".")]
    if matches:
        return max(matches, key=len)
    parts = classname.split(".")
    if parts and parts[0] == "tests":
        return "/".join(parts) + ".py"
    return "tests/unknown.py"


def _parse_junit(paths: list[Path], known_files: set[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    tests: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"exit_code": 0, "passed_tests": [], "failed_tests": [], "skipped_tests": [], "case_count": 0}
    )
    totals = {"tests": 0, "passed": 0, "failures": 0, "errors": 0, "skipped": 0}
    junit_sources: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"JUnit result is missing: {path}")
        root = ET.parse(path).getroot()
        cases = root.findall(".//testcase") if root.tag != "testcase" else [root]
        if not cases:
            raise ValueError(f"JUnit result contains no test cases: {path}")
        junit_sources.append({"path": str(path.resolve()), "sha256": file_sha256(path), "size": path.stat().st_size})
        for case in cases:
            totals["tests"] += 1
            file_name = _resolve_test_file(case, known_files)
            row = tests[file_name]
            row["case_count"] += 1
            name = _normalized_test_name(str(case.attrib.get("name") or "unknown"))
            if case.find("failure") is not None:
                totals["failures"] += 1
                row["exit_code"] = 1
                row["failed_tests"].append(name)
            elif case.find("error") is not None:
                totals["errors"] += 1
                row["exit_code"] = 1
                row["failed_tests"].append(name)
            elif case.find("skipped") is not None:
                totals["skipped"] += 1
                row["exit_code"] = 1
                row["skipped_tests"].append(name)
            else:
                totals["passed"] += 1
                row["passed_tests"].append(name)
    for row in tests.values():
        for key in ("passed_tests", "failed_tests", "skipped_tests"):
            row[key] = sorted(set(row[key]))
    return dict(tests), {**totals, "sources": junit_sources}


def _png_dimensions(path: Path) -> tuple[int, int]:
    with path.open("rb") as handle:
        if handle.read(8) != PNG_SIGNATURE:
            raise ValueError(f"invalid PNG signature: {path}")
        length = struct.unpack(">I", handle.read(4))[0]
        chunk = handle.read(4)
        if chunk != b"IHDR" or length < 8:
            raise ValueError(f"PNG IHDR is missing: {path}")
        width, height = struct.unpack(">II", handle.read(8))
    return width, height


def _screenshots(root: Path, expected: int) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for shot in sorted(root.glob("*.png")):
        try:
            width, height = _png_dimensions(shot)
            if shot.stat().st_size < 1024 or width < 320 or height < 240:
                raise ValueError(f"screenshot is too small: {shot} ({width}x{height}, {shot.stat().st_size} bytes)")
            rows.append(
                {
                    "path": str(shot.resolve()),
                    "sha256": file_sha256(shot),
                    "size": shot.stat().st_size,
                    "width": width,
                    "height": height,
                }
            )
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
    if len(rows) != expected:
        errors.append(f"expected {expected} valid screenshots, found {len(rows)}")
    return rows, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a commit-bound acceptance result from real pytest JUnit output.")
    parser.add_argument("--junit", action="append", required=True, help="JUnit XML produced by pytest; repeat for multiple suites")
    parser.add_argument("--browser-root", required=True)
    parser.add_argument("--expected-screenshots", type=int, default=8)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    manifest = completeness_e2e_manifest()
    known_files = {str(item.get("test_file") or "").replace("\\", "/") for item in manifest.values() if item.get("test_file")}
    known_files.add("tests/browser/test_enterprise_journeys.py")
    tests, junit = _parse_junit([Path(value) for value in args.junit], known_files)
    screenshots, screenshot_errors = _screenshots(Path(args.browser_root), args.expected_screenshots)

    missing_declared: list[str] = []
    for page_id, evidence in manifest.items():
        test_file = str(evidence.get("test_file") or "").replace("\\", "/")
        row = tests.get(test_file) or {}
        passed = set(row.get("passed_tests") or [])
        for test_name in evidence.get("test_names") or []:
            if test_name not in passed:
                missing_declared.append(f"{page_id}:{test_file}::{test_name}")

    required_journeys = {f"test_j{i:02d}_" for i in range(1, 9)}
    browser_passed = tests.get("tests/browser/test_enterprise_journeys.py", {}).get("passed_tests") or []
    missing_journeys = sorted(prefix for prefix in required_journeys if not any(name.startswith(prefix) for name in browser_passed))
    errors = [
        *(f"missing declared test result: {item}" for item in missing_declared),
        *(f"missing browser journey: {item}" for item in missing_journeys),
        *screenshot_errors,
    ]
    if junit["failures"] or junit["errors"] or junit["skipped"]:
        errors.append(
            f"pytest was not fully green: failures={junit['failures']} errors={junit['errors']} skipped={junit['skipped']}"
        )

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    payload = {
        "schema": "agent-security-enterprise-e2e-result@4.2.10",
        "status": "PASS" if not errors else "FAIL",
        "commit": commit,
        "started_at": datetime.fromtimestamp(
            min(Path(value).stat().st_mtime for value in args.junit), tz=timezone.utc
        ).isoformat().replace("+00:00", "Z"),
        "finished_at": _utc_now(),
        "exit_code": 0 if not errors else 1,
        "assertion_count": junit["passed"],
        "pytest": junit,
        "tests": tests,
        "screenshots": screenshots,
        "errors": errors,
        "generated_from": "pytest-junit-xml",
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(out)
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
