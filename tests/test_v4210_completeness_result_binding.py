import binascii
import json
import struct
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from assessment.api import v1
from assessment.contracts import completeness_rows
from assessment.store import file_sha256


def _chunk(name: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", binascii.crc32(name + data) & 0xFFFFFFFF)


def _png(path: Path, width: int = 640, height: int = 480) -> None:
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            row.extend(((x + y) % 256, (x * 3 + y) % 256, (x + y * 5) % 256))
        rows.append(bytes(row))
    payload = b"\x89PNG\r\n\x1a\n"
    payload += _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    payload += _chunk(b"IDAT", zlib.compress(b"".join(rows), 6))
    payload += _chunk(b"IEND", b"")
    path.write_bytes(payload)


def _result(path: Path, commit: str, test_file: str, test_name: str, shots: list[Path], *, finished_at: str | None = None):
    browser_names = [f"test_j{index:02d}_journey" for index in range(1, 9)]
    tests = {
        test_file: {"exit_code": 0, "passed_tests": [test_name]},
        "tests/browser/test_enterprise_journeys.py": {"exit_code": 0, "passed_tests": browser_names},
    }
    payload = {
        "schema": "agent-security-enterprise-e2e-result@4.2.10",
        "status": "PASS",
        "commit": commit,
        "generated_from": "pytest-junit-xml",
        "exit_code": 0,
        "assertion_count": 9,
        "finished_at": finished_at or datetime.now(timezone.utc).isoformat(),
        "tests": tests,
        "screenshots": [
            {"path": str(shot), "sha256": file_sha256(shot), "size": shot.stat().st_size, "width": 640, "height": 480}
            for shot in shots
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _shots(tmp_path: Path) -> list[Path]:
    rows = []
    for index in range(8):
        shot = tmp_path / f"shot-{index}.png"
        _png(shot)
        rows.append(shot)
    return rows


def test_v4210_completeness_requires_current_machine_generated_result(monkeypatch, tmp_path):
    result = tmp_path / "result.json"
    monkeypatch.setenv("ASSESSMENT_E2E_RESULT_PATH", str(result))
    assert v1.completeness_runtime_rows()[0]["e2e"] == "NOT_ASSERTED"

    evidence = v1.completeness_e2e_manifest()[completeness_rows()[0]["id"]]
    _result(result, v1.current_git_commit(), evidence["test_file"], evidence["test_names"][0], _shots(tmp_path))
    assert v1.completeness_runtime_rows()[0]["e2e"] == "PASS"


def test_v4210_completeness_rejects_stale_commit_timestamp_and_invalid_png(monkeypatch, tmp_path):
    result = tmp_path / "result.json"
    shots = _shots(tmp_path)
    monkeypatch.setenv("ASSESSMENT_E2E_RESULT_PATH", str(result))
    evidence = v1.completeness_e2e_manifest()[completeness_rows()[0]["id"]]
    _result(result, "stale-commit", evidence["test_file"], evidence["test_names"][0], shots)
    assert v1.completeness_runtime_rows()[0]["e2e"] == "STALE"

    expired = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    _result(result, v1.current_git_commit(), evidence["test_file"], evidence["test_names"][0], shots, finished_at=expired)
    assert v1.completeness_runtime_rows()[0]["e2e"] == "STALE"

    _result(result, v1.current_git_commit(), evidence["test_file"], evidence["test_names"][0], shots)
    shots[0].write_text("not png", encoding="utf-8")
    assert v1.completeness_runtime_rows()[0]["e2e"] == "STALE"
