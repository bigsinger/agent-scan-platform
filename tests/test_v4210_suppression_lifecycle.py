from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from assessment.main import app


client = TestClient(app)
FIXTURE = Path(__file__).parent / "fixtures" / "sample_agent_project"


def _scan():
    response = client.post(
        "/api/v1/quick-scans",
        json={"mode": "path", "target_path": str(FIXTURE), "max_files": 100},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_v4210_fingerprint_suppression_persists_across_scan_and_can_be_revoked():
    first = _scan()
    finding = next(item for item in first["findings"] if item["rule_id"] == "SECRET-KEY-001")
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    created = client.post(
        f"/api/v1/findings/{finding['id']}/suppress",
        json={"scope": "fingerprint", "reason": "approved synthetic fixture", "expires_at": expires},
    )
    assert created.status_code == 200, created.text
    suppression = created.json()["suppression"]
    assert suppression["status"] == "ACTIVE"
    assert created.json()["finding"]["suppressed"] is True

    active = client.get("/api/v1/finding-suppressions?status=ACTIVE")
    assert active.status_code == 200
    assert suppression["id"] in {item["id"] for item in active.json()["items"]}

    second = _scan()
    suppressed = next(item for item in second["findings"] if item["id"] == finding["id"])
    assert suppressed["status"] == "已抑制"
    assert suppressed["suppression_id"] == suppression["id"]
    assert second["assessment"]["suppressed_finding_count"] >= 1

    revoked = client.post(
        f"/api/v1/finding-suppressions/{suppression['id']}/revoke",
        json={"reason": "fixture validation complete"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["suppression"]["status"] == "REVOKED"

    third = _scan()
    restored = next(item for item in third["findings"] if item["id"] == finding["id"])
    assert restored.get("suppressed", False) is False
    assert restored["status"] == "待复核"


def test_v4210_suppression_rejects_missing_reason_and_past_expiration():
    finding = _scan()["findings"][0]
    assert client.post(f"/api/v1/findings/{finding['id']}/suppress", json={}).status_code == 422
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    response = client.post(
        f"/api/v1/findings/{finding['id']}/suppress",
        json={"reason": "expired test", "expires_at": past},
    )
    assert response.status_code == 422
