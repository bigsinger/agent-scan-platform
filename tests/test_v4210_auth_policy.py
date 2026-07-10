import pytest
import sqlite3
from fastapi.testclient import TestClient

import assessment.main as main_module
from assessment.api import v1 as api_v1
from assessment.store import AssessmentStore


def _app(monkeypatch, tmp_path):
    store = AssessmentStore(tmp_path / "auth.db")
    store.initialize()
    monkeypatch.setattr(main_module, "get_store", lambda: store)
    monkeypatch.setattr(api_v1, "get_store", lambda: store)
    monkeypatch.setenv("ASSESSMENT_LISTEN_HOST", "127.0.0.1")
    return main_module.create_app()


def test_v4210_auth_policy_requires_token_for_write(monkeypatch, tmp_path):
    monkeypatch.setenv("ASSESSMENT_ADMIN_TOKEN", "test-admin-token")
    client = TestClient(_app(monkeypatch, tmp_path))
    assert client.get("/api/v1/version").status_code == 200
    denied = client.post("/api/v1/tasks", json={"name": "blocked"})
    assert denied.status_code == 401
    allowed = client.post(
        "/api/v1/tasks",
        json={"name": "allowed"},
        headers={"X-Assessment-Token": "test-admin-token", "X-Correlation-ID": "correlation-auth-test"},
    )
    assert allowed.status_code == 200
    with sqlite3.connect(tmp_path / "auth.db") as conn:
        payload = conn.execute("SELECT payload_json FROM audit_event ORDER BY seq DESC LIMIT 1").fetchone()[0]
    assert "correlation-auth-test" in payload


def test_v4210_error_redaction_request_limits_and_security_headers(monkeypatch, tmp_path):
    client = TestClient(_app(monkeypatch, tmp_path))
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code in {404, 200}
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Correlation-ID")
    assert response.headers.get("Content-Security-Policy")
    malformed = client.post("/api/v1/tasks", content=b"{}", headers={"content-length": "invalid"})
    assert malformed.status_code == 400
    assert "invalid" not in str(malformed.json().get("error", {}).get("details", {})).lower()


def test_v4210_non_loopback_requires_admin_token(monkeypatch, tmp_path):
    store = AssessmentStore(tmp_path / "non-loopback.db")
    store.initialize()
    monkeypatch.setattr(main_module, "get_store", lambda: store)
    monkeypatch.setenv("ASSESSMENT_LISTEN_HOST", "0.0.0.0")
    monkeypatch.delenv("ASSESSMENT_ADMIN_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="requires ASSESSMENT_ADMIN_TOKEN"):
        main_module.create_app()


def test_v4210_chunked_body_limit_and_artifact_path_boundary(monkeypatch, tmp_path):
    store = AssessmentStore(tmp_path / "boundary.db")
    store.initialize()
    monkeypatch.setattr(main_module, "get_store", lambda: store)
    monkeypatch.setattr(api_v1, "get_store", lambda: store)
    monkeypatch.setenv("ASSESSMENT_LISTEN_HOST", "127.0.0.1")
    monkeypatch.delenv("ASSESSMENT_ADMIN_TOKEN", raising=False)
    client = TestClient(main_module.create_app())

    def chunks():
        yield b'{"name":"'
        yield b"x" * (2 * 1024 * 1024 + 1)
        yield b'"}'

    oversized = client.post(
        "/api/v1/tasks",
        content=chunks(),
        headers={"content-type": "application/json", "transfer-encoding": "chunked"},
    )
    assert oversized.status_code == 413

    outside = tmp_path / "outside-product-data.txt"
    outside.write_text("must never be downloadable", encoding="utf-8")
    store.upsert_record(
        "artifact",
        {
            "id": "art-outside",
            "absolute_path": str(outside),
            "relative_path": "../../outside-product-data.txt",
            "content_type": "text/plain",
        },
        status="READY",
    )
    denied = client.get("/api/v1/artifacts/art-outside/download")
    assert denied.status_code == 400
    assert "must never" not in denied.text
    assert client.get("/api/v1/reports/not-real/download").status_code == 404
