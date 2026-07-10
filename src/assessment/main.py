from __future__ import annotations

from pathlib import Path
import hmac
import os
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api.v1 import router as api_router
from .contracts import install_contract_openapi
from .scanning.jobs import recover_interrupted_scans
from .security import SensitiveDataGuard
from .store import get_store, set_audit_correlation_id


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML = STATIC_DIR / "assessment" / "index.html"
MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024


def create_app() -> FastAPI:
    listen_host = os.environ.get("ASSESSMENT_LISTEN_HOST", "127.0.0.1").strip().lower()
    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    if listen_host not in loopback_hosts and not os.environ.get("ASSESSMENT_ADMIN_TOKEN"):
        raise RuntimeError("non-loopback API binding requires ASSESSMENT_ADMIN_TOKEN")
    app = FastAPI(
        title="Agent 安全测评能力模块",
        version=__version__,
        description="V4.2.10 enterprise release gate local Agent security assessment module.",
    )

    store = get_store()
    store.initialize()
    recover_interrupted_scans(store)
    allowed_hosts = ["127.0.0.1", "localhost", "testserver"]
    if listen_host not in loopback_hosts:
        allowed_hosts.extend(host.strip() for host in os.environ.get("ASSESSMENT_TRUSTED_HOSTS", "").split(",") if host.strip())
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    install_contract_openapi(app)

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID") or uuid4().hex
        request.state.correlation_id = correlation_id
        set_audit_correlation_id(correlation_id)
        token = os.environ.get("ASSESSMENT_ADMIN_TOKEN")
        protected = request.method not in {"GET", "HEAD", "OPTIONS"} or request.url.path.endswith("/export") or "/download" in request.url.path
        if token and protected and request.url.path not in {"/healthz", "/api/v1/version"}:
            supplied = request.headers.get("X-Assessment-Token", "")
            if not hmac.compare_digest(supplied, token):
                return JSONResponse(status_code=401, content={"error": {"code": "AUTH_REQUIRED", "message": "authorization required", "correlation_id": correlation_id, "details": {}, "validation_errors": []}})
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                too_large = int(content_length) > MAX_REQUEST_BODY_BYTES
            except ValueError:
                return JSONResponse(status_code=400, content={"error": {"code": "INVALID_CONTENT_LENGTH", "message": "invalid content length", "correlation_id": correlation_id, "details": {}, "validation_errors": []}})
            if too_large:
                return JSONResponse(status_code=413, content={"error": {"code": "REQUEST_TOO_LARGE", "message": "request body exceeds limit", "correlation_id": correlation_id, "details": {}, "validation_errors": []}})
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(status_code=413, content={"error": {"code": "REQUEST_TOO_LARGE", "message": "request body exceeds limit", "correlation_id": correlation_id, "details": {}, "validation_errors": []}})
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        safe_detail = SensitiveDataGuard.sanitize_for_persist(detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": getattr(exc, "code", "HTTP_ERROR"),
                    "message": SensitiveDataGuard.redact_text(str(safe_detail.get("message") or "request failed")),
                    "correlation_id": request.headers.get("X-Correlation-ID", uuid4().hex),
                    "details": safe_detail,
                    "validation_errors": safe_detail.get("validation_errors", []),
                }
            },
        )

    @app.exception_handler(Exception)
    async def exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "internal server error",
                    "correlation_id": request.headers.get("X-Correlation-ID", uuid4().hex),
                    "details": {},
                    "validation_errors": [],
                }
            },
        )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/", include_in_schema=False)
    async def root() -> FileResponse:
        return FileResponse(INDEX_HTML)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(status_code=204)

    @app.get("/assessment", include_in_schema=False)
    async def assessment_root() -> FileResponse:
        return FileResponse(INDEX_HTML)

    @app.get("/assessment/{path:path}", include_in_schema=False)
    async def assessment_routes(path: str) -> FileResponse:
        return FileResponse(INDEX_HTML)

    return app


app = create_app()
