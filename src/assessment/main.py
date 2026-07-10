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
from .store import get_store


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML = STATIC_DIR / "assessment" / "index.html"


def create_app() -> FastAPI:
    app = FastAPI(
        title="Agent 安全测评能力模块",
        version=__version__,
        description="V4.2.10 enterprise release gate local Agent security assessment module.",
    )

    get_store().initialize()
    allowed_hosts = ["127.0.0.1", "localhost", "testserver"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    install_contract_openapi(app)

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID") or uuid4().hex
        token = os.environ.get("ASSESSMENT_ADMIN_TOKEN")
        protected = request.method not in {"GET", "HEAD", "OPTIONS"} or request.url.path.endswith("/export") or "/download" in request.url.path
        if token and protected and request.url.path not in {"/healthz", "/api/v1/version"}:
            supplied = request.headers.get("X-Assessment-Token", "")
            if not hmac.compare_digest(supplied, token):
                return JSONResponse(status_code=401, content={"error": {"code": "AUTH_REQUIRED", "message": "authorization required", "correlation_id": correlation_id, "details": {}, "validation_errors": []}})
        if request.headers.get("content-length") and int(request.headers["content-length"]) > 2 * 1024 * 1024:
            return JSONResponse(status_code=413, content={"error": {"code": "REQUEST_TOO_LARGE", "message": "request body exceeds limit", "correlation_id": correlation_id, "details": {}, "validation_errors": []}})
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": getattr(exc, "code", "HTTP_ERROR"),
                    "message": str(detail.get("message") or exc.detail),
                    "correlation_id": request.headers.get("X-Correlation-ID", uuid4().hex),
                    "details": detail,
                    "validation_errors": detail.get("validation_errors", []),
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
