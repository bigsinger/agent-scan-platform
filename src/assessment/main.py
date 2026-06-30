from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
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
        description="V4.1 local Agent security assessment module.",
    )

    get_store().initialize()
    install_contract_openapi(app)

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
                    "message": str(exc),
                    "correlation_id": request.headers.get("X-Correlation-ID", uuid4().hex),
                    "details": {},
                    "validation_errors": [],
                }
            },
        )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_router)

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
