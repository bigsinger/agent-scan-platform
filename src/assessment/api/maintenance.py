from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException

from ..maintenance import (
    apply_artifact_gc,
    apply_retention,
    artifact_gc_plan,
    artifact_integrity,
    retention_plan,
)
from ..store import get_store


router = APIRouter(prefix="/maintenance", tags=["maintenance"])


@router.post("/retention/preview")
async def preview_retention(body: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
    try:
        return retention_plan(get_store(), body.get("policies"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)}) from exc


@router.post("/retention/apply")
async def run_retention(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    if body.get("confirmation") != "APPLY_RETENTION":
        raise HTTPException(status_code=422, detail={"message": "confirmation must equal APPLY_RETENTION"})
    try:
        return apply_retention(get_store(), body.get("policies"), str(body.get("plan_id") or ""))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc)}) from exc


@router.post("/artifacts/verify")
async def verify_artifacts() -> dict[str, Any]:
    return artifact_integrity(get_store())


@router.post("/artifacts/gc-preview")
async def preview_artifact_gc(body: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
    try:
        return artifact_gc_plan(get_store(), int(body.get("min_age_days") or 30))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)}) from exc


@router.post("/artifacts/gc-apply")
async def run_artifact_gc(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    if body.get("confirmation") != "APPLY_ARTIFACT_GC":
        raise HTTPException(status_code=422, detail={"message": "confirmation must equal APPLY_ARTIFACT_GC"})
    try:
        return apply_artifact_gc(
            get_store(),
            str(body.get("plan_id") or ""),
            int(body.get("min_age_days") or 30),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"message": str(exc)}) from exc
