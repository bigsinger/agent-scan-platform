from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

from ..store import get_store, utc_now


router = APIRouter(tags=["findings"])


def _stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


@router.get("/finding-suppressions")
async def list_finding_suppressions(
    status: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> dict[str, Any]:
    items = get_store().list_records("finding_suppression", limit=limit)
    if status:
        items = [item for item in items if str(item.get("status") or "").upper() == status.upper()]
    return {"items": items, "total": len(items), "limit": limit}


@router.post("/findings/{finding_id}/suppress")
async def create_finding_suppression(
    finding_id: str, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    store = get_store()
    finding = store.get_record("finding", finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail={"message": "finding not found"})
    reason = str(body.get("reason") or "").strip()
    if len(reason) < 4:
        raise HTTPException(status_code=422, detail={"message": "suppression reason must contain at least four characters"})
    scope = str(body.get("scope") or "fingerprint").strip().lower().replace("-", "_")
    if scope not in {"fingerprint", "rule_path"}:
        raise HTTPException(status_code=422, detail={"message": "scope must be fingerprint or rule_path"})
    expires_at = str(body.get("expires_at") or "").strip()
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                raise ValueError
            expires_at = expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"message": "expires_at must be a future ISO-8601 timestamp"}) from exc
    fingerprint = str(finding.get("fingerprint") or "")
    rule_id = str(finding.get("rule_id") or finding.get("rule") or "")
    path_glob = str(body.get("path_glob") or finding.get("component") or "").replace("\\", "/") if scope == "rule_path" else ""
    if scope == "fingerprint" and not fingerprint:
        raise HTTPException(status_code=409, detail={"message": "finding has no stable fingerprint"})
    if scope == "rule_path" and (not rule_id or not path_glob):
        raise HTTPException(status_code=422, detail={"message": "rule_path suppression requires rule_id and path_glob"})
    target = fingerprint if scope == "fingerprint" else f"{rule_id}:{path_glob.lower()}"
    suppression = store.upsert_record(
        "finding_suppression",
        {
            "id": "sup_" + _stable_id(f"{scope}:{target}"),
            "scope": scope,
            "fingerprint": fingerprint if scope == "fingerprint" else "",
            "rule_id": rule_id if scope == "rule_path" else "",
            "path_glob": path_glob,
            "reason": reason,
            "actor": str(body.get("actor") or "local-user"),
            "expires_at": expires_at or None,
            "status": "ACTIVE",
            "finding_id": finding_id,
            "created_at": utc_now(),
            "mutates_installed_agents": False,
        },
        status="ACTIVE",
    )
    finding.update(
        {
            "status": "已抑制",
            "suppressed": True,
            "suppression_id": suppression["id"],
            "suppression_reason": reason,
            "suppression_expires_at": expires_at or None,
        }
    )
    finding = store.upsert_record("finding", finding, status="已抑制")
    store.audit_event(
        "finding.suppression.created",
        "finding",
        finding_id,
        {"suppression_id": suppression["id"], "scope": scope, "reason": reason, "expires_at": expires_at},
    )
    return {"suppression": suppression, "finding": finding, "mutates_installed_agents": False}


@router.post("/finding-suppressions/{suppression_id}/revoke")
async def revoke_finding_suppression(
    suppression_id: str, body: dict[str, Any] = Body(default_factory=dict)
) -> dict[str, Any]:
    store = get_store()
    suppression = store.get_record("finding_suppression", suppression_id)
    if not suppression:
        raise HTTPException(status_code=404, detail={"message": "finding suppression not found"})
    reason = str(body.get("reason") or "manual revoke").strip()
    suppression.update({"status": "REVOKED", "revoked_at": utc_now(), "revoke_reason": reason})
    suppression = store.upsert_record("finding_suppression", suppression, status="REVOKED")
    finding_id = str(suppression.get("finding_id") or "")
    finding = store.get_record("finding", finding_id) if finding_id else None
    if finding and finding.get("suppression_id") == suppression_id:
        finding.update(
            {
                "status": "待复核",
                "suppressed": False,
                "suppression_id": None,
                "suppression_reason": None,
                "suppression_expires_at": None,
            }
        )
        finding = store.upsert_record("finding", finding, status="待复核")
    store.audit_event(
        "finding.suppression.revoked",
        "finding",
        finding_id or suppression_id,
        {"suppression_id": suppression_id, "reason": reason},
    )
    return {"suppression": suppression, "finding": finding, "mutates_installed_agents": False}
