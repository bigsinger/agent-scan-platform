from __future__ import annotations

import json
from typing import Any

from ..store import AssessmentStore, new_id, utc_now
from .discovery import DiscoveryEngine


WATCHED_HIT_TYPES = {"Config", "MCP", "Skill"}


class PassiveGuard:
    """Read-only guard that watches discovered Agent config hashes.

    The guard never edits installed Agent files. It only re-runs local discovery,
    compares file hashes with the last baseline stored in this module's SQLite
    database, and records recommendations for the user to review.
    """

    def __init__(self, store: AssessmentStore) -> None:
        self.store = store
        self.discovery = DiscoveryEngine()

    def status(self) -> dict[str, Any]:
        snapshots = self.store.list_records("config_snapshot", limit=5000)
        guard_events = self.store.list_records("guard_event", limit=100)
        recommendations = self.store.list_records("defense_recommendation", limit=200)
        pending = [item for item in recommendations if str(item.get("status", "")).upper() in {"OPEN", "ACTIVE", "PENDING"}]
        high = [item for item in pending if item.get("severity") in {"高危 P1", "严重 P0"}]
        last_event = guard_events[0] if guard_events else None
        return {
            "mode": "read_only",
            "state": "ACTIVE" if snapshots else "NO_BASELINE",
            "watched_files": len(snapshots),
            "open_recommendations": len(pending),
            "high_risk_recommendations": len(high),
            "last_check_at": last_event.get("created_at") if last_event else "",
            "last_check_id": last_event.get("id") if last_event else "",
            "last_download": last_event.get("download") if last_event else "",
            "last_artifact_id": last_event.get("artifact_id") if last_event else "",
            "policy": {
                "mutates_installed_agents": False,
                "starts_stdio_mcp": False,
                "stores_raw_secret": False,
                "action": "discover + hash compare + local sqlite write",
            },
            "recommendations": pending[:10],
        }

    def check(self) -> dict[str, Any]:
        discovery = self.discovery.discover(None, scope="current-user")
        changes: list[dict[str, Any]] = []
        new_baselines = 0
        watched_hits = [hit for hit in discovery.hits if hit.get("type") in WATCHED_HIT_TYPES]
        seen_snapshot_ids: set[str] = set()

        for hit in watched_hits:
            snapshot_id = "cfg_" + str(hit.get("path_hash") or hit.get("id"))
            seen_snapshot_ids.add(snapshot_id)
            previous = self.store.get_record("config_snapshot", snapshot_id)
            snapshot = {
                "id": snapshot_id,
                "hit_id": hit.get("id"),
                "agent": hit.get("agent"),
                "type": hit.get("type"),
                "path": hit.get("path"),
                "path_hash": hit.get("path_hash"),
                "sha256": hit.get("sha256"),
                "source": hit.get("source"),
                "scope": hit.get("scope"),
                "last_seen_at": utc_now(),
            }
            if previous and previous.get("sha256") and previous.get("sha256") != hit.get("sha256"):
                change = self._record_change(previous, snapshot)
                changes.append(change)
            elif not previous:
                new_baselines += 1
            self.store.upsert_record("config_snapshot", snapshot, status="ACTIVE")

        deleted = []
        for previous in self.store.list_records("config_snapshot", limit=5000):
            if previous.get("id") not in seen_snapshot_ids and previous.get("status") == "ACTIVE":
                deleted.append(previous)
                previous["missing_since"] = utc_now()
                self.store.upsert_record("config_snapshot", previous, status="MISSING")

        recommendations = self._recommendations(discovery, changes, deleted)
        event = {
            "id": new_id("grd"),
            "status": "COMPLETED",
            "created_at": utc_now(),
            "hit_count": len(discovery.hits),
            "agent_count": len(discovery.agents),
            "watched_files": len(watched_hits),
            "new_baselines": new_baselines,
            "changed": len(changes),
            "missing": len(deleted),
            "recommendations": len(recommendations),
            "safe_mode": "local-readonly",
            "mutates_installed_agents": False,
            "starts_stdio_mcp": False,
            "evidence_schema": "agent-security-passive-guard-check@4.1",
        }
        artifact_payload = {
            "schema": event["evidence_schema"],
            "event": event,
            "changes": changes,
            "missing": deleted[:100],
            "recommendations": recommendations,
            "discovery": {
                "agents": discovery.agents,
                "mcp_servers": discovery.mcp_servers,
                "skills": discovery.skills[:200],
                "errors": discovery.errors,
            },
            "boundary": {
                "safe_mode": event["safe_mode"],
                "mutates_installed_agents": False,
                "starts_stdio_mcp": False,
                "network_probe": "disabled",
                "side_effects": "local sqlite artifact and audit only",
            },
        }
        artifact = self.store.write_artifact(
            "passive-guard-check",
            json.dumps(artifact_payload, ensure_ascii=False, indent=2),
            suffix="json",
            metadata={"guard_event_id": event["id"], "safe_mode": event["safe_mode"]},
        )
        event["artifact_id"] = artifact["id"]
        event["artifact_path"] = artifact.get("relative_path", "")
        event["download"] = f"/api/v1/artifacts/{artifact['id']}/download"
        self.store.upsert_record("guard_event", event, status="COMPLETED")
        self.store.audit_event("guard.check", "guard_event", event["id"], event)
        return {
            "event": event,
            "artifact": artifact,
            "download": event["download"],
            "changes": changes,
            "missing": deleted[:20],
            "recommendations": recommendations,
            "discovery": {
                "agents": discovery.agents,
                "mcp_servers": discovery.mcp_servers,
                "skills": discovery.skills[:50],
                "errors": discovery.errors,
            },
            "guard": self.status(),
        }

    def _record_change(self, previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        severity = "高危 P1" if current.get("type") == "MCP" else "中危 P2"
        change = {
            "id": "chg_" + str(current.get("path_hash")),
            "title": f"{current.get('agent')} {current.get('type')} 配置发生变化",
            "severity": severity,
            "agent": current.get("agent"),
            "type": current.get("type"),
            "path": current.get("path"),
            "previous_sha256": previous.get("sha256"),
            "current_sha256": current.get("sha256"),
            "status": "OPEN",
            "created_at": utc_now(),
            "recommendation": "请复核配置差异；若涉及 stdio MCP、外部命令或 Secret 变更，先保持默认拒绝并重新测评。",
            "safe_mode": "local-readonly",
            "mutates_installed_agents": False,
            "source": "passive-guard",
        }
        self.store.upsert_record("defense_recommendation", change, status="OPEN")
        return change

    def _recommendations(
        self,
        discovery: Any,
        changes: list[dict[str, Any]],
        missing: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        recommendations: list[dict[str, Any]] = list(changes)
        pending_stdio = [server for server in discovery.mcp_servers if server.get("transport") == "stdio"]
        if pending_stdio:
            rec = {
                "id": "rec_stdio_mcp_pending",
                "title": f"{len(pending_stdio)} 个 stdio MCP Server 需要审批",
                "severity": "高危 P1",
                "agent": "MCP",
                "type": "MCP_CONSENT",
                "status": "OPEN",
                "created_at": utc_now(),
                "recommendation": "保持默认拒绝；仅在确认命令、参数、工作目录和环境变量后允许一次或本任务允许。",
                "servers": [server.get("name") for server in pending_stdio[:20]],
                "safe_mode": "local-readonly",
                "mutates_installed_agents": False,
                "starts_stdio_mcp": False,
                "source": "passive-guard",
            }
            self.store.upsert_record("defense_recommendation", rec, status="OPEN")
            recommendations.append(rec)

        if missing:
            rec = {
                "id": "rec_config_missing",
                "title": f"{len(missing)} 个已登记配置本次未再发现",
                "severity": "中危 P2",
                "agent": "Local",
                "type": "CONFIG_MISSING",
                "status": "OPEN",
                "created_at": utc_now(),
                "recommendation": "确认是否为卸载、迁移、权限变化或路径不可读；不要自动清理历史证据。",
                "safe_mode": "local-readonly",
                "mutates_installed_agents": False,
                "source": "passive-guard",
            }
            self.store.upsert_record("defense_recommendation", rec, status="OPEN")
            recommendations.append(rec)

        return recommendations
