"""Agent Security v4.2 — 探针与可观测性 API 路由.

挂载方式: 由 api/v1.py 通过 router.include_router(probe_router) 引入.

注意: 路由注册顺序很重要! 具体路由 (如 /probes/events) 必须排在参数化路由 (如 /probes/{probe_id}) 之前。
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query

from ..observability.storage import (
    get_probe_event,
    insert_events_batch,
    list_probe_events,
    migrate_observability,
    probe_adapter_health,
    probe_event_stats,
)
from ..observability.redaction import redact_payload, stable_hash
from ..observability.chain_builder import build_chains, get_chain_detail
from ..store import get_store, new_id, utc_now

router = APIRouter(tags=["observability"])


# ── Probe Event Ingestion ─────────────────────────────────────
# 注意: /probes/events 必须在 /probes/{probe_id} 之前注册

@router.post("/probes/events")
async def post_probe_events(body: dict[str, Any] = Body(...)) -> dict:
    """批量上报规范化探针事件."""
    events = body.get("events", [])
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="'events' must be an array")
    for event in events:
        payload = event.get("payload", {})
        if isinstance(payload, dict) and len(payload) > 0:
            event["payload"] = redact_payload(payload)
        text = str(event.get("tool_name", "")) + str(event.get("session_id", ""))
        if not event.get("input_hash") and isinstance(payload, dict):
            event["input_hash"] = stable_hash(str(payload.get("command") or payload.get("input") or ""))
        event.setdefault("redaction_status", "redacted")
    store = get_store()
    result = insert_events_batch(store, events)
    store.audit_event(
        "post.probes.events", "probe_event",
        f"batch_{result['accepted']}",
        {"accepted": result["accepted"], "rejected": result["rejected"]},
    )
    return result


@router.get("/probes/events")
async def list_events(
    source_agent: str | None = Query(None),
    session_id: str | None = Query(None),
    event_type: str | None = Query(None),
    trace_id: str | None = Query(None),
    risk_min: int | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """查询探针事件."""
    store = get_store()
    items = list_probe_events(
        store, source_agent=source_agent, session_id=session_id,
        event_type=event_type, trace_id=trace_id, risk_min=risk_min,
        limit=limit, offset=offset,
    )
    stats = probe_event_stats(store)
    return {"items": items, "total": stats["total_events"], "stats": stats}


@router.get("/probes/events/{event_id}")
async def get_event(event_id: str) -> dict:
    """获取单条探针事件."""
    store = get_store()
    event = get_probe_event(store, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/probes")
async def list_probes() -> list[dict]:
    """列出所有探针适配器."""
    return probe_adapter_health(get_store())


@router.post("/probes")
async def create_probe(body: dict[str, Any] = Body(...)) -> dict:
    """注册/创建一个探针适配器."""
    store = get_store()
    record = store.upsert_record("probe_adapter", {
        "id": body.get("id") or body.get("adapter_id") or new_id("prb"),
        "agent_type": body.get("agent_type", "unknown"),
        "adapter_version": body.get("adapter_version", "0.1.0"),
        "install_status": body.get("install_status", "not_installed"),
        "mode": body.get("mode", "hook"),
        "endpoint": body.get("endpoint"),
        "enabled": int(body.get("enabled", False)),
        "fail_open": int(body.get("fail_open", True)),
        "raw_capture_enabled": int(body.get("raw_capture_enabled", False)),
        "last_heartbeat_at": utc_now(),
    })
    store.audit_event("post.probe", "probe_adapter", record["id"], {"agent_type": body.get("agent_type")})
    return record


@router.get("/probes/{probe_id}")
async def get_probe(probe_id: str) -> dict:
    """获取探针适配器详情."""
    store = get_store()
    probe = store.get_record("probe_adapter", probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="Probe not found")
    return probe


# ── Probe Sessions ────────────────────────────────────────────

@router.get("/probe-sessions")
async def list_probe_sessions(limit: int = Query(50, ge=1, le=200)) -> dict:
    """列出所有探针会话 (按 session_id 分组)."""
    store = get_store()
    with store.connect() as conn:
        rows = conn.execute("""
            SELECT session_id, source_agent, COUNT(*) AS event_count,
                   MIN(timestamp) AS first_event, MAX(timestamp) AS last_event,
                   MAX(risk_score) AS max_risk
            FROM probe_event
            WHERE session_id IS NOT NULL
            GROUP BY session_id
            ORDER BY last_event DESC
            LIMIT ?
        """, (limit,)).fetchall()
    sessions = []
    for r in rows:
        sessions.append({
            "session_id": r["session_id"],
            "source_agent": r["source_agent"],
            "event_count": r["event_count"],
            "first_event_at": r["first_event"],
            "last_event_at": r["last_event"],
            "max_risk_score": r["max_risk"],
        })
    return {"items": sessions, "total": len(sessions)}


# ── Behavior Chains ───────────────────────────────────────────

@router.get("/behavior/chains")
async def list_chains(
    agent: str | None = Query(None),
    risk_min: int | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """列出行为链."""
    store = get_store()
    chains = store.list_records("behavior_chain", limit=limit)
    if agent:
        chains = [c for c in chains if c.get("source_agent") == agent]
    if risk_min is not None:
        chains = [c for c in chains if c.get("risk_score", 0) >= risk_min]
    return {"items": chains, "total": len(chains)}


@router.post("/behavior/chains")
async def post_build_chains(body: dict[str, Any] = Body(default_factory=dict)) -> dict:
    """触发行为链重建, 支持 dry-run 和幂等 upsert."""
    action = str(body.get("action") or "build")
    if action != "build":
        raise HTTPException(status_code=400, detail="Unsupported action; expected 'build'")
    store = get_store()
    result = build_chains(
        store,
        since=body.get("since"),
        source_agent=body.get("source_agent"),
        limit=int(body.get("limit") or 5000),
        dry_run=bool(body.get("dry_run", False)),
    )
    store.audit_event(
        "post.behavior.chains.build",
        "behavior_chain",
        f"build_{result.get('created', 0)}_{result.get('updated', 0)}",
        {k: result.get(k) for k in ("status", "created", "updated", "skipped", "errors", "mutates_installed_agents")},
    )
    return result


@router.get("/behavior/chains/{chain_id}")
async def get_chain(chain_id: str) -> dict:
    """获取行为链详情 (含完整 from/to 事件、边和异常)."""
    detail = get_chain_detail(get_store(), chain_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Chain not found")
    return detail


# ── Anomalies ─────────────────────────────────────────────────

@router.get("/behavior/anomalies")
async def list_anomalies(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> dict:
    """列出行为异常."""
    store = get_store()
    anomalies = store.list_records("behavior_anomaly", status=status, limit=limit)
    if severity:
        anomalies = [a for a in anomalies if a.get("severity") == severity]
    return {"items": anomalies, "total": len(anomalies)}


@router.get("/behavior/rules")
async def list_anomaly_rules() -> dict:
    """列出 P0 异常规则描述."""
    rules = [
        {"rule_id": "ANOM-SECRET-IN-PROMPT", "severity": "high", "title": "敏感信息泄露",
         "description": "用户输入或工具参数中疑似 secret"},
        {"rule_id": "ANOM-DANGEROUS-SHELL", "severity": "high", "title": "危险 Shell 命令",
         "description": "shell 工具调用包含 rm -rf、del /s、curl|sh 等危险模式"},
        {"rule_id": "ANOM-SENSITIVE-READ-THEN-NETWORK", "severity": "high", "title": "敏感读取后网络发送",
         "description": "读取 ssh key/token/env 后短时间内调用网络发送工具"},
        {"rule_id": "ANOM-MCP-REPEATED-FAILURE", "severity": "medium", "title": "MCP 重复失败",
         "description": "同一 MCP server/tool 连续失败超过阈值"},
        {"rule_id": "ANOM-TOOL-LOOP", "severity": "medium", "title": "工具调用循环",
         "description": "同一 turn 内同一工具重复调用超过阈值"},
        {"rule_id": "ANOM-CROSS-WORKSPACE-PATH", "severity": "medium", "title": "越权路径访问",
         "description": "读取或写入当前 agent workspace 外高敏路径"},
        {"rule_id": "ANOM-APPROVAL-MISMATCH", "severity": "high", "title": "审批状态不匹配",
         "description": "PermissionRequest 显示未批准/被拒绝, 但后续出现同 tool_call completed"},
        {"rule_id": "ANOM-RAW-CAPTURE-ENABLED", "severity": "low", "title": "Raw Capture 已启用",
         "description": "探针被配置为保存 raw prompt/result"},
    ]
    return {"items": rules, "total": len(rules)}


# ── Observability Health ──────────────────────────────────────

@router.get("/observability/health")
async def observability_health() -> dict:
    """可观测性模块健康检查."""
    store = get_store()
    migrate_observability(store)
    stats = probe_event_stats(store)
    adapters = probe_adapter_health(store)
    with store.connect() as conn:
        span_count = conn.execute("SELECT COUNT(*) AS c FROM otel_span").fetchone()["c"]
        log_count = conn.execute("SELECT COUNT(*) AS c FROM otel_log").fetchone()["c"]
        metric_count = conn.execute("SELECT COUNT(*) AS c FROM otel_metric_point").fetchone()["c"]
    return {
        "receiver": {
            "status": "ok", "listen": "127.0.0.1:4318",
            "protocols": ["otlp_http_json", "normalized_json"],
            "receiver_state": "embedded-api-ok",
            "last_error": None,
        },
        "database": {
            "status": "ok",
            "total_probe_events": stats["total_events"],
            "last_event_at": stats["last_event_at"],
            "otel_spans": span_count,
            "otel_logs": log_count,
            "otel_metric_points": metric_count,
        },
        "probes": adapters,
    }


@router.get("/otel/spans")
async def list_otel_spans(trace_id: str | None = Query(None), limit: int = Query(50, ge=1, le=500)) -> dict:
    """查询 OTel spans."""
    store = get_store()
    clauses = ["1=1"]
    params: list[Any] = []
    if trace_id:
        clauses.append("trace_id=?")
        params.append(trace_id)
    params.append(limit)
    with store.connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM otel_span WHERE {' AND '.join(clauses)} ORDER BY COALESCE(start_time, created_at) DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@router.get("/otel/logs")
async def list_otel_logs(trace_id: str | None = Query(None), limit: int = Query(50, ge=1, le=500)) -> dict:
    """查询 OTel logs."""
    store = get_store()
    clauses = ["1=1"]
    params: list[Any] = []
    if trace_id:
        clauses.append("trace_id=?")
        params.append(trace_id)
    params.append(limit)
    with store.connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM otel_log WHERE {' AND '.join(clauses)} ORDER BY timestamp DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@router.get("/otel/metrics")
async def list_otel_metrics(metric_name: str | None = Query(None), limit: int = Query(50, ge=1, le=500)) -> dict:
    """查询 OTel metric points."""
    store = get_store()
    clauses = ["1=1"]
    params: list[Any] = []
    if metric_name:
        clauses.append("metric_name=?")
        params.append(metric_name)
    params.append(limit)
    with store.connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM otel_metric_point WHERE {' AND '.join(clauses)} ORDER BY timestamp DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


# ── Install Plan ──────────────────────────────────────────────

@router.post("/probes/install-plan")
async def create_install_plan(body: dict[str, Any] = Body(...)) -> dict:
    """创建探针 dry-run 安装计划: 后端真实探测配置, 不写文件不修改 Agent."""
    store = get_store()
    agent_type = str(body.get("agent_type", "unknown")).lower()
    dry_run = bool(body.get("dry_run", True))
    if not dry_run:
        raise HTTPException(status_code=400, detail="v4.2.5 only supports dry_run=true install plans")
    if agent_type == "codex":
        from ..probes.codex.codex_probe_hook import generate_install_plan
        generated = generate_install_plan(dry_run=True)
    elif agent_type == "hermes":
        from ..probes.hermes.hermes_probe_plugin import generate_install_plan
        generated = generate_install_plan(dry_run=True)
    else:
        generated = {
            "agent_type": agent_type,
            "install_status": "unsupported",
            "note": "仅支持 codex/hermes dry-run 安装计划",
            "steps": [],
            "rollback": [],
        }
    record = {
        "id": new_id("pln"),
        **generated,
        "agent_type": agent_type,
        "plan_status": "dry_run",
        "dry_run": True,
        "steps_json": __import__("json").dumps(generated.get("steps", []), ensure_ascii=False),
        "rollback_json": __import__("json").dumps(generated.get("rollback", []), ensure_ascii=False),
        "mutates_installed_agents": False,
        "agent_runtime_started": False,
        "stdio_mcp_started": False,
        "requires_confirmation": True,
        "collector_url": body.get("collector_url") or "http://127.0.0.1:8000/api/v1/probes/events",
        "created_at": utc_now(),
    }
    plan = store.upsert_record("probe_install_plan", record, status="dry_run")
    store.audit_event("post.probes.install_plan", "probe_install_plan", plan["id"],
                       {"agent_type": agent_type, "dry_run": True, "mutates_installed_agents": False})
    return plan


@router.get("/probes/install-plan/{plan_id}")
async def get_install_plan(plan_id: str) -> dict:
    """获取安装计划详情."""
    store = get_store()
    plan = store.get_record("probe_install_plan", plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Install plan not found")
    return plan
