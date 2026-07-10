"""Agent Security v4.2.5 — 行为链重建.

重建优先级:
  1. trace_id + span_id + parent_span_id  (OTel span 层级)
  2. session_id + run_id + turn_id        (Agent 会话层级)
  3. 时间窗口 + source_agent              (兜底关联)

v4.2.5 要求:
  - POST API 可触发 build
  - 重复执行幂等: chain_key 去重, edge 去重
  - dry_run 不写库
  - 返回 created/updated/skipped/errors 统计
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..store import AssessmentStore, new_id, utc_now
from .storage import create_behavior_chain, get_probe_event, list_probe_events
from .anomaly_rules import evaluate_event_rules


def build_chains(
    store: AssessmentStore,
    *,
    since: str | None = None,
    source_agent: str | None = None,
    limit: int = 5000,
    dry_run: bool = False,
) -> dict[str, Any]:
    """从 probe_event 重建行为链, 返回批次统计.

    Args:
        store: 数据库存储
        since: 仅处理该 ISO 时间之后事件
        source_agent: 仅处理指定 Agent
        limit: 最多读取事件数
        dry_run: 只返回将要创建/更新的链, 不落库
    """
    events = list_probe_events(store, source_agent=source_agent, limit=max(1, min(limit, 5000)))
    if since:
        events = [e for e in events if str(e.get("timestamp") or "") >= since]
    # list_probe_events 默认倒序, 链构建前统一升序
    events.sort(key=lambda e: str(e.get("timestamp") or ""))

    result: dict[str, Any] = {
        "status": "DRY_RUN" if dry_run else "BUILT",
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "chains": [],
        "errors": [],
        "mutates_installed_agents": False,
    }
    if not events:
        return result

    groups = _group_events(events)
    for chain_key, group_events in groups.items():
        if len(group_events) < 2:
            result["skipped"] += 1
            continue
        try:
            existing = _find_chain_by_key(store, chain_key)
            chain = _build_chain_from_events(
                store,
                group_events,
                chain_key=chain_key,
                existing=existing,
                dry_run=dry_run,
            )
            if chain:
                if dry_run:
                    pass
                elif existing:
                    result["updated"] += 1
                else:
                    result["created"] += 1
                result["chains"].append(chain)
            else:
                result["skipped"] += 1
        except Exception as exc:  # 单链失败不能影响整个批次
            result["errors"].append({"chain_key": chain_key, "error": str(exc)})
    return result


def _group_events(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """按 trace/session/window 分组, 返回 chain_key -> events."""
    groups: dict[str, list[dict[str, Any]]] = {}
    used: set[str] = set()

    for ev in events:
        trace_id = ev.get("trace_id")
        if trace_id:
            groups.setdefault(f"trace:{trace_id}", []).append(ev)
            used.add(ev["event_id"])

    for ev in events:
        if ev["event_id"] in used:
            continue
        session_id = ev.get("session_id")
        if session_id:
            agent = ev.get("source_agent") or "unknown"
            groups.setdefault(f"sid:{agent}:{session_id}", []).append(ev)
            used.add(ev["event_id"])

    orphans = [ev for ev in events if ev["event_id"] not in used]
    if orphans:
        current: list[dict[str, Any]] = []
        for ev in orphans:
            if not current:
                current = [ev]
                continue
            first = current[0]
            t1 = _parse_time(first.get("timestamp", ""))
            t2 = _parse_time(ev.get("timestamp", ""))
            same_agent = ev.get("source_agent") == first.get("source_agent")
            in_window = bool(t1 and t2 and (t2 - t1).total_seconds() <= 15 * 60)
            if same_agent and in_window:
                current.append(ev)
            else:
                _append_window_group(groups, current)
                current = [ev]
        _append_window_group(groups, current)
    return groups


def _append_window_group(groups: dict[str, list[dict[str, Any]]], events: list[dict[str, Any]]) -> None:
    if len(events) < 2:
        return
    first = events[0]
    agent = first.get("source_agent") or "unknown"
    first_ts = str(first.get("timestamp") or "")[:16]
    groups[f"window:{agent}:{first_ts}"] = events


def _find_chain_by_key(store: AssessmentStore, chain_key: str) -> dict[str, Any] | None:
    for chain in store.list_records("behavior_chain", limit=5000):
        if chain.get("chain_key") == chain_key:
            return chain
    return None


def _build_chain_from_events(
    store: AssessmentStore,
    events: list[dict[str, Any]],
    *,
    chain_key: str,
    existing: dict[str, Any] | None,
    dry_run: bool,
) -> dict[str, Any] | None:
    if len(events) < 2:
        return None
    events.sort(key=lambda e: str(e.get("timestamp") or ""))
    first, last = events[0], events[-1]
    source_agent = first.get("source_agent", "unknown")
    session_id = first.get("session_id") or last.get("session_id")
    trace_id = first.get("trace_id") or last.get("trace_id")
    chain_id = str((existing or {}).get("chain_id") or (existing or {}).get("id") or new_id("bch"))
    risk_score = max(int(ev.get("risk_score") or 0) for ev in events)
    tool_names = sorted({str(ev.get("tool_name") or "") for ev in events if ev.get("tool_name")})
    summary = f"{source_agent} · {chain_key}"
    if tool_names:
        summary += " · tools: " + ", ".join(tool_names[:5])

    edge_count = max(0, len(events) - 1)
    chain = {
        "id": chain_id,
        "chain_id": chain_id,
        "chain_key": chain_key,
        "root_trace_id": trace_id,
        "session_id": session_id,
        "source_agent": source_agent,
        "summary": summary,
        "event_count": len(events),
        "edge_count": edge_count,
        "risk_score": risk_score,
        "anomaly_count": 0,
        "status": "open",
        "first_event_at": first.get("timestamp"),
        "last_event_at": last.get("timestamp"),
        "updated_at": utc_now(),
    }
    if dry_run:
        return chain

    saved = create_behavior_chain(store, chain)
    _replace_edges(store, chain_id, events)
    anomalies = evaluate_event_rules(store, events, chain_id=chain_id)
    saved["anomaly_count"] = len(anomalies)
    saved["event_count"] = len(events)
    saved["edge_count"] = edge_count
    store.upsert_record("behavior_chain", saved, status=saved.get("status", "open"))
    return saved


def _replace_edges(store: AssessmentStore, chain_id: str, events: list[dict[str, Any]]) -> None:
    with store.connect() as conn:
        conn.execute("DELETE FROM behavior_edge WHERE chain_id=?", (chain_id,))
        seen: set[tuple[str, str, str]] = set()
        for i in range(len(events) - 1):
            from_ev = events[i]
            to_ev = events[i + 1]
            relation = _derive_relation(from_ev, to_ev)
            edge_key = (from_ev["event_id"], to_ev["event_id"], relation)
            if edge_key in seen:
                continue
            seen.add(edge_key)
            conn.execute(
                """INSERT INTO behavior_edge(id, chain_id, from_event_id, to_event_id, relation, latency_ms, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"edge_{uuid4().hex[:12]}",
                    chain_id,
                    from_ev["event_id"],
                    to_ev["event_id"],
                    relation,
                    _calc_latency(from_ev, to_ev),
                    utc_now(),
                ),
            )
        conn.commit()


def get_chain_detail(store: AssessmentStore, chain_id: str) -> dict[str, Any] | None:
    """返回链、边、完整事件列表和异常."""
    chain = store.get_record("behavior_chain", chain_id)
    if not chain:
        chain = _find_chain_by_key(store, chain_id)
    if not chain:
        return None
    actual_chain_id = str(chain.get("chain_id") or chain.get("id"))
    with store.connect() as conn:
        edge_rows = conn.execute(
            "SELECT * FROM behavior_edge WHERE chain_id=? ORDER BY created_at",
            (actual_chain_id,),
        ).fetchall()
    edges = [dict(row) for row in edge_rows]
    event_ids: list[str] = []
    for edge in edges:
        for key in ("from_event_id", "to_event_id"):
            event_id = edge.get(key)
            if event_id and event_id not in event_ids:
                event_ids.append(event_id)
    events = [ev for ev in (get_probe_event(store, event_id) for event_id in event_ids) if ev]
    events.sort(key=lambda e: str(e.get("timestamp") or ""))
    anomalies = [a for a in store.list_records("behavior_anomaly", limit=5000) if a.get("chain_id") == actual_chain_id]
    return {"chain": chain, "edges": edges, "events": events, "anomalies": anomalies}


def _derive_relation(from_ev: dict[str, Any], to_ev: dict[str, Any]) -> str:
    f_type = from_ev.get("event_type", "")
    t_type = to_ev.get("event_type", "")
    if f_type.endswith(".started") and t_type.endswith(".completed"):
        suffix = f_type.replace(".started", "")
        if t_type.startswith(suffix):
            return f"{suffix} → complete"
    if f_type == "agent.user_input.received" and t_type in ("llm.call.started", "agent.turn.started", "tool.call.started"):
        return "input → action"
    if f_type == "tool.call.started" and t_type == "tool.call.completed":
        return "tool → complete"
    if t_type == "mcp.rpc.started":
        return "→ mcp"
    return f"{f_type} → {t_type}"


def _calc_latency(from_ev: dict[str, Any], to_ev: dict[str, Any]) -> int | None:
    t1 = _parse_time(from_ev.get("timestamp", ""))
    t2 = _parse_time(to_ev.get("timestamp", ""))
    if t1 and t2:
        return int((t2 - t1).total_seconds() * 1000)
    dur = from_ev.get("duration_ms")
    return int(dur) if dur is not None else None


def _parse_time(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
