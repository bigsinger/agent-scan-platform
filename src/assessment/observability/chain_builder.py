"""Agent Security v4.2 — 行为链重建.

重建优先级:
  1. trace_id + span_id + parent_span_id  (OTel span 层级)
  2. session_id + run_id + turn_id        (Agent 会话层级)
  3. tool_call_id                          (工具调用关联)
  4. 时间窗口 + source_agent              (兜底关联)

用法:
  from assessment.observability.chain_builder import build_chains
  chains = build_chains(get_store())
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..store import AssessmentStore, get_store, new_id, utc_now
from .storage import (
    create_behavior_chain,
    create_behavior_anomaly,
    get_probe_event,
    list_probe_events,
    insert_events_batch,
)
from .anomaly_rules import evaluate_event_rules


# ── 链重建入口 ──────────────────────────────────────────────

def build_chains(store: AssessmentStore, *, since: str | None = None) -> list[dict[str, Any]]:
    """从 probe_event 重建行为链.

    Args:
        store: 数据库存储
        since: ISO 时间戳, 只处理该时间之后的事件. 默认全量.

    Returns:
        新建的行为链列表
    """
    events = list_probe_events(store, limit=5000)
    if since:
        events = [e for e in events if e.get("timestamp", "") >= since]

    if not events:
        return []

    # 按 trace_id 分组 (OTel 链路)
    trace_groups: dict[str, list[dict[str, Any]]] = {}
    # 按 session_id 分组 (Agent 会话)
    session_groups: dict[str, list[dict[str, Any]]] = {}

    for ev in events:
        tid = ev.get("trace_id")
        if tid:
            trace_groups.setdefault(tid, []).append(ev)
        sid = ev.get("session_id")
        if sid:
            session_groups.setdefault(sid, []).append(ev)

    created_chains: list[dict[str, Any]] = []

    # 策略 1: trace_id 分组构建
    for trace_id, trace_events in trace_groups.items():
        chain = _build_chain_from_events(store, trace_events, f"trace:{trace_id}")
        if chain:
            created_chains.append(chain)

    # 策略 2: 剩余未归入 trace 的 events 按 session 分组
    traced_event_ids = {e["event_id"] for tg in trace_groups.values() for e in tg}
    for session_id, session_events in session_groups.items():
        untraced = [e for e in session_events if e["event_id"] not in traced_event_ids]
        if len(untraced) < 2:
            continue
        chain = _build_chain_from_events(store, untraced, f"session:{session_id}")
        if chain:
            created_chains.append(chain)

    # 策略 3: 兜底 — 时间窗口 + source_agent
    all_chained_ids = set()
    for _, events in trace_groups.items():
        all_chained_ids.update(e["event_id"] for e in events)
    for _, events in session_groups.items():
        all_chained_ids.update(e["event_id"] for e in events)

    orphans = [e for e in events if e["event_id"] not in all_chained_ids]
    if orphans:
        # 按 agent + 15 分钟窗口分组
        orphans.sort(key=lambda e: e.get("timestamp", ""))
        window_minutes = 15
        current_window: list[dict[str, Any]] = []
        for ev in orphans:
            if not current_window:
                current_window.append(ev)
            else:
                t1 = _parse_time(current_window[0].get("timestamp", ""))
                t2 = _parse_time(ev.get("timestamp", ""))
                if (t2 - t1).total_seconds() <= window_minutes * 60 and ev.get("source_agent") == current_window[0].get("source_agent"):
                    current_window.append(ev)
                else:
                    if len(current_window) >= 2:
                        chain = _build_chain_from_events(store, current_window, f"window:{current_window[0].get('source_agent','?')}")
                        if chain:
                            created_chains.append(chain)
                    current_window = [ev]
        if len(current_window) >= 2:
            chain = _build_chain_from_events(store, current_window, f"window:{current_window[0].get('source_agent','?')}")
            if chain:
                created_chains.append(chain)

    return created_chains


# ── 单链构建 ────────────────────────────────────────────────

def _build_chain_from_events(
    store: AssessmentStore,
    events: list[dict[str, Any]],
    chain_source: str,
) -> dict[str, Any] | None:
    """从一组事件构建一条行为链."""
    if len(events) < 2:
        return None

    events.sort(key=lambda e: e.get("timestamp", ""))

    first = events[0]
    last = events[-1]
    source_agent = first.get("source_agent", "unknown")
    session_id = first.get("session_id") or last.get("session_id")
    trace_id = first.get("trace_id") or last.get("trace_id")

    # 生成摘要
    summary_parts: list[str] = []
    tool_names = set()
    event_types = set()
    for ev in events:
        tn = ev.get("tool_name")
        if tn:
            tool_names.add(tn)
        et = ev.get("event_type")
        if et:
            event_types.add(et)

    if session_id:
        summary_parts.append(f"session {session_id[:12]}...")
    if source_agent:
        summary_parts.append(source_agent)
    if tool_names:
        summary_parts.append(f"tools: {', '.join(sorted(tool_names)[:5])}")
    summary = " · ".join(summary_parts) if summary_parts else f"{len(events)} events"

    # 计算风险
    risk_score = max(ev.get("risk_score", 0) for ev in events)

    # 保存行为链
    chain = create_behavior_chain(store, {
        "chain_id": new_id("bch"),
        "root_trace_id": trace_id,
        "session_id": session_id,
        "source_agent": source_agent,
        "summary": summary,
        "risk_score": risk_score,
        "status": "open",
        "first_event_at": first.get("timestamp"),
        "last_event_at": last.get("timestamp"),
    })

    chain_id = chain.get("chain_id") or chain.get("id")
    chain_id_str = str(chain_id) if chain_id else new_id("bch")

    # 构建边 (events -> edges)
    for i in range(len(events) - 1):
        from_ev = events[i]
        to_ev = events[i + 1]
        relation = _derive_relation(from_ev, to_ev)
        latency_ms = _calc_latency(from_ev, to_ev)
        edge_id = f"edge_{uuid4().hex[:12]}"
        with store.connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO behavior_edge(id, chain_id, from_event_id, to_event_id, relation, latency_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (edge_id, chain_id_str, from_ev["event_id"], to_ev["event_id"], relation, latency_ms, utc_now()),
            )
            conn.commit()

    # 运行异常规则
    evaluate_event_rules(store, events, chain_id=chain_id_str)

    return chain


# ── 辅助函数 ────────────────────────────────────────────────

def _derive_relation(from_ev: dict[str, Any], to_ev: dict[str, Any]) -> str:
    """推断两个连续事件之间的关系."""
    f_type = from_ev.get("event_type", "")
    t_type = to_ev.get("event_type", "")

    if f_type.endswith(".started") and t_type.endswith(".completed"):
        suffix = f_type.replace(".started", "")
        if t_type.startswith(suffix):
            return f"{suffix} → complete"
    if f_type.endswith(".started") and t_type.endswith(".error"):
        suffix = f_type.replace(".started", "")
        if t_type.startswith(suffix):
            return f"{suffix} → error"
    if f_type == "agent.user_input.received" and t_type in ("llm.call.started", "agent.turn.started"):
        return "input → llm"
    if f_type == "agent.turn.started" and t_type == "tool.call.started":
        return "turn → tool"
    if f_type in ("tool.call.started",) and t_type in ("mcp.rpc.started",):
        return "tool → mcp"
    if f_type in ("tool.call.completed", "tool.call.error") and t_type == "tool.call.started":
        return "tool → tool"
    if f_type.endswith(".completed") and t_type == "agent.turn.completed":
        return "→ turn end"
    if f_type == "llm.call.started" and t_type in ("tool.call.started",):
        return "llm → tool"
    if t_type == "mcp.rpc.started":
        return "→ mcp"
    return f"{f_type} → {t_type}"


def _calc_latency(from_ev: dict[str, Any], to_ev: dict[str, Any]) -> int | None:
    """计算两个事件之间的时间差 (ms)."""
    t1 = _parse_time(from_ev.get("timestamp", ""))
    t2 = _parse_time(to_ev.get("timestamp", ""))
    if t1 and t2:
        return int((t2 - t1).total_seconds() * 1000)
    # 使用 duration_ms
    dur = from_ev.get("duration_ms")
    if dur is not None:
        return int(dur)
    return None


def _parse_time(ts: str) -> datetime | None:
    """解析 ISO 时间戳."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
