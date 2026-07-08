"""Agent Security v4.2 — 行为链重建.

重建优先级:
  1. trace_id + span_id + parent_span_id
  2. session_id + run_id + turn_id
  3. tool_call_id
  4. 时间窗口 + agent + workspace hash
"""
