-- Structured OTLP and behavior-edge storage.
CREATE TABLE IF NOT EXISTS probe_event (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    trace_id TEXT,
    span_id TEXT,
    parent_span_id TEXT,
    source_agent TEXT NOT NULL,
    adapter_id TEXT,
    session_id TEXT,
    run_id TEXT,
    turn_id TEXT,
    tool_call_id TEXT,
    tool_name TEXT,
    tool_type TEXT,
    mcp_server TEXT,
    mcp_tool TEXT,
    mcp_transport TEXT,
    phase TEXT,
    status TEXT,
    duration_ms INTEGER,
    input_size INTEGER,
    output_size INTEGER,
    input_hash TEXT,
    output_hash TEXT,
    redaction_status TEXT NOT NULL DEFAULT 'not_required',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_labels_json TEXT NOT NULL DEFAULT '[]',
    error_type TEXT,
    error_message_redacted TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    hash_chain_prev TEXT,
    hash_chain TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otel_span (
    span_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    parent_span_id TEXT,
    name TEXT NOT NULL,
    kind TEXT,
    start_time TEXT,
    end_time TEXT,
    duration_ms INTEGER,
    status_code TEXT,
    status_message TEXT,
    resource_json TEXT NOT NULL DEFAULT '{}',
    scope_json TEXT NOT NULL DEFAULT '{}',
    attrs_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otel_log (
    id TEXT PRIMARY KEY,
    trace_id TEXT,
    span_id TEXT,
    timestamp TEXT NOT NULL,
    severity_text TEXT,
    body_redacted TEXT,
    resource_json TEXT NOT NULL DEFAULT '{}',
    attrs_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otel_metric_point (
    id TEXT PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    value REAL,
    unit TEXT,
    resource_json TEXT NOT NULL DEFAULT '{}',
    attrs_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS behavior_edge (
    id TEXT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    from_event_id TEXT NOT NULL,
    to_event_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    latency_ms INTEGER,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probe_event_time ON probe_event(timestamp);
CREATE INDEX IF NOT EXISTS idx_probe_event_trace ON probe_event(trace_id);
CREATE INDEX IF NOT EXISTS idx_probe_event_session ON probe_event(session_id);
CREATE INDEX IF NOT EXISTS idx_probe_event_tool ON probe_event(tool_name);
CREATE INDEX IF NOT EXISTS idx_probe_event_risk ON probe_event(risk_score);
CREATE INDEX IF NOT EXISTS idx_otel_span_trace ON otel_span(trace_id);
CREATE INDEX IF NOT EXISTS idx_otel_span_created ON otel_span(created_at);
CREATE INDEX IF NOT EXISTS idx_otel_log_trace ON otel_log(trace_id);
CREATE INDEX IF NOT EXISTS idx_otel_log_created ON otel_log(created_at);
CREATE INDEX IF NOT EXISTS idx_otel_metric_created ON otel_metric_point(created_at);
CREATE INDEX IF NOT EXISTS idx_behavior_edge_chain ON behavior_edge(chain_id);
