#!/usr/bin/env bash
# Agent Security Assessment v4.2 — 停止所有服务
set -euo pipefail

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  停止 Agent Security 服务..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 从 PID 文件读取
MAIN_PID=""
OTEL_PID=""

if [ -f /tmp/agent_scan_main.pid ]; then
    MAIN_PID=$(cat /tmp/agent_scan_main.pid 2>/dev/null || true)
fi

if [ -f /tmp/agent_scan_otel.pid ]; then
    OTEL_PID=$(cat /tmp/agent_scan_otel.pid 2>/dev/null || true)
fi

# 也尝试 pkill
PIDS=""

if [ -n "$MAIN_PID" ]; then
    echo "  主平台 PID: $MAIN_PID"
    kill -9 "$MAIN_PID" 2>/dev/null && echo "  ✓ 已终止" || echo "  - 已不存在"
    PIDS="$MAIN_PID"
fi

if [ -n "$OTEL_PID" ]; then
    echo "  OTel PID: $OTEL_PID"
    kill -9 "$OTEL_PID" 2>/dev/null && echo "  ✓ 已终止" || echo "  - 已不存在"
    PIDS="$PIDS $OTEL_PID"
fi

# 补充清理所有 uvicorn assessment 进程
UVICORN_PIDS=$(ps aux 2>/dev/null | grep -E "uvicorn assessment" | grep -v grep | awk '{print $2}' || true)
if [ -n "$UVICORN_PIDS" ]; then
    echo ""
    echo "  发现残留 uvicorn 进程: $UVICORN_PIDS"
    for pid in $UVICORN_PIDS; do
        kill -9 "$pid" 2>/dev/null && echo "  ✓ 已终止 PID $pid" || true
    done
fi

rm -f /tmp/agent_scan_main.pid /tmp/agent_scan_otel.pid 2>/dev/null || true

echo ""
echo "  所有服务已停止"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
