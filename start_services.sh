#!/usr/bin/env bash
# Agent Security Assessment v4.2 — 一键启动服务
# 用法: 在 MSYS/bash (Hermes Terminal / git-bash) 中运行:
#   bash start_services.sh
# 或直接:
#   ./start_services.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT_MAIN=8000
PORT_OTEL=4318

# 导出 PYTHONPATH — 用相对路径 src 避免 MSYS 路径转换问题
export PYTHONPATH="src"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Agent Security Assessment v4.2"
echo "  探针与 OTel 旁路监控分析 — 一键启动"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 切到项目目录 ─────────────────────────────────────────────
cd "$PROJECT_DIR"
echo "项目目录: $PROJECT_DIR"
echo "PYTHONPATH: $PYTHONPATH"
echo ""

# ── 检测端口 ────────────────────────────────────────────────
echo "[1/3] 检测端口占用..."

kill_port() {
    local port="$1"
    local pids
    pids=$(netstat -ano 2>/dev/null | grep ":$port " | grep LISTENING | awk '{print $5}' | sort -u || true)
    if [ -n "$pids" ]; then
        echo "  ! 端口 $port 被占用, PID: $pids"
        for pid in $pids; do
            if [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
                echo "  - 已终止 PID $pid"
            fi
        done
        sleep 1
    else
        echo "  - 端口 $port 空闲"
    fi
}

kill_port "$PORT_MAIN"
kill_port "$PORT_OTEL"
echo ""

# ── 清理旧的 PID 文件 ───────────────────────────────────────
rm -f /tmp/agent_scan_main.pid /tmp/agent_scan_otel.pid 2>/dev/null || true

# ── 启动 OTel Receiver ─────────────────────────────────────
echo "[2/3] 启动 OTel Receiver (127.0.0.1:$PORT_OTEL)..."
python -m uvicorn \
    assessment.observability.receiver:create_receiver_app \
    --host 127.0.0.1 --port "$PORT_OTEL" --log-level warning &
OTEL_PID=$!
echo "$OTEL_PID" > /tmp/agent_scan_otel.pid 2>/dev/null || true
echo "  - PID: $OTEL_PID"
echo ""

# 等待一小段时间检测启动是否成功
sleep 2
if kill -0 "$OTEL_PID" 2>/dev/null; then
    echo "  - OTel Receiver 进程存活 ✓"
else
    echo "  - OTel Receiver 启动失败 ✗"
fi
echo ""

# ── 启动主平台 ──────────────────────────────────────────────
echo "[3/3] 启动主平台 (127.0.0.1:$PORT_MAIN)..."
python -m uvicorn \
    assessment.main:app \
    --host 127.0.0.1 --port "$PORT_MAIN" --log-level warning &
MAIN_PID=$!
echo "$MAIN_PID" > /tmp/agent_scan_main.pid 2>/dev/null || true
echo "  - PID: $MAIN_PID"
echo ""

sleep 2
if kill -0 "$MAIN_PID" 2>/dev/null; then
    echo "  - 主平台进程存活 ✓"
else
    echo "  - 主平台启动失败 ✗"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  启动完成"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  主平台:     http://127.0.0.1:$PORT_MAIN/"
echo "  健康检查:   http://127.0.0.1:$PORT_MAIN/api/v1/health"
echo "  可观测性:   http://127.0.0.1:$PORT_MAIN/api/v1/"
echo "              observability/health"
echo "  OTel:       http://127.0.0.1:$PORT_OTEL/healthz"
echo ""
echo "  测试上报:   powershell -ExecutionPolicy Bypass -File send_test_event.ps1"
echo ""
echo "  停止服务:"
echo "    方案一: kill $MAIN_PID $OTEL_PID"
echo "    方案二: pkill -f 'uvicorn assessment'"
echo "    方案三: bash stop_services.sh"
echo ""

# 等待任意子进程退出，防止脚本退出后关闭子进程
wait
