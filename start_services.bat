@echo off
chcp 65001 >nul
title Agent Security Assessment v4.2 — 服务启动

setlocal enabledelayedexpansion

set PROJECT_DIR=%~dp0
set PYTHONPATH=%PROJECT_DIR%src

echo ╔══════════════════════════════════════════════════════════╗
echo ║    Agent Security Assessment v4.2 — 一键启动服务        ║
echo ╚══════════════════════════════════════════════════════════╝
echo.

:: ── 检测端口占用 ──────────────────────────────────────────────
:check_ports
echo [1/5] 检测端口占用情况...

set PORT_MAIN=8000
set PORT_OTEL=4318
set PORT_CONFLICT=0

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT_MAIN% " ^| findstr "LISTEN"') do (
    echo   ⚠ 端口 %PORT_MAIN% 被 PID %%a 占用
    choice /c YN /m "  是否尝试终止该进程？"
    if !errorlevel! equ 1 (
        taskkill /F /PID %%a >nul 2>&1
        echo   → 已终止 PID %%a
        timeout /t 1 /nobreak >nul
    ) else (
        echo   → 跳过终止，如启动失败请手动释放端口
        set PORT_CONFLICT=1
    )
)

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT_OTEL% " ^| findstr "LISTEN"') do (
    echo   ⚠ 端口 %PORT_OTEL% 被 PID %%a 占用
    choice /c YN /m "  是否尝试终止该进程？"
    if !errorlevel! equ 1 (
        taskkill /F /PID %%a >nul 2>&1
        echo   → 已终止 PID %%a
        timeout /t 1 /nobreak >nul
    ) else (
        set PORT_CONFLICT=1
    )
)

echo.
echo [2/5] 设置环境变量...
cd /d "%PROJECT_DIR%"
set PYTHONPATH=%PROJECT_DIR%src
echo   PYTHONPATH=%PYTHONPATH%
echo.

:: ── 启动 OTel Receiver ────────────────────────────────────────
echo [3/5] 启动 OTel Receiver (127.0.0.1:%PORT_OTEL%)...
start "OTel Receiver" cmd /c "title OTel Receiver & cd /d %PROJECT_DIR% & set PYTHONPATH=%PYTHONPATH% & python -m uvicorn assessment.observability.receiver:create_receiver_app --host 127.0.0.1 --port %PORT_OTEL% --log-level warning"
if %errorlevel% neq 0 (
    echo   ✗ OTel Receiver 启动失败
) else (
    echo   ✓ OTel Receiver 正在启动...
)
echo.

:: ── 启动主平台 ────────────────────────────────────────────────
echo [4/5] 启动主平台 (127.0.0.1:%PORT_MAIN%)...
start "Agent Security Platform" cmd /c "title Agent Security Platform & cd /d %PROJECT_DIR% & set PYTHONPATH=%PYTHONPATH% & python -m uvicorn assessment.main:app --host 127.0.0.1 --port %PORT_MAIN% --log-level warning"
if %errorlevel% neq 0 (
    echo   ✗ 主平台启动失败
) else (
    echo   ✓ 主平台正在启动...
)
echo.

:: ── 等待启动完成 ──────────────────────────────────────────────
echo [5/5] 等待服务就绪...
timeout /t 3 /nobreak >nul

:: 验证主平台
for /l %%i in (1,1,5) do (
    >nul 2>&1 curl -s http://127.0.0.1:%PORT_MAIN%/api/v1/observability/health && (
        echo   ✓ 主平台  http://127.0.0.1:%PORT_MAIN%/
        goto :main_ok
    )
    timeout /t 1 /nobreak >nul
)
echo   ⚠ 主平台尚未响应，请稍后手动检查
:main_ok

:: 验证 OTel Receiver
for /l %%i in (1,1,5) do (
    >nul 2>&1 curl -s http://127.0.0.1:%PORT_OTEL%/healthz && (
        echo   ✓ OTel Receiver  http://127.0.0.1:%PORT_OTEL%/healthz
        goto :otel_ok
    )
    timeout /t 1 /nobreak >nul
)
echo   ⚠ OTel Receiver 尚未响应，请稍后手动检查
:otel_ok

echo.
echo ╔══════════════════════════════════════════════════════════╗
echo ║                   启动完成                              ║
echo ╠══════════════════════════════════════════════════════════╣
echo ║                                                         ║
echo ║  主平台:     http://127.0.0.1:%PORT_MAIN%/              ║
echo ║  健康检查:   http://127.0.0.1:%PORT_MAIN%/api/v1/health ║
echo ║  可观测性:   http://127.0.0.1:%PORT_MAIN%/api/v1/      ║
echo ║              observability/health                       ║
echo ║  OTel:       http://127.0.0.1:%PORT_OTEL%/healthz      ║
echo ║                                                         ║
echo ║  上报事件例: PowerShell 运行 send_test_event.ps1        ║
echo ║                                                         ║
echo ║  停止服务:   关闭对应的命令行窗口即可                   ║
echo ║                                                         ║
echo ╚══════════════════════════════════════════════════════════╝
echo.
pause
