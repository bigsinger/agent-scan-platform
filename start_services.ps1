<#
.SYNOPSIS
    Agent Security Assessment v4.2 - One-click service startup
.DESCRIPTION
    Starts main platform (port 8000) and OTel Receiver (port 4318)
    in separate windows. Close each window individually to stop.
    Run from PowerShell directly
.NOTES
    Usage: Right-click -> Run with PowerShell
           powershell -ExecutionPolicy Bypass -File start_services.ps1
#>

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "Agent Security Assessment v4.2"

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PortMain = 8000
$PortOtel = 4318

function Write-Step($Text) { Write-Host "`n$Text" -ForegroundColor Yellow }
function Write-OK($Text)   { Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Warn($Text) { Write-Host "  [!] $Text" -ForegroundColor DarkYellow }
function Write-Info($Text) { Write-Host "  $Text" }

Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Agent Security Assessment v4.2" -ForegroundColor Cyan
Write-Host "  Probe and OTel Observability - One-click Start" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

Set-Location $ProjectDir
Write-Info "Project: $ProjectDir"

$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ERROR] Python not found" -ForegroundColor Red
    pause
    exit 1
}
Write-Info "Python: $pythonVersion"

# --- Check and free ports ---
Write-Step "[1/4] Checking ports..."

function Test-Port {
    param($portNumber)
    $connections = netstat -ano | Select-String (':' + $portNumber + '\s') | Select-String 'LISTEN'
    if ($connections) {
        $procIds = $connections | ForEach-Object { $_ -split '\s+' | Select-Object -Last 1 } | Where-Object { $_ -ne '' } | Sort-Object -Unique
        Write-Warn ('Port ' + $portNumber + ' is occupied by PID: ' + ($procIds -join ','))
        foreach ($procId in $procIds) {
            try {
                Stop-Process -Id $procId -Force -ErrorAction Stop
                Write-OK ('Terminated PID ' + $procId)
            } catch {
                Write-Warn ('Failed to terminate PID ' + $procId + ': ' + $_.Exception.Message)
            }
        }
        Start-Sleep -Seconds 1
    } else {
        Write-OK ('Port ' + $portNumber + ' is free')
    }
}

Test-Port $PortMain
Test-Port $PortOtel

# --- Start OTel Receiver in a new window ---
Write-Step "[2/4] Starting OTel Receiver (port $PortOtel)"

$otelCmd = 'cmd /c "title OTel Receiver && set PYTHONPATH=' + $ProjectDir + '\src && python -m uvicorn assessment.observability.receiver:create_receiver_app --host 127.0.0.1 --port ' + $PortOtel + ' --log-level warning"'
Start-Process -WindowStyle Normal -FilePath "cmd.exe" -ArgumentList "/c start `"OTel Receiver`" cmd /c $otelCmd"
Write-OK "OTel Receiver launching..."

Start-Sleep -Seconds 2

# --- Start Main Platform in a new window ---
Write-Step "[3/4] Starting Main Platform (port $PortMain)"

$mainCmd = 'cmd /c "title Agent Security Platform && set PYTHONPATH=' + $ProjectDir + '\src && python -m uvicorn assessment.main:app --host 127.0.0.1 --port ' + $PortMain + ' --log-level warning"'
Start-Process -WindowStyle Normal -FilePath "cmd.exe" -ArgumentList "/c start `"Agent Security Platform`" cmd /c $mainCmd"
Write-OK "Main Platform launching..."

Start-Sleep -Seconds 2

# --- Verify ---
Write-Step "[4/4] Verifying services..."

$allOk = $true

Start-Sleep -Seconds 1

try {
    $healthUrl = 'http://127.0.0.1:' + $PortMain + '/api/v1/observability/health'
    $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 5
    Write-OK 'Main platform health check passed'
} catch {
    Write-Warn ('Main platform not responding yet: ' + $_.Exception.Message)
    $allOk = $false
}

try {
    $otelUrl = 'http://127.0.0.1:' + $PortOtel + '/healthz'
    $otelHealth = Invoke-RestMethod -Uri $otelUrl -TimeoutSec 5
    Write-OK 'OTel Receiver health check passed'
} catch {
    Write-Warn ('OTel Receiver not responding yet: ' + $_.Exception.Message)
    $allOk = $false
}

# --- Summary ---
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
if ($allOk) {
    Write-Host '  All services started successfully!' -ForegroundColor Green
} else {
    Write-Host '  Some services still starting...' -ForegroundColor DarkYellow
    Write-Host '  Check again in a few seconds.' -ForegroundColor DarkYellow
}
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host ('  Main Platform: http://127.0.0.1:' + $PortMain + '/') -ForegroundColor White
Write-Host ('  Health Check:  http://127.0.0.1:' + $PortMain + '/api/v1/health') -ForegroundColor White
Write-Host ('  Observability: http://127.0.0.1:' + $PortMain + '/api/v1/observability/health') -ForegroundColor White
Write-Host ('  OTel Receiver: http://127.0.0.1:' + $PortOtel + '/healthz') -ForegroundColor White
Write-Host ""
Write-Host '  Test event:    Right-click send_test_event.ps1 -> Run with PowerShell' -ForegroundColor White
Write-Host '  Stop services: Close the two service windows' -ForegroundColor White
Write-Host '                 Or run stop_services.ps1' -ForegroundColor White
Write-Host ""

try {
    Start-Process ('http://127.0.0.1:' + $PortMain + '/')
} catch {
    # ignore
}

Write-Host ""
Write-Host 'Press any key to close this window (services will keep running)...' -ForegroundColor DarkGray
pause
