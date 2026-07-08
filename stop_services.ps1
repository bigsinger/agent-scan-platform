<#
.SYNOPSIS
    Agent Security Assessment v4.2 - Stop all services
.DESCRIPTION
    Frees ports 8000 and 4318 by terminating holding processes
.NOTES
    Usage: powershell -ExecutionPolicy Bypass -File stop_services.ps1
#>

Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host '  Stopping Agent Security services...' -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ''

$stopped = 0

# Find and kill processes holding our ports via netstat
foreach ($port in @(8000, 4318)) {
    $connections = netstat -ano | Select-String (':' + $port + '\s') | Select-String 'LISTEN'
    if ($connections) {
        $procIds = $connections | ForEach-Object { $_ -split '\s+' | Select-Object -Last 1 } | Where-Object { $_ -ne '' } | Sort-Object -Unique
        foreach ($procId in $procIds) {
            try {
                Stop-Process -Id $procId -Force -ErrorAction Stop
                Write-Host ('  [OK] Freed port ' + $port + ' (PID ' + $procId + ')') -ForegroundColor Green
                $stopped++
            } catch {
                Write-Host ('  [!] Failed to free port ' + $port + ' (PID ' + $procId + ')') -ForegroundColor DarkYellow
            }
        }
    } else {
        Write-Host ('  - Port ' + $port + ' is already free') -ForegroundColor DarkGray
    }
}

Write-Host ''
if ($stopped -gt 0) {
    Write-Host ('  Stopped ' + $stopped + ' processes') -ForegroundColor Green
} else {
    Write-Host '  No running services found' -ForegroundColor DarkGray
}
Write-Host '  All services stopped' -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
pause
