[CmdletBinding()]
param([string]$DataRoot = "", [int]$GraceSeconds = 5)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $DataRoot) { $DataRoot = Join-Path $ProjectDir "data" }
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
$Manifest = Join-Path $DataRoot "run\services.json"
if (-not (Test-Path -LiteralPath $Manifest)) { Write-Host "No service manifest found"; exit 0 }

function Get-Sha256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $_.ToString("x2") }) -join "") }
    finally { $sha.Dispose() }
}

$data = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
$expectedRunRoot = [IO.Path]::GetFullPath((Join-Path $DataRoot "run"))
$stopped = 0
$refused = 0
foreach ($service in $data.services) {
    try {
        if ([IO.Path]::GetFullPath([string]$service.run_root) -ne $expectedRunRoot) { throw "run_root mismatch" }
        $process = Get-Process -Id ([int]$service.pid) -ErrorAction Stop
        $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.pid)"
        if (-not $cim) { throw "process command line is unavailable" }
        if ([IO.Path]::GetFullPath($process.Path) -ne [IO.Path]::GetFullPath([string]$service.executable_path)) { throw "executable path mismatch" }
        if ((Get-Sha256 ([string]$cim.CommandLine)) -ne [string]$service.command_line_hash) { throw "command line hash mismatch" }
        if ($process.StartTime.ToUniversalTime().ToString("o") -ne [string]$service.process_start_time) { throw "process start time mismatch" }
        $launcher = $null
        if ($service.launcher_pid) {
            $launcher = Get-Process -Id ([int]$service.launcher_pid) -ErrorAction Stop
            $launcherCim = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.launcher_pid)"
            if (-not $launcherCim) { throw "launcher command line is unavailable" }
            if ([IO.Path]::GetFullPath($launcher.Path) -ne [IO.Path]::GetFullPath([string]$service.launcher_executable_path)) { throw "launcher executable path mismatch" }
            if ((Get-Sha256 ([string]$launcherCim.CommandLine)) -ne [string]$service.launcher_command_line_hash) { throw "launcher command line hash mismatch" }
            if ($launcher.StartTime.ToUniversalTime().ToString("o") -ne [string]$service.launcher_start_time) { throw "launcher start time mismatch" }
            if ([int]$cim.ParentProcessId -ne [int]$service.launcher_pid -and [int]$service.pid -ne [int]$service.launcher_pid) { throw "listener is no longer owned by the recorded launcher" }
        }
        $listener = Get-NetTCPConnection -LocalPort ([int]$service.listen_port) -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $process.Id } | Select-Object -First 1
        if (-not $listener) { throw "owned process no longer owns the recorded listen port" }
        if ($process.MainWindowHandle -ne 0) { $process.CloseMainWindow() | Out-Null }
        if ($process.MainWindowHandle -ne 0) { Wait-Process -Id $process.Id -Timeout $GraceSeconds -ErrorAction SilentlyContinue }
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        if ($launcher) {
            Start-Sleep -Milliseconds 300
            if (-not $launcher.HasExited) { Stop-Process -Id $launcher.Id -Force }
        }
        $stopped++
    }
    catch {
        $refused++
        Write-Warning "PID $($service.pid) identity validation failed; refusing to stop: $($_.Exception.Message)"
    }
}
if ($refused -eq 0) { Remove-Item -LiteralPath $Manifest -Force -ErrorAction SilentlyContinue }
Write-Host "Stopped owned services: $stopped; refused: $refused"
if ($refused -gt 0) { exit 2 }
