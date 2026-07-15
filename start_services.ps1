[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [int]$MainPort = 8000,
    [int]$OtelPort = 4318,
    [string]$DataRoot = "",
    [string]$LogRoot = "",
    [switch]$Lite,
    [switch]$Foreground,
    [string]$ListenHost = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $DataRoot) { $DataRoot = Join-Path $ProjectDir "data" }
if (-not $LogRoot) { $LogRoot = Join-Path $DataRoot "logs" }
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
$LogRoot = [IO.Path]::GetFullPath($LogRoot)
$RunRoot = Join-Path $DataRoot "run"
$Manifest = Join-Path $RunRoot "services.json"
New-Item -ItemType Directory -Force -Path $RunRoot, $LogRoot | Out-Null

function Get-Sha256([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $_.ToString("x2") }) -join "") }
    finally { $sha.Dispose() }
}

function Get-ListenPid([int]$Port) {
    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($connection) { return [int]$connection.OwningProcess }
    return $null
}

function Rotate-Log([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    for ($index = 3; $index -ge 1; $index--) {
        $source = if ($index -eq 1) { $Path } else { "$Path." + ($index - 1) }
        $target = "$Path.$index"
        if (Test-Path -LiteralPath $source) { Move-Item -LiteralPath $source -Destination $target -Force }
    }
}

function Wait-Healthy([string]$Url, [Diagnostics.Process]$Process, [string]$LogPath) {
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($Process.HasExited) { throw "Service PID $($Process.Id) exited during startup. See $LogPath" }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 1
            if ($response.StatusCode -eq 200) { return }
        }
        catch { Start-Sleep -Milliseconds 100 }
    }
    throw "Service health check timed out: $Url. See $LogPath"
}

if ($ListenHost -notin @("127.0.0.1", "localhost", "::1") -and -not $env:ASSESSMENT_ADMIN_TOKEN) {
    throw "Non-loopback binding requires ASSESSMENT_ADMIN_TOKEN."
}
$requiredPorts = @($MainPort)
if (-not $Lite) { $requiredPorts += $OtelPort }
foreach ($port in $requiredPorts) {
    $owner = Get-ListenPid $port
    if ($owner) { throw "Port $port is occupied by PID $owner; refusing to stop or replace a non-owned process." }
}

$Python = Join-Path $ProjectDir ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uv) { throw "Project .venv is missing and uv is unavailable. Run 'uv sync --locked'." }
    & $uv.Source sync --locked
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Python)) { throw "uv sync --locked did not create a usable project .venv." }
}
$Python = [IO.Path]::GetFullPath($Python)
$env:PYTHONPATH = Join-Path $ProjectDir "src"
$env:ASSESSMENT_DB_PATH = Join-Path $DataRoot "db\app.db"
$env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $DataRoot "artifacts"
$env:ASSESSMENT_STATE_ROOT = $DataRoot
$env:ASSESSMENT_LISTEN_HOST = $ListenHost
$env:ASSESSMENT_OTEL_LISTEN = "$ListenHost`:$OtelPort"

$started = @()
function Start-Owned([string]$Name, [int]$Port, [string]$Application, [switch]$Factory) {
    $stdout = Join-Path $LogRoot "$Name.out.log"
    $stderr = Join-Path $LogRoot "$Name.err.log"
    Rotate-Log $stdout
    Rotate-Log $stderr
    $arguments = @("-m", "uvicorn", $Application, "--host", $ListenHost, "--port", [string]$Port, "--log-level", "info")
    if ($Factory) { $arguments += "--factory" }
    $process = Start-Process -FilePath $Python -ArgumentList $arguments -WorkingDirectory $ProjectDir -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $script:started += $process
    Start-Sleep -Milliseconds 200
    return [ordered]@{
        name = $Name
        launcher_pid = $process.Id
        listen_host = $ListenHost
        listen_port = $Port
        health_url = "http://$ListenHost`:$Port/healthz"
        run_root = $RunRoot
        stdout_log = $stdout
        stderr_log = $stderr
        process = $process
    }
}

function Resolve-OwnedIdentity($Service) {
    $listenerPid = Get-ListenPid ([int]$Service.listen_port)
    if (-not $listenerPid) { throw "No listener owns port $($Service.listen_port) after health check." }
    $listenerCim = Get-CimInstance Win32_Process -Filter "ProcessId=$listenerPid"
    $launcherCim = Get-CimInstance Win32_Process -Filter "ProcessId=$($Service.launcher_pid)"
    if (-not $listenerCim -or -not $launcherCim) { throw "Owned process identity is unavailable after startup." }
    if ($listenerPid -ne [int]$Service.launcher_pid -and [int]$listenerCim.ParentProcessId -ne [int]$Service.launcher_pid) {
        throw "Listener PID $listenerPid is not the verified launcher or its direct child."
    }
    $listener = Get-Process -Id $listenerPid -ErrorAction Stop
    $launcher = Get-Process -Id ([int]$Service.launcher_pid) -ErrorAction Stop
    $Service.pid = $listenerPid
    $Service.process_start_time = $listener.StartTime.ToUniversalTime().ToString("o")
    $Service.executable_path = [IO.Path]::GetFullPath($listener.Path)
    $Service.command_line_hash = Get-Sha256 ([string]$listenerCim.CommandLine)
    $Service.launcher_start_time = $launcher.StartTime.ToUniversalTime().ToString("o")
    $Service.launcher_executable_path = [IO.Path]::GetFullPath($launcher.Path)
    $Service.launcher_command_line_hash = Get-Sha256 ([string]$launcherCim.CommandLine)
    return $Service
}

try {
    $main = Start-Owned "main" $MainPort "assessment.main:app"
    Wait-Healthy $main.health_url $main.process $main.stderr_log
    $main = Resolve-OwnedIdentity $main
    $serviceList = @($main)
    if (-not $Lite) {
        $otel = Start-Owned "otel" $OtelPort "assessment.observability.receiver:create_receiver_app" -Factory
        Wait-Healthy $otel.health_url $otel.process $otel.stderr_log
        $otel = Resolve-OwnedIdentity $otel
        $serviceList += $otel
    }
    $entries = @()
    foreach ($service in $serviceList) {
        $entry = [ordered]@{}
        foreach ($key in @("name", "pid", "process_start_time", "executable_path", "command_line_hash", "launcher_pid", "launcher_start_time", "launcher_executable_path", "launcher_command_line_hash", "listen_host", "listen_port", "health_url", "run_root", "stdout_log", "stderr_log")) { $entry[$key] = $service[$key] }
        $entries += $entry
    }
    [ordered]@{
        schema = "agent-security-service-manifest@4.2.10"
        created_at = (Get-Date).ToUniversalTime().ToString("o")
        project_dir = $ProjectDir
        mode = $(if ($Lite) { "lite" } else { "full" })
        services = $entries
        mutates_foreign_processes = $false
    } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath $Manifest
    if (-not $NoBrowser) { Start-Process "http://127.0.0.1:$MainPort/assessment" }
    Write-Host "Main service: http://127.0.0.1:$MainPort/assessment"
    if ($Lite) { Write-Host "OTel receiver: skipped (lite mode)" }
    else { Write-Host "OTel receiver: http://127.0.0.1:$OtelPort/healthz" }
    Write-Host "Service manifest: $Manifest"
    if ($Foreground) { Wait-Process -Id $main.pid }
}
catch {
    foreach ($process in $started) {
        if ($process) {
            Get-CimInstance Win32_Process -Filter "ParentProcessId=$($process.Id)" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    throw
}
