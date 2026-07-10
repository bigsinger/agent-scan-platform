<#
.SYNOPSIS
    Exercises ownership-safe service lifecycle behavior on Windows.
#>
[CmdletBinding()]
param(
    [switch]$IncludeOwnedLifecycle,
    [int]$MainPort = 18000,
    [int]$OtelPort = 14318
)

$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $PSScriptRoot
$StartScript = Join-Path $ProjectDir 'start_services.ps1'
$StopScript = Join-Path $ProjectDir 'stop_services.ps1'
$RunRoot = Join-Path ([IO.Path]::GetTempPath()) ("agent-security-service-ownership-" + [guid]::NewGuid())
$DataRoot = Join-Path $RunRoot 'data'
$LogRoot = Join-Path $RunRoot 'logs'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

New-Item -ItemType Directory -Force -Path $DataRoot, $LogRoot | Out-Null
$foreign = $null
$victim = $null
try {
    $foreign = Start-Process -FilePath powershell -ArgumentList @('-NoProfile', '-Command', "`$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$MainPort); `$l.Start(); Start-Sleep -Seconds 60") -PassThru
    Start-Sleep -Milliseconds 800
    $startProc = Start-Process -FilePath powershell -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$StartScript,'-NoBrowser','-MainPort',$MainPort,'-OtelPort',$OtelPort,'-DataRoot',$DataRoot,'-LogRoot',$LogRoot) -Wait -PassThru -NoNewWindow
    Assert-True ($startProc.ExitCode -ne 0) 'start script accepted a foreign listener unexpectedly'
    Assert-True (-not $foreign.HasExited) 'start script terminated the foreign listener'
    Write-Host '[PASS] foreign listener survives startup refusal' -ForegroundColor Green

    $victim = Start-Process -FilePath powershell -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 60') -PassThru
    Start-Sleep -Milliseconds 300
    $manifestDir = Join-Path $DataRoot 'run'
    New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
    $forged = [ordered]@{
        schema = 'agent-security-service-manifest@4.2.10'
        services = @([ordered]@{
            name = 'forged'
            pid = $victim.Id
            process_start_time = '2000-01-01T00:00:00.0000000Z'
            executable_path = 'C:\not-the-real-executable.exe'
            command_line_hash = '0' * 64
            listen_host = '127.0.0.1'
            listen_port = 1
            run_root = [IO.Path]::GetFullPath($DataRoot)
        })
    }
    $forged | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $manifestDir 'services.json')
    & powershell -NoProfile -ExecutionPolicy Bypass -File $StopScript -DataRoot $DataRoot
    Assert-True (-not $victim.HasExited) 'stop script terminated a process referenced only by a forged manifest'
    Write-Host '[PASS] forged manifest does not stop unrelated process' -ForegroundColor Green

    if ($IncludeOwnedLifecycle) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $StartScript -NoBrowser -MainPort ($MainPort + 1) -OtelPort ($OtelPort + 1) -DataRoot $DataRoot -LogRoot $LogRoot
        Assert-True ($LASTEXITCODE -eq 0) 'owned service startup failed'
        $manifest = Get-Content (Join-Path $DataRoot 'run\services.json') -Raw | ConvertFrom-Json
        foreach ($service in $manifest.services) { Assert-True ([bool](Get-Process -Id $service.pid -ErrorAction SilentlyContinue)) "owned PID $($service.pid) is not running" }
        & powershell -NoProfile -ExecutionPolicy Bypass -File $StopScript -DataRoot $DataRoot
        Assert-True ($LASTEXITCODE -eq 0) 'owned service stop failed'
        Write-Host '[PASS] owned lifecycle start and stop' -ForegroundColor Green
    }
}
finally {
    foreach ($process in @($foreign, $victim)) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item -LiteralPath $RunRoot -Recurse -Force -ErrorAction SilentlyContinue
}
