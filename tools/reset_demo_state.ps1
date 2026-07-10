param([switch]$Apply, [switch]$KeepDiscovery)
$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $Db = Join-Path (Get-Location) "data\db\app.db"
    $ReportDir = Join-Path (Get-Location) "data\artifacts\reset"
    New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
    $Report = Join-Path $ReportDir ("reset-demo-state-" + (Get-Date -Format "yyyyMMddHHmmss") + ".json")
    $Mode = if ($Apply) { "APPLY" } else { "DRY_RUN" }
    $Payload = @{ mode=$Mode; db=$Db; keep_discovery=[bool]$KeepDiscovery; mutates_installed_agents=$false; stdio_mcp_started=$false }
    $Payload | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $Report
    Write-Host "Reset demo state $Mode"
    Write-Host "Report: $Report"
    if (-not $Apply) { Write-Host "Dry-run only; no SQLite rows changed." }
}
finally { Pop-Location }
