param([string]$OutputRoot = "")
$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (-not $OutputRoot) { $OutputRoot = Join-Path (Get-Location) ("data\artifacts\final-delivery\" + (Get-Date -Format "yyyyMMddHHmmss")) }
    New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
    $manifest = @{
        schema = "agent-security-final-delivery@4.2.9"
        generated_at = (Get-Date).ToString("o")
        redaction_summary = "No raw secrets are included; use references and hashes only."
        safety = @{ mutates_installed_agents = $false; stdio_mcp_started = $false; skill_code_executed = $false }
        files = @()
    }
    foreach ($file in @("doc\FINAL_ACCEPTANCE_CHECKLIST.md", "doc\SECURITY_BOUNDARY.md", "doc\RELEASE_NOTES_v4_2_9.md", "doc\SPEC_VALIDATION.md")) {
        if (Test-Path $file) {
            Copy-Item $file $OutputRoot -Force
            $manifest.files += (Split-Path $file -Leaf)
        }
    }
    $manifestPath = Join-Path $OutputRoot "manifest.json"
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $manifestPath
    $hash = (Get-FileHash $manifestPath -Algorithm SHA256).Hash
    Write-Host "Final delivery package: $OutputRoot"
    Write-Host "manifest_sha256=$hash"
}
finally { Pop-Location }
