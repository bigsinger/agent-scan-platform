[CmdletBinding()]
param([string]$OutputRoot = "")

$ErrorActionPreference = "Stop"
function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") }) -join "") }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Get-ContentType([string]$Path) {
    switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        ".json" { return "application/json" }
        ".html" { return "text/html" }
        ".md" { return "text/markdown" }
        ".txt" { return "text/plain" }
        ".ps1" { return "text/x-powershell" }
        ".toml" { return "application/toml" }
        ".sql" { return "application/sql" }
        ".whl" { return "application/zip" }
        ".zip" { return "application/zip" }
        ".gz" { return "application/gzip" }
        ".png" { return "image/png" }
        ".xml" { return "application/xml" }
        default { return "application/octet-stream" }
    }
}
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $Project = Get-Location
    $Python = Join-Path $Project ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python)) { throw "Project .venv is required. Run uv sync --locked." }
    $Commit = (git rev-parse HEAD).Trim()
    $AcceptanceStateRoot = if ($env:ASSESSMENT_STATE_ROOT) { [IO.Path]::GetFullPath($env:ASSESSMENT_STATE_ROOT) } else { Join-Path $Project "data" }
    $SensitiveAuditPath = Join-Path $AcceptanceStateRoot "acceptance\sensitive-data-audit.json"
    if (-not (Test-Path -LiteralPath $SensitiveAuditPath)) { throw "Current sensitive-data audit is required before packaging: $SensitiveAuditPath" }
    $SensitiveAudit = Get-Content -LiteralPath $SensitiveAuditPath -Raw | ConvertFrom-Json
    if ($SensitiveAudit.schema -ne "agent-security-sensitive-audit@4.2.10" -or $SensitiveAudit.count -ne 0 -or $SensitiveAudit.raw_values_emitted) { throw "Sensitive-data audit is not a zero-hit v4.2.10 result" }
    $ShortCommit = $Commit.Substring(0, 7)
    if (-not $OutputRoot) { $OutputRoot = Join-Path $Project ("data\artifacts\final-delivery\v4.2.10-" + $ShortCommit) }
    $OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
    $Stage = Join-Path $OutputRoot "package"
    if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Stage | Out-Null
    $Dist = Join-Path $Stage "dist"
    $Docs = Join-Path $Stage "docs"
    $Ops = Join-Path $Stage "operations"
    $Sample = Join-Path $Stage "sample-evidence"
    New-Item -ItemType Directory -Force -Path $Dist, $Docs, $Ops, $Sample | Out-Null

    $AcceptancePath = if ($env:ASSESSMENT_E2E_RESULT_PATH) { $env:ASSESSMENT_E2E_RESULT_PATH } else { Join-Path $Project "data\acceptance\latest-e2e-result.json" }
    if (-not (Test-Path -LiteralPath $AcceptancePath)) { throw "Current acceptance result is required before packaging: $AcceptancePath" }
    $Acceptance = Get-Content -LiteralPath $AcceptancePath -Raw | ConvertFrom-Json
    if ($Acceptance.schema -ne "agent-security-enterprise-e2e-result@4.2.10" -or $Acceptance.generated_from -ne "pytest-junit-xml" -or $Acceptance.status -ne "PASS" -or $Acceptance.commit -ne $Commit -or $Acceptance.exit_code -ne 0) { throw "Acceptance result is not a machine-generated PASS for current commit $Commit" }
    if (@($Acceptance.screenshots).Count -lt 8 -or @($Acceptance.pytest.sources).Count -lt 2) { throw "Acceptance result does not contain eight screenshots and both JUnit suites" }

    & uv build --wheel --sdist --out-dir $Dist
    if ($LASTEXITCODE -ne 0) { throw "uv build failed" }
    Copy-Item -LiteralPath "uv.lock" -Destination $Stage -Force
    $AcceptanceDir = Join-Path $Stage "acceptance"
    $AcceptanceBrowser = Join-Path $AcceptanceDir "browser"
    $AcceptanceJunit = Join-Path $AcceptanceDir "junit"
    New-Item -ItemType Directory -Force -Path $AcceptanceBrowser, $AcceptanceJunit | Out-Null
    Copy-Item -LiteralPath $SensitiveAuditPath -Destination (Join-Path $AcceptanceDir "sensitive-data-audit.json") -Force
    if ($env:ASSESSMENT_LIVE_MACHINE_RESULT_PATH) {
        if (-not (Test-Path -LiteralPath $env:ASSESSMENT_LIVE_MACHINE_RESULT_PATH)) { throw "Live-machine acceptance result is missing" }
        Copy-Item -LiteralPath $env:ASSESSMENT_LIVE_MACHINE_RESULT_PATH -Destination (Join-Path $AcceptanceDir "live-machine-readonly.json") -Force
    }
    if ($env:ASSESSMENT_LIVE_SENSITIVE_AUDIT_PATH) {
        if (-not (Test-Path -LiteralPath $env:ASSESSMENT_LIVE_SENSITIVE_AUDIT_PATH)) { throw "Live-machine sensitive-data audit is missing" }
        $LiveSensitive = Get-Content -LiteralPath $env:ASSESSMENT_LIVE_SENSITIVE_AUDIT_PATH -Raw | ConvertFrom-Json
        if ($LiveSensitive.count -ne 0) { throw "Live-machine sensitive-data audit contains hits" }
        Copy-Item -LiteralPath $env:ASSESSMENT_LIVE_SENSITIVE_AUDIT_PATH -Destination (Join-Path $AcceptanceDir "live-machine-sensitive-data-audit.json") -Force
    }
    foreach ($shot in $Acceptance.screenshots) {
        $source = [IO.Path]::GetFullPath([string]$shot.path)
        if (-not (Test-Path -LiteralPath $source)) { throw "Acceptance screenshot is missing: $source" }
        if ((Get-FileSha256 $source) -ne ([string]$shot.sha256).ToLowerInvariant()) { throw "Acceptance screenshot hash mismatch: $source" }
        $bytes = [IO.File]::ReadAllBytes($source)
        if ($bytes.Length -lt 1024 -or -not ($bytes[0] -eq 137 -and $bytes[1] -eq 80 -and $bytes[2] -eq 78 -and $bytes[3] -eq 71 -and $bytes[4] -eq 13 -and $bytes[5] -eq 10 -and $bytes[6] -eq 26 -and $bytes[7] -eq 10)) { throw "Acceptance screenshot is invalid: $source" }
        $name = Split-Path $source -Leaf
        Copy-Item -LiteralPath $source -Destination (Join-Path $AcceptanceBrowser $name) -Force
        $shot.path = "acceptance/browser/$name"
    }
    foreach ($sourceInfo in $Acceptance.pytest.sources) {
        $source = [IO.Path]::GetFullPath([string]$sourceInfo.path)
        if (-not (Test-Path -LiteralPath $source)) { throw "Acceptance JUnit source is missing: $source" }
        if ((Get-FileSha256 $source) -ne ([string]$sourceInfo.sha256).ToLowerInvariant()) { throw "Acceptance JUnit hash mismatch: $source" }
        $name = Split-Path $source -Leaf
        Copy-Item -LiteralPath $source -Destination (Join-Path $AcceptanceJunit $name) -Force
        $sourceInfo.path = "acceptance/junit/$name"
    }
    $PortableAcceptancePath = Join-Path $Stage "latest-e2e-result.json"
    $Acceptance | ConvertTo-Json -Depth 20 | Set-Content -Encoding UTF8 -LiteralPath $PortableAcceptancePath
    Copy-Item -LiteralPath $PortableAcceptancePath -Destination (Join-Path $Stage "enterprise-acceptance-result.json") -Force

    $RequirementsPath = Join-Path $Stage "requirements.lock.txt"
    & uv export --locked --no-dev --no-emit-project --format requirements-txt --output-file $RequirementsPath
    if ($LASTEXITCODE -ne 0) { throw "locked requirements export failed" }
    $DependencyAuditPath = Join-Path $Stage "dependency-audit.json"
    & uvx pip-audit --path (Join-Path $Project ".venv\Lib\site-packages") --format json --output $DependencyAuditPath --progress-spinner off --timeout 10
    if ($LASTEXITCODE -ne 0) { throw "dependency vulnerability audit failed" }
    if (-not (Test-Path -LiteralPath $DependencyAuditPath)) { throw "dependency audit output missing" }

    $BuildRuntime = Join-Path ([IO.Path]::GetTempPath()) ("agent-security-package-runtime-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $BuildRuntime | Out-Null
    $env:ASSESSMENT_DB_PATH = Join-Path $BuildRuntime "app.db"
    $env:ASSESSMENT_STATE_ROOT = Join-Path $BuildRuntime "state"
    $env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $BuildRuntime "artifacts"
    $env:ASSESSMENT_DISABLE_BACKGROUND_JOBS = "true"
    $env:ASSESSMENT_LISTEN_HOST = "127.0.0.1"
    $env:PYTHONPATH = Join-Path $Project "src"
    $openApiScript = @'
import json, sys
from assessment.main import app
from assessment.security import SensitiveDataGuard
payload=SensitiveDataGuard.sanitize_for_persist(app.openapi())
open(sys.argv[1], 'w', encoding='utf-8').write(json.dumps(payload, ensure_ascii=False, indent=2))
'@
    $openApiScript | & $Python - (Join-Path $Stage "openapi.json")
    if ($LASTEXITCODE -ne 0) { throw "OpenAPI export failed" }

    $SampleRoot = Join-Path ([IO.Path]::GetTempPath()) ("agent-security-delivery-sample-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $SampleRoot | Out-Null
    try {
        $sampleScript = @'
import json, os, sys
from pathlib import Path
os.environ['ASSESSMENT_DB_PATH']=str(Path(sys.argv[1])/'app.db')
os.environ['ASSESSMENT_STATE_ROOT']=str(Path(sys.argv[1])/'state')
os.environ['ASSESSMENT_ARTIFACT_ROOT']=str(Path(sys.argv[1])/'artifacts')
os.environ['ASSESSMENT_DISABLE_BACKGROUND_JOBS']='true'
from assessment.scanning import LocalScanEngine
from assessment.security import SensitiveDataGuard
from assessment.store import get_store
store=get_store()
store.initialize()
scan=LocalScanEngine(store).run_quick_scan({'mode':'path','target_path':sys.argv[2],'max_files':100})
summary={
 'schema':'agent-security-delivery-sample@4.2.10',
 'assessment':scan.assessment,
 'findings':scan.findings,
 'evidence':scan.evidence,
 'report':scan.report,
 'mutates_installed_agents':False,
 'stdio_mcp_started':False,
}
summary=SensitiveDataGuard.sanitize_for_persist(summary)
Path(sys.argv[3]).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
'@
        $sampleScript | & $Python - $SampleRoot (Join-Path $Project "tests\fixtures\sample_agent_project") (Join-Path $Sample "fixture-scan.json")
        if ($LASTEXITCODE -ne 0) { throw "Isolated fixture sample generation failed" }
        $GeneratedArtifacts = Join-Path $SampleRoot "artifacts"
        if (Test-Path -LiteralPath $GeneratedArtifacts) { Copy-Item -LiteralPath $GeneratedArtifacts -Destination (Join-Path $Sample "artifacts") -Recurse -Force }
    }
    finally { Remove-Item -LiteralPath $SampleRoot -Recurse -Force -ErrorAction SilentlyContinue }

    $lockText = Get-Content -LiteralPath "uv.lock" -Raw
    $dependencies = @()
    foreach ($block in [regex]::Matches($lockText, '(?ms)^\[\[package\]\].*?(?=^\[\[package\]\]|\z)')) {
        $name = [regex]::Match($block.Value, '(?m)^name = "([^"]+)"').Groups[1].Value
        $version = [regex]::Match($block.Value, '(?m)^version = "([^"]+)"').Groups[1].Value
        if ($name) { $dependencies += [ordered]@{ name = $name; version = $version; source = "uv.lock" } }
    }
    [ordered]@{
        schema = "agent-security-sbom@4.2.10"
        commit = $Commit
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        dependency_count = $dependencies.Count
        dependencies = $dependencies
    } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Stage "sbom.json")

    $MigrationStage = Join-Path $Stage "migrations"
    New-Item -ItemType Directory -Force -Path $MigrationStage | Out-Null
    $migrationEntries = @()
    Get-ChildItem -LiteralPath "src\assessment\persistence\migrations" -Filter "*.sql" -File | Sort-Object Name | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $MigrationStage $_.Name) -Force
        $migrationEntries += [ordered]@{
            version = $_.BaseName.Split('_')[0]
            file = "migrations/$($_.Name)"
            sha256 = Get-FileSha256 $_.FullName
        }
    }
    if (-not $migrationEntries.Count) { throw "schema migration files are missing" }
    [ordered]@{
        schema = "agent-security-schema-migrations@4.2.10"
        current_version = "4.2.10"
        migrations = $migrationEntries
    } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Stage "migration-manifest.json")

    $docFiles = @(
        "README.md",
        "doc\FINAL_ACCEPTANCE_CHECKLIST.md",
        "doc\SECURITY_BOUNDARY.md",
        "doc\RELEASE_NOTES_v4_2_10.md",
        "doc\ENTERPRISE_ACCEPTANCE_REPORT_v4_2_10.md",
        "doc\OPERATIONS_DEPLOYMENT.md",
        "doc\USER_GUIDE.md",
        "doc\SPEC_VALIDATION.md",
        "doc\agent_security_assessment_v4_2_10_enterprise_release_gate_spec.md"
    )
    foreach ($file in $docFiles) {
        if (-not (Test-Path -LiteralPath $file)) { throw "Required delivery document is missing: $file" }
        Copy-Item -LiteralPath $file -Destination (Join-Path $Docs (Split-Path $file -Leaf)) -Force
    }
    Copy-Item -LiteralPath "doc\agent_security_assessment_v4_1_full\e2e_manifest.json" -Destination (Join-Path $Stage "e2e_manifest.json") -Force
    foreach ($file in @("start_services.ps1", "stop_services.ps1", "tools\audit_sensitive_data.ps1", "tools\reset_demo_state.ps1", "tools\verify_delivery_package.ps1")) {
        Copy-Item -LiteralPath $file -Destination (Join-Path $Ops (Split-Path $file -Leaf)) -Force
    }
    Get-ChildItem -LiteralPath $Stage -File -Recurse | Where-Object { $_.Extension -in @(".md", ".txt", ".ps1", ".json", ".yaml", ".yml", ".toml") } | ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw
        $sanitized = $content.Replace("F:\bigsinger\agent-scan-platform", "<install-root>")
        $sanitized = [regex]::Replace($sanitized, '(?i)C:\\Users\\[^\\\s"'']+', '<user-home>')
        if ($sanitized -ne $content) { Set-Content -LiteralPath $_.FullName -Value $sanitized -Encoding UTF8 }
    }

    $sampleEntries = @()
    Get-ChildItem -LiteralPath $Sample -File -Recurse | ForEach-Object {
        $sampleEntries += [ordered]@{
            path = $_.FullName.Substring($Sample.Length).TrimStart('\', '/').Replace('\', '/')
            size = $_.Length
            sha256 = Get-FileSha256 $_.FullName
        }
    }
    [ordered]@{
        schema = "agent-security-sample-evidence-integrity@4.2.10"
        status = "PASS"
        fixture_only = $true
        files = $sampleEntries
    } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Sample "integrity.json")

    $files = @()
    Get-ChildItem -LiteralPath $Stage -File -Recurse | ForEach-Object {
        $relative = $_.FullName.Substring($Stage.Length).TrimStart('\', '/').Replace('\', '/')
        $files += [ordered]@{
            path = $relative
            size = $_.Length
            sha256 = Get-FileSha256 $_.FullName
            content_type = Get-ContentType $_.FullName
            source = "release-build"
        }
    }
    $manifest = [ordered]@{
        schema = "agent-security-final-delivery@4.2.10"
        version = "4.2.10"
        commit = $Commit
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        acceptance_result_sha256 = Get-FileSha256 $PortableAcceptancePath
        safety = [ordered]@{ customer_data = $false; raw_secret = $false; agent_config = $false; fixture_only = $true }
        files = $files
    }
    $manifestPath = Join-Path $Stage "manifest.json"
    $manifest | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 -LiteralPath $manifestPath
    $manifestHash = Get-FileSha256 $manifestPath
    $manifestHash | Set-Content -Encoding ASCII -LiteralPath (Join-Path $Stage "manifest.sha256")
    $zip = Join-Path $OutputRoot ("agent-security-assessment-v4.2.10-" + $ShortCommit + ".zip")
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $zip -Force
    Write-Host "Final delivery package: $zip"
    Write-Host "manifest_path=$manifestPath"
    Write-Host "manifest_sha256=$manifestHash"
}
finally {
    if ($BuildRuntime -and (Test-Path -LiteralPath $BuildRuntime)) { Remove-Item -LiteralPath $BuildRuntime -Recurse -Force -ErrorAction SilentlyContinue }
    Pop-Location
}
