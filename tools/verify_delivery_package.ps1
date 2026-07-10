[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PackagePath)

$ErrorActionPreference = "Stop"
function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString("x2") }) -join "") }
    finally { $sha.Dispose(); $stream.Dispose() }
}
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("agent-package-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
try {
    Expand-Archive -LiteralPath $PackagePath -DestinationPath $Temp -Force
    $manifestPath = Join-Path $Temp "manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw "manifest.json missing" }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne "agent-security-final-delivery@4.2.10" -or $manifest.version -ne "4.2.10") { throw "delivery manifest schema/version mismatch" }
    foreach ($file in $manifest.files) {
        $path = Join-Path $Temp $file.path
        if (-not (Test-Path -LiteralPath $path)) { throw "missing file $($file.path)" }
        $hash = Get-FileSha256 $path
        if ($hash -ne ([string]$file.sha256).ToLowerInvariant()) { throw "sha mismatch $($file.path)" }
        if ((Get-Item -LiteralPath $path).Length -ne [int64]$file.size) { throw "size mismatch $($file.path)" }
        if (-not $file.content_type -or -not $file.source) { throw "manifest metadata missing for $($file.path)" }
    }

    $required = @(
        "openapi.json", "sbom.json", "requirements.lock.txt", "dependency-audit.json",
        "migration-manifest.json", "latest-e2e-result.json", "enterprise-acceptance-result.json",
        "e2e_manifest.json", "acceptance\sensitive-data-audit.json",
        "sample-evidence\fixture-scan.json", "sample-evidence\integrity.json", "manifest.sha256"
    )
    foreach ($relative in $required) { if (-not (Test-Path -LiteralPath (Join-Path $Temp $relative))) { throw "required delivery file missing: $relative" } }
    if (-not (Get-ChildItem -LiteralPath (Join-Path $Temp "dist") -Filter "*.whl" -File)) { throw "wheel missing" }
    if (-not (Get-ChildItem -LiteralPath (Join-Path $Temp "dist") -Filter "*.tar.gz" -File)) { throw "sdist missing" }
    $acceptance = Get-Content -LiteralPath (Join-Path $Temp "latest-e2e-result.json") -Raw | ConvertFrom-Json
    if ($acceptance.status -ne "PASS" -or $acceptance.commit -ne $manifest.commit -or $acceptance.exit_code -ne 0) { throw "packaged acceptance result is not valid for manifest commit" }
    $acceptanceHash = Get-FileSha256 (Join-Path $Temp "latest-e2e-result.json")
    if ($acceptanceHash -ne ([string]$manifest.acceptance_result_sha256).ToLowerInvariant()) { throw "packaged acceptance result hash mismatch" }
    if (@($acceptance.screenshots).Count -lt 8 -or @($acceptance.pytest.sources).Count -lt 2) { throw "packaged acceptance evidence is incomplete" }
    foreach ($shot in $acceptance.screenshots) {
        $path = Join-Path $Temp ([string]$shot.path)
        if (-not (Test-Path -LiteralPath $path)) { throw "packaged screenshot missing: $($shot.path)" }
        if ((Get-FileSha256 $path) -ne ([string]$shot.sha256).ToLowerInvariant()) { throw "packaged screenshot hash mismatch: $($shot.path)" }
    }
    foreach ($source in $acceptance.pytest.sources) {
        $path = Join-Path $Temp ([string]$source.path)
        if (-not (Test-Path -LiteralPath $path)) { throw "packaged JUnit source missing: $($source.path)" }
        if ((Get-FileSha256 $path) -ne ([string]$source.sha256).ToLowerInvariant()) { throw "packaged JUnit hash mismatch: $($source.path)" }
    }
    $manifestHashFile = (Get-Content -LiteralPath (Join-Path $Temp "manifest.sha256") -Raw).Trim().ToLowerInvariant()
    if ($manifestHashFile -ne (Get-FileSha256 $manifestPath)) { throw "manifest.sha256 does not match manifest.json" }
    $sensitiveAudit = Get-Content -LiteralPath (Join-Path $Temp "acceptance\sensitive-data-audit.json") -Raw | ConvertFrom-Json
    if ($sensitiveAudit.count -ne 0 -or $sensitiveAudit.raw_values_emitted) { throw "packaged sensitive-data audit is not clean" }
    $sampleIntegrity = Get-Content -LiteralPath (Join-Path $Temp "sample-evidence\integrity.json") -Raw | ConvertFrom-Json
    if ($sampleIntegrity.status -ne "PASS" -or -not $sampleIntegrity.fixture_only) { throw "sample evidence integrity result is invalid" }
    foreach ($entry in $sampleIntegrity.files) {
        $path = Join-Path (Join-Path $Temp "sample-evidence") ([string]$entry.path)
        if (-not (Test-Path -LiteralPath $path) -or (Get-FileSha256 $path) -ne ([string]$entry.sha256).ToLowerInvariant()) { throw "sample evidence hash mismatch: $($entry.path)" }
    }
    $dependencyAudit = Get-Content -LiteralPath (Join-Path $Temp "dependency-audit.json") -Raw | ConvertFrom-Json
    $vulnerabilities = @(
        foreach ($dependency in @($dependencyAudit.dependencies)) {
            foreach ($vulnerability in @($dependency.vulns)) {
                if ($null -ne $vulnerability) { $vulnerability }
            }
        }
    )
    $vulnerabilityCount = $vulnerabilities.Count
    if ($vulnerabilityCount -ne 0) { throw "dependency audit contains $vulnerabilityCount vulnerabilities" }
    $unexpectedSkips = @(
        $dependencyAudit.dependencies | Where-Object {
            $_.skip_reason -and $_.name -ne "agent-security-assessment"
        }
    )
    if ($unexpectedSkips.Count -ne 0) { throw "dependency audit unexpectedly skipped $($unexpectedSkips.Count) third-party dependencies" }
    $migrationManifest = Get-Content -LiteralPath (Join-Path $Temp "migration-manifest.json") -Raw | ConvertFrom-Json
    if ($migrationManifest.current_version -ne "4.2.10" -or @($migrationManifest.migrations).Count -lt 3) { throw "migration manifest is incomplete" }
    foreach ($migration in $migrationManifest.migrations) {
        $path = Join-Path $Temp ([string]$migration.file)
        if (-not (Test-Path -LiteralPath $path) -or (Get-FileSha256 $path) -ne ([string]$migration.sha256).ToLowerInvariant()) { throw "migration hash mismatch: $($migration.file)" }
    }

    $textExtensions = @(".json", ".md", ".txt", ".ps1", ".toml", ".yaml", ".yml", ".html")
    $text = Get-ChildItem -LiteralPath $Temp -File -Recurse | Where-Object { $textExtensions -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 5MB } | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop }
    $joined = $text -join "`n"
    if ($joined -match 'sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}') { throw "secret-shaped value found" }
    if ($joined -match '(?i)C:\\Users\\[^<\\\s]+|F:\\bigsinger\\agent-scan-platform') { throw "user or repository absolute path found" }

    $wheel = Get-ChildItem -LiteralPath (Join-Path $Temp "dist") -Filter "*.whl" -File | Select-Object -First 1
    $Venv = Join-Path $Temp "wheel-smoke-venv"
    $env:PYTHONPATH = ""
    $env:PYTHONNOUSERSITE = "1"
    & python -m venv --system-site-packages $Venv
    if ($LASTEXITCODE -ne 0) { throw "fresh wheel smoke venv creation failed" }
    $VenvPython = Join-Path $Venv "Scripts\python.exe"
    & $VenvPython -m pip install --force-reinstall --no-deps $wheel.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "wheel installation failed" }
    $env:ASSESSMENT_DB_PATH = Join-Path $Temp "wheel-smoke.db"
    $env:ASSESSMENT_STATE_ROOT = Join-Path $Temp "wheel-smoke-state"
    $env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $Temp "wheel-smoke-artifacts"
    & $VenvPython -c "import sys; from pathlib import Path; import assessment; from assessment.main import app; module=Path(assessment.__file__).resolve(); prefix=Path(sys.prefix).resolve(); assert module.is_relative_to(prefix), f'{module} is outside {prefix}'; assert app.version == '4.2.10'; print(f'wheel import smoke PASS: {module}')"
    if ($LASTEXITCODE -ne 0) { throw "installed wheel import smoke failed" }
    Write-Host "delivery package verified: $PackagePath"
}
finally { Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue }
