param([string]$OutputRoot = "")
$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $Project = Get-Location
    $Commit = (git rev-parse --short HEAD).Trim()
    if (-not $OutputRoot) { $OutputRoot = Join-Path $Project ("data\artifacts\final-delivery\v4.2.10-" + $Commit) }
    $Stage = Join-Path $OutputRoot "package"
    New-Item -ItemType Directory -Force -Path $Stage | Out-Null
    $Dist = Join-Path $Stage "dist"; New-Item -ItemType Directory -Force -Path $Dist | Out-Null

    uv build --wheel --sdist --out-dir $Dist
    Copy-Item uv.lock $Stage -Force
    python -c "from assessment.main import app; import json; open(r'$Stage/openapi.json','w',encoding='utf-8').write(json.dumps(app.openapi(),ensure_ascii=False,indent=2))"
    $sbom = @{schema='agent-security-sbom@4.2.10'; commit=$Commit; generated_at=(Get-Date).ToString('o'); dependencies=@()}
    $lock = Get-Content uv.lock -Raw
    foreach ($match in [regex]::Matches($lock,'(?m)^name = "([^"]+)"')) { $sbom.dependencies += @{name=$match.Groups[1].Value} }
    $sbom | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 (Join-Path $Stage 'sbom.json')

    foreach ($file in @('README.md','doc\FINAL_ACCEPTANCE_CHECKLIST.md','doc\SECURITY_BOUNDARY.md','doc\RELEASE_NOTES_v4_2_10.md','doc\ENTERPRISE_ACCEPTANCE_REPORT_v4_2_10.md','doc\OPERATIONS_DEPLOYMENT.md','doc\USER_GUIDE.md','doc\SPEC_VALIDATION.md','doc\agent_security_assessment_v4_1_full\e2e_manifest.json','data\acceptance\latest-e2e-result.json')) {
        if (Test-Path $file) { Copy-Item $file (Join-Path $Stage (Split-Path $file -Leaf)) -Force }
    }
    $files = @()
    Get-ChildItem $Stage -File -Recurse | ForEach-Object {
        $files += @{path=$_.FullName.Substring($Stage.Length).TrimStart('\','/').Replace('\','/'); size=$_.Length; sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash; content_type='application/octet-stream'; source='release-build'}
    }
    $manifest = @{schema='agent-security-final-delivery@4.2.10'; version='4.2.10'; commit=$Commit; generated_at=(Get-Date).ToString('o'); safety=@{customer_data=$false; raw_secret=$false; agent_config=$false}; files=$files}
    $manifestPath=Join-Path $Stage 'manifest.json'; $manifest | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $manifestPath
    $manifestHash=(Get-FileHash $manifestPath -Algorithm SHA256).Hash
    $zip=Join-Path $OutputRoot ("agent-security-assessment-v4.2.10-"+$Commit+".zip")
    if(Test-Path $zip){Remove-Item $zip -Force}; Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $zip -Force
    Write-Host "Final delivery package: $zip"
    Write-Host "manifest_path=$manifestPath"
    Write-Host "manifest_sha256=$manifestHash"
}
finally { Pop-Location }
