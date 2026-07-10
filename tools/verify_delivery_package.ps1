param([Parameter(Mandatory=$true)][string]$PackagePath)
$ErrorActionPreference = "Stop"
$Temp = Join-Path ([System.IO.Path]::GetTempPath()) ("agent-package-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
try {
  Expand-Archive -Path $PackagePath -DestinationPath $Temp -Force
  $manifest = Join-Path $Temp "manifest.json"
  if (-not (Test-Path $manifest)) { throw "manifest.json missing" }
  $data = Get-Content $manifest -Raw | ConvertFrom-Json
  foreach ($file in $data.files) {
    $p = Join-Path $Temp $file.path
    if (-not (Test-Path $p)) { throw "missing file $($file.path)" }
    $h = (Get-FileHash $p -Algorithm SHA256).Hash
    if ($h -ne $file.sha256) { throw "sha mismatch $($file.path)" }
  }
  $text = Get-ChildItem $Temp -File -Recurse | Where-Object { $_.Length -lt 2MB } | ForEach-Object { Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue }
  if (($text -join "`n") -match 'sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}') { throw "secret-shaped value found" }
  Write-Host "delivery package verified: $PackagePath"
}
finally { Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue }
