param([string]$DataRoot="",[int]$GraceSeconds=5)
$ErrorActionPreference="Stop"
$ProjectDir=Split-Path -Parent $MyInvocation.MyCommand.Path
if(-not $DataRoot){$DataRoot=Join-Path $ProjectDir "data"}
$Manifest=Join-Path $DataRoot "run\services.json"
if(-not (Test-Path $Manifest)){Write-Host "No service manifest found"; exit 0}
$data=Get-Content $Manifest -Raw | ConvertFrom-Json
$stopped=0
foreach($svc in $data.services){
  try{
    $proc=Get-Process -Id ([int]$svc.pid) -ErrorAction Stop
    if($proc.Path -ne $svc.executable_path){ Write-Warning "PID $($svc.pid) identity mismatch; refusing to stop"; continue }
    $proc.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds $GraceSeconds
    if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force }
    $stopped++
  }catch{ Write-Warning $_.Exception.Message }
}
Write-Host "Stopped owned services: $stopped"
