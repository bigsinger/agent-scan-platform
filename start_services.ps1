param([switch]$NoBrowser,[int]$MainPort=8000,[int]$OtelPort=4318,[string]$DataRoot="",[string]$LogRoot="",[switch]$Foreground)
$ErrorActionPreference="Stop"
$ProjectDir=Split-Path -Parent $MyInvocation.MyCommand.Path
if(-not $DataRoot){$DataRoot=Join-Path $ProjectDir "data"}
if(-not $LogRoot){$LogRoot=Join-Path $DataRoot "logs"}
$RunRoot=Join-Path $DataRoot "run"
New-Item -ItemType Directory -Force -Path $RunRoot,$LogRoot | Out-Null
$Manifest=Join-Path $RunRoot "services.json"
function Get-ListenPid([int]$Port){
  $c=Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if($c){return [int]$c.OwningProcess}; return $null
}
function Start-Owned([string]$Name,[int]$Port,[string]$Module){
  $pidOnPort=Get-ListenPid $Port
  if($pidOnPort){ throw "Port $Port is occupied by PID $pidOnPort; refusing to stop non-owned process." }
  $env:PYTHONPATH=Join-Path $ProjectDir "src"
  $args=@('run','--locked','--with','fastapi','--with','uvicorn','python','-m','uvicorn',$Module,'--host','127.0.0.1','--port',[string]$Port,'--log-level','warning')
  $log=Join-Path $LogRoot "$Name.log"
  if($Foreground){ & uv @args } else { $p=Start-Process -FilePath 'uv' -ArgumentList $args -WorkingDirectory $ProjectDir -PassThru -RedirectStandardOutput $log -RedirectStandardError $log; return $p }
}
$main=Start-Owned 'main' $MainPort 'assessment.main:app'
$otel=Start-Owned 'otel' $OtelPort 'assessment.observability.receiver:create_receiver_app'
$entries=@()
foreach($svc in @(@{name='main';p=$main;port=$MainPort},@{name='otel';p=$otel;port=$OtelPort})){
 if($svc.p){$proc=Get-Process -Id $svc.p.Id; $entries += @{name=$svc.name; pid=$svc.p.Id; process_start_time=$proc.StartTime.ToString('o'); executable_path=$proc.Path; command_line_hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($svc.p.StartInfo.Arguments)))) ; listen_host='127.0.0.1'; listen_port=$svc.port; run_root=$RunRoot}}
}
@{schema='agent-security-service-manifest@4.2.10'; services=$entries; mutates_foreign_processes=$false} | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $Manifest
if(-not $NoBrowser){ Start-Process "http://127.0.0.1:$MainPort/assessment" }
Write-Host "services started; manifest=$Manifest"
