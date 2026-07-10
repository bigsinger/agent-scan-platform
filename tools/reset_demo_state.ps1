param([switch]$Apply, [switch]$KeepDiscovery, [string]$DataRoot = "")
$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (-not $DataRoot) { $DataRoot = Join-Path (Get-Location) "data" }
    $DataRoot = [System.IO.Path]::GetFullPath($DataRoot)
    $Db = Join-Path $DataRoot "db\app.db"
    $ReportDir = Join-Path $DataRoot "artifacts\reset"
    New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
    $Report = Join-Path $ReportDir ("reset-demo-state-" + (Get-Date -Format "yyyyMMddHHmmss") + ".json")
    $Mode = if ($Apply) { "APPLY" } else { "DRY_RUN" }
    $script = @'
import json, sqlite3, shutil, sys
from pathlib import Path
root=Path(sys.argv[1]); apply=sys.argv[2]=='1'; keep=sys.argv[3]=='1'
db=root/'db'/'app.db'; artifact=root/'artifacts'
protected={'discovery_run','discovery_hit','agent','agent_asset'} if keep else set()
counts={}; backup=None
if db.exists():
  con=sqlite3.connect(db)
  tables=[r[0] for r in con.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
  for t in tables:
    if t in protected: continue
    try: counts[t]=con.execute(f'select count(*) from "{t}"').fetchone()[0]
    except Exception: pass
  if apply:
    backup=root/'backups'/('reset-'+__import__('datetime').datetime.now().strftime('%Y%m%d%H%M%S')+'.db')
    backup.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(db,backup)
    for t in counts: con.execute(f'delete from "{t}"')
    con.commit()
  con.close()
files=[p for p in artifact.rglob('*') if p.is_file()] if artifact.exists() else []
if apply and artifact.exists():
  for p in files:
    if 'reset' not in p.parts: p.unlink()
print(json.dumps({'mode':'APPLY' if apply else 'DRY_RUN','db':str(db),'backup':str(backup) if backup else None,'keep_discovery':keep,'row_counts':counts,'artifact_files':len(files),'mutates_installed_agents':False,'stdio_mcp_started':False},ensure_ascii=False))
'@
    $ApplyFlag = if ($Apply) { 1 } else { 0 }
    $KeepFlag = if ($KeepDiscovery) { 1 } else { 0 }
    $result = $script | python - $DataRoot $ApplyFlag $KeepFlag
    $result | Set-Content -Encoding UTF8 $Report
    Write-Host "Reset demo state $Mode"
    Write-Host "Report: $Report"
    if (-not $Apply) { Write-Host "Dry-run only; no SQLite rows or artifact files changed." }
}
finally { Pop-Location }
