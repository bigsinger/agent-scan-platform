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
    $Python = Join-Path (Get-Location) ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python)) { throw "Project .venv is required. Run uv sync --locked." }
    $script = @'
import hashlib, json, sqlite3, sys
from pathlib import Path
root=Path(sys.argv[1]); apply=sys.argv[2]=='1'; keep=sys.argv[3]=='1'
db=root/'db'/'app.db'; artifact=root/'artifacts'
runtime={
 'discovery_run','discovery_hit','agent_instance','config_snapshot','component','component_relation',
 'assessment','assessment_scope','task','task_stage','task_event','scan_stage','scan_file_cache','scan_job','process_execution',
 'mcp_consent','consent_request','mcp_server','mcp_tool','mcp_prompt','mcp_resource','mcp_signature','tool_label','toxic_flow',
 'skill','skill_file','scanner_run','test_run','redteam_run','redteam_message','finding','finding_instance','finding_suppression','evidence','artifact',
 'attack_path','attack_path_node','attack_path_edge','policy_draft','report','retest','retest_run','guard_event','defense_recommendation',
 'probe_event','otel_span','otel_log','otel_metric_point','behavior_chain','behavior_anomaly','behavior_edge'
}
discovery={'discovery_run','discovery_hit','agent_instance','config_snapshot','component','component_relation','mcp_server','mcp_tool','mcp_prompt','mcp_resource','mcp_signature','skill','skill_file'}
protected=(discovery|{'artifact'}) if keep else set()
counts={}; backup=None; artifact_manifest=None
if db.exists():
  con=sqlite3.connect(db)
  tables=[r[0] for r in con.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
  for t in tables:
    if t not in runtime or t in protected: continue
    try: counts[t]=con.execute(f'select count(*) from "{t}"').fetchone()[0]
    except Exception: pass
  if apply:
    backup=root/'backups'/('reset-'+__import__('datetime').datetime.now().strftime('%Y%m%d%H%M%S')+'.db')
    backup.parent.mkdir(parents=True,exist_ok=True)
    target=sqlite3.connect(backup)
    try: con.backup(target)
    finally: target.close()
    for t in counts: con.execute(f'delete from "{t}"')
    con.commit()
  con.close()
files=[p for p in artifact.rglob('*') if p.is_file() and (not p.relative_to(artifact).parts or p.relative_to(artifact).parts[0] != 'reset')] if artifact.exists() else []
if apply and artifact.exists():
  if not keep and files:
    artifact_manifest=root/'backups'/('reset-'+__import__('datetime').datetime.now().strftime('%Y%m%d%H%M%S')+'-artifacts.json')
    artifact_manifest.parent.mkdir(parents=True,exist_ok=True)
    manifest={'schema':'agent-security-reset-artifacts@4.2.10','files':[
      {'path':str(p.relative_to(artifact)).replace('\\','/'),'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
      for p in files
    ]}
    artifact_manifest.write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    for p in files: p.unlink()
print(json.dumps({'mode':'APPLY' if apply else 'DRY_RUN','db':'<state>/db/app.db','backup':('<state>/backups/'+backup.name) if backup else None,'artifact_manifest':('<state>/backups/'+artifact_manifest.name) if artifact_manifest else None,'keep_discovery':keep,'row_counts':counts,'artifact_files':0 if keep else len(files),'mutates_installed_agents':False,'stdio_mcp_started':False},ensure_ascii=False))
'@
    $ApplyFlag = if ($Apply) { 1 } else { 0 }
    $KeepFlag = if ($KeepDiscovery) { 1 } else { 0 }
    $result = $script | & $Python - $DataRoot $ApplyFlag $KeepFlag
    $result | Set-Content -Encoding UTF8 $Report
    Write-Host "Reset demo state $Mode"
    Write-Host "Report: $Report"
    if (-not $Apply) { Write-Host "Dry-run only; no SQLite rows or artifact files changed." }
}
finally { Pop-Location }
