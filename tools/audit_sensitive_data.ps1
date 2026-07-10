[CmdletBinding()]
param([string]$DataRoot = "", [switch]$Apply)

$ErrorActionPreference = "Stop"
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (-not $DataRoot) { $DataRoot = Join-Path (Get-Location) "data" }
    $DataRoot = [IO.Path]::GetFullPath($DataRoot)
    $Python = Join-Path (Get-Location) ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python)) { throw "Project .venv is required. Run uv sync --locked." }
    $env:PYTHONPATH = Join-Path (Get-Location) "src"
    $ReportDir = Join-Path $DataRoot "acceptance"
    New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
    $Report = Join-Path $ReportDir "sensitive-data-audit.json"
    $script = @'
import hashlib, json, shutil, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path
from assessment.security import SensitiveDataGuard

root=Path(sys.argv[1]); apply=sys.argv[2]=='1'
db=root/'db'/'app.db'; artifacts=root/'artifacts'
stamp=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
backup_root=root/'backups'/('sensitive-audit-'+stamp)
hits=[]; rewritten={'sqlite_cells':0,'artifact_files':0}; backup=None

def findings(source, text):
    for item in SensitiveDataGuard.findings(text):
        hits.append({'source':source,'rule_id':item.type,'fingerprint':item.fingerprint,'length':item.length})

if db.exists():
    con=sqlite3.connect(db)
    con.row_factory=sqlite3.Row
    tables=[row[0] for row in con.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'")]
    if apply:
        backup_root.mkdir(parents=True,exist_ok=True)
        backup=backup_root/'app.db'
        target=sqlite3.connect(backup)
        try: con.backup(target)
        finally: target.close()
    for table in tables:
        columns=[row[1] for row in con.execute(f'pragma table_info("{table}")') if str(row[2]).upper() in {'TEXT',''}]
        if not columns: continue
        quoted=', '.join('"'+column.replace('"','""')+'"' for column in columns)
        try: rows=con.execute(f'select rowid, {quoted} from "{table}"').fetchall()
        except sqlite3.DatabaseError: continue
        for row in rows:
            for index,column in enumerate(columns, start=1):
                value=row[index]
                if not isinstance(value,str): continue
                before=len(hits); findings('sqlite:'+table+'.'+column,value)
                if apply and len(hits)>before:
                    safe=SensitiveDataGuard.redact_text(value)
                    con.execute(f'update "{table}" set "{column}"=? where rowid=?',(safe,row[0]))
                    rewritten['sqlite_cells']+=1
    if apply: con.commit()
    con.close()

artifact_paths=sorted(path for path in artifacts.rglob('*') if path.is_file()) if artifacts.exists() else []
for path in artifact_paths:
    try: text=path.read_text(encoding='utf-8')
    except (OSError,UnicodeError): continue
    before=len(hits); findings('artifact:'+str(path.relative_to(root)).replace('\\','/'),text)
    if apply and len(hits)>before:
        destination=backup_root/'artifacts'/path.relative_to(artifacts)
        destination.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(path,destination)
        temporary=path.with_name(path.name+'.sensitive-audit-tmp')
        temporary.write_text(SensitiveDataGuard.redact_text(text),encoding='utf-8')
        temporary.replace(path); rewritten['artifact_files']+=1

remaining=[]
if apply:
    # Re-audit without retaining raw values or duplicate pre-apply hits.
    initial_count=len(hits); hits=[]
    if db.exists():
        con=sqlite3.connect(db)
        for (table,) in con.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%'"):
            try:
                for row in con.execute(f'select * from "{table}"'):
                    findings('sqlite:'+table,json.dumps(tuple(row),ensure_ascii=False,default=str))
            except sqlite3.DatabaseError: pass
        con.close()
    for path in artifact_paths:
        try: findings('artifact:'+str(path.relative_to(root)).replace('\\','/'),path.read_text(encoding='utf-8'))
        except (OSError,UnicodeError): pass
else:
    initial_count=len(hits)

print(json.dumps({
 'schema':'agent-security-sensitive-audit@4.2.10','apply':apply,'initial_count':initial_count,
 'count':len(hits),'hits':hits,'rewritten':rewritten,'backup':str(backup_root) if apply else None,
 'raw_values_emitted':False,'agent_paths_scanned':False,'mutates_installed_agents':False
},ensure_ascii=False))
'@
    $ApplyFlag = if ($Apply) { 1 } else { 0 }
    $Output = $script | & $Python - $DataRoot $ApplyFlag
    if ($LASTEXITCODE -ne 0) { throw "Sensitive data audit process failed" }
    $Output | Set-Content -Encoding UTF8 -LiteralPath $Report
    Write-Host "Sensitive audit report: $Report"
    $Parsed = $Output | ConvertFrom-Json
    if ($Parsed.count -gt 0) { throw "Sensitive data audit failed: $($Parsed.count) hits" }
}
finally { Pop-Location }
