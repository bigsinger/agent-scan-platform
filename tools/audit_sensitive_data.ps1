param([string]$DataRoot = "", [switch]$Apply)
$ErrorActionPreference = "Stop"
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
  if (-not $DataRoot) { $DataRoot = Join-Path (Get-Location) 'data' }
  $reportDir=Join-Path $DataRoot 'acceptance'; New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
  $report=Join-Path $reportDir 'sensitive-data-audit.json'
  $script=@'
import json,re,sys,sqlite3,hashlib
from pathlib import Path
root=Path(sys.argv[1]); apply=sys.argv[2]=='1'
patterns=[('openai',re.compile(r'sk-[A-Za-z0-9_-]{8,}')),('aws',re.compile(r'AKIA[0-9A-Z]{16}')),('bearer',re.compile(r'(?i)Bearer\s+[A-Za-z0-9._-]{12,}')),('assign',re.compile(r'(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([^\s,;]{6,})'))]
hits=[]
def check(source,text):
 for rid,pat in patterns:
  for m in pat.finditer(text):
   if rid=='assign' and m.lastindex and m.group(2) in {'[REDACTED]','<REDACTED>','<REDACTED_SECRET>'}: continue
   hits.append({'source':source,'rule_id':rid,'fingerprint':hashlib.sha256(m.group(0).encode()).hexdigest()[:16]})
db=root/'db'/'app.db'
if db.exists():
 con=sqlite3.connect(db)
 for (name,) in con.execute("select name from sqlite_master where type='table'"):
  try:
   for row in con.execute(f'select * from "{name}"'):
    check('sqlite:'+name,json.dumps(tuple(row),ensure_ascii=False,default=str))
  except Exception: pass
 con.close()
for p in (root/'artifacts').rglob('*') if (root/'artifacts').exists() else []:
 if p.is_file():
  try: check('artifact:'+str(p.relative_to(root)),p.read_text(encoding='utf-8',errors='ignore'))
  except Exception: pass
print(json.dumps({'schema':'agent-security-sensitive-audit@4.2.10','apply':apply,'hits':hits,'count':len(hits),'raw_values_emitted':False},ensure_ascii=False))
'@
  $ApplyFlag = if ($Apply) { 1 } else { 0 }
  $out=$script | python - $DataRoot $ApplyFlag
  $out | Set-Content -Encoding UTF8 $report
  Write-Host "Sensitive audit report: $report"
  $parsed=$out | ConvertFrom-Json
  if($parsed.count -gt 0){ Write-Error "Sensitive data audit failed: $($parsed.count) hits" }
}
finally { Pop-Location }
