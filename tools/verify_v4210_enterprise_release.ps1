[CmdletBinding()]
param([switch]$SkipBrowserInstall)

$ErrorActionPreference = "Stop"
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $Project = Get-Location
    $Python = Join-Path $Project ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python)) { throw "Project .venv is required. Run uv sync --locked." }
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw "uv is required for the release test dependency environment." }
    $RunRoot = Join-Path ([IO.Path]::GetTempPath()) ("agent-scan-v4210-" + [guid]::NewGuid().ToString("N"))
    $DataRoot = Join-Path $RunRoot "data"
    $JunitRoot = Join-Path $DataRoot "acceptance\junit"
    $BrowserRoot = Join-Path $DataRoot "acceptance\browser"
    $FinalE2eResult = Join-Path $DataRoot "acceptance\latest-e2e-result.json"
    $PendingE2eResult = Join-Path $DataRoot "acceptance\.pending-e2e-result.json"
    New-Item -ItemType Directory -Force -Path $JunitRoot, $BrowserRoot | Out-Null
    $env:ASSESSMENT_DB_PATH = Join-Path $DataRoot "db\app.db"
    $env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $DataRoot "artifacts"
    $env:ASSESSMENT_STATE_ROOT = $DataRoot
    $env:ASSESSMENT_DISABLE_BACKGROUND_JOBS = "true"
    $env:ASSESSMENT_E2E_RESULT_PATH = $PendingE2eResult
    $env:ASSESSMENT_BROWSER_RESULT_ROOT = $BrowserRoot
    $env:ASSESSMENT_LISTEN_HOST = "127.0.0.1"
    $env:PYTHONPATH = Join-Path $Project "src"
    Write-Host "v4.2.10 isolated run root: $RunRoot"

    function Invoke-Step([string]$Name, [scriptblock]$Action) {
        Write-Host "`n==> $Name" -ForegroundColor Cyan
        & $Action
        if ($LASTEXITCODE -ne 0) { throw "Step failed: $Name (exit=$LASTEXITCODE)" }
    }

    function Get-ProtectedFingerprint {
        $script = @'
import hashlib, json, os
from pathlib import Path
root=Path.cwd()
paths=[root/'data'/'db'/'app.db', root/'data'/'db'/'app.db-wal', root/'data'/'db'/'app.db-shm', Path.home()/'.codex'/'config.toml']
local=Path(os.environ.get('LOCALAPPDATA',''))
paths += [local/'hermes'/'config.yaml', Path.home()/'.hermes'/'config.yaml', Path.home()/'.hermes'/'config.yml']
artifact=root/'data'/'artifacts'
if artifact.exists(): paths += sorted(p for p in artifact.rglob('*') if p.is_file())
rows=[]
for path in paths:
 if not path.is_file(): continue
 try: digest=hashlib.sha256(path.read_bytes()).hexdigest()
 except OSError: continue
 try: name=str(path.relative_to(root))
 except ValueError: name='<agent-home>/'+path.name
 rows.append({'path':name.replace('\\','/'),'size':path.stat().st_size,'sha256':digest})
print(hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest())
'@
        return ($script | & $Python -).Trim()
    }

    $ProtectedBefore = Get-ProtectedFingerprint
    Invoke-Step "locked dependency graph" { & uv lock --check }
    Invoke-Step "python syntax" { & $Python -m py_compile src\assessment\api\v1.py src\assessment\main.py src\assessment\store.py src\assessment\security.py src\assessment\observability\receiver.py src\assessment\observability\storage.py src\assessment\scanning\scanner.py src\assessment\scanning\jobs.py src\assessment\probes\hermes\hermes_probe_plugin.py tools\generate_acceptance_result.py }
    Invoke-Step "node syntax" { & node --check src\assessment\static\assessment\app.js }
    Invoke-Step "frontend offline" { & $Python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58 }
    if (-not $SkipBrowserInstall) {
        Invoke-Step "install Playwright Chromium" { & uv run --with playwright python -m playwright install chromium }
    }
    $BrowserJunit = Join-Path $JunitRoot "browser.xml"
    Invoke-Step "eight real browser journeys" { & uv run --with pytest --with playwright --with httpx2 python -m pytest tests\browser -q --junitxml=$BrowserJunit }
    $FullJunit = Join-Path $JunitRoot "pytest.xml"
    Invoke-Step "full non-browser pytest" { & uv run --with pytest --with httpx2 python -m pytest tests --ignore=tests\browser -q --junitxml=$FullJunit }
    Invoke-Step "generate JUnit-bound acceptance result" { & $Python tools\generate_acceptance_result.py --junit $BrowserJunit --junit $FullJunit --browser-root $BrowserRoot --expected-screenshots 8 --output $env:ASSESSMENT_E2E_RESULT_PATH }

    Write-Host "`n==> completeness gate" -ForegroundColor Cyan
    $completeness = @'
import asyncio
from assessment.api.v1 import completeness_runtime_rows, completeness_summary, version
from assessment.store import get_store
get_store().initialize()
summary=completeness_summary(completeness_runtime_rows())
print(summary)
assert summary['pages']==58
assert summary['audit_passed']==58
assert summary['contract_passed']==58
assert summary['e2e_passed']==58
assert summary['gaps']==0
release=asyncio.run(version())
assert release['app']=='4.2.10' and release['spec']=='V4.2.10'
'@
    $completeness | & $Python -
    if ($LASTEXITCODE -ne 0) { throw "completeness assertion failed" }

    $LiveAcceptance = Join-Path $DataRoot "acceptance\live-machine-readonly.json"
    $LiveRuntime = Join-Path $DataRoot "live-machine-runtime"
    $env:ASSESSMENT_LIVE_MACHINE_RESULT_PATH = $LiveAcceptance
    $env:ASSESSMENT_LIVE_SENSITIVE_AUDIT_PATH = Join-Path $LiveRuntime "acceptance\sensitive-data-audit.json"
    Write-Host "`n==> live machine read-only discovery and bounded config scans" -ForegroundColor Cyan
    $liveMachine = @'
import hashlib, json, os, sys, time
from datetime import datetime, timezone
from pathlib import Path
runtime=Path(sys.argv[1])
os.environ['ASSESSMENT_DB_PATH']=str(runtime/'db'/'app.db')
os.environ['ASSESSMENT_STATE_ROOT']=str(runtime)
os.environ['ASSESSMENT_ARTIFACT_ROOT']=str(runtime/'artifacts')
os.environ['ASSESSMENT_DISABLE_BACKGROUND_JOBS']='true'
os.environ['ASSESSMENT_LISTEN_HOST']='127.0.0.1'
from assessment.scanning import LocalScanEngine
from assessment.security import SensitiveDataGuard
from assessment.store import get_store

store=get_store()
store.initialize()
engine=LocalScanEngine(store)
started=time.perf_counter()
discovery=engine.run_discovery({'scope':'current-user','probe_installed':True})
discovery_seconds=time.perf_counter()-started
agents={str(agent.get('adapter') or '').strip().lower():agent for agent in discovery.agents}
assert 'codex' in agents, 'Installed Codex was not discovered'
assert 'hermes' in agents, 'Installed Hermes was not discovered'
assert discovery.run.get('mutates_installed_agents') is False
assert discovery.run.get('stdio_mcp_started') is False
assert discovery.run.get('agent_runtime_started') is False

machine_payload={
    'mode':'machine', 'max_files':300, 'max_file_bytes':262144,
    'max_depth':12, 'execution_mode':'readonly',
}
started=time.perf_counter()
cold=engine.run_quick_scan(machine_payload)
cold_seconds=time.perf_counter()-started
artifact_count_before_warm=len(store.list_records('artifact',limit=5000))
started=time.perf_counter()
warm=engine.run_quick_scan(machine_payload)
warm_seconds=time.perf_counter()-started
artifact_count_after_warm=len(store.list_records('artifact',limit=5000))
occurrences=int(warm.assessment.get('occurrence_count') or 0)
reused=int(warm.assessment.get('reused_evidence_count') or 0)
cache_hits=int(warm.assessment.get('static_cache_hits') or 0)
assert cold_seconds <= 120, f'300-file cold scan exceeded budget: {cold_seconds:.3f}s'
assert warm_seconds <= 30, f'300-file unchanged rescan exceeded budget: {warm_seconds:.3f}s'
assert warm.files_scanned == 300
assert len(warm.findings) < occurrences
assert cache_hits >= int(warm.files_scanned * 0.95)
assert reused >= int(len(warm.evidence) * 0.95)
assert artifact_count_after_warm-artifact_count_before_warm <= 2+(len(warm.evidence)-reused)
if warm.assessment.get('stage')=='WAITING_CONSENT':
    assert int(warm.assessment.get('progress') or 0) < 100
else:
    assert int(warm.assessment.get('progress') or 0) == 100

def candidate(adapter):
    token='.codex' if adapter=='codex' else 'hermes'
    preferred=[]
    for path in discovery.scan_paths:
        path=Path(path)
        raw=str(path).lower()
        if token not in raw or not path.is_file():
            continue
        score=(0 if path.name.lower().startswith('config.') else 1, len(path.parts), len(str(path)))
        preferred.append((score,path))
    assert preferred, f'No readable {adapter} configuration was discovered'
    return sorted(preferred,key=lambda row:row[0])[0][1]

scans=[]
for adapter in ('codex','hermes'):
    path=candidate(adapter)
    before=hashlib.sha256(path.read_bytes()).hexdigest()
    scan=engine.run_quick_scan({
        'mode':'path', 'target_path':str(path), 'max_files':20,
        'max_file_bytes':262144, 'max_depth':4, 'include_skills':False,
        'include_mcp':True, 'execution_mode':'readonly',
    })
    after=hashlib.sha256(path.read_bytes()).hexdigest()
    assert before==after, f'{adapter} configuration changed during read-only scan'
    assert scan.files_scanned >= 1
    assert scan.report.get('id')
    assert scan.assessment.get('mutates_installed_agents') is False
    assert scan.assessment.get('stdio_mcp_started') is False
    assert scan.assessment.get('agent_runtime_started') is False
    scans.append({
        'adapter':adapter, 'config_unchanged':True,
        'files_scanned':scan.files_scanned, 'files_skipped':scan.files_skipped,
        'findings':len(scan.findings), 'evidence':len(scan.evidence),
        'assessment_status':scan.assessment.get('status'),
        'report_status':scan.report.get('status'),
    })

payload={
    'schema':'agent-security-live-machine-readonly@4.2.10',
    'generated_at':datetime.now(timezone.utc).isoformat(),
    'status':'PASS',
    'agents':[{
        'adapter':adapter,
        'name':agents[adapter].get('name'),
        'version':agents[adapter].get('version') or '-',
    } for adapter in ('codex','hermes')],
    'discovery':{
        'hits':len(discovery.hits), 'skills':len(discovery.skills),
        'mcp_servers':len(discovery.mcp_servers), 'errors':len(discovery.errors),
        'elapsed_seconds':round(discovery_seconds,3),
    },
    'machine_scan':{
        'cold_seconds':round(cold_seconds,3), 'warm_seconds':round(warm_seconds,3),
        'files_scanned':warm.files_scanned, 'logical_findings':len(warm.findings),
        'occurrences':occurrences, 'evidence':len(warm.evidence),
        'reused_evidence':reused, 'static_cache_hits':cache_hits,
        'artifact_growth_on_rescan':artifact_count_after_warm-artifact_count_before_warm,
        'assessment_status':warm.assessment.get('status'),
        'stage':warm.assessment.get('stage'), 'progress':warm.assessment.get('progress'),
        'report_status':warm.report.get('status'),
    },
    'scans':scans,
    'safety':{
        'mutates_installed_agents':False, 'stdio_mcp_started':False,
        'agent_runtime_started':False, 'config_hashes_unchanged':True,
    },
}
payload=SensitiveDataGuard.sanitize_for_persist(payload)
Path(sys.argv[2]).write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(payload,ensure_ascii=False))
'@
    $liveMachine | & $Python - $LiveRuntime $LiveAcceptance
    if ($LASTEXITCODE -ne 0) { throw "live machine read-only acceptance failed" }

    Invoke-Step "owned service lifecycle and foreign process safety" { & powershell -NoProfile -ExecutionPolicy Bypass -File tools\test_service_ownership.ps1 -IncludeOwnedLifecycle }
    Invoke-Step "sensitive data audit (isolated test runtime)" { & powershell -NoProfile -ExecutionPolicy Bypass -File tools\audit_sensitive_data.ps1 -DataRoot $DataRoot }
    Invoke-Step "sensitive data audit (live machine runtime)" { & powershell -NoProfile -ExecutionPolicy Bypass -File tools\audit_sensitive_data.ps1 -DataRoot $LiveRuntime }

    Write-Host "`n==> delivery package" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File tools\export_final_delivery_package.ps1 -OutputRoot (Join-Path $RunRoot "delivery")
    if ($LASTEXITCODE -ne 0) { throw "delivery export failed" }
    $Zip = Get-ChildItem -LiteralPath (Join-Path $RunRoot "delivery") -Filter "agent-security-assessment-v4.2.10-*.zip" -File | Select-Object -First 1
    if (-not $Zip) { throw "delivery zip not found" }
    Invoke-Step "verify delivery package and wheel smoke" { & powershell -NoProfile -ExecutionPolicy Bypass -File tools\verify_delivery_package.ps1 -PackagePath $Zip.FullName }

    $ProtectedAfter = Get-ProtectedFingerprint
    if ($ProtectedAfter -ne $ProtectedBefore) { throw "Formal data or installed Agent configuration changed during isolated acceptance." }
    Move-Item -LiteralPath $PendingE2eResult -Destination $FinalE2eResult -Force
    $env:ASSESSMENT_E2E_RESULT_PATH = $FinalE2eResult
    Write-Host "`nv4.2.10 enterprise release gate verification passed" -ForegroundColor Green
    Write-Host "acceptance_result=$env:ASSESSMENT_E2E_RESULT_PATH"
    Write-Host "live_machine_result=$LiveAcceptance"
    Write-Host "delivery_package=$($Zip.FullName)"
    Write-Host "protected_fingerprint=$ProtectedAfter"
}
finally { Pop-Location }
