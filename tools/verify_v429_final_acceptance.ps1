$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    function Invoke-Step($Name, $Command) {
        Write-Host "`n==> $Name"
        Write-Host $Command
        cmd /c $Command
        if ($LASTEXITCODE -ne 0) { throw "Step failed: $Name" }
    }

    $RunRoot = Join-Path $env:TEMP ("agent-scan-v429-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
    $env:ASSESSMENT_DB_PATH = Join-Path $RunRoot "app.db"
    $env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $RunRoot "artifacts"
    $env:ASSESSMENT_STATE_ROOT = Join-Path $RunRoot "state"
    $env:ASSESSMENT_DISABLE_BACKGROUND_JOBS = "true"
    $env:PYTHONPATH = ""
    Write-Host "v4.2.9 isolated run root: $RunRoot"

    $PytestPrefix = "python -m pytest"
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) { $PytestPrefix = "uv run --with pytest --with httpx2 python -m pytest" }

    Invoke-Step "node syntax check" "node --check src\assessment\static\assessment\app.js"
    Invoke-Step "frontend offline check" "python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58"
    Invoke-Step "dashboard create profiles" "$PytestPrefix tests\test_v429_dashboard_create_profiles_e2e.py -q"
    Invoke-Step "task execution redteam" "$PytestPrefix tests\test_v429_task_execution_redteam_e2e.py -q"
    Invoke-Step "result closure" "$PytestPrefix tests\test_v429_result_closure_e2e.py -q"
    Invoke-Step "admin operations" "$PytestPrefix tests\test_v429_admin_operations_e2e.py -q"
    Invoke-Step "detail pages" "$PytestPrefix tests\test_v429_detail_pages_e2e.py -q"
    Invoke-Step "api aliases" "$PytestPrefix tests\test_v429_api_alias_contract.py -q"
    Invoke-Step "security boundary" "$PytestPrefix tests\test_v429_security_boundary.py -q"
    Invoke-Step "browser journeys" "$PytestPrefix tests\test_v429_browser_journeys.py -q"
    Invoke-Step "test isolation" "$PytestPrefix tests\test_v429_test_isolation.py -q"
    Invoke-Step "full test suite" "$PytestPrefix -q"

    $env:PYTHONPATH = "src"
    @'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
summary = payload['summary']
print(summary)
assert summary['pages'] == 58
assert summary['audit_passed'] == 58
assert summary['contract_passed'] == 58
assert summary['e2e_passed'] == 58
assert summary['gaps'] == 0
'@ | python -
    if ($LASTEXITCODE -ne 0) { throw "completeness assertion failed" }
    Write-Host "`nv4.2.9 final acceptance verification passed"
    Write-Host "Run root: $RunRoot"
}
finally { Pop-Location }
