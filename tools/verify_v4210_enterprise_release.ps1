$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    function Invoke-Step($Name, $Command) {
        Write-Host "`n==> $Name"
        Write-Host $Command
        cmd /c $Command
        if ($LASTEXITCODE -ne 0) { throw "Step failed: $Name" }
    }

    $RunRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("agent-scan-v4210-" + [guid]::NewGuid().ToString("N"))
    $env:ASSESSMENT_DB_PATH = Join-Path $RunRoot "app.db"
    $env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $RunRoot "artifacts"
    $env:ASSESSMENT_STATE_ROOT = Join-Path $RunRoot "state"
    $env:ASSESSMENT_DISABLE_BACKGROUND_JOBS = "true"
    $env:ASSESSMENT_E2E_RESULT_PATH = Join-Path $RunRoot "latest-e2e-result.json"
    $env:PYTHONPATH = ""
    New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
    Write-Host "v4.2.10 isolated run root: $RunRoot"

    $PytestPrefix = "python -m pytest"
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) { $PytestPrefix = "uv run --with pytest --with httpx2 python -m pytest" }

    Invoke-Step "python syntax" "python -m py_compile src\assessment\api\v1.py src\assessment\main.py src\assessment\store.py src\assessment\security.py src\assessment\observability\receiver.py src\assessment\observability\api.py src\assessment\scanning\scanner.py"
    Invoke-Step "node syntax" "node --check src\assessment\static\assessment\app.js"
    Invoke-Step "frontend offline" "python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58"
    Invoke-Step "browser journeys" "uv run --with pytest --with playwright python -m pytest tests\browser -q"
    Invoke-Step "generate acceptance result" "uv run --with pytest --with httpx2 python tools\generate_acceptance_result.py --browser-root data\acceptance\browser --output $env:ASSESSMENT_E2E_RESULT_PATH"
    Invoke-Step "v4210 security and release tests" "$PytestPrefix tests\test_v4210_sensitive_data_guard.py tests\test_v4210_completeness_result_binding.py tests\test_v4210_auth_policy.py tests\test_v4210_finding_rollup.py tests\test_v4210_task_state_machine.py tests\test_v4210_reset_and_delivery.py tests\test_v4210_service_script_safety.py tests\test_v4210_probe_capability_lifecycle.py tests\test_v4210_otel_receiver_hardening.py -q"
    Invoke-Step "service ownership" "powershell -ExecutionPolicy Bypass -File tools\test_service_ownership.ps1"
    Invoke-Step "sensitive audit" "powershell -ExecutionPolicy Bypass -File tools\audit_sensitive_data.ps1 -DataRoot $RunRoot"
    Invoke-Step "pytest api contract" "$PytestPrefix tests\\test_api_contract.py -q"
    Invoke-Step "pytest frontend and real scans" "$PytestPrefix tests\\test_frontend_static.py tests\\test_real_scan_pipeline.py -q"
    Invoke-Step "pytest v4210-v426" "$PytestPrefix tests\\test_v4210_auth_policy.py tests\\test_v4210_completeness_result_binding.py tests\\test_v4210_finding_rollup.py tests\\test_v4210_otel_receiver_hardening.py tests\\test_v4210_probe_capability_lifecycle.py tests\\test_v4210_reset_and_delivery.py tests\\test_v4210_sensitive_data_guard.py tests\\test_v4210_service_script_safety.py tests\\test_v4210_task_state_machine.py tests\\test_v425_observability_e2e.py tests\\test_v426_behavior_anomaly_rules.py tests\\test_v426_observability_pages.py tests\\test_v426_otel_receiver_ingestion.py tests\\test_v426_probe_install_safety.py tests\\test_v426_scan_scope_policy.py -q"
    Invoke-Step "pytest v427-v428" "$PytestPrefix tests\\test_v427_core_local_assessment_flow.py tests\\test_v427_discovery_display_contract.py tests\\test_v427_discovery_export_display.py tests\\test_v427_discovery_page_static.py tests\\test_v427_skill_metadata_parser.py tests\\test_v428_abom_adapter_e2e.py tests\\test_v428_agent_identity_normalization.py tests\\test_v428_agent_scan_mapping_e2e.py tests\\test_v428_discovery_server_query.py tests\\test_v428_docs_command_hygiene.py tests\\test_v428_mcp_skill_api_contract.py tests\\test_v428_mcp_skill_rules.py tests\\test_v428_mcp_static_consent_e2e.py tests\\test_v428_self_project_legacy_policy.py tests\\test_v428_skill_scan_detail_e2e.py tests\\test_v428_test_isolation.py -q"
    Invoke-Step "pytest v429 group A" "$PytestPrefix tests\\test_v429_admin_operations_e2e.py tests\\test_v429_api_alias_contract.py tests\\test_v429_browser_journeys.py tests\\test_v429_dashboard_create_profiles_e2e.py -q"
    Invoke-Step "pytest v429 group B" "$PytestPrefix tests\\test_v429_detail_pages_e2e.py tests\\test_v429_result_closure_e2e.py tests\\test_v429_security_boundary.py tests\\test_v429_task_execution_redteam_e2e.py -q"
    Invoke-Step "v429 isolation smoke" "$PytestPrefix tests\\test_v429_test_isolation.py -q"

    Write-Host "`n==> completeness gate"
    @'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
summary = client.get('/api/v1/completeness?page_size=200').json()['summary']
print(summary)
assert summary['pages'] == 58
assert summary['audit_passed'] == 58
assert summary['contract_passed'] == 58
assert summary['e2e_passed'] == 58
assert summary['gaps'] == 0
version = client.get('/api/v1/version').json()
print(version)
assert version['app'] == '4.2.10'
assert version['spec'] == 'V4.2.10'
'@ | python -
    if ($LASTEXITCODE -ne 0) { throw "completeness assertion failed" }

    Write-Host "`n==> delivery package"
    powershell -ExecutionPolicy Bypass -File tools\export_final_delivery_package.ps1 -OutputRoot (Join-Path $RunRoot "delivery")
    if ($LASTEXITCODE -ne 0) { throw "delivery export failed" }
    $Zip = Get-ChildItem (Join-Path $RunRoot "delivery") -Filter "agent-security-assessment-v4.2.10-*.zip" | Select-Object -First 1
    if (-not $Zip) { throw "delivery zip not found" }
    powershell -ExecutionPolicy Bypass -File tools\verify_delivery_package.ps1 -PackagePath $Zip.FullName
    if ($LASTEXITCODE -ne 0) { throw "delivery verify failed" }

    Write-Host "`nv4.2.10 enterprise release gate verification passed"
}
finally {
    Pop-Location
}
