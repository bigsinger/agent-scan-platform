$ErrorActionPreference = "Stop"

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    function Invoke-Step($Name, $Command) {
        Write-Host "`n==> $Name"
        Write-Host $Command
        cmd /c $Command
        if ($LASTEXITCODE -ne 0) { throw "Step failed: $Name" }
    }

    $PytestPrefix = "python -m pytest"
    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if ($uv) {
        $PytestPrefix = "uv run --with pytest --with httpx2 python -m pytest"
    }

    Invoke-Step "node syntax check" "node --check src\assessment\static\assessment\app.js"
    Invoke-Step "frontend offline check" "python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58"

    if ($uv) {
        $env:PYTHONPATH = ""
    }

    Invoke-Step "v4.2.6 otel receiver ingestion" "$PytestPrefix tests\test_v426_otel_receiver_ingestion.py -q"
    Invoke-Step "v4.2.6 behavior anomaly rules" "$PytestPrefix tests\test_v426_behavior_anomaly_rules.py -q"
    Invoke-Step "v4.2.6 probe install safety" "$PytestPrefix tests\test_v426_probe_install_safety.py -q"
    Invoke-Step "v4.2.6 scan scope policy" "$PytestPrefix tests\test_v426_scan_scope_policy.py -q"
    Invoke-Step "v4.2.6 observability pages" "$PytestPrefix tests\test_v426_observability_pages.py -q"
    Invoke-Step "legacy 48/58 regression tests" "$PytestPrefix tests\test_api_contract.py::test_all_spec_pages_have_completeness_rows tests\test_frontend_static.py::test_frontend_seed_fallback_does_not_ship_prototype_runtime_data -q"
    Invoke-Step "full test suite" "$PytestPrefix -q"

    Write-Host "`nv4.2.6 acceptance verification passed"
}
finally {
    Pop-Location
}
