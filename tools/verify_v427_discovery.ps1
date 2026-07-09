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
        $env:PYTHONPATH = ""
    }
    Invoke-Step "node syntax check" "node --check src\assessment\static\assessment\app.js"
    Invoke-Step "frontend offline check" "python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58"
    Invoke-Step "v4.2.7 skill metadata" "$PytestPrefix tests\test_v427_skill_metadata_parser.py -q"
    Invoke-Step "v4.2.7 discovery display" "$PytestPrefix tests\test_v427_discovery_display_contract.py -q"
    Invoke-Step "v4.2.7 discovery page static" "$PytestPrefix tests\test_v427_discovery_page_static.py -q"
    Invoke-Step "v4.2.7 discovery export" "$PytestPrefix tests\test_v427_discovery_export_display.py -q"
    Invoke-Step "v4.2.7 core local assessment flow" "$PytestPrefix tests\test_v427_core_local_assessment_flow.py -q"
    Invoke-Step "full test suite" "$PytestPrefix -q"
    Write-Host "`nv4.2.7 discovery acceptance verification passed"
}
finally {
    Pop-Location
}
