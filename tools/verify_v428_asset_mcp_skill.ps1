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
    Invoke-Step "discovery server query" "$PytestPrefix tests\test_v428_discovery_server_query.py -q"
    Invoke-Step "self-project legacy policy" "$PytestPrefix tests\test_v428_self_project_legacy_policy.py -q"
    Invoke-Step "agent identity normalization" "$PytestPrefix tests\test_v428_agent_identity_normalization.py -q"
    Invoke-Step "test isolation" "$PytestPrefix tests\test_v428_test_isolation.py -q"
    Invoke-Step "mcp skill api contract" "$PytestPrefix tests\test_v428_mcp_skill_api_contract.py -q"
    Invoke-Step "mcp static consent e2e" "$PytestPrefix tests\test_v428_mcp_static_consent_e2e.py -q"
    Invoke-Step "skill scan detail e2e" "$PytestPrefix tests\test_v428_skill_scan_detail_e2e.py -q"
    Invoke-Step "agent scan mapping e2e" "$PytestPrefix tests\test_v428_agent_scan_mapping_e2e.py -q"
    Invoke-Step "abom adapter e2e" "$PytestPrefix tests\test_v428_abom_adapter_e2e.py -q"
    Invoke-Step "mcp skill rules" "$PytestPrefix tests\test_v428_mcp_skill_rules.py -q"
    Invoke-Step "docs command hygiene" "$PytestPrefix tests\test_v428_docs_command_hygiene.py -q"
    Invoke-Step "full test suite" "$PytestPrefix -q"
    Write-Host "`nv4.2.8 asset/mcp/skill acceptance verification passed"
}
finally { Pop-Location }
