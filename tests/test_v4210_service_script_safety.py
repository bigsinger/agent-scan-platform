from pathlib import Path


def test_v4210_service_scripts_do_not_kill_by_port():
    start = Path('start_services.ps1').read_text(encoding='utf-8')
    stop = Path('stop_services.ps1').read_text(encoding='utf-8')
    assert 'Stop-Process -Id $procId' not in start
    assert 'Get-NetTCPConnection -LocalPort $Port' in start
    assert 'refusing to stop or replace a non-owned process' in start
    assert 'identity validation failed; refusing to stop' in stop
    assert 'services.json' in start and 'services.json' in stop
    assert '.venv\\Scripts\\python.exe' in start
    assert 'command_line_hash' in start and 'process_start_time' in stop
    assert '-MainPort' in start or '$MainPort' in start
    assert '-OtelPort' in start or '$OtelPort' in start
