from pathlib import Path


def test_v428_docs_have_no_vertical_tabs_or_bash_heredoc():
    bad = []
    heredoc = []
    for path in Path('doc').rglob('*.md'):
        data = path.read_bytes()
        if bytes([11]) in data:
            bad.append(str(path))
        text = data.decode('utf-8', errors='replace')
        if "python - <<'PY'" in text:
            heredoc.append(str(path))
    assert not bad
    assert not heredoc
    spec = Path('doc/SPEC_VALIDATION.md').read_text(encoding='utf-8')
    assert 'powershell -ExecutionPolicy Bypass -File tools\\verify_v428_asset_mcp_skill.ps1' in spec
