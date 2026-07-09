from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "assessment" / "static" / "assessment" / "app.js"
HTML = ROOT / "src" / "assessment" / "static" / "assessment" / "index.html"


def test_v427_discovery_page_has_type_tabs_and_drawer():
    html = HTML.read_text(encoding="utf-8")
    assert "type-tabs" in html
    for label in ["Agent", "Skills", "MCP", "Config"]:
        assert label in html
    assert "discoveryHitDrawerOpen" in html
    assert "selectedDiscoveryHit.display" in html
    assert "mutates_installed_agents=false" in html
    assert "stdio_mcp_started=false" in html


def test_v427_discovery_page_shows_skill_fields_and_search_haystack():
    html = HTML.read_text(encoding="utf-8")
    app = APP.read_text(encoding="utf-8")
    for label in ["名称与摘要", "版本/状态", "关键属性", "路径", "风险/证据"]:
        assert label in html
    for token in ["display.title", "display.subtitle", "display.primary_path", "display.risk_summary"]:
        assert token in app
    assert "openDiscoveryHit" in app
    assert "discoveryActionLabel" in app
