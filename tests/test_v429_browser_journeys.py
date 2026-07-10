from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_browser_release_suite_contains_eight_real_journeys_and_no_placeholder():
    source = (ROOT / "tests" / "browser" / "test_enterprise_journeys.py").read_text(encoding="utf-8")
    for index in range(1, 9):
        assert f"def test_j{index:02d}_" in source
    assert "journey-placeholder" not in source
    assert "pytest.skip" not in source
    assert ".screenshot(" in source
    assert "expect_response" in source
