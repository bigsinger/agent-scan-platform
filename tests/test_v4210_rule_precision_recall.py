from pathlib import Path

from assessment.scanning.rules import RULES, analyze_text, rule_catalog


ROOT = Path(__file__).parent / "fixtures" / "rules"
HIGH = ("P0", "P1")


def _high_rule_ids(path: Path) -> set[str]:
    matches = analyze_text(path, path.read_text(encoding="utf-8"), ROOT)
    return {match.rule_id for match in matches if any(level in match.severity for level in HIGH)}


def test_v4210_p0_p1_precision_recall_and_benign_p0_gate():
    expected = {
        "secret.env": {"SECRET-KEY-001"},
        "destructive.sh": {"FLOW-DESTRUCTIVE-001"},
        "danger.mcp.json": {"MCP-CMD-001", "MCP-ENV-001", "MCP-APPROVAL-001", "MCP-SECRET-KEY-001", "SECRET-KEY-001", "FLOW-DESTRUCTIVE-001", "SKILL-CODE-001"},
        "SKILL.md": {"MCP-PI-001", "SKILL-PI-001", "FLOW-DESTRUCTIVE-001", "SKILL-CODE-001", "SKILL-SHELL-001"},
    }
    expected_total = 0
    detected_total = 0
    positive_high_total = 0
    for path in (ROOT / "positive").rglob("*"):
        if not path.is_file():
            continue
        actual = _high_rule_ids(path)
        wanted = expected[path.name]
        expected_total += len(wanted)
        detected_total += len(actual & wanted)
        positive_high_total += len(actual)

    benign_high = []
    benign_p0 = []
    for path in (ROOT / "benign").rglob("*"):
        if not path.is_file():
            continue
        matches = analyze_text(path, path.read_text(encoding="utf-8"), ROOT)
        benign_high.extend(match for match in matches if any(level in match.severity for level in HIGH))
        benign_p0.extend(match for match in matches if "P0" in match.severity)

    recall = detected_total / expected_total
    precision = detected_total / max(1, positive_high_total + len(benign_high))
    assert recall >= 0.90, (recall, detected_total, expected_total)
    assert precision >= 0.95, (precision, positive_high_total, benign_high)
    assert benign_p0 == []


def test_v4210_every_rule_registers_delivery_metadata_and_edge_placeholders_are_safe():
    catalog = {item["id"]: item for item in rule_catalog()}
    assert len(catalog) == len(RULES)
    for rule in RULES:
        item = catalog[rule.id]
        assert item["standards"]
        assert item["false_positive_guidance"]
        assert item["positive_sample"].endswith(f"{rule.id}.txt")
        assert item["benign_sample"].endswith(f"{rule.id}.txt")
    edge = ROOT / "edge" / "placeholder.env"
    assert _high_rule_ids(edge) == set()
