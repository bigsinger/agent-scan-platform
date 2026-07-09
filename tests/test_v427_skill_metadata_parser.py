from pathlib import Path

from assessment.scanning.skill_metadata import parse_skill_metadata


def test_v427_skill_metadata_frontmatter_and_counts(tmp_path):
    root = tmp_path / "jwt-skill"
    root.mkdir()
    (root / "SKILL.md").write_text("""---
name: jwt-confusion
version: 1.2.3
description: JWT algorithm confusion testing guidance
author: sec-team
tags: [jwt, security]
---
# Ignored Heading

Body with curl example.
""", encoding="utf-8")
    (root / "scripts").mkdir()
    (root / "scripts" / "check.py").write_text("import requests\n", encoding="utf-8")
    meta = parse_skill_metadata(root / "SKILL.md")
    assert meta["name"] == "jwt-confusion"
    assert meta["description"] == "JWT algorithm confusion testing guidance"
    assert meta["version"] == "1.2.3"
    assert meta["files"] == 2
    assert meta["scripts"] == 1
    assert meta["has_network_keywords"] is True


def test_v427_skill_metadata_heading_and_directory_fallback(tmp_path):
    root = tmp_path / "heading-skill"
    root.mkdir()
    (root / "SKILL.md").write_text("# Heading Skill\n\nFirst useful paragraph.\n", encoding="utf-8")
    meta = parse_skill_metadata(root / "SKILL.md")
    assert meta["name"] == "Heading Skill"
    assert meta["description"] == "First useful paragraph."
    assert meta["version"] == "-"
    empty = tmp_path / "empty-skill"
    empty.mkdir()
    (empty / "SKILL.md").write_text("", encoding="utf-8")
    assert parse_skill_metadata(empty / "SKILL.md")["name"] == "empty-skill"


def test_v427_skill_metadata_redacts_secret_and_truncates(tmp_path):
    root = tmp_path / "secret-skill"
    root.mkdir()
    (root / "SKILL.md").write_text("---\ndescription: use api_key=supersecret123\n---\n" + "A" * (260 * 1024), encoding="utf-8")
    meta = parse_skill_metadata(root / "SKILL.md")
    assert meta["metadata_truncated"] is True
    assert "supersecret123" not in str(meta)
    assert meta["has_secret_like_text"] is True
