"""Read-only Skill metadata extraction for discovery display.

Never imports or executes Skill code. Reads only SKILL.md text with a size cap.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .redaction import redact_text

MAX_SKILL_MD_BYTES = 256 * 1024
SCRIPT_SUFFIXES = (".py", ".js", ".ts", ".sh", ".ps1", ".bat", ".cmd")


def parse_skill_metadata(skill_md: Path) -> dict[str, Any]:
    skill_root = skill_md.parent
    raw_bytes = b""
    truncated = False
    try:
        raw_bytes = skill_md.read_bytes()
        if len(raw_bytes) > MAX_SKILL_MD_BYTES:
            raw_bytes = raw_bytes[:MAX_SKILL_MD_BYTES]
            truncated = True
    except OSError:
        raw_bytes = b""
    text = raw_bytes.decode("utf-8", errors="replace")
    frontmatter, body = _split_frontmatter(text)
    metadata = _parse_simple_yaml(frontmatter) if frontmatter else {}
    heading = _first_heading(body)
    description = metadata.get("description") or _first_paragraph_after_heading(body) or _preview(body)
    file_count, script_count, network_keywords, shell_keywords, secret_like = _count_files(skill_root)
    name = str(metadata.get("name") or heading or skill_root.name or "unknown-skill").strip()
    tags = metadata.get("tags") or []
    if isinstance(tags, str):
        tags = [part.strip() for part in re.split(r"[, ]+", tags) if part.strip()]
    return {
        "name": redact_text(name, max_len=160),
        "description": redact_text(str(description or ""), max_len=240),
        "version": str(metadata.get("version") or "-").strip() or "-",
        "author": redact_text(str(metadata.get("author") or ""), max_len=120),
        "tags": [redact_text(str(tag), max_len=60) for tag in tags[:20]],
        "entry_file": "SKILL.md",
        "metadata_truncated": truncated,
        "files": file_count,
        "scripts": script_count,
        "has_network_keywords": network_keywords,
        "has_shell_keywords": shell_keywords,
        "has_secret_like_text": secret_like or _has_secret_like(text),
    }


def _split_frontmatter(text: str) -> tuple[str, str]:
    if not text.startswith("---"):
        return "", text
    match = re.match(r"^---\s*\r?\n(.*?)\r?\n---\s*\r?\n?(.*)$", text, re.S)
    if not match:
        return "", text
    return match.group(1), match.group(2)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"\'')
        if value.startswith("[") and value.endswith("]"):
            value = [part.strip().strip('"\'') for part in value[1:-1].split(",") if part.strip()]
        data[key] = value
    return data


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        m = re.match(r"^#\s+(.+?)\s*$", line)
        if m:
            return m.group(1).strip()
    return ""


def _first_paragraph_after_heading(text: str) -> str:
    lines = []
    started = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            started = True
            continue
        if not stripped:
            if lines:
                break
            continue
        if started or not lines:
            if not stripped.startswith(("```", "---")):
                lines.append(stripped)
        if len(" ".join(lines)) > 240:
            break
    return " ".join(lines).strip()


def _preview(text: str) -> str:
    clean = re.sub(r"\s+", " ", text).strip()
    return clean[:160]


def _has_secret_like(text: str) -> bool:
    return bool(re.search(r"token|secret|password|api[_-]?key|authorization|bearer", text, re.I))


def _count_files(root: Path) -> tuple[int, int, bool, bool, bool]:
    file_count = 0
    script_count = 0
    network = False
    shell = False
    secret = False
    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", "node_modules", "__pycache__"} for part in path.parts):
                continue
            file_count += 1
            if path.suffix.lower() in SCRIPT_SUFFIXES:
                script_count += 1
            if path.name == "SKILL.md" or path.suffix.lower() in SCRIPT_SUFFIXES:
                sample = path.read_text(encoding="utf-8", errors="replace")[:8192]
                network = network or bool(re.search(r"\b(curl|wget|requests|httpx|fetch|Invoke-WebRequest)\b", sample, re.I))
                shell = shell or bool(re.search(r"\b(shell|bash|powershell|subprocess|os\.system)\b", sample, re.I))
                secret = secret or _has_secret_like(sample)
            if file_count > 5000:
                break
    except OSError:
        pass
    return file_count, script_count, network, shell, secret
