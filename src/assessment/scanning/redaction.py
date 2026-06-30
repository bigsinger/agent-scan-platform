from __future__ import annotations

import hashlib
import re
from pathlib import Path


SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{16,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s,;]{8,})"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]


def redact_text(value: str, max_len: int = 800) -> str:
    redacted = value.replace("\x00", "")
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(lambda m: f"{m.group(1)}=<REDACTED>", redacted)
        elif pattern.groups == 1:
            redacted = pattern.sub(lambda m: f"{m.group(1)}<REDACTED>", redacted)
        else:
            redacted = pattern.sub("<REDACTED_SECRET>", redacted)
    redacted = re.sub(r"(?i)(authorization:\s*)(?:bearer\s+)?[A-Za-z0-9._\-]{16,}", r"\1<REDACTED>", redacted)
    if len(redacted) > max_len:
        return redacted[: max_len - 16] + "...<TRUNCATED>"
    return redacted


def safe_display_path(path: Path, root: Path | None = None) -> str:
    resolved = path.resolve()
    if root:
        try:
            return "<target>/" + resolved.relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    home = Path.home().resolve()
    try:
        return "~/" + resolved.relative_to(home).as_posix()
    except ValueError:
        return "<external>/" + resolved.name


def stable_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
