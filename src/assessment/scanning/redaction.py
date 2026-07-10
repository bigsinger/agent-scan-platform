from __future__ import annotations

import hashlib
from pathlib import Path

from ..security import SensitiveDataGuard


def redact_text(value: str, max_len: int = 800) -> str:
    return SensitiveDataGuard.redact_text(value, max_len=max_len)


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
