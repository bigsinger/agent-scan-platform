from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SensitiveFinding:
    type: str
    fingerprint: str
    length: int
    masked_suffix: str


class SensitiveDataError(ValueError):
    def __init__(self, findings: list[SensitiveFinding]) -> None:
        super().__init__("sensitive data is not safe to persist")
        self.findings = findings


class SensitiveDataGuard:
    """Single redaction and persistence gate for DB rows, artifacts, reports and logs.

    The guard stores only type, hash/fingerprint and length metadata for detected
    secrets. It never returns raw token values in findings.
    """

    PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("openai_key", re.compile(r"sk-[A-Za-z0-9_\-]{8,}")),
        ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("bearer_token", re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{12,}")),
        ("assignment_secret", re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|session|cookie)\b\s*[:=]\s*['\"]?([^'\"\r\n\s,;]{6,})")),
        ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
        ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{16,}")),
        ("gitlab_token", re.compile(r"glpat-[A-Za-z0-9_\-]{16,}")),
        ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
        ("azure_token", re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
        ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}")),
        ("authorization_header", re.compile(r"(?i)(authorization\s*[:=]\s*)[^\s,;]{8,}")),
    ]

    REDACTION = "<REDACTED>"

    @classmethod
    def fingerprint(cls, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]

    @classmethod
    def findings(cls, text: str) -> list[SensitiveFinding]:
        hits: list[SensitiveFinding] = []
        if not text:
            return hits
        for name, pattern in cls.PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(0)
                if name == "assignment_secret" and match.lastindex and match.lastindex >= 2:
                    raw = match.group(2)
                if "REDACTED" in raw or raw.strip().strip('"\'') in {cls.REDACTION, "[REDACTED]", "<REDACTED>", "<REDACTED_SECRET>"}:
                    continue
                hits.append(
                    SensitiveFinding(
                        type=name,
                        fingerprint=cls.fingerprint(raw),
                        length=len(raw),
                        masked_suffix=raw[-4:] if len(raw) >= 4 else "",
                    )
                )
        return hits

    @classmethod
    def redact_text(cls, value: str, max_len: int | None = None) -> str:
        redacted = str(value).replace("\x00", "")
        for name, pattern in cls.PATTERNS:
            if name == "assignment_secret":
                redacted = pattern.sub(lambda m: f"{m.group(1)}={cls.REDACTION}", redacted)
            elif name in {"bearer_token", "authorization_header"}:
                redacted = pattern.sub(cls.REDACTION, redacted)
            else:
                redacted = pattern.sub(cls.REDACTION, redacted)
        if max_len is not None and len(redacted) > max_len:
            return redacted[: max_len - 16] + "...<TRUNCATED>"
        return redacted

    @classmethod
    def sanitize(cls, value: Any) -> Any:
        if isinstance(value, str):
            return cls.redact_text(value)
        if isinstance(value, bytes):
            return cls.redact_text(value.decode("utf-8", errors="replace")).encode("utf-8")
        if isinstance(value, list):
            return [cls.sanitize(item) for item in value]
        if isinstance(value, tuple):
            return [cls.sanitize(item) for item in value]
        if isinstance(value, dict):
            return {str(k): cls.sanitize(v) for k, v in value.items()}
        return value

    @classmethod
    def assert_safe_to_persist(cls, value: Any) -> None:
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        elif isinstance(value, str):
            text = value
        else:
            text = json.dumps(value, ensure_ascii=False, default=str)
        hits = cls.findings(text)
        if hits:
            raise SensitiveDataError(hits)

    @classmethod
    def sanitize_for_persist(cls, value: Any) -> Any:
        sanitized = cls.sanitize(value)
        cls.assert_safe_to_persist(sanitized)
        return sanitized
