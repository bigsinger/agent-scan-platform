from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ALLOWED_SCAN_MODES = {"machine", "path", "mcp", "assessment"}


@dataclass(slots=True)
class ScanLimits:
    max_files: int = 2500
    max_file_bytes: int = 1024 * 1024
    max_depth: int = 16


@dataclass(slots=True)
class ScanRequest:
    mode: str = "path"
    target_path: Path | None = None
    adapter: str = "auto"
    include_skills: bool = True
    include_mcp: bool = True
    include_discovery: bool = True
    limits: ScanLimits = field(default_factory=ScanLimits)

    @classmethod
    def from_payload(cls, payload: dict[str, Any], default_path: Path) -> "ScanRequest":
        mode = str(payload.get("mode") or "path").strip().lower()
        if mode not in ALLOWED_SCAN_MODES:
            raise ValueError(f"unsupported quick scan mode: {mode}")
        raw_target = (
            payload.get("target_path")
            or payload.get("path")
            or payload.get("target")
            or payload.get("url")
            or payload.get("workspace")
        )
        if raw_target:
            target = Path(str(raw_target)).expanduser()
        elif mode == "machine":
            target = None
        else:
            target = default_path
        max_files = int(payload.get("max_files") or 2500)
        max_file_bytes = int(payload.get("max_file_bytes") or 1024 * 1024)
        max_depth = int(payload.get("max_depth") or 16)
        return cls(
            mode=mode,
            target_path=target,
            adapter=str(payload.get("adapter") or "auto"),
            include_skills=bool(payload.get("include_skills", True)),
            include_mcp=bool(payload.get("include_mcp", True)),
            include_discovery=bool(payload.get("include_discovery", True)),
            limits=ScanLimits(max_files=max_files, max_file_bytes=max_file_bytes, max_depth=max_depth),
        )


@dataclass(slots=True)
class RuleMatch:
    rule_id: str
    title: str
    severity: str
    category: str
    confidence: float
    remediation: str
    path: Path
    display_path: str
    line: int
    snippet: str
    reason: str
    source: str = "local-static"


@dataclass(slots=True)
class DiscoveryResult:
    run: dict[str, Any]
    hits: list[dict[str, Any]] = field(default_factory=list)
    agents: list[dict[str, Any]] = field(default_factory=list)
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    consents: list[dict[str, Any]] = field(default_factory=list)
    skills: list[dict[str, Any]] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    scan_paths: list[Path] = field(default_factory=list, repr=False)


@dataclass(slots=True)
class ScanResult:
    assessment: dict[str, Any]
    discovery: DiscoveryResult
    findings: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    report: dict[str, Any]
    files_scanned: int
    files_skipped: int
    events: list[dict[str, Any]] = field(default_factory=list)
