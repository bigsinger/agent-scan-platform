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
    run_local_analyzers: bool = True
    use_existing_sca: bool = False
    remote_analysis_requested: bool = False
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
            include_skills=flag(payload, ("include_skills", "scan_skills", "scanSkills"), True),
            include_mcp=flag(payload, ("include_mcp", "scan_mcp", "scanMcp"), True),
            include_discovery=flag(payload, ("include_discovery", "run_discovery", "runDiscovery"), True),
            run_local_analyzers=flag(payload, ("run_local_analyzers", "local_analyzers", "runLocalAnalyzers"), True),
            use_existing_sca=flag(payload, ("use_existing_sca", "invoke_existing_sca", "useExistingSca"), False),
            remote_analysis_requested=flag(payload, ("remote_analysis_requested", "remoteAnalysisRequested", "remote_analysis", "remoteAnalysis", "cloud_analysis"), False),
            limits=ScanLimits(max_files=max_files, max_file_bytes=max_file_bytes, max_depth=max_depth),
        )

    @property
    def scan_options(self) -> dict[str, Any]:
        cloud_status = "OPTIONAL_DISABLED" if self.remote_analysis_requested else "DISABLED"
        return {
            "scan_skills": self.include_skills,
            "include_skills": self.include_skills,
            "include_mcp": self.include_mcp,
            "include_discovery": self.include_discovery,
            "run_local_analyzers": self.run_local_analyzers,
            "use_existing_sca": self.use_existing_sca,
            "external_sca_executed": False,
            "remote_analysis_requested": self.remote_analysis_requested,
            "remote_analysis": False,
            "cloud_analysis_status": cloud_status,
            "mutates_installed_agents": False,
        }


def flag(payload: dict[str, Any], keys: tuple[str, ...], default: bool) -> bool:
    for key in keys:
        if key not in payload:
            continue
        value = payload.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "y", "on", "enabled", "开启"}:
                return True
            if normalized in {"0", "false", "no", "n", "off", "disabled", "关闭"}:
                return False
        return bool(value)
    return default


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
