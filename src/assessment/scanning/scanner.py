from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse, urlunparse

from ..reports import ReportRenderer
from ..store import AssessmentStore, REPO_ROOT, new_id, utc_now
from .discovery import DiscoveryEngine, extract_mcp_servers, strip_json_comments
from .mcp_static import derive_mcp_tools, highest_mcp_risk, mcp_static_risks, sanitize_mcp_server, tool_flows
from .models import DiscoveryResult, RuleMatch, ScanRequest, ScanResult, effective_user_scope, flag, normalize_user_scope
from .redaction import file_digest, redact_text, safe_display_path, stable_hash
from .rules import analyze_text, rule_catalog
from .scope import (
    filter_self_project_dirs,
    may_contain_self_test_asset,
    self_project_scope,
    should_skip_self_project_path,
)


SCAN_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".toml",
    ".yaml",
    ".yml",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".env",
    ".ini",
    ".cfg",
    ".xml",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "data",
    "logs",
    ".mypy_cache",
    ".ruff_cache",
}

RULE_CACHE_VERSION = file_digest(Path(__file__).with_name("rules.py"))


class ScanCancelled(RuntimeError):
    """Raised at a bounded read checkpoint after a scan cancellation request."""


class LocalScanEngine:
    def __init__(
        self,
        store: AssessmentStore,
        *,
        progress_callback: Callable[[str, int, dict[str, Any]], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        self.store = store
        self.discovery = DiscoveryEngine()
        self.reporter = ReportRenderer(store)
        self.progress_callback = progress_callback
        self.cancel_check = cancel_check

    def _checkpoint(self, stage: str, progress: int, **details: Any) -> None:
        if self.cancel_check and self.cancel_check():
            raise ScanCancelled("scan cancellation requested")
        if self.progress_callback:
            self.progress_callback(stage, max(0, min(int(progress), 99)), details)

    def run_quick_scan(self, payload: dict[str, Any]) -> ScanResult:
        request = ScanRequest.from_payload(payload, default_path=REPO_ROOT)
        return self.run_assessment(request, name="快速扫描", assessment_id=str(payload.get("_assessment_id") or "") or None)

    def precheck_quick_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = ScanRequest.from_payload(payload, default_path=REPO_ROOT)
        mode = request.mode
        if mode == "machine" and request.target_path is None:
            discovery = self.discovery.discover(None, scope=request.scan_options["effective_user_scope"])
            self._apply_request_options(discovery, request)
            return {
                "status": "PASS" if discovery.hits else "EMPTY",
                "mode": mode,
                "target": "本机 Agent 配置",
                "readable": True,
                "agents": len(discovery.agents),
                "configs": len([hit for hit in discovery.hits if hit.get("type") in {"Config", "MCP"}]),
                "mcp_servers": len(discovery.mcp_servers),
                "skills": len(discovery.skills),
                "scan_files": len(discovery.scan_paths) if request.run_local_analyzers else 0,
                "candidate_scan_files": len(discovery.scan_paths),
                "scan_options": request.scan_options,
                "remote_analysis": False,
                "remote_analysis_requested": request.remote_analysis_requested,
                "cloud_analysis_status": request.scan_options["cloud_analysis_status"],
                "mutates_installed_agents": False,
                "user_scope": request.user_scope,
                "user_scope_requested": request.user_scope,
                "effective_user_scope": request.scan_options["effective_user_scope"],
                "execution_mode": request.execution_mode,
                "effective_execution_mode": request.scan_options["effective_execution_mode"],
                "mcp_policy": request.scan_options["mcp_policy"],
                "stdio_mcp_started": False,
                "agent_runtime_started": False,
                "dry_run_redteam_requested": request.scan_options["dry_run_redteam_requested"],
                "dry_run_redteam_executed": False,
                "errors": discovery.errors,
            }
        if mode == "mcp":
            return self._precheck_mcp_target(request)
        target = request.target_path or REPO_ROOT
        exists = target.exists()
        readable = os.access(target, os.R_OK) if exists else False
        estimated_files = len(iter_scan_files(target, min(request.limits.max_files, 500), request.limits.max_depth)) if exists and readable else 0
        project_scope = self_project_scope(target)
        return {
            "status": "PASS" if exists and readable else "FAILED",
            "mode": mode,
            "target": safe_display_path(target, target if target.is_dir() else target.parent),
            "exists": exists,
            "readable": readable,
            "scan_files": estimated_files if request.run_local_analyzers else 0,
            "candidate_scan_files": estimated_files,
            "max_files": request.limits.max_files,
            "scan_options": request.scan_options,
            "remote_analysis": False,
            "remote_analysis_requested": request.remote_analysis_requested,
            "cloud_analysis_status": request.scan_options["cloud_analysis_status"],
            "mutates_installed_agents": False,
            "user_scope": request.user_scope,
            "user_scope_requested": request.user_scope,
            "effective_user_scope": request.scan_options["effective_user_scope"],
            "execution_mode": request.execution_mode,
            "effective_execution_mode": request.scan_options["effective_execution_mode"],
            "mcp_policy": request.scan_options["mcp_policy"],
            "stdio_mcp_started": False,
            "agent_runtime_started": False,
            "dry_run_redteam_requested": request.scan_options["dry_run_redteam_requested"],
            "dry_run_redteam_executed": False,
            "self_project_scope": project_scope,
            "self_project_source_excluded": project_scope.get("source_excluded", False),
            "errors": [] if exists and readable else [{"target": str(target), "error": "路径不存在或无权限"}],
        }

    def _apply_request_options(self, result: DiscoveryResult, request: ScanRequest) -> None:
        if not request.include_skills:
            result.hits = [hit for hit in result.hits if hit.get("type") != "Skill"]
            result.components = [component for component in result.components if component.get("type") != "Skill"]
            result.scan_paths = [path for path in result.scan_paths if not looks_like_skill_path(path)]
            result.skills = []
        if not request.include_mcp:
            result.hits = [hit for hit in result.hits if hit.get("type") != "MCP"]
            result.components = [component for component in result.components if component.get("type") not in {"MCP", "MCP Server", "MCP Tool"}]
            result.scan_paths = [path for path in result.scan_paths if not looks_like_mcp_path(path)]
            result.mcp_servers = []
            result.consents = []
        result.run.update(
            {
                "scan_options": request.scan_options,
                "skill_count": len(result.skills),
                "mcp_count": len(result.mcp_servers),
                "hit_count": len(result.hits),
                "scan_file_count": len(result.scan_paths),
                "run_local_analyzers": request.run_local_analyzers,
                "remote_analysis": False,
                "remote_analysis_requested": request.remote_analysis_requested,
                "cloud_analysis_status": request.scan_options["cloud_analysis_status"],
                "mutates_installed_agents": False,
                "user_scope": request.user_scope,
                "user_scope_requested": request.user_scope,
                "effective_user_scope": request.scan_options["effective_user_scope"],
                "execution_mode": request.execution_mode,
                "effective_execution_mode": request.scan_options["effective_execution_mode"],
                "mcp_policy": request.scan_options["mcp_policy"],
                "stdio_mcp_started": False,
                "agent_runtime_started": False,
                "dry_run_redteam_requested": request.scan_options["dry_run_redteam_requested"],
                "dry_run_redteam_executed": False,
            }
        )

    @staticmethod
    def _merge_cached_agent_probe(result: DiscoveryResult, cached_agents: list[dict[str, Any]]) -> None:
        def agent_key(item: dict[str, Any]) -> str:
            return str(item.get("adapter") or item.get("product") or item.get("name") or "").strip().lower()

        cached_by_key: dict[str, dict[str, Any]] = {}
        for item in cached_agents:
            cached_key = agent_key(item)
            if cached_key:
                cached_by_key.setdefault(cached_key, item)
        current_keys: set[str] = set()
        probe_fields = {
            "version",
            "version_raw",
            "version_source",
            "version_probe",
            "probe_method",
            "probe_source",
            "probe_status",
            "probe_evidence",
            "command_started",
            "package_version",
            "install_source",
        }
        for item in result.agents:
            current_key = agent_key(item)
            current_keys.add(current_key)
            cached = cached_by_key.get(current_key)
            if not cached:
                continue
            for field in probe_fields:
                value = cached.get(field)
                if value is not None and value != "" and value != []:
                    item[field] = value
            item["probe_cache_reused"] = True
        for cached_key, cached in cached_by_key.items():
            if cached_key and cached_key not in current_keys:
                retained = dict(cached)
                retained["probe_cache_reused"] = True
                retained["status"] = retained.get("status") or "ACTIVE"
                result.agents.append(retained)
        result.run.update(
            {
                "installed_agent_probe_cached": True,
                "installed_agent_probe_command_started": False,
                "installed_agent_probe_cache_count": len(cached_by_key),
                "installed_agent_probe_refresh_hint": "set refresh_agent_versions=true to execute a fresh read-only version probe",
            }
        )

    def run_assessment(
        self,
        request: ScanRequest,
        name: str = "本地 Agent 安全测评",
        assessment_id: str | None = None,
    ) -> ScanResult:
        target = request.target_path.expanduser() if request.target_path else None
        machine_mode = request.mode == "machine" and target is None
        mcp_mode = request.mode == "mcp"
        target_root = REPO_ROOT if mcp_mode else Path.home() if machine_mode else (target if target and target.is_dir() else target.parent if target else REPO_ROOT)
        if mcp_mode:
            display_target = mcp_target_label(request)
        elif machine_mode:
            display_target = "本机 Agent 配置"
        else:
            display_target = safe_display_path(target or REPO_ROOT, target_root if target and target.exists() else REPO_ROOT)
        scan_options = request.scan_options
        project_scope = self_project_scope(target)
        assessment = {
            "id": assessment_id or new_id("asm"),
            "name": f"{name} · {request.mode}",
            "target": display_target,
            "adapter": request.adapter or "auto",
            "profile": "standard-complete",
            "stage": "DISCOVERY",
            "progress": 5,
            "critical": 0,
            "high": 0,
            "slot": "local",
            "status": "运行中",
            "started_at": utc_now(),
            "safe_mode": "read_only",
            "remote_analysis": False,
            "remote_analysis_requested": request.remote_analysis_requested,
            "cloud_analysis_status": scan_options["cloud_analysis_status"],
            "scan_skills": request.include_skills,
            "include_skills": request.include_skills,
            "run_local_analyzers": request.run_local_analyzers,
            "use_existing_sca": request.use_existing_sca,
            "external_sca_executed": False,
            "scan_options": scan_options,
            "mutates_installed_agents": False,
            "user_scope": request.user_scope,
            "user_scope_requested": request.user_scope,
            "effective_user_scope": scan_options["effective_user_scope"],
            "execution_mode": request.execution_mode,
            "effective_execution_mode": scan_options["effective_execution_mode"],
            "mcp_policy": scan_options["mcp_policy"],
            "stdio_mcp_started": False,
            "agent_runtime_started": False,
            "dry_run_redteam_requested": scan_options["dry_run_redteam_requested"],
            "dry_run_redteam_executed": False,
            "self_project_scope": project_scope,
            "self_project_source_excluded": project_scope.get("source_excluded", False),
        }
        self.store.upsert_record("assessment", assessment, status="RUNNING")
        self._checkpoint("RUNNING_DISCOVERY", 5, target=display_target)
        events: list[dict[str, Any]] = []
        events.append(self._event(assessment["id"], "assessment.started", "测评已启动，进入本地只读扫描", {"target": display_target, "scan_options": scan_options}))
        events.append(
            self._event(
                assessment["id"],
                "scan.boundary.resolved",
                "扫描边界已解析：不会启动 stdio MCP，不会修改已安装 Agent",
                {
                    "user_scope_requested": scan_options["user_scope_requested"],
                    "effective_user_scope": scan_options["effective_user_scope"],
                    "execution_mode": scan_options["execution_mode"],
                    "effective_execution_mode": scan_options["effective_execution_mode"],
                    "mcp_policy": scan_options["mcp_policy"],
                },
            )
        )
        if project_scope.get("source_excluded"):
            events.append(
                self._event(
                    assessment["id"],
                    "scan.scope.self_project_excluded",
                    "已跳过本项目源码、文档和运维目录，仅允许显式测试 MCP/Skill 资产进入扫描",
                    project_scope,
                )
            )

        if mcp_mode:
            return self._run_mcp_assessment(request, assessment, events)

        if target is not None and not target.exists():
            assessment.update({"status": "失败", "stage": "FAILED", "progress": 100, "finished_at": utc_now()})
            self.store.upsert_record("assessment", assessment, status="FAILED")
            events.append(self._event(assessment["id"], "assessment.failed", "目标路径不存在或不可访问", {"target": str(target), "scan_options": scan_options}))
            empty_discovery = DiscoveryResult(run={"id": new_id("disc"), "status": "FAILED", "scope": "explicit-path"})
            report = self.reporter.create_report(assessment, [], [], {"errors": [{"target": display_target, "error": "not_found"}]})
            self._sync_state(assessment, empty_discovery, [], [], report, events)
            return ScanResult(assessment, empty_discovery, [], [], report, 0, 0, events)

        cached_agents = (
            self.store.list_records("agent_instance", limit=200)
            if machine_mode and not request.refresh_agent_versions
            else []
        )
        discovery = self.discovery.discover(
            None if machine_mode else [target],
            scope=scan_options["effective_user_scope"] if machine_mode else "explicit-path",
            probe_installed=not bool(cached_agents) if machine_mode else False,
        )
        if cached_agents:
            self._merge_cached_agent_probe(discovery, cached_agents)
        self._checkpoint(
            "RUNNING_STATIC",
            25,
            discovered_agents=len(discovery.agents),
            discovered_files=len(discovery.scan_paths),
        )
        self._apply_request_options(discovery, request)
        self._persist_discovery(discovery)
        events.append(
            self._event(
                assessment["id"],
                "discovery.completed",
                f"发现完成：Agent {len(discovery.agents)}，MCP {len(discovery.mcp_servers)}，Skill {len(discovery.skills)}",
                {"run_id": discovery.run["id"]},
            )
        )

        self.store.upsert_record(
            "scan_stage",
            {
                "id": new_id("stg"),
                "assessment_id": assessment["id"],
                "name": "LOCAL_STATIC",
                "status": "RUNNING",
                "started_at": utc_now(),
            },
            status="RUNNING",
        )
        files_scanned = 0
        files_skipped = 0
        static_cache_hits = 0
        raw_matches: list[RuleMatch] = []
        scanned_file_digests: dict[Path, str] = {}
        file_cache = {
            str(item.get("id")): item
            for item in self.store.list_records("scan_file_cache", limit=5000)
            if item.get("id")
        }
        file_cache_updates: list[dict[str, Any]] = []
        cache_scope = stable_hash(f"{request.mode}:{target_root.resolve()}", 24)
        scan_paths = discovery.scan_paths[: request.limits.max_files] if machine_mode else iter_scan_files(target or REPO_ROOT, request.limits.max_files, request.limits.max_depth)
        if not request.include_skills:
            scan_paths = [path for path in scan_paths if not looks_like_skill_path(path)]
        if request.run_local_analyzers:
            candidate_count = max(1, min(len(scan_paths), request.limits.max_files))
            for index, path in enumerate(scan_paths, start=1):
                self._checkpoint(
                    "RUNNING_STATIC",
                    25 + int(55 * min(index, candidate_count) / candidate_count),
                    scanned_files=files_scanned,
                    skipped_files=files_skipped,
                    candidate_files=candidate_count,
                    current_path=safe_display_path(path, target_root),
                )
                try:
                    stat = path.stat()
                    if stat.st_size > request.limits.max_file_bytes:
                        files_skipped += 1
                        continue
                    path_hash = stable_hash(str(path.resolve()).lower(), 32)
                    cache_id = "sfc_" + stable_hash(f"{cache_scope}:{path_hash}", 24)
                    digest = file_digest(path)
                    scanned_file_digests[path] = digest
                    cached = file_cache.get(cache_id)
                    restored = restore_cached_matches(path, cached) if cached and cached.get("file_sha256") == digest and cached.get("rule_cache_version") == RULE_CACHE_VERSION else None
                    if restored is not None:
                        files_scanned += 1
                        static_cache_hits += 1
                        raw_matches.extend(restored)
                        continue
                    text = read_text(path)
                    if text is None:
                        files_skipped += 1
                        continue
                    files_scanned += 1
                    matches = analyze_text(path, text, target_root)
                    raw_matches.extend(matches)
                    file_cache_updates.append(
                        {
                            "id": cache_id,
                            "path_hash": path_hash,
                            "display_path": safe_display_path(path, target_root),
                            "file_sha256": digest,
                            "file_size": stat.st_size,
                            "file_mtime_ns": stat.st_mtime_ns,
                            "rule_cache_version": RULE_CACHE_VERSION,
                            "cache_scope": cache_scope,
                            "matches": [cache_rule_match(match) for match in matches],
                            "redaction_status": "redacted",
                            "updated_at": utc_now(),
                        }
                    )
                except OSError:
                    files_skipped += 1
                if files_scanned >= request.limits.max_files:
                    break
            self.store.upsert_records("scan_file_cache", file_cache_updates, status="READY")
        else:
            events.append(
                self._event(
                    assessment["id"],
                    "local_static.skipped",
                    "本地规则分析器已按本次扫描选项跳过，仅保留发现与报告闭环",
                    {"candidate_scan_files": len(scan_paths), "scan_options": scan_options},
                )
            )

        findings, evidence = self._rollup_matches(assessment, raw_matches, target_root, scanned_file_digests)
        suppressed_findings = self._apply_finding_suppressions(findings, evidence)
        self.store.upsert_records("evidence", evidence, status="READY")
        self.store.upsert_records("finding", findings)
        self.store.upsert_records("rule", rule_catalog(), status="PUBLISHED")
        reused_evidence = sum(1 for item in evidence if item.get("artifact_reused"))
        events.append(
            self._event(
                assessment["id"],
                "local_static.completed",
                f"本地规则扫描完成：扫描 {files_scanned} 个文件，跳过 {files_skipped} 个文件，发现 {len(findings)} 项风险",
                {
                    "files_scanned": files_scanned,
                    "files_skipped": files_skipped,
                    "finding_count": len(findings),
                    "occurrence_count": len(raw_matches),
                    "evidence_count": len(evidence),
                    "reused_evidence_count": reused_evidence,
                    "suppressed_finding_count": suppressed_findings,
                    "static_cache_hits": static_cache_hits,
                    "static_cache_misses": len(file_cache_updates),
                },
            )
        )
        if request.use_existing_sca:
            events.append(
                self._event(
                    assessment["id"],
                    "external_sca.skipped",
                    "已记录调用已有 Skill/SCA 的请求；本地企业模式不会自动执行外部扫描器",
                    {"use_existing_sca": True, "external_sca_executed": False},
                )
            )
        if request.remote_analysis_requested:
            events.append(
                self._event(
                    assessment["id"],
                    "cloud_analysis.disabled",
                    "已记录远程分析请求；本地企业模式保持 remote_analysis=false，未连接 Snyk 云端",
                    {"remote_analysis_requested": True, "remote_analysis": False},
                )
            )

        active_findings = [finding for finding in findings if not finding.get("suppressed")]
        p0 = len([f for f in active_findings if "P0" in f["severity"] or "严重" in f["severity"]])
        p1 = len([f for f in active_findings if "P1" in f["severity"] or "高危" in f["severity"]])
        assessment.update(
            {
                "stage": "REPORT",
                "progress": 95,
                "critical": p0,
                "high": p1,
                "status": "部分完成" if discovery.consents else "已完成",
                "finished_at": utc_now(),
                "files_scanned": files_scanned,
                "files_skipped": files_skipped,
                "finding_count": len(findings),
                "active_finding_count": len(active_findings),
                "suppressed_finding_count": suppressed_findings,
                "occurrence_count": len(raw_matches),
                "evidence_count": len(evidence),
                "reused_evidence_count": reused_evidence,
                "incremental_reuse": reused_evidence > 0,
                "static_cache_hits": static_cache_hits,
                "static_cache_misses": len(file_cache_updates),
                "pending_consents": len(discovery.consents),
                "scan_options": scan_options,
                "self_project_scope": project_scope,
                "self_project_source_excluded": project_scope.get("source_excluded", False),
            }
        )
        self.store.upsert_record("assessment", assessment, status="COMPLETED")
        self._checkpoint("RUNNING_REPORT", 90, findings=len(findings), evidence=len(evidence))
        report = self.reporter.create_report(
            assessment,
            findings,
            evidence,
            discovery={
                "run": discovery.run,
                "hits": discovery.hits,
                "agents": discovery.agents,
                "mcp_servers": discovery.mcp_servers,
                "skills": discovery.skills,
                "errors": discovery.errors,
                "scan_options": scan_options,
            },
        )
        events.append(
            self._event(
                assessment["id"],
                "report.ready",
                "HTML/JSON 报告已生成",
                {"report_id": report["id"], "html_path": report.get("html_path"), "json_path": report.get("json_path")},
            )
        )
        assessment["stage"] = "DONE" if not discovery.consents else "WAITING_CONSENT"
        assessment["progress"] = 100 if not discovery.consents else 95
        self.store.upsert_record("assessment", assessment, status="COMPLETED" if not discovery.consents else "WAITING_CONSENT")
        self._sync_state(assessment, discovery, findings, evidence, report, events)
        return ScanResult(assessment, discovery, findings, evidence, report, files_scanned, files_skipped, events)

    def _precheck_mcp_target(self, request: ScanRequest) -> dict[str, Any]:
        discovery = self._discover_mcp_target(request)
        self._apply_request_options(discovery, request)
        has_server = bool(discovery.mcp_servers)
        target_label = mcp_target_label(request)
        return {
            "status": "PASS" if has_server else "FAILED",
            "mode": "mcp",
            "target": target_label,
            "readable": has_server,
            "agents": len(discovery.agents),
            "configs": len([hit for hit in discovery.hits if hit.get("type") in {"Config", "MCP"}]),
            "mcp_servers": len(discovery.mcp_servers),
            "skills": 0,
            "scan_files": 0,
            "candidate_scan_files": len(discovery.scan_paths),
            "scan_options": request.scan_options,
            "remote_analysis": False,
            "remote_analysis_requested": request.remote_analysis_requested,
            "cloud_analysis_status": request.scan_options["cloud_analysis_status"],
            "mutates_installed_agents": False,
            "user_scope": request.user_scope,
            "user_scope_requested": request.user_scope,
            "effective_user_scope": request.scan_options["effective_user_scope"],
            "execution_mode": request.execution_mode,
            "effective_execution_mode": request.scan_options["effective_execution_mode"],
            "mcp_policy": request.scan_options["mcp_policy"],
            "stdio_mcp_started": False,
            "agent_runtime_started": False,
            "dry_run_redteam_requested": request.scan_options["dry_run_redteam_requested"],
            "dry_run_redteam_executed": False,
            "errors": discovery.errors,
        }

    def _run_mcp_assessment(
        self,
        request: ScanRequest,
        assessment: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> ScanResult:
        discovery = self._discover_mcp_target(request)
        self._apply_request_options(discovery, request)
        self._persist_discovery(discovery)
        events.append(
            self._event(
                assessment["id"],
                "discovery.completed",
                f"MCP 目标识别完成：MCP {len(discovery.mcp_servers)}，待审批 {len(discovery.consents)}",
                {"run_id": discovery.run["id"], "errors": discovery.errors[:3]},
            )
        )

        inspection = self._inspect_mcp_discovery_servers(assessment, discovery)
        findings = inspection["findings"]
        evidence = inspection["evidence"]
        events.append(
            self._event(
                assessment["id"],
                "mcp_static.completed",
                f"MCP 静态检查完成：{len(discovery.mcp_servers)} 个 Server，{len(findings)} 项风险",
                {
                    "mcp_servers": len(discovery.mcp_servers),
                    "finding_count": len(findings),
                    "tool_count": inspection["tool_count"],
                    "flow_count": inspection["flow_count"],
                    "stdio_mcp_started": False,
                },
            )
        )

        p0 = len([f for f in findings if "P0" in f["severity"] or "严重" in f["severity"]])
        p1 = len([f for f in findings if "P1" in f["severity"] or "高危" in f["severity"]])
        completed = bool(discovery.mcp_servers)
        assessment.update(
            {
                "stage": "DONE" if completed and not discovery.consents else "WAITING_CONSENT" if completed else "FAILED",
                "progress": 100,
                "critical": p0,
                "high": p1,
                "status": "部分完成" if discovery.consents else "已完成" if completed else "失败",
                "finished_at": utc_now(),
                "files_scanned": 0,
                "files_skipped": 0,
                "finding_count": len(findings),
                "pending_consents": len(discovery.consents),
                "scan_options": request.scan_options,
            }
        )
        self.store.upsert_record("assessment", assessment, status="COMPLETED" if completed else "FAILED")
        report = self.reporter.create_report(
            assessment,
            findings,
            evidence,
            discovery={
                "run": discovery.run,
                "hits": discovery.hits,
                "agents": discovery.agents,
                "mcp_servers": discovery.mcp_servers,
                "skills": discovery.skills,
                "errors": discovery.errors,
                "scan_options": request.scan_options,
            },
        )
        events.append(
            self._event(
                assessment["id"],
                "report.ready",
                "HTML/JSON 报告已生成",
                {"report_id": report["id"], "html_path": report.get("html_path"), "json_path": report.get("json_path")},
            )
        )
        self._sync_state(assessment, discovery, findings, evidence, report, events)
        return ScanResult(assessment, discovery, findings, evidence, report, 0, 0, events)

    def _discover_mcp_target(self, request: ScanRequest) -> DiscoveryResult:
        run = {
            "id": new_id("disc"),
            "status": "COMPLETED",
            "scope": "explicit-mcp",
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "safe_mode": "local-readonly",
            "mutates_installed_agents": False,
            "stdio_mcp_started": False,
            "agent_runtime_started": False,
            "note": "单个 MCP 只读静态识别；未启动 stdio MCP Server，未连接 Remote MCP。",
        }
        raw = (request.target_ref or "").strip()
        target = request.target_path.expanduser() if request.target_path else None
        if raw and looks_like_mcp_url(raw):
            return self._discovery_from_mcp_records(run, [mcp_server_from_url(raw)])
        if raw and looks_like_inline_mcp_config(raw):
            records = mcp_servers_from_text(raw, source_label="inline-mcp-config", source_hash=stable_hash(raw, 64))
            if records:
                return self._discovery_from_mcp_records(run, records)
            result = DiscoveryResult(run=run)
            result.run["status"] = "FAILED"
            result.errors.append({"target": "inline-mcp-config", "error": "MCP JSON 无法解析，或未包含 mcpServers/command/url"})
            return result
        try:
            target_exists = bool(target and target.exists())
        except OSError as exc:
            result = DiscoveryResult(run=run)
            result.run["status"] = "FAILED"
            result.errors.append({"target": raw or "mcp", "error": f"目标路径不可访问：{exc}"})
            return result
        if target and target_exists:
            discovery = self.discovery.discover([target], scope="explicit-mcp", probe_installed=False)
            discovery.run.update(run)
            discovery.hits = [hit for hit in discovery.hits if hit.get("type") in {"Config", "MCP"}]
            discovery.skills = []
            discovery.scan_paths = []
            discovery.components = [component for component in discovery.components if component.get("type") in {"Config", "MCP", "MCP Server"}]
            if discovery.mcp_servers:
                discovery.run.update(
                    {
                        "finished_at": utc_now(),
                        "hit_count": len(discovery.hits),
                        "agent_count": len(discovery.agents),
                        "mcp_count": len(discovery.mcp_servers),
                        "skill_count": 0,
                        "error_count": len(discovery.errors),
                    }
                )
                return discovery
            text = read_text(target) if target.is_file() else None
            if text:
                records = mcp_servers_from_text(text, source_label=safe_display_path(target, target.parent), source_hash=file_digest(target))
                if records:
                    return self._discovery_from_mcp_records(run, records)
            discovery.errors.append({"target": safe_display_path(target, target.parent if target_exists else REPO_ROOT), "error": "未从目标中识别到 MCP Server"})
            discovery.run["status"] = "FAILED"
            return discovery
        result = DiscoveryResult(run=run)
        result.run["status"] = "FAILED"
        result.errors.append({"target": raw or "mcp", "error": "请填写 Remote MCP URL、.mcp.json 文件路径或 MCP JSON 配置"})
        return result

    def _discovery_from_mcp_records(self, run: dict[str, Any], records: list[dict[str, Any]]) -> DiscoveryResult:
        result = DiscoveryResult(run=run)
        now = utc_now()
        for server in records:
            result.mcp_servers.append(server)
            source = str(server.get("config") or server.get("url") or server.get("name") or "mcp")
            result.hits.append(
                {
                    "id": "hit_" + stable_hash(f"{server.get('id')}:{source}", 20),
                    "type": "MCP",
                    "agent": server.get("agent") or "MCP",
                    "path": source,
                    "path_hash": stable_hash(source),
                    "scope": "explicit-mcp",
                    "source": "quick-scan-mcp",
                    "sha256": server.get("config_sha256") or stable_hash(source, 64),
                    "status": "可导入",
                    "created_at": now,
                }
            )
            result.components.append(
                {
                    "id": "cmp_" + stable_hash(str(server.get("id") or source), 20),
                    "type": "MCP Server",
                    "name": server.get("name") or server.get("id"),
                    "source": source,
                    "trust": "Local" if server.get("transport") == "stdio" else "Remote",
                    "risk": server.get("risk") or "待检查",
                    "riskClass": server.get("riskClass") or "medium",
                }
            )
            if server.get("transport") == "stdio":
                result.consents.append(
                    {
                        "id": "consent_" + stable_hash(str(server.get("id")), 20),
                        "server": server.get("name"),
                        "mcp_server_id": server.get("id"),
                        "agent": server.get("agent") or "MCP",
                        "command": server.get("command") or "",
                        "args": server.get("args") or [],
                        "env": {key: "<REDACTED>" for key in server.get("env_keys") or []},
                        "config": source,
                        "config_sha256": server.get("config_sha256"),
                        "status": "待审批",
                        "scope": "本任务",
                        "reason": "stdio MCP 默认不启动，需逐项审批",
                        "created_at": now,
                    }
                )
        result.run.update(
            {
                "finished_at": utc_now(),
                "hit_count": len(result.hits),
                "agent_count": 0,
                "mcp_count": len(result.mcp_servers),
                "skill_count": 0,
                "error_count": len(result.errors),
            }
        )
        return result

    def _inspect_mcp_discovery_servers(self, assessment: dict[str, Any], discovery: DiscoveryResult) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        updated_servers: list[dict[str, Any]] = []
        tool_count = 0
        flow_count = 0

        for server in discovery.mcp_servers:
            checked_at = utc_now()
            risks = mcp_static_risks(server)
            highest = highest_mcp_risk(risks)
            signature_payload = {
                "server_id": server.get("id"),
                "name": server.get("name"),
                "transport": server.get("transport"),
                "config_sha256": server.get("config_sha256"),
                "command": server.get("command"),
                "args": server.get("args", []),
                "url": server.get("url"),
                "risk_rules": [risk["rule"] for risk in risks],
            }
            signature_hash = stable_hash(json.dumps(signature_payload, ensure_ascii=False, sort_keys=True), 16)
            signature = {
                "id": "sig_" + stable_hash(str(server.get("id")) + signature_hash, 20),
                "server_id": server.get("id"),
                "server": server.get("name"),
                "signature": "static:" + signature_hash,
                "transport": server.get("transport"),
                "risk_rules": [risk["rule"] for risk in risks],
                "safe_mode": "local-readonly",
                "external_process_started": False,
                "mcp_started": False,
                "checked_at": checked_at,
            }
            updated_signature = self.store.upsert_record("mcp_signature", signature, status="READY")
            updated_server = dict(server)
            updated_server.update(
                {
                    "signature": updated_signature["signature"],
                    "inspection_status": "已检查",
                    "inspected_at": checked_at,
                    "risk": highest["label"],
                    "riskClass": highest["class"],
                    "status": "待审批" if str(server.get("transport")) == "stdio" else "已静态检查",
                    "statusClass": "medium" if str(server.get("transport")) == "stdio" else highest["class"],
                    "safe_mode": "local-readonly",
                    "external_process_started": False,
                    "mcp_started": False,
                }
            )
            updated_server = self.store.upsert_record("mcp_server", updated_server, status=str(updated_server.get("status") or "INSPECTED"))
            updated_servers.append(updated_server)

            updated_tools: list[dict[str, Any]] = []
            updated_flows: list[dict[str, Any]] = []
            for tool in derive_mcp_tools(updated_server, risks, checked_at):
                updated_tool = self.store.upsert_record("mcp_tool", tool, status=str(tool.get("status") or "STATIC_ONLY"))
                updated_tools.append(updated_tool)
                for label in updated_tool.get("labels") or []:
                    self.store.upsert_record(
                        "tool_label",
                        {
                            "id": "tl_" + stable_hash(f"{updated_tool.get('id')}:{label}", 20),
                            "tool_id": updated_tool.get("id"),
                            "server_id": updated_tool.get("server_id"),
                            "server": updated_tool.get("server"),
                            "label": label,
                            "source": "quick-scan-mcp-static",
                            "safe_mode": "local-readonly",
                            "mutates_installed_agents": False,
                            "created_at": checked_at,
                        },
                        status="ACTIVE",
                    )
                for flow in tool_flows(updated_tool, updated_server):
                    updated_flow = self.store.upsert_record("toxic_flow", flow, status=str(flow.get("status") or "STATIC_ONLY"))
                    updated_flows.append(updated_flow)
            tool_count += len(updated_tools)
            flow_count += len(updated_flows)

            server_findings: list[dict[str, Any]] = []
            for risk in risks:
                if risk.get("severity") not in {"严重 P0", "高危 P1", "中危 P2"}:
                    continue
                finding = {
                    "id": "fnd_" + stable_hash(f"{assessment.get('id')}:{server.get('id')}:{risk['rule']}:{signature_hash}", 24),
                    "assessment_id": assessment["id"],
                    "title": risk["title"],
                    "severity": risk["severity"],
                    "sevClass": risk["class"],
                    "summary": risk["summary"],
                    "agent": server.get("agent") or "MCP",
                    "rule": risk["rule"],
                    "rule_id": risk["rule"],
                    "source": "Quick MCP Static Inspect",
                    "confidence": risk["confidence"],
                    "component": server.get("name") or server.get("id"),
                    "evidence": risk["evidence"],
                    "fix": risk["fix"],
                    "remediation": risk["fix"],
                    "status": "待复核",
                    "priority": priority_for(risk["severity"]),
                    "safe_mode": "local-readonly",
                    "created_at": checked_at,
                }
                updated_finding = self.store.upsert_record("finding", finding, status="NEEDS_REVIEW")
                findings.append(updated_finding)
                server_findings.append(updated_finding)

            evidence_payload = {
                "schema": "agent-security-quick-mcp-static-scan@4.1",
                "assessment_id": assessment["id"],
                "server": sanitize_mcp_server(updated_server),
                "signature": updated_signature,
                "risks": risks,
                "tools": updated_tools,
                "toxic_flows": updated_flows,
                "finding_ids": [finding["id"] for finding in server_findings],
                "safe_mode": "local-readonly",
                "mutates_installed_agents": False,
                "external_process_started": False,
                "mcp_started": False,
                "boundary": "快速扫描单个 MCP 只做静态解析；未启动 stdio MCP Server，未执行命令，未连接 Remote MCP。",
                "checked_at": checked_at,
            }
            artifact = self.store.write_artifact(
                "quick-mcp-static-inspection",
                json.dumps(evidence_payload, ensure_ascii=False, indent=2),
                suffix="json",
                metadata={"assessment_id": assessment["id"], "server_id": server.get("id"), "safe_mode": "local-readonly"},
            )
            ev = {
                "id": new_id("ev"),
                "assessment_id": assessment["id"],
                "type": "quick_mcp_static_inspection",
                "collector": "quick-mcp-static-inspect",
                "redaction": "已脱敏",
                "level": highest["class"],
                "text": f"MCP 快速静态检查：{server.get('name')} · {highest['label']}",
                "content": json.dumps({"server": sanitize_mcp_server(updated_server), "risks": risks[:5]}, ensure_ascii=False),
                "mcp_server_id": server.get("id"),
                "finding_ids": [finding["id"] for finding in server_findings],
                "artifact_id": artifact["id"],
                "artifact_path": artifact["relative_path"],
                "safe_mode": "local-readonly",
                "created_at": checked_at,
            }
            ev["download"] = f"/api/v1/evidence/{ev['id']}/download"
            updated_evidence = self.store.upsert_record("evidence", ev, status="READY")
            evidence.append(updated_evidence)
            for finding in server_findings:
                finding["evidence_ids"] = [updated_evidence["id"]]
                self.store.upsert_record("finding", finding, status="NEEDS_REVIEW")

        discovery.mcp_servers = updated_servers
        return {"findings": findings, "evidence": evidence, "tool_count": tool_count, "flow_count": flow_count}

    def run_discovery(self, payload: dict[str, Any]) -> DiscoveryResult:
        raw_paths = payload.get("paths") or payload.get("additional_paths") or payload.get("path") or payload.get("target_path")
        paths: list[Path] = []
        if isinstance(raw_paths, list):
            paths.extend(Path(str(path)).expanduser() for path in raw_paths if path)
        elif raw_paths:
            paths.append(Path(str(raw_paths)).expanduser())
        probe_installed = payload.get("probe_installed")
        if probe_installed is not None:
            probe_installed = bool(probe_installed)
        previous_hits = self.store.list_records("discovery_hit", limit=10000)
        previous_by_path_hash = {str(hit.get("path_hash")): hit for hit in previous_hits if hit.get("path_hash")}
        options = discovery_options(payload)
        requested_scope = normalize_user_scope(payload.get("scope") or payload.get("user_scope") or payload.get("userScope"))
        actual_scope = effective_user_scope(requested_scope)
        result = self.discovery.discover(paths or None, scope=actual_scope, probe_installed=probe_installed)
        result.run.update(
            {
                "user_scope_requested": requested_scope,
                "effective_user_scope": actual_scope,
                "scope": actual_scope,
                "scope_note": "所有可读用户会记录为请求范围；当前本地发现实际限制为当前用户。"
                if requested_scope != actual_scope
                else "",
            }
        )
        self._apply_discovery_options(result, options, previous_by_path_hash)
        self._persist_discovery(result)
        state = self.store.get_state()
        merge_front(state, "discoveryRuns", [result.run])
        merge_front(state, "discoveryHits", result.hits)
        merge_front(state, "agentAssets", result.agents)
        merge_front(state, "mcpServers", result.mcp_servers)
        merge_front(state, "consents", result.consents)
        merge_front(state, "skills", result.skills)
        merge_front(state, "components", result.components)
        merge_front(state, "discoveryErrors", result.errors)
        if result.agents:
            state["selectedAsset"] = result.agents[0]
        if result.skills:
            state["selectedSkill"] = result.skills[0]
        self.store.save_state(state)
        return result

    def _apply_discovery_options(self, result: DiscoveryResult, options: dict[str, Any], previous_by_path_hash: dict[str, dict]) -> None:
        for hit in result.hits:
            previous = previous_by_path_hash.get(str(hit.get("path_hash") or ""))
            if not previous:
                change_status = "NEW"
            elif str(previous.get("sha256") or "") != str(hit.get("sha256") or ""):
                change_status = "CHANGED"
            else:
                change_status = "UNCHANGED"
            hit["change_status"] = change_status
            hit["changed"] = change_status in {"NEW", "CHANGED"}

        change_summary = {
            "new": len([hit for hit in result.hits if hit.get("change_status") == "NEW"]),
            "changed": len([hit for hit in result.hits if hit.get("change_status") == "CHANGED"]),
            "unchanged": len([hit for hit in result.hits if hit.get("change_status") == "UNCHANGED"]),
        }

        def keep_hit(hit: dict) -> bool:
            kind = str(hit.get("type") or "")
            if kind == "Config" and not options["include_agent_configs"]:
                return False
            if kind == "Skill" and not options["include_skills"]:
                return False
            if kind == "MCP" and not options["include_mcp"]:
                return False
            if options["changes_only"] and hit.get("change_status") == "UNCHANGED":
                return False
            return True

        result.hits = [hit for hit in result.hits if keep_hit(hit)]
        kept_hit_paths = {str(hit.get("path") or "") for hit in result.hits}
        kept_hit_hashes = {str(hit.get("path_hash") or "") for hit in result.hits}
        kept_products = {str(hit.get("agent") or "") for hit in result.hits}

        if not options["include_skills"]:
            result.skills = []
        elif options["changes_only"]:
            result.skills = [skill for skill in result.skills if skill_selected_by_hits(skill, kept_hit_paths)]

        if not options["include_mcp"]:
            result.mcp_servers = []
            result.consents = []
        elif options["changes_only"]:
            result.mcp_servers = [server for server in result.mcp_servers if str(server.get("config") or "") in kept_hit_paths]
            kept_mcp_ids = {str(server.get("id") or "") for server in result.mcp_servers}
            kept_mcp_names = {str(server.get("name") or "") for server in result.mcp_servers}
            result.consents = [
                consent
                for consent in result.consents
                if str(consent.get("mcp_server_id") or "") in kept_mcp_ids or str(consent.get("server") or "") in kept_mcp_names
            ]

        result.components = [
            component
            for component in result.components
            if component_selected_by_options(component, options, kept_hit_paths)
        ]
        result.scan_paths = [path for path in result.scan_paths if stable_hash(str(path.resolve())) in kept_hit_hashes]

        kept_products.update(str(server.get("agent") or "") for server in result.mcp_servers)
        kept_products.update(str(skill.get("agent") or "") for skill in result.skills)
        filtered_agents = []
        for agent in result.agents:
            product = str(agent.get("adapter") or agent.get("name") or "")
            if product not in kept_products:
                continue
            agent["configs"] = len([hit for hit in result.hits if hit.get("agent") == product and hit.get("type") in {"Config", "MCP"}])
            agent["mcp"] = len([server for server in result.mcp_servers if server.get("agent") == product])
            agent["skills"] = len([skill for skill in result.skills if skill.get("agent") == product])
            filtered_agents.append(agent)
        result.agents = filtered_agents

        change_summary["returned"] = len(result.hits)
        result.run.update(
            {
                "discovery_options": options,
                "change_summary": change_summary,
                "hit_count": len(result.hits),
                "agent_count": len(result.agents),
                "mcp_count": len(result.mcp_servers),
                "skill_count": len(result.skills),
                "scan_file_count": len(result.scan_paths),
                "safe_mode": "local-readonly",
                "mutates_installed_agents": False,
            }
        )

    def _persist_discovery(self, result: DiscoveryResult) -> None:
        self.store.upsert_record("discovery_run", result.run, status=result.run.get("status", "COMPLETED"))
        self.store.upsert_records("discovery_hit", result.hits, status="READY")
        self.store.upsert_records("agent_instance", result.agents, status="ACTIVE")
        self.store.upsert_records("mcp_server", result.mcp_servers, status="DISCOVERED")
        self.store.upsert_records("mcp_consent", result.consents, status="PENDING")
        self.store.upsert_records("consent_request", result.consents, status="PENDING")
        self.store.upsert_records("skill", result.skills, status="DISCOVERED")
        self.store.upsert_records("skill_file", result.skills, status="DISCOVERED")
        self.store.upsert_records("component", result.components, status="DISCOVERED")

    def _event(self, assessment_id: str, event_type: str, message: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = {"message": message, **(payload or {})}
        event = self.store.scan_event(assessment_id, event_type, data)
        return {"seq": event["seq"], "time": event["created_at"], "type": event_type, "text": message, "payload": data}

    def _rollup_matches(
        self,
        assessment: dict[str, Any],
        matches: list[RuleMatch],
        target_root: Path,
        known_digests: dict[Path, str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        grouped: dict[str, list[RuleMatch]] = {}
        for match in matches:
            fingerprint = stable_hash(f"{match.rule_id}:{match.display_path}:{match.category}", 24)
            grouped.setdefault(fingerprint, []).append(match)

        findings: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        instances: list[dict[str, Any]] = []
        digest_cache: dict[Path, str] = dict(known_digests or {})
        artifacts_by_id = {
            str(item.get("id")): item
            for item in self.store.list_records("artifact", limit=5000)
            if item.get("id")
        }
        reusable_evidence: dict[str, dict[str, Any]] = {}
        for item in self.store.list_records("evidence", limit=5000):
            cache_key = str(item.get("scan_cache_key") or "")
            artifact = artifacts_by_id.get(str(item.get("artifact_id") or ""))
            if cache_key and artifact and Path(str(artifact.get("absolute_path") or "")).is_file():
                reusable_evidence.setdefault(cache_key, item)
        created_at = utc_now()
        for fingerprint, occurrences in grouped.items():
            first = occurrences[0]
            finding_id = "fnd_" + fingerprint
            evidence_id = "ev_" + stable_hash(f"{assessment['id']}:{finding_id}", 20)
            preview = [
                {
                    "line": item.line,
                    "path": item.display_path,
                    "snippet": item.snippet,
                    "reason": item.reason,
                    "context": item.context,
                    "review_signal": item.review_signal,
                }
                for item in occurrences[:50]
            ]
            if first.path not in digest_cache:
                try:
                    digest_cache[first.path] = file_digest(first.path)
                except OSError:
                    digest_cache[first.path] = stable_hash(first.display_path, 64)
            occurrence_signature = stable_hash(
                json.dumps(
                    [[item.line, item.snippet, item.reason, item.severity, item.context, item.review_signal] for item in occurrences],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                64,
            )
            cache_key = stable_hash(
                f"{first.rule_id}:{first.display_path}:{digest_cache[first.path]}:{occurrence_signature}",
                64,
            )
            content = {
                "schema": "agent-security-evidence-rollup@4.2.10",
                "assessment_id": assessment["id"],
                "finding_id": finding_id,
                "rule_id": first.rule_id,
                "path": first.display_path,
                "occurrence_count": len(occurrences),
                "occurrences": preview,
                "omitted_occurrences": max(0, len(occurrences) - len(preview)),
            }
            previous = reusable_evidence.get(cache_key)
            if previous:
                artifact = artifacts_by_id[str(previous["artifact_id"])]
            else:
                artifact = self.store.write_artifact(
                    "evidence-redacted",
                    json.dumps(content, ensure_ascii=False, indent=2),
                    suffix="json",
                    metadata={
                        "assessment_id": assessment["id"],
                        "finding_id": finding_id,
                        "rule_id": first.rule_id,
                        "occurrence_count": len(occurrences),
                        "scan_cache_key": cache_key,
                    },
                )
            ev = {
                "id": evidence_id,
                "assessment_id": assessment["id"],
                "finding_id": finding_id,
                "rule_id": first.rule_id,
                "type": "file-snippet-rollup",
                "collector": "local-static",
                "redaction": "已脱敏",
                "path": first.display_path,
                "location": f"{first.display_path}:{first.line}",
                "line": first.line,
                "sha256": digest_cache[first.path],
                "artifact_id": artifact["id"],
                "artifact_path": artifact["relative_path"],
                "artifact_reused": bool(previous),
                "source_evidence_id": previous.get("id") if previous else None,
                "scan_cache_key": cache_key,
                "content": first.snippet,
                "text": f"{first.rule_id} 在 {first.display_path} 命中 {len(occurrences)} 次",
                "level": severity_class(first.severity),
                "occurrence_count": len(occurrences),
                "occurrences_preview": preview[:20],
                "context": first.context,
                "original_severity": first.original_severity or first.severity,
                "review_signal": any(item.review_signal for item in occurrences),
                "time": created_at,
                "status": "READY",
            }
            evidence.append(ev)
            findings.append(
                {
                    "id": finding_id,
                    "assessment_id": assessment["id"],
                    "title": first.title,
                    "summary": f"{first.display_path} 命中 {first.rule_id}，共 {len(occurrences)} 个 occurrence，需要安全复核。",
                    "severity": first.severity,
                    "original_severity": first.original_severity or first.severity,
                    "sevClass": severity_class(first.severity),
                    "rule": first.rule_id,
                    "rule_id": first.rule_id,
                    "source": first.source,
                    "agent": assessment.get("adapter") or "Local",
                    "component": first.display_path,
                    "confidence": f"{first.confidence:.2f}",
                    "context": first.context,
                    "review_signal": any(item.review_signal for item in occurrences),
                    "compat": compatible_code(first.rule_id),
                    "evidence": first.snippet,
                    "evidence_ids": [evidence_id],
                    "occurrence_count": len(occurrences),
                    "file_count": 1,
                    "occurrences_preview": [
                        {"line": item.line, "path": item.display_path, "evidence_id": evidence_id}
                        for item in occurrences[:20]
                    ],
                    "fix": first.remediation,
                    "remediation": first.remediation,
                    "status": "待复核",
                    "priority": priority_for(first.severity),
                    "fingerprint": fingerprint,
                    "created_at": created_at,
                }
            )
            for item in occurrences:
                instances.append(
                    {
                        "id": "fin_" + stable_hash(f"{finding_id}:{item.line}:{item.snippet}", 20),
                        "finding_id": finding_id,
                        "assessment_id": assessment["id"],
                        "rule_id": item.rule_id,
                        "path": item.display_path,
                        "line": item.line,
                        "evidence_id": evidence_id,
                        "snippet": item.snippet,
                        "context": item.context,
                        "original_severity": item.original_severity or item.severity,
                        "review_signal": item.review_signal,
                        "created_at": created_at,
                    }
                )
        self.store.upsert_records("finding_instance", instances, status="READY")
        return findings, evidence

    def _apply_finding_suppressions(
        self,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
    ) -> int:
        now = datetime.now(timezone.utc)
        active: list[dict[str, Any]] = []
        expired: list[dict[str, Any]] = []
        for suppression in self.store.list_records("finding_suppression", limit=5000):
            if str(suppression.get("status") or "").upper() != "ACTIVE":
                continue
            expires_at = str(suppression.get("expires_at") or "").strip()
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry <= now:
                        suppression.update({"status": "EXPIRED", "expired_at": utc_now()})
                        expired.append(suppression)
                        continue
                except ValueError:
                    suppression.update({"status": "EXPIRED", "expired_at": utc_now(), "expiration_error": "invalid_timestamp"})
                    expired.append(suppression)
                    continue
            active.append(suppression)
        self.store.upsert_records("finding_suppression", expired)

        suppressed_by_finding: dict[str, dict[str, Any]] = {}
        for finding in findings:
            component = str(finding.get("component") or "").replace("\\", "/").lower()
            for suppression in active:
                scope = str(suppression.get("scope") or "fingerprint").lower()
                matched = scope == "fingerprint" and suppression.get("fingerprint") == finding.get("fingerprint")
                if scope == "rule_path":
                    path_glob = str(suppression.get("path_glob") or "").replace("\\", "/").lower()
                    matched = suppression.get("rule_id") == finding.get("rule_id") and bool(path_glob) and fnmatch(component, path_glob)
                if not matched:
                    continue
                finding.update(
                    {
                        "status": "已抑制",
                        "suppressed": True,
                        "suppression_id": suppression.get("id"),
                        "suppression_scope": scope,
                        "suppression_reason": suppression.get("reason"),
                        "suppression_expires_at": suppression.get("expires_at"),
                    }
                )
                suppressed_by_finding[str(finding["id"])] = suppression
                break
        for item in evidence:
            suppression = suppressed_by_finding.get(str(item.get("finding_id") or ""))
            if suppression:
                item.update({"suppressed": True, "suppression_id": suppression.get("id")})
        return len(suppressed_by_finding)

    def _sync_state(
        self,
        assessment: dict[str, Any],
        discovery: DiscoveryResult,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        report: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> None:
        state = self.store.get_state()
        merge_front(state, "tasks", [assessment])
        merge_front(state, "discoveryRuns", [discovery.run])
        merge_front(state, "discoveryHits", discovery.hits)
        merge_front(state, "agentAssets", discovery.agents)
        merge_front(state, "mcpServers", discovery.mcp_servers)
        merge_front(state, "consents", discovery.consents)
        merge_front(state, "skills", discovery.skills)
        merge_front(state, "components", discovery.components)
        merge_front(state, "discoveryErrors", discovery.errors)
        merge_front(state, "findings", findings)
        merge_front(state, "evidenceItems", evidence)
        merge_front(state, "reports", [report])
        state["taskEvents"] = events + [event for event in state.get("taskEvents", []) if event.get("seq") not in {e.get("seq") for e in events}]
        state["selectedTask"] = assessment
        if findings:
            state["selectedFinding"] = findings[0]
        if evidence:
            state["selectedEvidence"] = evidence[0]
        if discovery.agents:
            state["selectedAsset"] = discovery.agents[0]
        if discovery.skills:
            state["selectedSkill"] = discovery.skills[0]
        self.store.save_state(state)


def iter_scan_files(target: Path, max_files: int, max_depth: int) -> list[Path]:
    if target.is_file():
        return [target] if should_scan_file(target) and not should_skip_self_project_path(target) else []
    if should_skip_self_project_path(target) and not may_contain_self_test_asset(target):
        return []
    result: list[Path] = []
    for current, dirs, files in os.walk(target):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(target).parts)
        except ValueError:
            depth = 0
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache")]
        filter_self_project_dirs(current_path, dirs)
        if depth >= max_depth:
            dirs[:] = []
        for filename in files:
            path = current_path / filename
            if should_skip_self_project_path(path):
                continue
            if should_scan_file(path):
                result.append(path)
            if len(result) >= max_files:
                return result
    return result


def mcp_target_label(request: ScanRequest) -> str:
    raw = (request.target_ref or "").strip()
    if raw:
        if looks_like_mcp_url(raw):
            return redact_mcp_url(raw)
        if looks_like_inline_mcp_config(raw):
            return "inline-mcp-config"
        return raw
    if request.target_path:
        return safe_display_path(request.target_path, request.target_path.parent if request.target_path.exists() else REPO_ROOT)
    return "MCP Server"


def looks_like_mcp_url(value: str) -> bool:
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False
    return parsed.scheme.lower() in {"http", "https", "ws", "wss"} and bool(parsed.netloc)


def looks_like_inline_mcp_config(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("{") and stripped.endswith("}")


def mcp_server_from_url(raw_url: str) -> dict[str, Any]:
    parsed = urlparse(raw_url.strip())
    host = parsed.hostname or "remote-mcp"
    name = host if parsed.path in {"", "/"} else f"{host}{parsed.path}".strip("/")
    config_hash = stable_hash(raw_url, 64)
    transport = "http" if parsed.scheme.lower() in {"http", "https"} else parsed.scheme.lower()
    return {
        "id": "mcp_remote_" + stable_hash(raw_url, 20),
        "name": name[:120],
        "agent": "Remote MCP",
        "transport": transport,
        "config": "remote-url",
        "status": "已静态检查",
        "statusClass": "medium",
        "signature": "未握手",
        "risk": "待检查",
        "riskClass": "medium",
        "command": "",
        "args": [],
        "env_keys": [],
        "url": redact_mcp_url(raw_url),
        "url_has_credentials": bool(parsed.username or parsed.password),
        "config_sha256": config_hash,
        "safe_mode": "local-readonly",
        "external_process_started": False,
        "mcp_started": False,
    }


def redact_mcp_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url.strip())
    except ValueError:
        return redact_text(raw_url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        netloc = f"{host}:{parsed.port}" if parsed.port else host
    except ValueError:
        netloc = host
    return redact_text(urlunparse(parsed._replace(netloc=netloc)))


def mcp_servers_from_text(text: str, source_label: str, source_hash: str) -> list[dict[str, Any]]:
    try:
        config = json.loads(strip_json_comments(text))
    except json.JSONDecodeError:
        return []
    if not isinstance(config, dict):
        return []
    servers = extract_mcp_servers(config)
    if not servers and any(key in config for key in ("command", "cmd", "url", "endpoint")):
        servers = {str(config.get("name") or "inline-mcp"): config}
    return [mcp_server_from_config(name, server, source_label, source_hash) for name, server in servers.items()]


def mcp_server_from_config(name: str, server: dict[str, Any], source_label: str, source_hash: str) -> dict[str, Any]:
    command = str(server.get("command") or server.get("cmd") or "")
    raw_args = server.get("args") or []
    args = raw_args if isinstance(raw_args, list) else [raw_args]
    env = server.get("env") or server.get("environment") or {}
    url = str(server.get("url") or server.get("endpoint") or "")
    transport = "stdio" if command else "http" if url else str(server.get("transport") or "unknown")
    parsed_url = urlparse(url) if url else None
    return {
        "id": "mcp_" + stable_hash(source_hash + name, 20),
        "name": name,
        "agent": str(server.get("agent") or "MCP"),
        "transport": transport,
        "config": source_label,
        "status": "待审批" if transport == "stdio" else "已静态检查",
        "statusClass": "medium",
        "signature": "未握手",
        "risk": "待审批" if transport == "stdio" else "待检查",
        "riskClass": "medium",
        "command": redact_text(command),
        "args": [redact_text(str(arg)) for arg in args[:20]],
        "env_keys": sorted(env.keys()) if isinstance(env, dict) else [],
        "url": redact_mcp_url(url) if url else "",
        "url_has_credentials": bool(parsed_url and (parsed_url.username or parsed_url.password)),
        "config_sha256": source_hash,
        "safe_mode": "local-readonly",
        "external_process_started": False,
        "mcp_started": False,
    }


def should_scan_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in {"skill.md", "agents.md", "claude.md", ".mcp.json", ".env"}:
        return True
    if "mcp" in lower and path.suffix.lower() in {".json", ".toml", ".yaml", ".yml"}:
        return True
    if path.suffix.lower() in SCAN_EXTENSIONS:
        return True
    return False


def looks_like_skill_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return path.name.lower() == "skill.md" or "skills" in parts


def looks_like_mcp_path(path: Path) -> bool:
    name = path.name.lower()
    return name in {".mcp.json", "mcp.json", "mcp.yaml", "mcp.yml", "mcp.toml"} or "mcp" in name


def discovery_options(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "include_agent_configs": flag(payload, ("include_agent_configs", "include_configs", "discovery_agent_configs", "discoveryAgentConfigs"), True),
        "include_skills": flag(payload, ("include_skills", "discovery_skills", "discoverySkills"), True),
        "include_mcp": flag(payload, ("include_mcp", "discovery_mcp", "discoveryMcp"), True),
        "changes_only": flag(payload, ("changes_only", "changed_only", "discovery_changes_only", "discoveryChangesOnly"), False),
        "safe_mode": "local-readonly",
        "mutates_installed_agents": False,
        "stdio_mcp_started": False,
        "agent_runtime_started": False,
    }


def skill_selected_by_hits(skill: dict[str, Any], kept_hit_paths: set[str]) -> bool:
    skill_path = str(skill.get("path") or "")
    if not skill_path:
        return False
    return any(path == skill_path or path.startswith(skill_path.rstrip("/\\") + "/") or path.startswith(skill_path.rstrip("/\\") + "\\") for path in kept_hit_paths)


def component_selected_by_options(component: dict[str, Any], options: dict[str, Any], kept_hit_paths: set[str]) -> bool:
    kind = str(component.get("type") or "")
    if kind == "Config" and not options["include_agent_configs"]:
        return False
    if kind == "Skill" and not options["include_skills"]:
        return False
    if kind == "MCP" and not options["include_mcp"]:
        return False
    if options["changes_only"]:
        source = str(component.get("source") or "")
        return source in kept_hit_paths
    return True


def cache_rule_match(match: RuleMatch) -> dict[str, Any]:
    return {
        "rule_id": match.rule_id,
        "title": match.title,
        "severity": match.severity,
        "category": match.category,
        "confidence": match.confidence,
        "remediation": match.remediation,
        "display_path": match.display_path,
        "line": match.line,
        "snippet": match.snippet,
        "reason": match.reason,
        "source": match.source,
        "context": match.context,
        "original_severity": match.original_severity,
        "review_signal": match.review_signal,
    }


def restore_cached_matches(path: Path, cached: dict[str, Any]) -> list[RuleMatch] | None:
    raw_matches = cached.get("matches")
    if not isinstance(raw_matches, list) or len(raw_matches) > 10000:
        return None
    restored: list[RuleMatch] = []
    try:
        for item in raw_matches:
            if not isinstance(item, dict):
                return None
            restored.append(
                RuleMatch(
                    rule_id=str(item["rule_id"]),
                    title=str(item["title"]),
                    severity=str(item["severity"]),
                    category=str(item["category"]),
                    confidence=float(item["confidence"]),
                    remediation=str(item["remediation"]),
                    path=path,
                    display_path=str(item["display_path"]),
                    line=int(item["line"]),
                    snippet=str(item["snippet"]),
                    reason=str(item["reason"]),
                    source=str(item.get("source") or "local-static"),
                    context=str(item.get("context") or "unknown"),
                    original_severity=str(item.get("original_severity") or ""),
                    review_signal=bool(item.get("review_signal")),
                )
            )
    except (KeyError, TypeError, ValueError):
        return None
    return restored


def read_text(path: Path) -> str | None:
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return None
    if b"\x00" in sample:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def merge_front(state: dict[str, Any], key: str, records: list[dict[str, Any]], max_items: int = 300) -> None:
    if not records:
        return
    existing = state.setdefault(key, [])
    by_id = {str(item.get("id") or item.get("server") or item.get("name")): item for item in existing}
    ordered = []
    for record in records:
        identity = str(record.get("id") or record.get("server") or record.get("name"))
        by_id[identity] = record
        ordered.append(record)
    for item in existing:
        identity = str(item.get("id") or item.get("server") or item.get("name"))
        if identity not in {str(r.get("id") or r.get("server") or r.get("name")) for r in records}:
            ordered.append(by_id[identity])
    state[key] = ordered[:max_items]


def severity_class(severity: str) -> str:
    if "P0" in severity or "严重" in severity:
        return "critical"
    if "P1" in severity or "高危" in severity:
        return "high"
    if "P2" in severity or "中危" in severity:
        return "medium"
    return "low"


def priority_for(severity: str) -> str:
    if "P0" in severity or "严重" in severity:
        return "P0"
    if "P1" in severity or "高危" in severity:
        return "P1"
    if "P2" in severity or "中危" in severity:
        return "P2"
    return "P3"


def compatible_code(rule_id: str) -> str:
    if rule_id == "MCP-PI-001":
        return "E001"
    if rule_id == "MCP-CMD-001":
        return "W019"
    if rule_id == "SKILL-PI-001":
        return "E004"
    if rule_id.startswith("SECRET"):
        return "DM-05"
    return rule_id
