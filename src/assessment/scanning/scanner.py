from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..reports import ReportRenderer
from ..store import AssessmentStore, REPO_ROOT, new_id, utc_now
from .discovery import DiscoveryEngine
from .models import DiscoveryResult, RuleMatch, ScanRequest, ScanResult, flag
from .redaction import file_digest, redact_text, safe_display_path, stable_hash
from .rules import analyze_text, rule_catalog


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


class LocalScanEngine:
    def __init__(self, store: AssessmentStore) -> None:
        self.store = store
        self.discovery = DiscoveryEngine()
        self.reporter = ReportRenderer(store)

    def run_quick_scan(self, payload: dict[str, Any]) -> ScanResult:
        request = ScanRequest.from_payload(payload, default_path=REPO_ROOT)
        return self.run_assessment(request, name="快速扫描")

    def precheck_quick_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = ScanRequest.from_payload(payload, default_path=REPO_ROOT)
        mode = request.mode
        if mode == "machine" and request.target_path is None:
            discovery = self.discovery.discover(None, scope=str(payload.get("scope") or "current-user"))
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
                "errors": discovery.errors,
            }
        target = request.target_path or REPO_ROOT
        exists = target.exists()
        readable = os.access(target, os.R_OK) if exists else False
        estimated_files = len(iter_scan_files(target, min(request.limits.max_files, 500), request.limits.max_depth)) if exists and readable else 0
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
            "errors": [] if exists and readable else [{"target": str(target), "error": "路径不存在或无权限"}],
        }

    def _apply_request_options(self, result: DiscoveryResult, request: ScanRequest) -> None:
        if not request.include_skills:
            result.hits = [hit for hit in result.hits if hit.get("type") != "Skill"]
            result.components = [component for component in result.components if component.get("type") != "Skill"]
            result.scan_paths = [path for path in result.scan_paths if not looks_like_skill_path(path)]
            result.skills = []
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
            }
        )

    def run_assessment(self, request: ScanRequest, name: str = "本地 Agent 安全测评") -> ScanResult:
        target = request.target_path.expanduser() if request.target_path else None
        machine_mode = request.mode == "machine" and target is None
        target_root = Path.home() if machine_mode else (target if target and target.is_dir() else target.parent if target else REPO_ROOT)
        display_target = "本机 Agent 配置" if machine_mode else safe_display_path(target or REPO_ROOT, target_root if target and target.exists() else REPO_ROOT)
        scan_options = request.scan_options
        assessment = {
            "id": new_id("asm"),
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
            "mcp_policy": "per-server-consent",
        }
        self.store.upsert_record("assessment", assessment, status="RUNNING")
        events: list[dict[str, Any]] = []
        events.append(self._event(assessment["id"], "assessment.started", "测评已启动，进入本地只读扫描", {"target": display_target, "scan_options": scan_options}))

        if target is not None and not target.exists():
            assessment.update({"status": "失败", "stage": "FAILED", "progress": 100, "finished_at": utc_now()})
            self.store.upsert_record("assessment", assessment, status="FAILED")
            events.append(self._event(assessment["id"], "assessment.failed", "目标路径不存在或不可访问", {"target": str(target), "scan_options": scan_options}))
            empty_discovery = DiscoveryResult(run={"id": new_id("disc"), "status": "FAILED", "scope": "explicit-path"})
            report = self.reporter.create_report(assessment, [], [], {"errors": [{"target": display_target, "error": "not_found"}]})
            self._sync_state(assessment, empty_discovery, [], [], report, events)
            return ScanResult(assessment, empty_discovery, [], [], report, 0, 0, events)

        discovery = self.discovery.discover(None if machine_mode else [target], scope="current-user" if machine_mode else "explicit-path")
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
        raw_matches: list[RuleMatch] = []
        scan_paths = discovery.scan_paths[: request.limits.max_files] if machine_mode else iter_scan_files(target or REPO_ROOT, request.limits.max_files, request.limits.max_depth)
        if not request.include_skills:
            scan_paths = [path for path in scan_paths if not looks_like_skill_path(path)]
        if request.run_local_analyzers:
            for path in scan_paths:
                try:
                    if path.stat().st_size > request.limits.max_file_bytes:
                        files_skipped += 1
                        continue
                    text = read_text(path)
                    if text is None:
                        files_skipped += 1
                        continue
                    files_scanned += 1
                    raw_matches.extend(analyze_text(path, text, target_root))
                except OSError:
                    files_skipped += 1
                if files_scanned >= request.limits.max_files:
                    break
        else:
            events.append(
                self._event(
                    assessment["id"],
                    "local_static.skipped",
                    "本地规则分析器已按本次扫描选项跳过，仅保留发现与报告闭环",
                    {"candidate_scan_files": len(scan_paths), "scan_options": scan_options},
                )
            )

        evidence = [self._evidence_from_match(assessment["id"], match, target_root) for match in raw_matches]
        findings = self._findings_from_matches(assessment, raw_matches, evidence)
        self.store.upsert_records("evidence", evidence, status="READY")
        self.store.upsert_records("finding", findings, status="NEEDS_REVIEW")
        self.store.upsert_records("rule", rule_catalog(), status="PUBLISHED")
        events.append(
            self._event(
                assessment["id"],
                "local_static.completed",
                f"本地规则扫描完成：扫描 {files_scanned} 个文件，跳过 {files_skipped} 个文件，发现 {len(findings)} 项风险",
                {"files_scanned": files_scanned, "files_skipped": files_skipped, "finding_count": len(findings)},
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

        p0 = len([f for f in findings if "P0" in f["severity"] or "严重" in f["severity"]])
        p1 = len([f for f in findings if "P1" in f["severity"] or "高危" in f["severity"]])
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
                "pending_consents": len(discovery.consents),
                "scan_options": scan_options,
            }
        )
        self.store.upsert_record("assessment", assessment, status="COMPLETED")
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
        assessment["progress"] = 100
        assessment["stage"] = "DONE" if not discovery.consents else "WAITING_CONSENT"
        self.store.upsert_record("assessment", assessment, status="COMPLETED")
        self._sync_state(assessment, discovery, findings, evidence, report, events)
        return ScanResult(assessment, discovery, findings, evidence, report, files_scanned, files_skipped, events)

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
        result = self.discovery.discover(paths or None, scope=str(payload.get("scope") or "current-user"), probe_installed=probe_installed)
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

    def _evidence_from_match(self, assessment_id: str, match: RuleMatch, target_root: Path) -> dict[str, Any]:
        evidence_id = "ev_" + stable_hash(f"{assessment_id}:{match.rule_id}:{match.display_path}:{match.line}:{match.snippet}", 20)
        content = {
            "rule_id": match.rule_id,
            "path": match.display_path,
            "line": match.line,
            "snippet": match.snippet,
            "reason": match.reason,
        }
        artifact = self.store.write_artifact(
            "evidence-redacted",
            json.dumps(content, ensure_ascii=False, indent=2),
            suffix="json",
            metadata={"assessment_id": assessment_id, "rule_id": match.rule_id},
        )
        try:
            digest = file_digest(match.path)
        except OSError:
            digest = stable_hash(match.display_path, 64)
        return {
            "id": evidence_id,
            "assessment_id": assessment_id,
            "finding_id": "",
            "type": "file-snippet",
            "collector": "local-static",
            "redaction": "已脱敏",
            "path": match.display_path,
            "location": f"{match.display_path}:{match.line}",
            "line": match.line,
            "sha256": digest,
            "artifact_id": artifact["id"],
            "artifact_path": artifact["relative_path"],
            "content": match.snippet,
            "text": f"{match.rule_id} 命中 {match.display_path}:{match.line}",
            "level": severity_class(match.severity),
            "time": utc_now(),
            "status": "READY",
        }

    def _findings_from_matches(
        self,
        assessment: dict[str, Any],
        matches: list[RuleMatch],
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        evidence_by_key = {
            f"{ev['path']}:{ev['line']}:{ev['content']}": ev for ev in evidence
        }
        findings: dict[str, dict[str, Any]] = {}
        for match in matches:
            fingerprint = stable_hash(f"{match.rule_id}:{match.display_path}:{match.line}:{match.snippet}", 24)
            finding_id = "fnd_" + fingerprint
            ev = evidence_by_key.get(f"{match.display_path}:{match.line}:{match.snippet}")
            if ev:
                ev["finding_id"] = finding_id
            finding = findings.get(finding_id)
            if finding is None:
                finding = {
                    "id": finding_id,
                    "assessment_id": assessment["id"],
                    "title": match.title,
                    "summary": f"{match.display_path}:{match.line} 命中 {match.rule_id}，需要安全复核。",
                    "severity": match.severity,
                    "sevClass": severity_class(match.severity),
                    "rule": match.rule_id,
                    "rule_id": match.rule_id,
                    "source": match.source,
                    "agent": assessment.get("adapter") or "Local",
                    "component": match.display_path,
                    "confidence": f"{match.confidence:.2f}",
                    "compat": compatible_code(match.rule_id),
                    "evidence": match.snippet,
                    "evidence_ids": [],
                    "fix": match.remediation,
                    "remediation": match.remediation,
                    "status": "待复核",
                    "priority": priority_for(match.severity),
                    "fingerprint": fingerprint,
                    "created_at": utc_now(),
                }
                findings[finding_id] = finding
            if ev and ev["id"] not in finding["evidence_ids"]:
                finding["evidence_ids"].append(ev["id"])
        return list(findings.values())

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
        return [target]
    result: list[Path] = []
    for current, dirs, files in os.walk(target):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(target).parts)
        except ValueError:
            depth = 0
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache")]
        if depth >= max_depth:
            dirs[:] = []
        for filename in files:
            path = current_path / filename
            if should_scan_file(path):
                result.append(path)
            if len(result) >= max_files:
                return result
    return result


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
