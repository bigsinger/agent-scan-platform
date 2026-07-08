from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from ..store import new_id, utc_now
from .models import DiscoveryResult
from .redaction import file_digest, redact_text, safe_display_path, stable_hash
from .scope import filter_self_project_dirs, may_contain_self_test_asset, should_skip_self_project_path


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
    "log",
    "sessions",
    "archived_sessions",
    "attachments",
    "browser",
    "cache",
    "node",
    "node_repl",
    "tmp",
    "temp",
    "output",
    "reports",
    "sandboxes",
    "state-snapshots",
    "traces",
    "audio_cache",
    "image_cache",
    "vendor_imports",
    "computer-use",
    "computer-use-turn-ended",
    "process_manager",
    "sqlite",
    "memories",
}

CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".claude.json",
    "settings.json",
    "config.toml",
    "AGENTS.md",
    "CLAUDE.md",
    "SKILL.md",
    ".env",
    "config.yaml",
    "config.yml",
    "package.json",
    "pyproject.toml",
}


CODEX_EXE_CANDIDATES = (
    Path("C:/Program Files/WindowsApps/OpenAI.Codex_26.616.10790.0_x64__2p2nqsd0c76g0/app/Codex.exe"),
    Path("C:/Program Files/WindowsApps/OpenAI.Codex_26.616.10790.0_x64__2p2nqsd0c76g0/app/resources/codex.exe"),
    Path.home() / "AppData" / "Local" / "Microsoft" / "WindowsApps" / "Codex.exe",
)

MAX_DISCOVERY_FILES_PER_ROOT = 300


class DiscoveryEngine:
    def discover(self, paths: list[Path] | None = None, scope: str = "current-user", probe_installed: bool | None = None) -> DiscoveryResult:
        explicit = bool(paths)
        if probe_installed is None:
            probe_installed = not explicit
        run = {
            "id": new_id("disc"),
            "status": "COMPLETED",
            "scope": scope,
            "started_at": utc_now(),
            "finished_at": utc_now(),
            "safe_mode": "local-readonly",
            "mutates_installed_agents": False,
            "stdio_mcp_started": False,
            "agent_runtime_started": False,
            "note": "只读发现；未启动 stdio MCP Server",
        }
        result = DiscoveryResult(run=run)
        if probe_installed:
            self._probe_installed_agents(result)
        roots = self._candidate_roots(paths or [])
        seen: set[str] = set()
        for root in roots:
            if not root.exists():
                continue
            for path in self._iter_candidate_files(root):
                key = str(path.resolve()).lower()
                if key in seen:
                    continue
                seen.add(key)
                try:
                    self._inspect_path(path, result, root, explicit)
                except OSError as exc:
                    result.errors.append({"id": "err_" + stable_hash(str(path)), "path": safe_display_path(path), "error": str(exc), "status": "权限跳过"})
        self._finalize_agents(result)
        run["finished_at"] = utc_now()
        run["hit_count"] = len(result.hits)
        run["agent_count"] = len(result.agents)
        run["mcp_count"] = len(result.mcp_servers)
        run["skill_count"] = len(result.skills)
        run["error_count"] = len(result.errors)
        return result

    def _candidate_roots(self, explicit_paths: list[Path]) -> list[Path]:
        if explicit_paths:
            candidates = [path.expanduser() for path in explicit_paths]
            return unique_paths(candidates)
        home = Path.home()
        local_appdata = Path(os.environ.get("LOCALAPPDATA") or (home / "AppData" / "Local"))
        roaming_appdata = Path(os.environ.get("APPDATA") or (home / "AppData" / "Roaming"))
        candidates = [
            home / ".claude",
            home / ".claude.json",
            home / ".codex" / "config.toml",
            home / ".codex" / "AGENTS.md",
            home / ".codex" / "skills",
            home / ".codex" / "rules",
            home / ".cursor",
            home / ".windsurf",
            home / ".kiro",
            home / ".gemini",
            home / ".openclaw",
            home / ".hermes",
            local_appdata / "hermes" / "config.yaml",
            local_appdata / "hermes" / ".env",
            local_appdata / "hermes" / "skills",
            local_appdata / "hermes" / "config",
            roaming_appdata / "Claude",
            roaming_appdata / "Code" / "User",
            roaming_appdata / "Cursor" / "User",
            local_appdata / "Programs" / "Cursor",
            local_appdata / "Programs" / "Windsurf",
        ]
        return unique_paths(candidates)

    def _iter_candidate_files(self, root: Path) -> list[Path]:
        if root.is_file():
            if should_skip_self_project_path(root):
                return []
            return [root] if root.name in CONFIG_NAMES or "mcp" in root.name.lower() else [root]
        if should_skip_self_project_path(root) and not may_contain_self_test_asset(root):
            return []
        matches: list[Path] = []
        for current, dirs, files in os.walk(root):
            current_path = Path(current)
            depth = len(current_path.relative_to(root).parts) if current_path != root else 0
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache")]
            filter_self_project_dirs(current_path, dirs)
            if depth > 8:
                dirs[:] = []
                continue
            for filename in files:
                path = current_path / filename
                if should_skip_self_project_path(path):
                    continue
                lower = filename.lower()
                if filename in CONFIG_NAMES or lower.endswith((".mcp.json", ".toml", ".yaml", ".yml")) or "mcp" in lower:
                    matches.append(path)
            if len(matches) >= MAX_DISCOVERY_FILES_PER_ROOT:
                break
        return matches

    def _inspect_path(self, path: Path, result: DiscoveryResult, root: Path, explicit: bool) -> None:
        display_root = (root if root.is_dir() else root.parent) if explicit else None
        display_path = safe_display_path(path, display_root)
        product = classify_product(path)
        kind = classify_kind(path)
        digest = file_digest(path) if path.is_file() else stable_hash(str(path))
        scope = scope_for_path(path, root)
        hit = {
            "id": "hit_" + stable_hash(str(path.resolve())),
            "type": kind,
            "agent": product,
            "path": display_path,
            "path_hash": stable_hash(str(path.resolve())),
            "scope": scope,
            "source": "explicit-path" if explicit else "well-known",
            "sha256": digest,
            "status": "可导入",
            "created_at": utc_now(),
        }
        result.hits.append(hit)
        if path.is_file() and should_scan_discovered_file(path):
            result.scan_paths.append(path)
        result.components.append(
            {
                "id": "cmp_" + stable_hash(kind + str(path.resolve())),
                "type": kind,
                "name": path.name,
                "source": display_path,
                "trust": "Local",
                "risk": "待扫描",
                "riskClass": "medium",
            }
        )
        if kind == "Skill":
            result.skills.append(self._skill_record(path, product, display_root))
        if kind in {"MCP", "Config"}:
            self._inspect_mcp_config(path, product, result, display_root)

    def _skill_record(self, path: Path, product: str, display_root: Path | None) -> dict:
        skill_root = path.parent
        file_count = 0
        script_count = 0
        for current, dirs, files in os.walk(skill_root):
            current_path = Path(current)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for filename in files:
                file_count += 1
                if filename.lower().endswith((".py", ".js", ".ts", ".sh", ".ps1", ".bat", ".cmd")):
                    script_count += 1
            if file_count > 5000:
                break
        return {
            "id": "skill_" + stable_hash(str(skill_root.resolve())),
            "name": skill_root.name,
            "agent": product,
            "path": safe_display_path(skill_root, display_root),
            "real_path": str(skill_root.resolve()),
            "scope": "Project",
            "metadata": "SKILL.md",
            "files": file_count,
            "scripts": script_count,
            "risk": "待扫描",
            "riskClass": "medium",
            "status": "已发现",
            "sha256": file_digest(path),
        }

    def _inspect_mcp_config(self, path: Path, product: str, result: DiscoveryResult, display_root: Path | None) -> None:
        config = read_structured_config(path)
        servers = extract_mcp_servers(config)
        for name, server in servers.items():
            server_id = "mcp_" + stable_hash(str(path.resolve()) + name)
            command = str(server.get("command") or server.get("cmd") or "")
            args = server.get("args") or []
            env = server.get("env") or server.get("environment") or {}
            url = server.get("url") or server.get("endpoint") or ""
            transport = "stdio" if command else "http" if url else "unknown"
            risk = "待审批" if transport == "stdio" else "待检查"
            mcp_record = {
                "id": server_id,
                "name": name,
                "agent": product,
                "transport": transport,
                "config": safe_display_path(path, display_root),
                "status": "待审批" if transport == "stdio" else "未握手",
                "statusClass": "medium",
                "signature": "未握手",
                "risk": risk,
                "riskClass": "medium",
                "command": redact_text(command),
                "args": [redact_text(str(arg)) for arg in args[:20]],
                "env_keys": sorted(env.keys()) if isinstance(env, dict) else [],
                "url": redact_text(str(url)),
                "config_sha256": file_digest(path),
            }
            result.mcp_servers.append(mcp_record)
            if transport == "stdio":
                result.consents.append(
                    {
                        "id": "consent_" + stable_hash(server_id),
                        "server": name,
                        "mcp_server_id": server_id,
                        "agent": product,
                        "command": redact_text(command),
                        "args": [redact_text(str(arg)) for arg in args[:20]],
                        "env": {key: "<REDACTED>" for key in sorted(env.keys())} if isinstance(env, dict) else {},
                        "config": safe_display_path(path, display_root),
                        "config_sha256": file_digest(path),
                        "status": "待审批",
                        "scope": "本任务",
                        "reason": "stdio MCP 默认不启动，需逐项审批",
                        "created_at": utc_now(),
                    }
                )
    def _finalize_agents(self, result: DiscoveryResult) -> None:
        by_product: dict[str, list[dict[str, Any]]] = {}
        for hit in result.hits:
            by_product.setdefault(hit["agent"], []).append(hit)
        for product, hits in by_product.items():
            if product == "Generic":
                continue
            mcp_count = len([s for s in result.mcp_servers if s["agent"] == product])
            skill_count = len([s for s in result.skills if s["agent"] == product])
            installed_hits = [h for h in hits if h.get("type") == "Agent"]
            version = next((h.get("version") for h in installed_hits if h.get("version")), "")
            install_path = next((h.get("path") for h in installed_hits if h.get("path")), hits[0]["path"])
            probe_source = next((h.get("probe_source") for h in installed_hits if h.get("probe_source")), "")
            probe_method = next((h.get("probe_method") for h in installed_hits if h.get("probe_method")), "config-path")
            command_started = any(bool(h.get("command_started")) for h in installed_hits)
            # 判断是否为活跃安装
            is_running = any(h.get("command_started") for h in installed_hits)
            has_verified = any(h.get("verified") for h in installed_hits)
            has_config = any(h.get("type") in {"Config", "MCP"} for h in hits)
            has_skill = any(h.get("type") == "Skill" for h in hits)
            is_active = has_verified or (is_running and has_config)
            install_status = "已安装" if is_active else "残留" if installed_hits else ("配置命中" if has_config else "探测命中")
            notes = ""
            if not is_active and installed_hits:
                notes = "仅探测到程序存在，未发现活跃配置或运行态证据"
            elif not has_config and not has_skill and not is_active:
                notes = "仅有配置文件残留，Agent 可能已卸载"
            result.agents.append(
                {
                    "id": "agt_"
                    + stable_hash(product + "".join(h["path_hash"] for h in hits)),
                    "name": product + " · Local",
                    "adapter": product,
                    "coverage": "完整" if product in {"Claude Code", "Codex", "Hermes"} else "扩展",
                    "path": install_path,
                    "configs": len([h for h in hits if h["type"] in {"Config", "MCP"}]),
                    "mcp": mcp_count,
                    "skills": skill_count,
                    "score": 100,
                    "p0": 0,
                    "p1": 0,
                    "probe": "正常" if is_active else ("探测" if installed_hits else "配置"),
                    "caps": ["Discovery", "MCP", "Skill", "Local Rules"],
                    "version": version,
                    "probe_source": probe_source,
                    "probe_method": probe_method,
                    "command_started": command_started,
                    "install_status": install_status,
                    "notes": notes,
                    "status": "ACTIVE" if is_active else "RESIDUAL",
                    "created_at": utc_now(),
                }
            )

    def _probe_installed_agents(self, result: DiscoveryResult) -> None:
        hermes = probe_command_version("Hermes", "hermes", ["--version"], timeout=12)
        if hermes:
            project = parse_line_value(hermes.get("stdout", ""), "Project")
            path = Path(project) if project else Path(str(hermes.get("executable") or "hermes"))
            self._add_agent_probe(
                result,
                "Hermes",
                path,
                version=parse_first_version_line(hermes.get("stdout", "")),
                source="hermes --version",
                verified=True,
                details={
                    "python": parse_line_value(hermes.get("stdout", ""), "Python"),
                    "openai_sdk": parse_line_value(hermes.get("stdout", ""), "OpenAI SDK"),
                    "update": parse_line_value(hermes.get("stdout", ""), "Update available"),
                    "probe_method": "version-command",
                    "command_started": True,
                    "executable": display_installed_path(Path(str(hermes.get("executable") or "hermes"))),
                    "returncode": hermes.get("returncode", 0),
                },
            )

        codex_path = first_existing_codex_path()
        if codex_path:
            codex_version = parse_codex_package_version(codex_path)
            self._add_agent_probe(
                result,
                "Codex",
                codex_path,
                version=codex_version,
                source="WindowsApps package",
                verified=True,
                details={
                    "file": codex_path.name,
                    "probe_method": "package-metadata",
                    "command_started": False,
                    "executable": display_installed_path(codex_path),
                    "package_version": codex_version,
                    "note": "Codex WindowsApps executable is not required to run for discovery.",
                },
            )

        for product, command in [("Claude Code", "claude"), ("OpenClaw", "openclaw"), ("Gemini", "gemini")]:
            probe = probe_command_version(product, command, ["--version"], timeout=4)
            if probe:
                self._add_agent_probe(
                    result,
                    product,
                    Path(str(probe.get("executable") or command)),
                    version=parse_first_version_line(probe.get("stdout", "")),
                    source=f"{command} --version",
                )

        for product, path in [
            ("Cursor", Path(os.environ.get("LOCALAPPDATA") or "") / "Programs" / "Cursor" / "Cursor.exe"),
            ("Windsurf", Path(os.environ.get("LOCALAPPDATA") or "") / "Programs" / "Windsurf" / "Windsurf.exe"),
        ]:
            if path.exists():
                self._add_agent_probe(result, product, path, version="", source="well-known executable")

    def _add_agent_probe(
        self,
        result: DiscoveryResult,
        product: str,
        path: Path,
        version: str = "",
        source: str = "installed-probe",
        details: dict[str, Any] | None = None,
        *,
        verified: bool = False,
    ) -> None:
        resolved_text = str(path)
        try:
            resolved_text = str(path.resolve())
        except OSError:
            pass
        hit_id = "hit_" + stable_hash(f"{product}:{resolved_text}:installed")
        if any(hit.get("id") == hit_id for hit in result.hits):
            return
        hit = {
            "id": hit_id,
            "type": "Agent",
            "agent": product,
            "path": display_installed_path(path),
            "path_hash": stable_hash(resolved_text),
            "scope": scope_for_path(path, path.parent if path.parent else Path.home()),
            "source": source,
            "sha256": stable_hash(f"{product}:{version}:{resolved_text}", 64),
            "status": "已安装",
            "version": version,
            "details": details or {},
            "probe_source": source,
            "probe_method": str((details or {}).get("probe_method") or ("version-command" if "--version" in source else "package-metadata")),
            "command_started": bool((details or {}).get("command_started") or "--version" in source),
            "verified": verified,
            "mutates_installed_agents": False,
            "created_at": utc_now(),
        }
        result.hits.append(hit)
        result.components.append(
            {
                "id": "cmp_" + stable_hash(product + resolved_text),
                "type": "Agent",
                "name": product,
                "source": hit["path"],
                "trust": "Local",
                "risk": "待扫描",
                "riskClass": "low",
                "version": version,
                "probe_method": hit["probe_method"],
                "command_started": hit["command_started"],
            }
        )


def classify_product(path: Path) -> str:
    normalized = path.as_posix().lower()
    if ".claude" in normalized or "claude" in normalized:
        return "Claude Code"
    if ".codex" in normalized or "agents.md" in normalized:
        return "Codex"
    if "openclaw" in normalized or "clawdbot" in normalized:
        return "OpenClaw"
    if "hermes" in normalized:
        return "Hermes"
    if "cursor" in normalized:
        return "Cursor"
    if "windsurf" in normalized:
        return "Windsurf"
    if "gemini" in normalized:
        return "Gemini"
    return "Generic"


def classify_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "skill.md":
        return "Skill"
    if "mcp" in name or name == "claude_desktop_config.json":
        return "MCP"
    if name in {"agents.md", "claude.md", ".claude.json", "settings.json", "config.toml"}:
        return "Config"
    return "Config"


def should_scan_discovered_file(path: Path) -> bool:
    if not path.is_file():
        return False
    lower = path.name.lower()
    if lower in {name.lower() for name in CONFIG_NAMES}:
        return True
    return "mcp" in lower or lower.endswith((".toml", ".yaml", ".yml"))


def scope_for_path(path: Path, root: Path) -> str:
    home = Path.home().resolve()
    try:
        path.resolve().relative_to(home)
        return "User"
    except (OSError, ValueError):
        pass
    normalized = path.as_posix().lower()
    if "program files" in normalized or "windowsapps" in normalized:
        return "System"
    try:
        path.resolve().relative_to(root.resolve())
        return "Project"
    except (OSError, ValueError):
        return "External"


def display_installed_path(path: Path) -> str:
    normalized = path.as_posix()
    lower = normalized.lower()
    if "/windowsapps/" in lower:
        return "<program-files>/" + normalized.split("/WindowsApps/", 1)[-1]
    if "/program files/" in lower:
        return "<program-files>/" + normalized.split("/Program Files/", 1)[-1]
    return safe_display_path(path)


def probe_command_version(product: str, command: str, args: list[str], timeout: int) -> dict[str, str] | None:
    executable = shutil.which(command)
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, *args],
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or "").strip()
    if completed.returncode != 0 and not output:
        return None
    return {"product": product, "executable": executable, "stdout": output, "returncode": completed.returncode}


def first_existing_codex_path() -> Path | None:
    for command in ("codex", "Codex.exe"):
        executable = shutil.which(command)
        if executable:
            return Path(executable)
    for candidate in CODEX_EXE_CANDIDATES:
        if candidate.exists():
            return candidate
    windows_apps = Path("C:/Program Files/WindowsApps")
    try:
        matches = sorted(
            [
                *windows_apps.glob("OpenAI.Codex_*/app/Codex.exe"),
                *windows_apps.glob("OpenAI.Codex_*/app/resources/codex.exe"),
            ],
            reverse=True,
        )
    except OSError:
        matches = []
    return matches[0] if matches else None


def parse_codex_package_version(path: Path) -> str:
    match = re.search(r"OpenAI\.Codex_([^_\\/]+)", path.as_posix())
    return match.group(1) if match else ""


def parse_first_version_line(output: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            version = re.search(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?", stripped)
            if version:
                product = stripped.split(version.group(0), 1)[0].strip(" -·")
                return redact_text((product + " " + version.group(0)).strip(), max_len=160)
            return redact_text(stripped, max_len=160)
    return ""


def parse_line_value(output: str, key: str) -> str:
    prefix = key.lower() + ":"
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(prefix):
            return stripped.split(":", 1)[1].strip()
    return ""


def read_structured_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lower = path.name.lower()
    if lower.endswith(".toml"):
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return {}
    if lower.endswith(".json") or "json" in lower:
        stripped = strip_json_comments(text)
        try:
            value = json.loads(stripped)
            return value if isinstance(value, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def strip_json_comments(text: str) -> str:
    without_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(^|\s)//.*$", "", without_block, flags=re.M)


def extract_mcp_servers(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(config, dict):
        return {}
    candidates = [
        config.get("mcpServers"),
        config.get("mcp_servers"),
        config.get("servers"),
        config.get("mcp", {}).get("servers") if isinstance(config.get("mcp"), dict) else None,
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            return {str(name): value for name, value in candidate.items() if isinstance(value, dict)}
        if isinstance(candidate, list):
            result = {}
            for index, item in enumerate(candidate):
                if isinstance(item, dict):
                    result[str(item.get("name") or f"server_{index+1}")] = item
            return result
    return {}


def unique_paths(candidates: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            key = str(candidate.resolve()).lower()
        except OSError:
            key = str(candidate).lower()
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique
