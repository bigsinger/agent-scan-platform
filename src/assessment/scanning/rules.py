from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import RuleMatch
from .redaction import redact_text, safe_display_path


@dataclass(frozen=True, slots=True)
class LocalRule:
    id: str
    title: str
    severity: str
    category: str
    confidence: float
    remediation: str
    patterns: tuple[re.Pattern[str], ...]
    file_name_hints: tuple[str, ...] = ()
    source: str = "local-static"
    standards: tuple[str, ...] = ()
    false_positive_guidance: str = "确认命中内容是否位于注释、文档样例、占位符或不可执行上下文。"

    def applies_to_file(self, path: Path) -> bool:
        if not self.file_name_hints:
            return True
        normalized = path.as_posix().lower()
        return any(hint in normalized for hint in self.file_name_hints)


RULES: tuple[LocalRule, ...] = (
    LocalRule(
        id="SECRET-KEY-001",
        title="文件中出现疑似 API Key / Token / 密码",
        severity="严重 P0",
        category="数据与记忆安全",
        confidence=0.92,
        remediation="移除明文密钥，改用 Secret Reference 或本机凭据管理器，并轮换已暴露凭据。",
        patterns=(
            re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9_\-]{16,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s,;]{8,}"),
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ),
    ),
    LocalRule(
        id="MCP-PI-001",
        title="Tool/Prompt 描述包含提示注入指令",
        severity="高危 P1",
        category="工具执行安全",
        confidence=0.86,
        remediation="将外部内容与系统指令隔离，删除要求忽略系统/开发者指令的描述，并为工具返回值增加不可信标记。",
        patterns=(
            re.compile(r"(?i)\b(ignore|disregard|override)\b.{0,48}\b(previous|system|developer|instruction|prompt)s?\b"),
            re.compile(r"(?i)\b(system prompt|developer message|hidden instruction|jailbreak)\b"),
            re.compile(r"忽略.{0,20}(之前|以上|系统|开发者|安全).{0,20}(指令|提示|规则)"),
            re.compile(r"(泄露|输出|打印).{0,20}(系统提示|隐藏指令|密钥|token|密码)"),
        ),
    ),
    LocalRule(
        id="FLOW-DESTRUCTIVE-001",
        title="脚本或配置包含危险命令执行链",
        severity="严重 P0",
        category="工具执行安全",
        confidence=0.9,
        remediation="移除下载即执行、递归删除、PowerShell IEX 等命令；必须改为可审计、固定版本、逐项审批的执行流程。",
        patterns=(
            re.compile(r"(?i)\brm\s+-rf\s+[/~$]"),
            re.compile(r"(?i)Remove-Item\b.{0,80}-(Recurse|r)\b.{0,80}-(Force|f)\b"),
            re.compile(r"(?i)\b(curl|wget)\b.{0,160}\|\s*(sh|bash|zsh|powershell|pwsh)\b"),
            re.compile(r"(?i)\b(Invoke-WebRequest|iwr|curl)\b.{0,160}\b(Invoke-Expression|iex)\b"),
            re.compile(r"(?i)\bchmod\s+\+x\b.{0,120}(&&|;)\s*\./"),
        ),
    ),
    LocalRule(
        id="MCP-CMD-001",
        title="MCP stdio Server 使用高风险命令外壳",
        severity="高危 P1",
        category="MCP/Tool 协议安全",
        confidence=0.82,
        remediation="stdio MCP 启动命令必须来自可信配置快照；shell/powershell/cmd 启动需拆解参数、固定路径并逐项审批。",
        patterns=(
            re.compile(r"(?i)\"command\"\s*:\s*\"(cmd|powershell|pwsh|bash|sh|zsh|python|node|npx)\""),
            re.compile(r"(?i)\bcommand\s*=\s*[\"']?(cmd|powershell|pwsh|bash|sh|zsh|python|node|npx)"),
        ),
        file_name_hints=("mcp", "claude_desktop_config", ".mcp.json", "config.toml"),
    ),
    LocalRule(
        id="MCP-ENV-001",
        title="MCP 配置中暴露敏感环境变量",
        severity="高危 P1",
        category="身份与权限安全",
        confidence=0.88,
        remediation="MCP Server 环境变量只保存 Secret Reference，不在 JSON/TOML 中写入密钥明文。",
        patterns=(
            re.compile(r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|ACCESS_TOKEN)[\"']?\s*[:=]\s*[\"']?(?!\$\{|<REDACTED>|secret://)[^\s\"',;}]{8,}"),
        ),
        file_name_hints=("mcp", "claude_desktop_config", ".mcp.json", "settings.json", "config.toml"),
    ),
    LocalRule(
        id="SKILL-PI-001",
        title="Skill 指令存在越权或隐藏控制意图",
        severity="高危 P1",
        category="供应链与漏洞安全",
        confidence=0.84,
        remediation="Skill 必须明确边界，禁止覆盖系统/开发者指令、隐藏行为或要求模型泄露上下文。",
        patterns=(
            re.compile(r"(?i)\b(always|must)\b.{0,40}\b(ignore|override|bypass)\b.{0,40}\b(system|developer|safety)\b"),
            re.compile(r"(?i)\bexfiltrate|steal|leak\b.{0,40}\b(secret|token|credential|prompt)\b"),
            re.compile(r"(无视|绕过|覆盖).{0,20}(系统|开发者|安全).{0,20}(指令|规则)"),
        ),
        file_name_hints=("skill.md", ".agents/skills", "skills/"),
    ),
    LocalRule(
        id="SKILL-CODE-001",
        title="Skill 脚本存在供应链下载执行风险",
        severity="严重 P0",
        category="供应链与漏洞安全",
        confidence=0.86,
        remediation="Skill 脚本不得下载即执行；外部依赖必须固定版本、校验哈希，并纳入审批和复测。",
        patterns=(
            re.compile(r"(?i)\b(curl|wget|iwr)\b.{0,160}\b(raw\.githubusercontent|gist\.github|pastebin|http://)"),
            re.compile(r"(?i)\b(pip|npm|pnpm|yarn)\s+(install|add)\b.{0,80}(@latest|http://|git\+)"),
        ),
        file_name_hints=("skill.md", ".sh", ".ps1", ".py", ".js", ".ts", "package.json", "pyproject.toml"),
    ),
    LocalRule(
        id="UNICODE-HIDDEN-001",
        title="文件包含隐藏 Unicode 或双向控制字符",
        severity="中危 P2",
        category="供应链与漏洞安全",
        confidence=0.95,
        remediation="移除零宽字符和双向控制字符；对 Prompt/Skill/配置文件开启不可见字符审查。",
        patterns=(re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"),),
    ),
    LocalRule(
        id="CODEX-CONFIG-001",
        title="Agent/Codex 配置关闭审批或放开沙箱",
        severity="高危 P1",
        category="治理与审计安全",
        confidence=0.9,
        remediation="本地测评或企业使用时不得长期使用 approval_policy=never 与 danger-full-access；生产应使用最小权限沙箱。",
        patterns=(
            re.compile(r"(?i)approval[_-]?policy\s*[:=]\s*[\"']?never[\"']?"),
            re.compile(r"(?i)sandbox[_-]?mode\s*[:=]\s*[\"']?danger-full-access[\"']?"),
        ),
        file_name_hints=("config.toml", "settings.json", "agents.md", ".codex", ".agents"),
    ),
    LocalRule(
        id="REMOTE-MCP-001",
        title="远程 MCP 或工具端点缺少安全边界说明",
        severity="中危 P2",
        category="通信安全",
        confidence=0.72,
        remediation="远程 MCP 必须使用 HTTPS、认证和 SSRF allowlist；报告中保留连接审批和拒绝记录。",
        patterns=(
            re.compile(r"(?i)\"url\"\s*:\s*\"http://(?!127\.0\.0\.1|localhost)"),
            re.compile(r"(?i)\bhttp://(?!127\.0\.0\.1|localhost)[^\s\"']+/mcp"),
        ),
        file_name_hints=("mcp", ".json", ".toml", ".md"),
    ),
    LocalRule(id="MCP-PKG-001", title="MCP command 使用未固定远程包", severity="高危 P1", category="MCP/Tool 协议安全", confidence=0.82, remediation="固定 package 版本并校验来源。", patterns=(re.compile(r"(?i)\bnpx\b(?![^\n@]*@\d)"),), file_name_hints=("mcp", ".json", ".toml")),
    LocalRule(id="MCP-PIPE-001", title="MCP command 使用 shell pipeline", severity="严重 P0", category="MCP/Tool 协议安全", confidence=0.86, remediation="禁止管道下载执行，拆分为可审计步骤。", patterns=(re.compile(r"(?i)(curl|wget).{0,120}\|\s*(bash|sh|pwsh|powershell)"),), file_name_hints=("mcp", ".json", ".toml")),
    LocalRule(id="MCP-FS-001", title="MCP 暴露宽泛文件系统路径", severity="高危 P1", category="MCP/Tool 协议安全", confidence=0.78, remediation="限制到工作区 allowlist。", patterns=(re.compile(r"(?i)[\"']?(path|root|directory|allowed[_-]?directories)[\"']?\s*[:=]\s*[\"']?(/|C:\\\\|~[/\\\\]|<home>)"),), file_name_hints=("mcp", "filesystem", ".json", ".toml")),
    LocalRule(id="TOOL-DESTRUCTIVE-001", title="Tool schema 含破坏性动作且无确认", severity="高危 P1", category="工具执行安全", confidence=0.8, remediation="为 delete/write/exec 类工具增加确认和审计。", patterns=(re.compile(r"(?i)[\"']?(name|operation|action)[\"']?\s*[:=]\s*[\"']?(delete|remove|write_file|exec|shell|terminate)\b"),), file_name_hints=("tool", "schema", ".json", ".md")),
    LocalRule(id="TOOL-NETWORK-001", title="Tool schema 包含网络外联 sink", severity="中危 P2", category="通信安全", confidence=0.75, remediation="标记网络 sink 并加入 egress allowlist。", patterns=(re.compile(r"(?i)\b(http|webhook|post|upload|socket|fetch)\b"),), file_name_hints=("tool", "schema", ".json", ".md")),
    LocalRule(id="SKILL-SHELL-001", title="Skill 文档要求执行 shell 命令", severity="高危 P1", category="供应链与漏洞安全", confidence=0.8, remediation="将 shell 命令改为 dry-run 或审批步骤。", patterns=(re.compile(r"(?i)\b(run|execute|invoke|use|call)\b.{0,60}\b(bash|sh|powershell|cmd\.exe)\b"), re.compile(r"(执行|运行|调用).{0,40}(bash|sh|powershell|cmd\.exe)"), re.compile(r"(?i)^\s*(bash|sh|powershell|cmd\.exe)\s+"), re.compile(r"(?i)\b(subprocess\.(run|Popen)|os\.system)\s*\(")), file_name_hints=("skill.md", "skills/")),
    LocalRule(id="SKILL-NET-001", title="Skill 存在网络访问指令", severity="中危 P2", category="供应链与漏洞安全", confidence=0.78, remediation="明确网络访问目的和 allowlist。", patterns=(re.compile(r"(?i)\b(curl|wget|requests|httpx|fetch|Invoke-WebRequest)\b"),), file_name_hints=("skill.md", "skills/")),
    LocalRule(id="SKILL-SECRET-001", title="Skill 包含 secret-like 内容", severity="中危 P2", category="身份与权限安全", confidence=0.72, remediation="确认是否为真实凭据；真实明文由 SECRET-KEY-001 提升为 P0 并要求轮换。", patterns=(re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]"),), file_name_hints=("skill.md", "skills/")),
    LocalRule(id="SKILL-WRITE-001", title="Skill 写入工作区外路径", severity="高危 P1", category="工具执行安全", confidence=0.76, remediation="限制写入 data/work 或项目临时目录。", patterns=(re.compile(r"(?i)(write|save|output).{0,80}(/etc/|~/.ssh|C:\\\\Windows|<home>)"),), file_name_hints=("skill.md", "skills/")),
    LocalRule(id="SKILL-INSTALL-001", title="Skill 运行时安装包", severity="中危 P2", category="供应链与漏洞安全", confidence=0.78, remediation="依赖应固定并提前构建。", patterns=(re.compile(r"(?i)\b(pip|npm|pnpm|yarn)\s+(install|add)\b"),), file_name_hints=("skill.md", "skills/", ".sh", ".ps1")),
    LocalRule(id="SKILL-URL-001", title="Skill 隐含外部 URL", severity="中危 P2", category="通信安全", confidence=0.72, remediation="外部 URL 必须声明用途和信任边界。", patterns=(re.compile(r"(?i)https?://(?!127\.0\.0\.1|localhost)"),), file_name_hints=("skill.md", "skills/")),
    LocalRule(id="CONFIG-ALLOW-001", title="配置授予危险工具 always-allow", severity="高危 P1", category="治理与审计安全", confidence=0.88, remediation="危险工具必须按任务审批。", patterns=(re.compile(r"(?i)(always[_-]?allow|allowAlways).{0,80}(shell|exec|write|delete)"),), file_name_hints=("config", "settings", ".json", ".toml")),
    LocalRule(id="MCP-APPROVAL-001", title="stdio MCP 显式关闭审批", severity="高危 P1", category="MCP/Tool 协议安全", confidence=0.84, remediation="stdio MCP 必须生成 consent 记录并逐项审批。", patterns=(re.compile(r"(?i)(approval|required[_-]?consent|confirm)[\"']?\s*[:=]\s*[\"']?(false|never|disabled)"), re.compile(r"(?i)(auto[_-]?start|always[_-]?allow)[\"']?\s*[:=]\s*true")), file_name_hints=("mcp", ".json", ".toml")),
    LocalRule(id="MCP-UNKNOWN-001", title="MCP transport 使用未知值", severity="中危 P2", category="MCP/Tool 协议安全", confidence=0.8, remediation="显式声明 stdio/http/sse transport。", patterns=(re.compile(r"(?i)transport\s*[:=]\s*[\"']?(?!stdio\b|http\b|sse\b)[A-Za-z][A-Za-z0-9_-]+"),), file_name_hints=("mcp", ".json", ".toml")),
    LocalRule(id="MCP-SECRET-KEY-001", title="MCP env 暴露 secret-like 值", severity="高危 P1", category="身份与权限安全", confidence=0.9, remediation="env 只保存 secret reference。", patterns=(re.compile(r"(?i)(API_KEY|SECRET|TOKEN|PASSWORD)[\"']?\s*[:=]\s*[\"']?(?!\$\{|<REDACTED>|secret://)[^\s\"',;}]{8,}"),), file_name_hints=("mcp", ".json", ".toml")),
)


BENIGN_CONTEXT_RE = re.compile(
    r"(?i)\b((example|sample)\s+(only|value|placeholder)|placeholder|dummy|redacted|reference|do\s+not|never\s+run|for\s+detection|training)\b|\$\{|secret://|示例|占位|脱敏|不要|禁止|仅用于(检测|培训)"
)


def line_context(path: Path, line: str, in_markdown_fence: bool) -> str:
    suffix = path.suffix.lower()
    stripped = line.lstrip()
    if suffix in {".md", ".markdown", ".txt"}:
        return "markdown_code" if in_markdown_fence else "markdown_prose"
    if stripped.startswith(("#", "//", "/*", "*", "--", ";")):
        return "comment"
    if suffix in {".json", ".jsonl", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".env", ".xml"}:
        return "config"
    if suffix in {".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".ps1", ".bat", ".cmd"}:
        return "executable_code"
    return "text"


def effective_match_level(rule: LocalRule, path: Path, line: str, context: str) -> tuple[str, float, bool]:
    severity = rule.severity
    confidence = rule.confidence
    high = "P0" in severity or "P1" in severity
    normalized = path.as_posix().lower()
    reference_document = path.name.lower().startswith("readme") or any(
        token in normalized for token in ("/docs/", "/documentation/", "/examples/", "/samples/")
    )
    review_signal = False
    if high and rule.id != "SECRET-KEY-001" and (context == "comment" or reference_document):
        review_signal = True
    if high and BENIGN_CONTEXT_RE.search(line):
        review_signal = True
    if review_signal:
        severity = "中危 P2"
        confidence = min(confidence, 0.6)
    return severity, confidence, review_signal


def analyze_text(path: Path, text: str, target_root: Path) -> list[RuleMatch]:
    findings: list[RuleMatch] = []
    lines = text.splitlines() or [text]
    in_markdown_fence = False
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if path.suffix.lower() in {".md", ".markdown"} and line.lstrip().startswith("```"):
            in_markdown_fence = not in_markdown_fence
            continue
        context = line_context(path, line, in_markdown_fence)
        for rule in RULES:
            if not rule.applies_to_file(path):
                continue
            for pattern in rule.patterns:
                match = pattern.search(line)
                if not match:
                    continue
                snippet = redact_text(line.strip())
                severity, confidence, review_signal = effective_match_level(rule, path, line, context)
                findings.append(
                    RuleMatch(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=severity,
                        category=rule.category,
                        confidence=confidence,
                        remediation=rule.remediation,
                        path=path,
                        display_path=safe_display_path(path, target_root),
                        line=line_number,
                        snippet=snippet,
                        reason=f"规则 {rule.id} 命中模式 {pattern.pattern[:64]}；上下文={context}",
                        source=rule.source,
                        context=context,
                        original_severity=rule.severity,
                        review_signal=review_signal,
                    )
                )
                break
    return findings


def rule_catalog() -> list[dict]:
    return [
        {
            "id": rule.id,
            "name": rule.title,
            "severity": rule.severity,
            "category": rule.category,
            "confidence": rule.confidence,
            "source": rule.source,
            "standards": list(rule.standards or default_standards(rule)),
            "false_positive_guidance": rule.false_positive_guidance,
            "positive_sample": f"tests/fixtures/rules/positive/{rule.id}.txt",
            "benign_sample": f"tests/fixtures/rules/benign/{rule.id}.txt",
            "status": "已发布",
            "version": "1.0.0",
        }
        for rule in RULES
    ]


def default_standards(rule: LocalRule) -> tuple[str, ...]:
    if rule.id.startswith("SECRET") or "SECRET" in rule.id:
        return ("CWE-798", "OWASP-LLM06")
    if "PI" in rule.id or "PROMPT" in rule.id:
        return ("OWASP-LLM01", "MITRE-ATLAS AML.T0051")
    if rule.id.startswith("MCP") or rule.id.startswith("TOOL"):
        return ("OWASP-LLM07", "OWASP-LLM08")
    if rule.id.startswith("SKILL"):
        return ("OWASP-LLM03", "CWE-829")
    return ("OWASP-LLM09",)
