# Agent Security Assessment v4.2.10 企业交付真实性与安全收敛 SPEC

版本：`v4.2.10-enterprise-release-gate`

文档状态：开发基线 / 企业发布阻断项整改

适用仓库：`F:\bigsinger\agent-scan-platform`

基线提交：`ad82350 feat(v4.2.9): finalize delivery closure and full E2E acceptance`

评估日期：2026-07-10

目标读者：直接实施本迭代的开发 AI、测试人员、产品验收人员、企业 POC 运维人员

## 1. 结论先行

### 1.1 当前企业交付门禁

```yaml
gate: FAIL
quality_score: 20
release_level:
  internal_demo: PASS
  supervised_local_poc: CONCERNS
  enterprise_customer_evaluation: FAIL
  production: FAIL
nfr_validation:
  security: FAIL
  reliability: FAIL
  performance: CONCERNS
  maintainability: CONCERNS
  delivery_operations: FAIL
```

质量分按 3 个一级门禁失败项和 2 个关注项计算，不按同类缺陷条数重复扣分：

`100 - 3 * 20 - 2 * 10 = 20`

### 1.2 不能判定企业可交付的直接原因

1. 真实 machine 扫描后发现未完全脱敏的 `sk-...` 模式进入 Evidence 和 artifact，违反“不保存明文 Secret”的核心安全承诺。
2. `58/58 E2E PASS` 由手工 manifest 和“测试文件存在”推导，并不依赖测试运行结果；浏览器测试实际只写入文本伪装的 PNG。
3. 300 个文件生成 4,805 个 Finding、4,805 个 Evidence 和 4,807 个 artifact，结果噪声和制品膨胀无法支持企业人工研判。
4. machine 扫描耗时 267.7 秒，HTTP 请求同步阻塞；任务同时出现 `progress=100`、`WAITING_CONSENT`、`部分完成`，报告却为 `READY` 的状态冲突。
5. 探针只支持 dry-run 安装计划。Hermes 被系统误判为已安装探针，但本机 `hermes hooks list`、`hermes hooks doctor` 和自定义插件列表均证明没有探针接入。
6. 主 API 和 OTel Receiver 没有真正的鉴权、请求体上限、限流、Trusted Host、保留期与背压；`ASSESSMENT_ADMIN_TOKEN` 只被用来判断一个设置字段，没有保护 API。
7. 启停脚本会强制结束任何占用 8000/4318 的进程；演示重置 `-Apply` 实际不重置数据；最终交付包只复制 4 个 Markdown 文件。
8. README、用户手册、运维手册、HTML 标题、数据库元数据仍混用 V4.1、4.1.0、48 页面和 v4.2.9，交付口径不一致。

### 1.3 当前已经具备、必须保留的真实能力

以下能力在本轮实测中成立，v4.2.10 不得回退：

- `tools\verify_v429_final_acceptance.ps1` 运行成功，耗时 393 秒，`169 passed`。
- 验收脚本使用临时 SQLite、artifact root 和 state root，正式库与正式 artifact 前后指纹完全一致。
- Python lock 可解析，wheel 和 sdist 可构建。
- 对 `uv.lock` 导出的 15 个运行依赖执行 `pip-audit`，当前未发现已知漏洞。
- 真实 Chromium 浏览器可打开 Dashboard、Discovery、Task、Report 页面，无控制台错误、页面异常和外网请求。
- 浏览器中可完成 fixture 发现、Skill 类型化详情抽屉、路径快速扫描、任务详情、报告内 Evidence 预览且不离开报告上下文。
- 真实本机发现能识别 Hermes `v0.18.2`、Codex Appx `26.707.3563.0`，并把 Claude Code、Cursor 配置残留标为 `RESIDUAL`。
- 本机发现和 machine 扫描没有扫描本项目 `src/`、`doc/`，且没有启动 stdio MCP、没有修改已安装 Agent。
- 真实 machine 扫描能生成 Finding、Evidence 和 HTML/JSON 报告，说明核心静态扫描管线不是纯原型。

## 2. 本轮验收事实

### 2.1 自动化验收结果

执行：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v429_final_acceptance.ps1
```

结果：

```text
frontend pages=58
pytest=169 passed
pages=58
audit_passed=58
contract_passed=58
e2e_passed=58
gaps=0
elapsed=393s
```

该结果只能证明测试套件当前为绿色，不能证明 58 个页面均完成真实浏览器 E2E，原因见 2.2。

### 2.2 E2E 完整度是假阳性

当前实现：

- `src/assessment/api/v1.py` 的 `completeness_e2e_manifest()` 读取 `e2e_manifest.json`。
- `completeness_runtime_rows()` 仅检查：manifest 的 `status == PASS` 且 `test_file` 存在。
- 它不验证测试名是否存在、不读取 pytest 退出码、不检查测试时间、不校验 Git commit、不验证截图格式。
- `tests/test_v429_browser_journeys.py` 在 Playwright 可用时只创建 `journey-placeholder.png`，文件内容是 `v429-browser-e2e-placeholder`。
- 当前 Python 环境和 Chromium 均可正常运行，因此不存在“浏览器环境无法安装”的客观阻碍。
- 58 个页面的 manifest 只映射到 13 个测试文件，多个页面共用仅验证 HTTP 200 或字典结构的浅断言。

因此，当前 `/api/v1/completeness` 的 `e2e_passed=58` 不具备企业审计证据效力。

### 2.3 真实浏览器抽查

使用隔离数据库和 Chromium 完成以下旅程：

1. 打开 `/assessment`，Dashboard 正常渲染。
2. 打开 `/assessment/discovery`，对 `tests/fixtures/sample_agent_project` 执行发现。
3. 返回 3 条命中，Skill 筛选和类型化详情抽屉可用。
4. 打开 `/assessment/quick-scan`，执行 path 模式扫描。
5. 返回 25 个 Finding、25 个 Evidence 和真实 Report ID。
6. 自动进入任务详情。
7. 从报告中心打开报告预览。
8. 报告内 Evidence 预览保持在报告上下文。
9. 无 Console error、page error 或外网请求。

抽查同时发现：

- 多个 `<label>` 没有 `for`，也没有包裹输入控件，无法使用可访问名称定位。
- 任务详情显示 `100% + WAITING_CONSENT + 0/0 Job`。
- 报告记录为 `READY`，但报告预览中的 HTML、JSON、章节状态仍为 `PENDING`。

### 2.4 真实本机发现

隔离执行耗时 40.8 秒：

```text
hits=361
agents=4
mcp=2
skills=296
errors=0
Hermes=Hermes Agent v0.18.2, ACTIVE, version-command
Codex=26.707.3563.0, ACTIVE, package-metadata
Claude Code=RESIDUAL
Cursor=RESIDUAL
```

安全边界：

```text
safe_mode=local-readonly
mutates_installed_agents=false
stdio_mcp_started=false
```

### 2.5 真实 machine 快速扫描

参数：

```json
{
  "mode": "machine",
  "max_files": 300,
  "max_file_bytes": 1048576,
  "scan_skills": true,
  "run_local_analyzers": true,
  "execution_mode": "readonly"
}
```

结果：

```text
elapsed=267.7s
files_scanned=300
files_skipped=0
agents=4
discovery_hits=361
mcp=2
skills=296
findings=4805
evidence=4805
events=5
report_status=READY
self_project_hits=0
```

严重度：

```text
P0=73
P1=3020
P2=1712
```

主要规则命中：

```text
MCP-FS-001=1730
SKILL-SHELL-001=770
SKILL-URL-001=640
TOOL-NETWORK-001=521
SKILL-NET-001=474
TOOL-DESTRUCTIVE-001=305
```

262 个路径产生 4,805 条 Evidence，单路径最多 236 条，59 个路径超过 20 条。当前 fingerprint 虽然形式上唯一，但没有把同一风险的多次 occurrence 聚合成企业可研判的逻辑 Finding。

### 2.6 敏感数据抽查

对上述隔离 machine 扫描结果执行二次脱敏检测：

```text
Evidence 中仍含 sk-... 模式：19 条
需要再次脱敏的 artifact：44 个
包含明文绝对用户路径的 Evidence：0
包含明文绝对用户路径的 artifact：0
```

路径 token 化是有效的，但 Secret 脱敏不是全链路强制，企业安全门禁必须判 FAIL。

### 2.7 探针兼容性抽查

本机状态：

```text
Hermes Agent v0.18.2
Codex Appx 26.707.3563.0，另有 26.707.3748.0 包目录
```

项目 dry-run 计划返回：

```text
Codex: ready_to_install, hooks_exist=false
Hermes: installed, hooks_exist=true
```

真实 Hermes 命令返回：

```text
hermes hooks list: No shell hooks configured
hermes hooks doctor: No shell hooks configured
hermes plugins list --plain --no-bundled: 空
```

结论：Hermes 探针安装状态检测存在假阳性。当前实现只用配置文本是否包含 `hooks:` 或 `probe` 判断，不足以证明 Hook 或 Plugin 已加载。

Codex 适配仍假设可向 `~/.codex/config.toml` 写入一组生命周期 Hook，但没有对当前 Appx/CLI 版本做 schema 或能力探测，也没有真实 E2E 证据。

### 2.8 运维、数据和交付现状

正式运行数据在验收前已经达到：

```text
SQLite file=47,849,472 bytes
artifact rows=14,085
evidence rows=10,275
report rows=762
task rows=248
artifact files=15,811
artifact bytes=272,656,682
```

问题：

- 没有正式数据保留和压缩策略。
- `start_services.ps1` 会强制终止任何占用 8000/4318 的进程。
- `stop_services.ps1` 同样按端口终止进程，不验证 PID 是否属于本产品。
- 启动脚本使用环境里的任意 `python`，没有 locked environment 安装或版本校验。
- `reset_demo_state.ps1 -Apply` 只写一份 JSON 报告，实际不重置 SQLite 或 artifact。
- `export_final_delivery_package.ps1` 只复制 4 份 Markdown 和一个 manifest，不包含 wheel、报告、Evidence、验收结果、SBOM 或逐文件哈希。
- `src/assessment/persistence/migrations/001_initial.sql` 只有注释，不是可执行迁移。
- 没有 CI workflow、Windows 服务定义、容器交付或正式升级迁移链。

## 3. v4.2.10 唯一目标

本版本不得继续增加新页面或原型展示。唯一目标是把现有产品推进到“企业客户可以在本地独立安装、真实测评、获得可信结果、验证安全边界并导出可审计交付包”的 Release Candidate。

必须同时满足：

```yaml
release_target:
  automated_tests: PASS
  browser_e2e: PASS
  completeness_truthful: PASS
  sensitive_data_gate: PASS
  real_machine_scan: PASS
  finding_quality_gate: PASS
  async_task_state_machine: PASS
  auth_network_boundary: PASS
  probe_capability_truthful: PASS
  otel_receiver_hardened: PASS
  safe_operations: PASS
  final_delivery_package: PASS
  docs_consistent: PASS
```

任何一项 FAIL，版本不得标记“企业可交付”。

## 4. 实施原则

1. 不修改真实 Codex/Hermes 配置，除非用户在 UI/CLI 中对具体变更显式确认。
2. 所有真实探针安装必须先 dry-run、备份、能力检测，再 apply；必须支持原子回滚和卸载。
3. Agent、MCP、Skill 的默认扫描继续只读，不启动 stdio MCP，不执行 Skill。
4. Secret 在进入 SQLite、artifact、报告、日志、探针 buffer 之前必须完成脱敏；检测失败时宁可拒绝持久化。
5. 不能用固定 JSON、手工 PASS、测试文件存在或 HTTP 200 代替真实功能验收。
6. 不允许为通过验收降低断言、吞掉异常、伪造截图或把失败标记为 skip。
7. 本项目 `src/`、`doc/` 和普通项目文件继续默认跳过；仅允许扫描明确标记的测试 MCP/Skill fixture。
8. 所有测试继续使用隔离 DB、artifact、state 和 probe home。

## 5. P0 任务：发布前必须首先完成

### T01 让完整度和 E2E 证据可信

#### 问题

当前 E2E 状态来自可手工编辑的 manifest，浏览器测试是占位文件。

#### 实现要求

1. 删除 `tests/test_v429_browser_journeys.py` 中的 placeholder 逻辑。
2. 增加真实 Playwright 依赖组和 Chromium 安装命令。
3. 增加 `tests/browser/`，至少包含 8 条真实旅程：
   - J01 首次启动与空库 Dashboard。
   - J02 本机发现、类型筛选、Skill 抽屉、分页和导出。
   - J03 path 快速扫描到任务详情、Finding、Evidence、Report。
   - J04 machine 扫描异步进度、等待审批、取消和重试。
   - J05 MCP 静态检查、Consent、命令变化和重新审批。
   - J06 Skill 扫描、变化扫描、详情和证据下载。
   - J07 报告内查看 Finding/Evidence 并返回原上下文。
   - J08 Settings、SQLite、Completeness、最终交付包。
4. 每条旅程必须：
   - 使用真实浏览器。
   - 启动隔离服务。
   - 检查 Console error 和 page error。
   - 检查没有意外外网请求。
   - 生成有效 PNG，必须通过图片签名和最小尺寸校验。
   - 保存 JSON 结果，包含 commit、开始/结束时间、退出码、断言数、截图 SHA-256。
5. `e2e_manifest.json` 只描述“页面映射到哪些测试”，不得保存最终 PASS。
6. 新增机器生成的 `data/acceptance/latest-e2e-result.json` 或等价临时结果文件。
7. `/api/v1/completeness` 只有在以下条件全部成立时才标记 E2E PASS：
   - 测试文件存在。
   - 测试名存在。
   - 最新结果中的退出码为 0。
   - 结果 commit 等于当前 Git commit。
   - 结果生成时间在允许窗口内。
   - 所有声明截图 SHA-256 可校验。
8. 结果缺失、过期、commit 不一致或截图损坏时必须显示 `NOT_ASSERTED` 或 `STALE`。

#### 新增测试

- `tests/test_v4210_completeness_result_binding.py`
- `tests/test_v4210_e2e_manifest_validation.py`
- `tests/browser/test_enterprise_journeys.py`

#### 验收条件

- 删除任意结果文件或修改 commit 后，`e2e_passed` 必须下降。
- 把任意浏览器旅程改成失败后，完整度不得仍显示 58/58。
- PNG 文件前 8 字节必须是标准 PNG 签名，不接受文本占位文件。
- Release 模式不允许因为缺少浏览器而 skip；应明确 FAIL 并给出安装命令。

### T02 全链路 Secret 脱敏与持久化阻断

#### 问题

真实 machine 扫描中仍有 token-shaped Secret 进入 Evidence 和 artifact。

#### 实现要求

1. 建立单一 `SensitiveDataGuard`，禁止扫描、OTel、Probe、Report 各自维护不一致的弱脱敏逻辑。
2. 至少覆盖：
   - OpenAI 风格 `sk-...`。
   - AWS Access Key。
   - Bearer Token。
   - API Key、Token、Secret、Password 赋值。
   - PEM Private Key。
   - Cookie、Session、Authorization。
   - 常见 GitHub、GitLab、Slack、Azure、Google Token。
3. 在以下边界强制调用：
   - `finding`、`evidence` 写库前。
   - artifact 写盘前。
   - HTML/JSON/SARIF 报告渲染前。
   - audit_event、diagnostic_event 写库前。
   - `/api/v1/probes/events` 和 OTLP traces/logs/metrics 入库前。
   - Probe fail-open JSONL buffer 写入前。
   - 导出、备份说明、最终交付包生成前。
4. 增加 `assert_safe_to_persist()`：若脱敏后仍匹配禁止模式，拒绝持久化并生成不含原值的安全事件。
5. Secret Finding 只保存：类型、来源 token、位置、指纹、长度、末尾最多 4 位可选掩码，不保存原始值。
6. 路径继续使用 `<target>`、`~`、`<external>`，报告不得恢复绝对用户目录。
7. 增加历史数据审计工具：
   - `tools/audit_sensitive_data.ps1` 默认 dry-run。
   - 输出表/文件计数、规则 ID、哈希，不输出命中原文。
   - `-Apply` 必须先备份，再原子重写或隔离 artifact。
   - 不允许自动扫描或修改 Agent 文件。

#### 新增测试

- `tests/test_v4210_sensitive_data_guard.py`
- `tests/test_v4210_evidence_persistence_boundary.py`
- `tests/test_v4210_report_redaction.py`
- `tests/test_v4210_otel_redaction.py`
- `tests/test_v4210_probe_buffer_redaction.py`

#### 验收条件

- 对 fixture 和真实 machine 隔离扫描结果执行二次安全审计，命中必须为 0。
- SQLite、artifact、HTML、JSON、日志和 probe buffer 均为 0。
- 测试不得打印测试 Secret 原值。
- 对 1,000 个随机变体做属性测试，脱敏不得抛异常或泄漏输入。

### T03 安全启停与进程所有权

#### 问题

当前脚本会结束占用固定端口的任意进程。

#### 实现要求

1. `start_services.ps1` 发现端口被占用时只能：
   - 如果 PID 文件、进程创建时间、可执行路径和命令行均证明属于本产品，则复用或提示重启。
   - 否则失败退出或自动选择空闲端口，绝不能 kill。
2. 启动后写入 PID manifest：
   - `pid`
   - `process_start_time`
   - `executable_path`
   - `command_line_hash`
   - `listen_host`
   - `listen_port`
   - `run_root`
3. `stop_services.ps1` 只能停止 PID manifest 中且身份校验一致的进程。
4. 优先优雅终止，超时后只对已验证的自有进程强制结束。
5. 脚本必须支持：
   - `-NoBrowser`
   - `-MainPort`
   - `-OtelPort`
   - `-DataRoot`
   - `-LogRoot`
   - `-Foreground`
6. 使用项目 `.venv` 或 `uv run --locked`，不得使用未验证的任意 Python。
7. 增加日志轮转和启动失败日志。

#### 新增测试

- `tests/test_v4210_service_script_safety.py`
- `tools/test_service_ownership.ps1`

#### 验收条件

- 先用独立测试进程占用 8000，启动脚本不得结束它。
- stop 脚本不得结束伪造 PID 文件指向的其他进程。
- 产品自己的两个服务可正常启动、健康检查和停止。

## 6. P1 任务：核心产品可信度

### T04 Finding 聚合、误报治理与规则质量门禁

#### 目标

把“每次正则命中一条 Finding”改为“逻辑 Finding + occurrence 实例”，让结果可研判。

#### 实现要求

1. 逻辑 Finding 指纹至少包含：
   - `rule_id`
   - 规范化资产 ID。
   - token 化路径或组件 ID。
   - 语义 sink/source。
   - 配置键或命令类型。
2. 同一逻辑风险的多行、多次扫描命中写入 `finding_instance`，不重复创建 Finding。
3. UI 默认展示逻辑 Finding 数，详情页展示 occurrence 数、文件数和位置列表。
4. P0/P1 规则必须有明确的利用条件，不能仅因文档出现 `shell`、URL 或文件路径就判高危。
5. 增加上下文分类：配置、可执行脚本、Markdown 说明、代码块、注释、示例、测试数据。
6. 对文档代码块和安全培训样例默认降级为“Review Signal”，除非它被实际注册为 Hook、Skill 执行入口或 MCP 命令。
7. 支持稳定 suppression：
   - 按 finding fingerprint。
   - 按 rule + path glob。
   - 按到期时间。
   - 保存理由、操作人和审计事件。
8. 增加规则基准语料：
   - `tests/fixtures/rules/positive/`
   - `tests/fixtures/rules/benign/`
   - `tests/fixtures/rules/edge/`
9. 每条规则必须登记：严重度、CWE/OWASP/ATLAS 映射、正样本、负样本、修复建议、误报说明。

#### 质量指标

- 基准语料 P0/P1 precision 不低于 95%。
- 基准语料 recall 不低于 90%。
- benign 语料 P0 误报必须为 0。
- 单文件同一规则默认只形成 1 个逻辑 Finding，occurrence 在详情聚合。
- 300 文件 machine 扫描的逻辑 Finding 数必须显著低于 occurrence 数，报告默认不展开全部 occurrence。

#### 新增测试

- `tests/test_v4210_finding_rollup.py`
- `tests/test_v4210_rule_precision_recall.py`
- `tests/test_v4210_suppression_lifecycle.py`

### T05 异步扫描任务与一致状态机

#### 问题

machine 扫描同步阻塞 267.7 秒，状态语义冲突。

#### 实现要求

1. `POST /api/v1/quick-scans` 默认在 2 秒内返回 `202` 和 task/job ID。
2. 扫描进入受控 worker，不在 API request 内执行完整目录遍历。
3. 明确定义状态机：

```text
DRAFT
  -> QUEUED
  -> RUNNING_DISCOVERY
  -> RUNNING_STATIC
  -> WAITING_CONSENT
  -> RUNNING_REPORT
  -> COMPLETED | PARTIAL_COMPLETED | FAILED | CANCELLED
```

4. 规则：
   - `WAITING_CONSENT` 时 progress 不得为 100。
   - `COMPLETED` 才允许 100。
   - `PARTIAL_COMPLETED` 必须列出未完成项。
   - Report `READY` 只有在 HTML/JSON 存在且 SHA-256 校验通过时成立。
   - HTML/JSON `PENDING` 时 Report 不得显示 `READY`。
5. task、scan_job、process_execution、task_event 必须承载真实运行状态，不再只写展示记录。
6. 支持幂等 cancel、retry、clone；取消必须让 worker 停止后续文件读取。
7. SSE 或轮询返回真实进度：已发现目录、已扫描文件、跳过数、当前规则、估计剩余时间。
8. 增加并发限制、重复提交去重、超时和崩溃恢复。
9. machine 扫描增加增量缓存：未变化文件复用 hash 和上次分析结果。

#### 性能目标

- 本验收机器 300 文件冷扫描不超过 120 秒。
- 300 文件无变化复扫不超过 30 秒。
- API 创建任务响应不超过 2 秒。
- UI 每 2 秒内可看到进度变化或明确等待原因。

#### 新增测试

- `tests/test_v4210_task_state_machine.py`
- `tests/test_v4210_scan_cancellation.py`
- `tests/test_v4210_scan_resume.py`
- `tests/test_v4210_incremental_scan.py`

### T06 主 API 与管理面安全

#### 实现要求

1. 默认仍绑定 `127.0.0.1`。
2. 监听地址由启动入口决定，不能只靠 Settings 页面字段假装限制。
3. 分级保护：
   - `/healthz`、版本信息可匿名。
   - 资产、Finding、Evidence、Report 读取需要只读 Token 或本地受信会话。
   - 所有写操作、导出、备份、重置和 Probe 安装需要 Admin Token。
4. 使用常量时间比较，Token 只来自环境变量、Windows Credential Manager 或 Secret Reference。
5. 非 loopback 绑定时，没有强 Token 必须拒绝启动。
6. 增加 `TrustedHostMiddleware`、严格 CORS、请求关联 ID 和安全响应头。
7. 异常响应不得返回原始 `str(exc)`、绝对路径、SQL 或 Secret。
8. 为 JSON、上传、报告导出定义请求体和响应体上限。
9. 写操作形成 actor、action、object、result、correlation ID 审计。

#### 新增测试

- `tests/test_v4210_auth_policy.py`
- `tests/test_v4210_non_loopback_startup.py`
- `tests/test_v4210_error_redaction.py`
- `tests/test_v4210_request_limits.py`

#### 验收条件

- 无 Token 调用写接口返回 401/403。
- 设置 `ASSESSMENT_ADMIN_TOKEN` 但不携带 Header 仍不得写入。
- `--host 0.0.0.0` 且无强 Token 时进程启动失败。
- health 响应不含路径、Token、异常栈和数据库细节。

### T07 Codex/Hermes 探针真实兼容与诚实能力矩阵

#### 当前问题

- 只生成 dry-run 计划，没有 apply/uninstall/rollback。
- Hermes 状态检测存在假阳性。
- Codex Hook 事件和配置 schema 未经当前安装版本证明。

#### 能力状态模型

每个 Agent/版本必须返回以下之一：

```text
SUPPORTED_FULL
SUPPORTED_PARTIAL
DRY_RUN_ONLY
UNSUPPORTED_VERSION
NOT_INSTALLED
INSTALLED_HEALTHY
INSTALLED_DEGRADED
```

不得把“配置中有 hooks 字样”映射成 `INSTALLED_HEALTHY`。

#### Hermes 要求

1. 以本机 `hermes hooks` 的真实 schema 和 shell hook 模型为准，或使用 Hermes 正式插件安装机制。
2. 通过 `hermes --version`、`hermes hooks list`、`hermes hooks doctor`、自定义插件列表形成只读能力探测。
3. 安装前生成精确 diff、备份、目标路径、命令哈希、timeout、事件列表和回滚步骤。
4. apply 必须由用户对具体 plan ID 显式确认。
5. 安装后运行合成事件自测，不发送真实用户 Prompt。
6. 自测失败自动回滚并保持 Hermes 可正常启动。
7. 支持 uninstall、disable、repair 和 drift detection。

#### Codex 要求

1. 通过 Appx 包元数据识别当前版本和实际 executable，不使用固定 WindowsApps 路径。
2. 在修改 `~/.codex/config.toml` 前，必须通过当前版本的本地 schema/help 或 OpenAI 官方文档证明对应 Hook/Plugin/OTel 配置受支持，禁止根据其他 Agent 的事件名推测 Codex 能力。
3. 如果当前 Codex 没有公开稳定的 Hook：
   - 标记 `SUPPORTED_PARTIAL` 或 `DRY_RUN_ONLY`。
   - 不写入虚构 `[hooks]` 配置。
   - 可采用明确说明边界的旁路日志/OTel/进程事件适配，但不得宣称“拦截所有行为”。
4. 对任何 Codex 配置变更执行备份、原子替换、schema 校验、启动前检查和回滚。

#### 稳定性要求

- 探针回调超时预算默认不超过 200ms，推荐 50ms 内返回。
- Collector 不可达必须 fail-open，不阻塞 Agent。
- 本地 buffer 有大小上限、轮转、文件权限和脱敏。
- Probe 异常不得改变工具调用结果、用户输入或 Agent 输出。
- 不允许在探针中执行 stdio MCP 或未审批命令。

#### 新增测试

- `tests/test_v4210_probe_capability_detection.py`
- `tests/test_v4210_hermes_probe_lifecycle.py`
- `tests/test_v4210_codex_probe_lifecycle.py`
- `tests/test_v4210_probe_fail_open_latency.py`
- `tests/test_v4210_probe_rollback.py`

#### 验收条件

- 当前本机没有 Hook/Plugin 时，Hermes 不得显示 installed。
- fake home 完成 apply、synthetic event、disable、uninstall、rollback 全链路。
- 对真实 Codex/Hermes 默认只做 capability probe，不自动 apply。
- 断开 Receiver 后 Agent 测试命令行为不变，Probe 返回不超过预算。

### T08 OTel Receiver 企业旁路加固

#### 实现要求

1. 去掉“骨架”定位，明确支持的协议和不支持项。
2. 优先使用 OpenTelemetry 官方协议模型解析 OTLP，不继续无限扩展手写 JSON parser。
3. 支持标准 OTLP/HTTP JSON；如声明支持 protobuf，则必须有真实 protobuf E2E。
4. 支持 gzip、trace/span ID 校验、时间戳校验和 partial success。
5. Receiver 默认 loopback；非 loopback 必须 Token 或 mTLS。
6. 增加：
   - 请求体大小上限。
   - 单批 span/log/metric 数量上限。
   - 每客户端速率限制。
   - 队列和背压。
   - SQLite 批量事务。
   - 幂等 key 和重复数据处理。
7. 禁止默认保存完整 Prompt/Result：
   - 默认 `hash-only`。
   - 可选 `redacted-preview`。
   - 原始模式默认禁用；若未来实现，必须加密、授权、短保留期和审计。
8. Receiver 计数不能只存在进程全局字典，重启后应从数据库派生或明确标记 session counter。
9. 增加 retention：按事件类型、时间和租户 dry-run 预览后清理。
10. 对 trace、session、tool_call、agent、risk 建索引并提供查询时间预算。

#### 新增测试

- `tests/test_v4210_otlp_protocol.py`
- `tests/test_v4210_otel_auth_limits.py`
- `tests/test_v4210_otel_backpressure.py`
- `tests/test_v4210_otel_retention.py`
- `tests/test_v4210_otel_deduplication.py`

#### 验收条件

- 超限请求返回 413/429，不造成 Receiver 崩溃或 SQLite 锁死。
- 10,000 个合成事件批量接收后无重复、无 Secret、链路可查询。
- Receiver 停止或过载时 Probe 保持 fail-open。

## 7. P1 任务：数据、交付与文档

### T09 数据保留、重置和迁移

#### 实现要求

1. `reset_demo_state.ps1` 必须真正实现：
   - 默认 dry-run，输出各表和文件的预计删除数。
   - `-Apply` 前自动 SQLite backup 和 artifact manifest。
   - `-KeepDiscovery` 保留 discovery_run/hit/agent 及关联证据。
   - 只清理本产品 DB/artifact，不接触 Agent 配置。
2. 增加 retention dry-run/apply：
   - task、event、finding、evidence、report、OTel、artifact 分别配置。
   - 数据库行和文件必须引用一致，不产生孤儿。
3. 增加 artifact 垃圾回收和完整性检查。
4. 建立可执行 schema migration：
   - schema version 表。
   - 每次迁移事务。
   - 升级前备份。
   - 失败回滚。
5. 正式库清理必须由用户单独确认，本迭代测试不得自动清理用户现有数据。

#### 新增测试

- `tests/test_v4210_reset_demo_state.py`
- `tests/test_v4210_retention.py`
- `tests/test_v4210_artifact_gc.py`
- `tests/test_v4210_schema_migration.py`

### T10 真正的最终交付包

#### 包内容

`tools/export_final_delivery_package.ps1` 必须生成 zip 和 manifest，至少包含：

- wheel 和 sdist，或明确的本地安装包。
- `uv.lock` 和依赖 SBOM。
- OpenAPI JSON。
- schema migration 清单。
- 运维部署、用户帮助、安全边界、发布说明。
- 最新 pytest、Playwright、Secret audit、dependency audit 结果。
- 浏览器截图和 SHA-256。
- 一份脱敏的 fixture 扫描报告、Evidence package 和校验结果。
- 版本、Git commit、构建环境和生成时间。
- 每个文件的相对路径、大小、SHA-256、内容类型和来源。

#### 要求

1. manifest 自身哈希单独输出。
2. 提供 `tools/verify_delivery_package.ps1`，在解压后离线校验。
3. 包内不得包含正式客户数据、用户绝对路径、Token、`.env`、真实 Agent 配置或正式 SQLite。
4. 在一个全新临时目录安装 wheel，启动服务，完成 health、fixture scan 和浏览器 smoke。
5. sdist 不应默认包含整个测试目录和开发缓存，除非在交付说明中明确。

#### 新增测试

- `tests/test_v4210_delivery_manifest.py`
- `tests/test_v4210_delivery_secret_scan.py`
- `tests/test_v4210_wheel_fresh_install.py`

### T11 版本、文档和 UI 状态统一

#### 必须修正

1. 以下位置统一为 v4.2.10 和 58 页面：
   - `README.md`
   - `doc/USER_GUIDE.md`
   - `doc/OPERATIONS_DEPLOYMENT.md`
   - `doc/SPEC_VALIDATION.md`
   - `src/assessment/main.py`
   - `src/assessment/store.py`
   - `src/assessment/static/assessment/index.html`
   - `src/assessment/__init__.py`
2. `app_version`、`schema_version`、报告模板版本和 Profile 版本不得继续固定为 4.1.0。
3. 文档不得同时声称“48 页面”和“58 页面”。
4. 文档必须区分：
   - 已真实实现。
   - 仅 dry-run。
   - 版本不支持。
   - 需要外部平台接入。
5. 更新企业验收清单，列出命令、预期结果、截图点、artifact 路径和失败排查。
6. 所有 PowerShell 命令在 Windows PowerShell 中实跑，不得使用 Bash heredoc。

### T12 前端可访问性和状态可读性

1. 所有 label 使用 `for/id` 或合法包裹关系。
2. icon button 有可访问名称和 tooltip。
3. 任务状态只显示一个主状态，次状态解释原因，不出现 100% 与等待状态冲突。
4. 报告 READY/PENDING/FAILED 与真实 artifact 一致。
5. 4,805 occurrence 不允许一次全部渲染；Finding/Evidence 表必须服务端分页或虚拟化。
6. 报告内查看 Finding/Evidence 默认抽屉或内联，不丢失筛选、滚动和报告上下文。
7. 增加 1366x768、1440x900、1920x1080 和 390x844 浏览器截图验收。

## 8. P2 任务：维护性收敛

### T13 拆分单体文件并删除死代码

当前规模：

```text
src/assessment/api/v1.py: 12,065 lines / 550,824 bytes
src/assessment/static/assessment/app.js: 4,358 lines / 231,664 bytes
src/assessment/static/assessment/index.html: 1,313 lines / 260,933 bytes
```

要求：

1. 将 API 按 discovery、scan、finding、report、admin、observability、probe 拆分 router/service。
2. 删除 `if False` 形式的失效分支和 v429 临时路由补丁。
3. 业务操作不得继续依赖一个通用 `handle_write()` 巨型分发器。
4. 前端至少按页面组拆分组件或模块；不得改变现有视觉和路由行为。
5. 先补回归测试再拆分，不把架构重构与业务语义修改混在一个提交。

该任务不得阻塞 P0 安全修复，但必须在企业 Release Candidate 前完成最小拆分，否则后续修复风险过高。

## 9. 实施顺序和提交边界

建议严格按以下顺序，不允许最后一次性提交全部内容：

1. `fix(security): enforce persistence redaction gate`
2. `fix(acceptance): bind completeness to real test results`
3. `fix(ops): enforce owned-process lifecycle`
4. `feat(scan): add finding rollup and rule quality gate`
5. `feat(tasks): add asynchronous scan state machine`
6. `feat(security): protect management and receiver APIs`
7. `feat(probes): implement truthful codex hermes capability lifecycle`
8. `feat(otel): harden receiver ingestion and retention`
9. `feat(delivery): implement reset migration and auditable package`
10. `refactor: split api and frontend modules`
11. `docs: align v4.2.10 release and enterprise acceptance`

每个提交必须包含对应测试和文档，不允许只改 manifest 或文字状态。

## 10. 必须新增的一键验收

新增：

```text
tools/verify_v4210_enterprise_release.ps1
```

脚本必须：

1. 创建唯一临时运行根目录。
2. 设置：

```powershell
$env:ASSESSMENT_DB_PATH = Join-Path $RunRoot 'app.db'
$env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $RunRoot 'artifacts'
$env:ASSESSMENT_STATE_ROOT = Join-Path $RunRoot 'state'
$env:ASSESSMENT_DISABLE_BACKGROUND_JOBS = 'true'
$env:ASSESSMENT_ADMIN_TOKEN = '<generated-test-token>'
$env:ASSESSMENT_OTEL_TOKEN = '<generated-test-token>'
```

`ASSESSMENT_DISABLE_BACKGROUND_JOBS=true` 只禁止服务启动时自动拉起非受控后台任务；异步状态机测试必须显式启动隔离的 in-process worker 或测试 worker，不能因此跳过真实队列、取消和恢复断言。

3. 记录正式 DB 和 artifact 的前后 hash/count，证明零污染。
4. 执行：

```powershell
uv lock --check
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest -q
python -m playwright install chromium
python -m pytest tests\browser -q
powershell -ExecutionPolicy Bypass -File tools\audit_sensitive_data.ps1 -DataRoot $RunRoot
powershell -ExecutionPolicy Bypass -File tools\verify_delivery_package.ps1 -PackagePath <path>
```

5. 执行真实本机只读 discovery，并断言当前可识别 Codex/Hermes；不得对真实配置 apply。
6. 执行有界 machine scan，输出耗时、逻辑 Finding、occurrence、Evidence、artifact 和状态机结果。
7. 执行 Secret 二次扫描，必须为 0。
8. 生成机器可读 `enterprise-acceptance-result.json`。
9. 只有全部阶段通过才更新 completeness result。
10. 任一阶段失败，脚本返回非 0，不能继续输出“final acceptance passed”。

## 11. 最终验收指标

| 维度 | 必须达到 |
|---|---|
| pytest | 全部通过，无 xfail 掩盖阻断项 |
| 浏览器 | 8 条真实旅程通过，截图可校验 |
| 完整度 | 58 页结果绑定当前 commit 的真实测试结果 |
| Secret | DB、artifact、报告、日志、buffer 二次扫描 0 命中 |
| 本机发现 | 正确识别当前 Codex/Hermes 版本，状态不假阳性 |
| machine scan | 异步返回，300 文件冷扫描不超过 120 秒 |
| 增量扫描 | 300 文件无变化复扫不超过 30 秒 |
| Finding | 逻辑 Finding 与 occurrence 分离，benign P0 误报为 0 |
| 状态机 | 不出现 100% + WAITING_CONSENT、READY + PENDING 冲突 |
| API 安全 | 写接口无 Token 为 401/403，非 loopback 无强 Token 拒绝启动 |
| Probe | Hermes/Codex 能力状态有版本证据，apply 仅显式确认，支持回滚 |
| OTel | 鉴权、限流、上限、背压、幂等、保留期通过 |
| 运维 | 不结束非本产品进程，启动/停止/备份/恢复可验证 |
| 重置 | dry-run 预览准确，Apply 先备份并真正清理 |
| 交付包 | zip、manifest、逐文件 SHA、wheel、SBOM、验收证据齐全 |
| 文档 | v4.2.10、58 页面、能力边界全局一致 |
| 正式数据 | 验收前后正式 DB 和 artifact 零变化 |

## 12. 拒收条件

出现以下任一情况，v4.2.10 直接拒收：

1. 仍用手工 `status=PASS` 让 completeness 变成 58/58。
2. 浏览器测试写 placeholder、空白截图或在 Release 模式 skip。
3. 任意 Secret 原文进入 SQLite、artifact、报告、日志或 buffer。
4. 启停脚本结束不属于本产品的进程。
5. machine 扫描仍同步阻塞 API 数分钟。
6. 同一文件同一规则的 occurrence 继续全部作为顶层 Finding 展示。
7. 任务出现 100% 与 WAITING/RUNNING 状态冲突。
8. Report READY 但 HTML/JSON 不存在、校验失败或仍显示 PENDING。
9. Hermes 未配置 Hook/Plugin 却显示 installed/healthy。
10. Codex 未证明 Hook 支持却修改其 config.toml。
11. Probe apply 未经过 plan ID、用户确认、备份和回滚验证。
12. Receiver 无鉴权即可在非 loopback 接收数据。
13. 无 Token 可以调用写接口、导出 Evidence 或执行备份/重置。
14. `reset_demo_state.ps1 -Apply` 仍然是 no-op。
15. 最终交付包仍只包含 Markdown。
16. 文档仍混用 48/58 页面或 4.1.0/4.2.10。
17. 验收污染正式 DB、artifact 或已安装 Agent 配置。
18. 未提交 Git，或代码、测试、文档不在同一提交链中。

## 13. 最终交付物

代码：

- 真实验收结果绑定机制。
- 统一 SensitiveDataGuard。
- Finding rollup 和规则质量门禁。
- 异步 task/job 状态机。
- API/Receiver 安全中间件。
- Codex/Hermes 真实能力探测和受控 Probe 生命周期。
- OTel Receiver 限流、背压、保留和幂等。
- 安全启停、重置、迁移、数据保留和交付包。

测试：

- 本 SPEC 列出的全部 v4210 测试。
- 8 条真实 Playwright 旅程。
- 真实本机只读 discovery/machine scan 验收。
- Secret 二次扫描。
- 新鲜目录 wheel 安装验收。

文档：

- 更新 `README.md`。
- 更新 `doc/OPERATIONS_DEPLOYMENT.md`。
- 更新 `doc/USER_GUIDE.md`。
- 更新 `doc/SPEC_VALIDATION.md`。
- 更新 `doc/SECURITY_BOUNDARY.md`。
- 新增 `doc/ENTERPRISE_ACCEPTANCE_REPORT_v4_2_10.md`。
- 新增 `doc/RELEASE_NOTES_v4_2_10.md`。

制品：

- `agent-security-assessment-v4.2.10-<commit>.zip`
- `manifest.json`
- `enterprise-acceptance-result.json`
- `dependency-audit.json`
- `sensitive-data-audit.json`
- Playwright screenshots 和 trace。
- 脱敏 fixture 报告与 Evidence package。

## 14. 开发 AI 完成后的回报格式

开发完成后必须提交以下内容，不能只说“已完成”：

```text
1. Git commit 列表
2. 变更文件列表
3. 每个 T01-T13 的完成状态
4. verify_v4210 完整输出摘要和退出码
5. pytest passed/failed/skipped 数量
6. Playwright 旅程数量、截图路径和 trace 路径
7. Secret audit 命中数
8. machine scan 耗时、逻辑 Finding、occurrence、Evidence、artifact 数
9. Codex/Hermes capability probe 结果
10. API/OTel 鉴权与限流测试结果
11. 正式 DB/artifact 前后指纹
12. 最终交付包路径、大小和 manifest SHA-256
13. 已知限制和未完成项
```

任何未完成项必须保持 FAIL/NOT_ASSERTED，禁止通过改文档或 manifest 隐藏。
