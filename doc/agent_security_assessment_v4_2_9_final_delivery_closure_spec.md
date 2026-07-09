# Agent Security Assessment v4.2.9 终局迭代 SPEC：全页面 E2E、浏览器验收与企业交付收敛

版本：v4.2.9-final-delivery-closure  
日期：2026-07-09  
状态：待第三方 AI 开发实施  
角色定位：产品验收、最终交付规划、企业级验收收敛  
适用仓库：`F:/bigsinger/agent-scan-platform`

## 1. 本轮定位

本轮是“终局收敛版”，目标不是继续扩新功能，而是把当前系统从“核心能力逐步可用”推进到“企业客户可以完整测评、验收、复盘、交付”的状态。

v4.2.8 已经显著推进：

- 本机发现体验完成产品化。
- Discovery 服务端查询、Agent 归一、MCP/Skill 专项、agent-scan 映射、ABOM/Adapter E2E 已通过。
- 完整测试通过，当前结果为 `153 passed`。
- 完整性矩阵达到 `audit_passed=58`、`contract_passed=58`、`e2e_passed=28`。

但离最终目标仍差 30 个页面 E2E、浏览器级交互证明、测试数据隔离、运营/系统页面闭环、管理口保护、最终文档和一键交付包。本轮必须一次性收敛这些缺口，避免继续反复迭代。

## 2. 当前验收事实

### 2.1 最新提交

```text
6cd594d feat(v4.2.8): normalize assets and validate MCP Skill E2E
```

评估开始时工作区干净。

### 2.2 v4.2.8 验收结果

执行命令：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v428_asset_mcp_skill.ps1
```

结果摘要：

```text
frontend offline check passed: pages=58
discovery server query: 2 passed
self-project legacy policy: 2 passed
agent identity normalization: 2 passed
test isolation: 1 passed
mcp skill api contract: 2 passed
mcp static consent e2e: 1 passed
skill scan detail e2e: 1 passed
agent scan mapping e2e: 1 passed
abom adapter e2e: 1 passed
mcp skill rules: 1 passed
docs command hygiene: 1 passed
full test suite: 153 passed in 236.03s
v4.2.8 asset/mcp/skill acceptance verification passed
```

### 2.3 当前完整性矩阵

当前 `/api/v1/completeness?page_size=200` 摘要：

```text
pages=58
apis=180
sqlite_tables=88
rules=25
audit_passed=58
contract_passed=58
e2e_passed=28
gaps=30
```

已 E2E PASS：

- P02 快速扫描
- P04 本机发现
- P05 Agent 资产
- P06 Agent 详情
- P07 ABOM
- P08 Adapter 覆盖
- P10 agent-scan 兼容
- P11 MCP Server
- P12 MCP 审批
- P13 Skills
- P14 Skill 详情
- P16 风险列表
- P17 证据中心
- P20 报告中心
- D05 agent-scan issue 详情
- D06 MCP Server 详情
- D07 Tool 详情
- D09 报告预览
- P49-P54
- D19-D22

仍未 E2E PASS 的 30 个页面：

```text
P01 /assessment
P03 /assessment/new
P09 /assessment/profiles
P15 /assessment/tasks
P18 /assessment/redteam-cases
P19 /assessment/python-exec
P21 /assessment/findings
P22 /assessment/findings/{id}
P23 /assessment/evidence
P24 /assessment/attack-paths
P25 /assessment/reports
P26 /assessment/retests
P27 /assessment/rules
P28 /assessment/scanners
P29 /assessment/schedules
P30 /assessment/integrations
P31 /assessment/settings
P32 /assessment/sqlite
P33 /assessment/licenses
P34 /assessment/completeness
D01 /assessment/adapters/openclaw
D02 /assessment/adapters/hermes
D03 /assessment/adapters/claude-code
D04 /assessment/adapters/codex
D08 /assessment/redteam-cases/{id}
D10 /assessment/profiles/{id}
D11 /assessment/rules/{id}
D12 /assessment/scanners/{id}
D13 /assessment/platform-embed
D14 /assessment/api-debug
```

### 2.4 已修复能力

v4.2.8 当前已确认：

- `GET /api/v1/discovery-hits?type=Skill` 只返回 Skill。
- `GET /api/v1/discovery-hits?q=jwt` 可服务端搜索。
- 默认发现列表不再展示普通 self-project 历史源码命中。
- `/api/v1/agents` 已归一为 Claude Code/Codex/Cursor/Generic/Hermes 等产品级资产。
- `/api/v1/mcp` 已返回别名响应，不再是通用 `NOT_IMPLEMENTED`。
- 规则数从 10 提升到 25。

### 2.5 仍存在的关键风险

1. 没有浏览器级 E2E：当前未发现 Playwright 或等价浏览器测试。
2. 30 个页面仍 `NOT_ASSERTED`，企业客户会认为这些页面未被证明可用。
3. 测试隔离不彻底：`tools/verify_v428_asset_mcp_skill.ps1` 仍跑主应用 TestClient，正式 SQLite 中已有大量 test/contract 记录，`artifact` 表行数超过 12000。
4. P19 自然路径存在别名缺口：`/api/v1/executions` 可用，但 `/api/v1/python-exec`、`/api/v1/process-executions`、`/api/v1/processes` 返回 404。
5. v4.2.8 E2E 有些测试仍偏浅，例如只验证列表存在或状态码，尚未覆盖真实 UI 操作、失败态、导出包内容、证据链一致性。
6. 管理口安全仍主要依赖默认本地绑定和设置校验，缺少统一“企业验收模式”的管理口保护测试。

## 3. 本轮最终目标

本轮完成后必须达到：

```text
pages=58
audit_passed=58
contract_passed=58
e2e_passed=58
gaps=0
rules>=25
full pytest PASS
browser e2e PASS
final delivery package PASS
```

企业级目标：

1. 本地一键启动、一键验收、一键导出演示/交付包。
2. 58 个页面全部 E2E PASS，且 manifest 指向真实测试。
3. 至少 5 条关键用户旅程有浏览器级 E2E。
4. 自动化测试默认使用隔离 DB 和隔离 artifact root，不污染本地正式库。
5. 管理口默认只监听 localhost；非 localhost 必须显式配置并启用保护。
6. 所有导出包具备 SHA-256、脱敏说明、来源链路和复测证据。
7. 文档命令可复制执行，无控制字符、无 Bash 风格 heredoc、无过期端口/路径。

## 4. 非目标与边界

本轮不新增大功能域，不引入云依赖，不自动接入真实 Agent hook。

禁止事项：

- 不修改真实 Codex/Hermes/Claude/Cursor/Windsurf/Kiro 配置。
- 不启动 stdio MCP。
- 不执行 Skill 代码。
- 不将本项目普通源码/文档作为被测资产。
- 不保存明文 Secret。
- 不通过硬编码 `e2e=PASS` 伪造完整性。

## 5. 终局开发任务

### T01. 测试运行态彻底隔离

目标：所有自动化测试和 verify 脚本默认使用临时数据库、临时 artifact 目录、临时 state 目录。

涉及文件：

- `src/assessment/store.py`
- `src/assessment/api/v1.py`
- `tests/conftest.py`
- `tools/verify_v429_final_acceptance.ps1`
- 所有 v429 测试

实现要求：

1. 支持环境变量：

```text
ASSESSMENT_DB_PATH
ASSESSMENT_ARTIFACT_ROOT
ASSESSMENT_STATE_ROOT
ASSESSMENT_DISABLE_BACKGROUND_JOBS=true
```

2. `assessment.main.app` 和 `get_store()` 必须尊重上述环境变量。
3. 所有 v429 测试通过 pytest fixture 设置临时目录。
4. verify 脚本在开头创建临时根目录：

```powershell
$RunRoot = Join-Path $env:TEMP ("agent-scan-v429-" + [guid]::NewGuid().ToString("N"))
$env:ASSESSMENT_DB_PATH = Join-Path $RunRoot "app.db"
$env:ASSESSMENT_ARTIFACT_ROOT = Join-Path $RunRoot "artifacts"
$env:ASSESSMENT_STATE_ROOT = Join-Path $RunRoot "state"
$env:ASSESSMENT_DISABLE_BACKGROUND_JOBS = "true"
```

5. 测试结束后输出临时目录位置，默认可删除。
6. 增加测试断言正式库 `data/db/app.db` 的 mtime 和 row counts 不因 v429 verify 改变。

验收：

- 跑完 v429 verify 后正式 `data/db/app.db` 不新增 `contract_*`、`v429_*`、`test_*` 记录。
- `artifact` 表不会因 v429 自动化验收继续膨胀。

### T02. 全页面 E2E Manifest 收敛

目标：把剩余 30 页全部从 `NOT_ASSERTED` 推进到 `PASS`。

涉及文件：

- `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`
- `src/assessment/api/v1.py`
- `tests/test_v429_*.py`

实现要求：

1. 新增页面级测试文件：

```text
tests/test_v429_dashboard_create_profiles_e2e.py
tests/test_v429_task_execution_redteam_e2e.py
tests/test_v429_result_closure_e2e.py
tests/test_v429_admin_operations_e2e.py
tests/test_v429_detail_pages_e2e.py
tests/test_v429_browser_journeys.py
```

2. Manifest 中每个 PASS 必须有：

- `page_id`
- `test_file`
- `test_names`
- `command`
- `assertions`
- `safety_invariants`

3. 不允许一个浅测试无差别覆盖 30 页。每个页面至少要有一个页面专属断言。
4. `/api/v1/completeness` 的 `e2e_passed` 必须由 manifest 和真实测试文件共同决定。

验收：

```text
e2e_passed=58
gaps=0
```

### T03. 浏览器级 E2E 基础设施

目标：证明真实前端可点击、可路由、可开抽屉、可返回上下文。

涉及文件：

- `pyproject.toml`
- `tests/test_v429_browser_journeys.py`
- `tools/verify_v429_final_acceptance.ps1`
- 可新增 `tests/browser_helpers.py`

实现要求：

1. 使用 Playwright 或等价浏览器测试工具。
2. 若本机缺浏览器，脚本必须明确提示安装命令，不能假 PASS。
3. 浏览器测试启动本地测试服务，使用隔离 DB。
4. 覆盖桌面视口和窄屏视口。
5. 捕获 console error、pageerror、failed request。
6. 至少保存关键截图到临时 artifact root。

必须覆盖 5 条旅程：

1. 本机发现：打开 P04，筛 Skill，搜索 jwt，打开详情抽屉，关闭后保持筛选。
2. 快速扫描到报告：P02 发起扫描，进入任务，查看 Finding/Evidence/Report。
3. MCP/Skill 专项：P11/P13 打开详情，检查不启动 stdio、不执行 Skill。
4. 规则到复测：P27 测试规则，P21 接受风险/误报，P26 创建复测。
5. 系统运维：P31 设置校验，P32 SQLite 检查，P34 完整性矩阵导出。

验收：

- 浏览器 E2E PASS。
- 无 console error。
- 截图非空。
- 文本不明显重叠。

### T04. Dashboard 与创建测评闭环

覆盖页面：P01、P03。

目标：从首页看真实运行态，再创建完整测评草稿并启动。

API/功能要求：

- `GET /api/v1/dashboard`
- `GET /api/v1/health`
- `POST /api/v1/assessments/drafts`
- `GET /api/v1/assessments/drafts/{id}`
- `POST /api/v1/assessments/drafts/{id}/validate`
- `POST /api/v1/assessments/drafts/{id}/start`

测试断言：

- Dashboard 指标来自真实 SQLite/API，不使用 seed demo。
- P03 wizard 校验必填项。
- 草稿保存后可恢复。
- 启动后生成真实 assessment/task。
- 安全边界字段为只读。

### T05. Profile 与 Adapter 详情

覆盖页面：P09、D01-D04、D10。

目标：Adapter 和 Profile 不只是列表，还能实际测试、复制、导出、进入详情。

要求：

- Adapter 详情覆盖 OpenClaw/Hermes/Claude Code/Codex。
- Hermes/Codex 详情必须基于本机真实发现记录。
- Profile 支持创建、复制、校验、导出。
- D10 Profile 详情支持 dry-run 预估。

测试断言：

- D01-D04 路由不回落 dashboard。
- 详情 API 返回 discovery/material/coverage/self_test。
- Profile 复制不覆盖原记录。
- 导出包有 SHA-256。

### T06. 任务与执行中心

覆盖页面：P15、P19。

目标：任务状态机、事件流、执行中心、失败恢复可验收。

API/别名要求：

- `GET /api/v1/tasks`
- `GET /api/v1/tasks/{id}`
- `GET /api/v1/tasks/{id}/events`
- `POST /api/v1/tasks/{id}/cancel`
- `POST /api/v1/tasks/{id}/retry`
- `POST /api/v1/tasks/{id}/clone`
- `GET /api/v1/executions`
- `GET /api/v1/executor`
- `GET /api/v1/python-exec` 必须返回别名或列表，不能 404。
- `GET /api/v1/process-executions` 必须返回别名或列表，不能 404。

测试断言：

- 任务从 queued/running/done/failed/cancelled 状态转换可控。
- 取消和重试有审计事件。
- 执行中心不执行未审批命令。
- 输出脱敏、限长、可下载。

### T07. 红队用例与 dry-run 闭环

覆盖页面：P18、D08。

目标：红队用例创建、变量渲染、dry-run、结果详情可验收。

要求：

- 创建 case。
- 校验变量。
- dry-run 不调用真实外部 LLM，不读取真实敏感文件。
- 生成 run、finding/evidence。
- D08 详情可查看变量、样本、结果和脱敏证据。

测试断言：

- dry-run 命中本地规则。
- `~/.ssh/id_rsa` 等敏感路径仅作为脱敏样本，不读取真实文件。
- 结果可导出。

### T08. 风险、证据、攻击路径完整闭环

覆盖页面：P21、P22、P23、P24。

目标：从 finding 到 evidence 到 attack path 到 policy draft 一条链路可验收。

要求：

- Finding 列表支持过滤、接受风险、误报、分派、复测。
- D22/P22 详情展示证据、来源链、修复建议、状态历史。
- Evidence 支持详情、脱敏、下载、导出包完整性校验。
- Attack path 支持构建、确认、生成 policy draft、导出。

测试断言：

- Finding/Evidence/AttackPath ID 互相可追溯。
- Evidence package 含 SHA-256、redaction_policy、source_chain。
- 报告中打开证据不丢失上下文。

### T09. 报告与复测最终交付

覆盖页面：P25、P26。

目标：报告中心和复测中心达到企业演示/交付标准。

要求：

- 创建报告。
- 预览报告。
- 下载 HTML/JSON。
- 生成 delivery package。
- 创建复测。
- 复测 diff 展示 before/after。
- 复测结果回写 Finding。

测试断言：

- 报告 package 包含 report、findings、evidence、hash manifest、redaction summary。
- 复测不重新扫描本项目普通源码。
- HTML 报告可离线打开。

### T10. 规则、扫描器、调度、集成

覆盖页面：P27、P28、P29、P30、D11、D12、D13。

目标：能力管理页面从“列表存在”推进到“测试、发布、运行、导出”闭环。

要求：

- Rule：创建、测试、发布、详情、导出。
- Scanner：self-test、启停状态、详情、导出。
- Schedule：创建、run-now、run-due、失败恢复、导出。
- Integration：test、sync、event ingest、export。
- Platform embed：模拟主平台 token/tenant 上下文，证明边界。

测试断言：

- 发布规则后不可静默覆盖。
- Scanner self-test 生成 artifact。
- Schedule run-now 生成 job。
- Integration 不保存明文 Secret，只允许 reference。
- D13 显示主平台托管和本地独立边界。

### T11. 系统运维与完整性

覆盖页面：P31、P32、P33、P34、D14。

目标：企业客户能检查设置、数据库、许可证、完整性和 API 调试。

要求：

- Settings：保存、测试、导出、恢复默认。
- SQLite：integrity-check、backup、checkpoint、restore-drill。
- Licenses：第三方 notices 导出。
- Completeness：导出完整性包。
- API Debug：请求真实 API，展示状态、correlation id、错误详情。

测试断言：

- 设置拒绝 `0.0.0.0` 且未托管的危险绑定。
- 设置拒绝原始 Secret。
- SQLite backup 包含 hash。
- License export 包含 Vue/FastAPI/SQLite/本项目依赖说明。
- D14 对未实现路由显示受控错误，不崩溃。

### T12. API 别名和路由一致性

目标：用户按页面路由或自然 API 名称访问时不踩 404。

必须处理：

- `/api/v1/python-exec`
- `/api/v1/process-executions`
- `/api/v1/processes`
- 所有页面 Page API Map 中引用的自然路径。

要求：

- 可用路径返回数据。
- 别名路径返回 `alias_for` 和相同 items。
- 真正不支持的路径必须在文档列出，不能被页面按钮调用。

测试：

- `tests/test_v429_api_alias_contract.py`

### T13. 管理口安全和部署模式

目标：企业测评时 API 暴露面可解释、可测试。

要求：

1. 默认只绑定 `127.0.0.1`。
2. 非 localhost 绑定必须满足：
   - `host_platform_managed=true`
   - 或显式 `ASSESSMENT_ADMIN_TOKEN`。
3. 管理类写接口支持可选 token 校验。
4. CORS 默认关闭或限制 localhost。
5. `/api/v1/health` 不泄露敏感路径/secret。

测试：

- 未授权写接口返回 401/403 或本地-only 说明。
- localhost 读接口保持可用。
- 文档清楚说明本地独立和主平台托管两种模式。

### T14. 数据清理与演示重置

目标：本地演示环境可恢复干净状态。

新增工具建议：

```text
tools/reset_demo_state.ps1
tools/export_final_delivery_package.ps1
```

功能：

- 清理 `contract_*`、`test_*`、`v42*_smoke_*` 测试数据。
- 可选择保留真实 discovery 结果。
- 备份正式 DB 后再清理。
- 输出清理报告 artifact。

测试断言：

- dry-run 清理只报告不修改。
- 非 dry-run 只修改本系统 SQLite，不删除真实 Agent 文件。

### T15. 最终文档与验收手册

必须更新：

- `doc/OPERATIONS_DEPLOYMENT.md`
- `doc/USER_GUIDE.md`
- `doc/SPEC_VALIDATION.md`
- `doc/FINAL_ACCEPTANCE_CHECKLIST.md` 新增
- `doc/SECURITY_BOUNDARY.md` 新增
- `doc/RELEASE_NOTES_v4_2_9.md` 新增

内容要求：

1. 一键启动。
2. 一键验收。
3. 58 页面验收矩阵。
4. 5 条浏览器旅程截图点。
5. 证据包位置。
6. 失败排查。
7. 安全边界。
8. 已知不交付项，如有必须清楚列出。
9. 企业客户试用流程：发现本机 -> 快速扫描 -> MCP/Skill -> 报告 -> 复测 -> 导出。

## 6. 验收脚本

新增：

```text
tools/verify_v429_final_acceptance.ps1
```

脚本必须执行：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest tests\test_v429_dashboard_create_profiles_e2e.py -q
python -m pytest tests\test_v429_task_execution_redteam_e2e.py -q
python -m pytest tests\test_v429_result_closure_e2e.py -q
python -m pytest tests\test_v429_admin_operations_e2e.py -q
python -m pytest tests\test_v429_detail_pages_e2e.py -q
python -m pytest tests\test_v429_api_alias_contract.py -q
python -m pytest tests\test_v429_security_boundary.py -q
python -m pytest tests\test_v429_browser_journeys.py -q
python -m pytest -q
```

脚本最后必须执行完整性断言：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
summary = payload['summary']
print(summary)
assert summary['pages'] == 58
assert summary['audit_passed'] == 58
assert summary['contract_passed'] == 58
assert summary['e2e_passed'] == 58
assert summary['gaps'] == 0
'@ | python -
```

## 7. 最终验收拒绝条件

出现以下任一情况，v4.2.9 不通过：

1. 完整测试失败。
2. 浏览器 E2E 未运行且没有明确 skip 原因。
3. `e2e_passed < 58`。
4. 任一页面仍是 `NOT_ASSERTED`。
5. `python-exec`、`process-executions` 等自然路径仍返回通用 404。
6. 测试污染正式 SQLite。
7. 证据/报告/导出包中出现明文 Secret。
8. 非 localhost 管理口无保护。
9. stdio MCP 被自动启动。
10. Skill 代码被执行。
11. 本项目普通源码/文档被扫描为真实资产。
12. 文档命令不可复制执行。
13. 没有最终交付包或最终验收清单。
14. 未更新文档或未提交 Git。

## 8. 建议实施顺序

1. 先完成测试隔离和 verify_v429 脚本框架。
2. 补 API 别名，消除自然路径 404。
3. 按剩余 30 页分组补 API E2E。
4. 补浏览器 E2E 基础设施和 5 条旅程。
5. 补管理口安全测试。
6. 补数据清理与最终交付包。
7. 更新 e2e manifest 到 58/58。
8. 更新最终文档。
9. 运行 final verify。
10. 提交 Git。

## 9. 给第三方 AI 的强约束

1. 不要硬编码完整性 PASS。
2. 不要为了通过测试删除真实用户数据。
3. 不要启动 stdio MCP。
4. 不要执行 Skill 代码。
5. 不要修改已安装 Agent 配置。
6. 不要让测试继续污染正式 DB。
7. 不要只写静态字符串测试冒充浏览器 E2E。
8. 每个页面 PASS 必须有页面专属断言。
9. 完成后必须更新文档并提交 Git。

