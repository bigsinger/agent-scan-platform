# Agent Security Assessment v4.2.7 迭代 SPEC：本机发现体验产品化与核心链路 E2E

版本：v4.2.7-iteration-spec
日期：2026-07-09
状态：待第三方 AI 开发实施
角色定位：产品验收、规划设计、企业交付差距收敛
适用仓库：`F:/bigsinger/agent-scan-platform`

## 1. 本轮背景

v4.2.6 已完成一轮较大的验收差距修复：OTel receiver、行为链、异常规则、探针安装计划、本项目扫描跳过策略、P49-P54/D19-D22 文档和 E2E manifest 都有了基础闭环。本轮评估时执行 `tools/verify_v426_acceptance.ps1`，完整测试已经通过。

但当前系统仍未达到最终目标：

1. 58 个页面中只有 P49-P54/D19-D22 共 10 个页面 E2E PASS，旧 48 个页面仍是 `NOT_ASSERTED`。
2. P04「本机发现」是当前产品核心入口，但 E2E 仍未断言通过。
3. 本机发现命中列表仍采用通用表格展示，Skill、MCP、Config、Agent 等不同类型混在一起，字段不符合用户理解方式。
4. Skill 命中目前主要显示类型、产品、路径、来源，缺少 skill 名、描述、版本、文件数、脚本数、风险摘要等面向人的信息。
5. v4.2.6 新增 prototype 文件虽然满足存在性检查，但很多是单行占位 HTML，还不是高质量产品原型。
6. `doc/SPEC_VALIDATION.md` 中 v4.2.6 验收命令存在 PowerShell 路径转义错误，应修复为可复制执行的命令。

本轮 v4.2.7 的重点是把“发现本机 -> 理解资产 -> 导入/忽略 -> 快速扫描 -> 风险/证据/报告”的核心本地测评链路做得更可用、更可验收。

## 2. 当前验收事实

### 2.1 Git 状态

当前最新提交：

```text
fb26085 feat(v4.2.6): close acceptance gaps for observability e2e
```

本轮评估开始时工作区干净。

### 2.2 v4.2.6 验收脚本结果

执行命令：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v426_acceptance.ps1
```

结果摘要：

```text
frontend offline check passed: pages=58
v4.2.6 otel receiver ingestion: 2 passed
v4.2.6 behavior anomaly rules: 2 passed
v4.2.6 probe install safety: 1 passed
v4.2.6 scan scope policy: 2 passed
v4.2.6 observability pages: 2 passed
legacy 48/58 regression tests: 2 passed
full test suite: 129 passed in 190.97s
v4.2.6 acceptance verification passed
```

结论：v4.2.6 本身可以视为通过自动化验收。

### 2.3 完整性矩阵结果

执行命令：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
print(payload['summary'])
for row in payload['items']:
    if row['id'] in {'P01','P02','P03','P04','P05','P06','P07','P08','P09','D09','P49','P50','P51','P52','P53','P54','D19','D20','D21','D22'}:
        print(row['id'], row['audit'], row['contract'], row['e2e'], row['status'])
'@ | python -
```

当前结果要点：

```text
pages=58
apis=176
sqlite_tables=88
rules=10
audit_passed=58
contract_passed=58
e2e_passed=10
gaps=48
```

已通过 E2E 的页面：

- P49 探针管理
- P50 OTel 接收服务
- P51 行为链时间线
- P52 异常分析
- P53 OTel Explorer
- P54 探针安装向导
- D19 探针详情
- D20 行为链详情
- D21 OTel Span 详情
- D22 探针安装计划详情

仍未通过 E2E 的关键页面：

- P01 仪表盘
- P02 快速扫描
- P03 创建测评
- P04 本机发现
- P05 Agent 资产
- P06 Agent 详情
- P07 ABOM
- P08 Adapter 覆盖
- P09 Profile
- D09 报告预览
- 以及其他旧 48 个页面。

### 2.4 本机发现当前 API 样例

执行命令：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/discovery-hits?page_size=100').json()
items = payload['items'] if isinstance(payload, dict) else payload
from collections import Counter
print('count', len(items))
print('types', Counter(item.get('type') for item in items))
for wanted in ['Agent', 'Skill', 'MCP', 'Config']:
    sample = next((item for item in items if item.get('type') == wanted), None)
    if sample:
        print(wanted, sample)
'@ | python -
```

当前结果要点：

```text
count=100
types=Counter({'Skill': 94, 'Agent': 4, 'MCP': 1, 'Config': 1})
```

Skill 命中样例：

```json
{
  "type": "Skill",
  "agent": "Hermes",
  "path": "~/AppData/Local/hermes/skills/.../SKILL.md",
  "scope": "User",
  "source": "well-known",
  "sha256": "...",
  "status": "可导入"
}
```

当前问题：这个样例对安全测评人员不友好。用户要看的是“这个 skill 是什么、有什么描述、属于哪个 Agent、版本是什么、在哪里、包含多少脚本、是否有风险、能否导入/扫描”，而不是只看一条 `SKILL.md` 文件路径。

### 2.5 本机发现当前前端结构

P04「发现命中」当前表格列：

```text
类型 / 产品 / 路径（脱敏） / 作用域 / 来源 / 版本或方法 / 时间 / 变化 / 状态 / 操作
```

问题：

- Skill、MCP、Config、Agent 共用同一列组，信息密度不对。
- Skill 没有直接展示 name、description、version、files、scripts。
- MCP 没有直接展示 server name、transport、command/url、env keys、审批状态。
- Config 没有直接展示 parser、配置类型、MCP server 数量、关联 Agent。
- Agent 没有直接展示安装状态、验证来源、配置数、MCP 数、Skill 数。
- 搜索只覆盖基础字段，没有覆盖 Skill 描述、MCP 名称、配置摘要。
- 导入资产按钮对所有类型都一样，缺少类型化操作语义。
- 没有发现命中详情抽屉，用户难以理解记录的安全边界、证据 hash、关联对象。

## 3. 本轮目标

v4.2.7 必须完成以下目标：

1. P04「本机发现」命中结果列表升级为类型化、人性化展示。
2. 后端为 discovery hit 输出稳定的 `display` 结构，前端不再靠临时拼接字段猜展示逻辑。
3. Skill 命中解析并展示 skill 名、描述、版本、路径、文件数、脚本数、风险摘要。
4. MCP、Config、Agent 命中也具备类型化摘要、字段和操作。
5. P04/P05/P06/P02/D09 等核心本地测评链路建立 E2E manifest 覆盖。
6. 旧 48 页 E2E 缺口开始收敛，本轮至少新增 8 个旧页面 E2E PASS。
7. 修复 v4.2.6 文档中的命令错误，并补充 discovery 体验验收说明。
8. 所有改动保持只读发现、安全脱敏、不启动 stdio MCP、不修改已安装智能体。

本轮完成后，完整性矩阵目标：

- `pages=58`
- `audit_passed=58`
- `contract_passed=58`
- `e2e_passed >= 18`
- P04/P05/P06/P02/D09 必须从 `NOT_ASSERTED` 变为 `PASS`。

## 4. 非目标

本轮不做以下事项：

- 不自动安装探针。
- 不修改真实 Codex/Hermes/Claude/Cursor/Windsurf/Kiro 配置。
- 不启动 stdio MCP Server。
- 不把本项目普通源码/文档作为扫描对象。
- 不一次性要求旧 48 页全部 E2E PASS。
- 不引入复杂前端框架或替换现有 Vue 静态架构。

## 5. 主要差距清单

### G1. 本机发现结果缺少类型化展示模型

严重级别：P0
影响页面：P04 本机发现、P05 Agent 资产、P06 Agent 详情、P10 MCP、P14 Skill 专项。

当前 `discovery_hit` 是通用记录，主要字段是：

- `type`
- `agent`
- `path`
- `scope`
- `source`
- `sha256`
- `status`

这对机器处理足够，但对人阅读不够。尤其是 Skill 类型，用户看到的是路径，不知道这个 skill 的名称、用途、版本、风险和是否值得导入。

下一轮需要为所有 discovery hit 增加统一 display contract。

### G2. Skill 元数据没有从 SKILL.md 中解析到命中结果

严重级别：P0
影响：用户无法判断发现的 Skill 是什么。

当前 `_skill_record()` 只输出：

- `name`: 目录名
- `agent`
- `path`
- `files`
- `scripts`
- `risk`
- `sha256`

但 `discovery_hit` 本身没有携带这些信息，且 Skill 记录也缺少：

- `description`
- `version`
- `author`
- `tags`
- `entry_file`
- `last_modified`
- `risk_summary`

下一轮应解析 `SKILL.md` 的 YAML frontmatter 或常见 markdown 标题/描述。

### G3. 发现命中表的操作没有按类型区分

严重级别：P1
影响：导入、忽略、扫描、查看详情等操作语义不清。

示例：

- Agent 命中：应提供“导入 Agent”“创建测评”“查看配置范围”。
- Skill 命中：应提供“查看 Skill”“扫描 Skill”“关联 Agent”。
- MCP 命中：应提供“查看 MCP”“审批检查”“静态扫描”。
- Config 命中：应提供“查看配置摘要”“解析 MCP”“生成快照”。

当前统一的“导入资产/忽略”无法表达这些差异。

### G4. P04 本机发现仍未 E2E PASS

严重级别：P0
影响：核心入口没有自动验收证明。

当前完整性矩阵中 P04：

```text
P04 PASS PASS NOT_ASSERTED 待验证
```

下一轮必须把 P04 加入 E2E manifest，并以真实 API + 前端静态 DOM/可选 Playwright smoke 证明页面可用。

### G5. 旧核心测评链路仍缺 E2E

严重级别：P0
影响：企业客户测评主流程未被自动证明。

建议本轮优先覆盖以下页面：

- P01 仪表盘
- P02 快速扫描
- P04 本机发现
- P05 Agent 资产
- P06 Agent 详情
- P10 MCP Server
- P16 风险列表
- P17 证据中心
- P20 报告中心
- D09 报告预览

本轮不要求旧 48 页全部覆盖，但需要让核心链路从 `NOT_ASSERTED` 推进到 `PASS`。

### G6. v4.2.6 prototype 文件存在但质量偏占位

严重级别：P1
影响：Audit 虽然 PASS，但文档质量不足以指导第三方实现。

v4.2.6 新增的 `prototype/pages/P49_*.html` 和 `D19_*.html` 多数是单行 HTML，包含最小标题、路由和 API 信息。它们可以通过存在性检查，但不足以称为详细原型。

下一轮应把 P04、P49-P54、D19-D22 中至少 P04 和相关 Discovery/Agent 原型升级到可读结构。

### G7. SPEC_VALIDATION 中有 PowerShell 命令转义错误

严重级别：P1
影响：企业客户复制命令会失败。

当前 `doc/SPEC_VALIDATION.md` 中 v4.2.6 命令显示为：

```text
tools<vertical-tab>erify_v426_acceptance.ps1
```

这是反斜杠路径被写入为控制字符导致的路径错误。必须改成：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v426_acceptance.ps1
```

## 6. 具体开发任务

### T01. 定义 discovery hit 类型化展示契约

目标：

- 后端为每条 discovery hit 输出统一 `display` 对象。
- 前端根据 `display` 渲染，而不是为每种类型散落拼接逻辑。

涉及文件：

- `src/assessment/scanning/discovery.py`
- `src/assessment/scanning/scanner.py`
- `src/assessment/api/v1.py`
- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`
- `tests/test_v427_discovery_display_contract.py`

推荐 `display` 结构：

```json
{
  "display": {
    "title": "exploiting-jwt-algorithm-confusion-attack",
    "subtitle": "JWT algorithm confusion attack testing skill",
    "type_label": "Skill",
    "icon": "skill",
    "badge": "Hermes",
    "version": "-",
    "primary_path": "~/AppData/Local/hermes/skills/.../SKILL.md",
    "fields": [
      {"label": "Agent", "value": "Hermes", "kind": "text"},
      {"label": "版本", "value": "-", "kind": "text"},
      {"label": "文件", "value": "8", "kind": "number"},
      {"label": "脚本", "value": "2", "kind": "number"},
      {"label": "Hash", "value": "4a6c169bf60353588", "kind": "hash"}
    ],
    "tags": ["local-readonly", "skill", "well-known"],
    "risk_summary": "待扫描",
    "safety_summary": "只读发现；未执行 Skill 代码",
    "primary_action": "查看 Skill",
    "secondary_actions": ["扫描 Skill", "忽略"]
  },
  "relationships": {
    "agent_id": null,
    "skill_id": "skill_xxx",
    "mcp_server_id": null,
    "config_snapshot_id": null
  }
}
```

要求：

1. `display.title` 必填。
2. `display.subtitle` 可为空，但 Skill 必须尽力从描述中填充。
3. 所有路径必须使用现有脱敏路径。
4. 所有 Secret、Token、API Key、Cookie、Authorization 仍必须脱敏。
5. `relationships` 用于详情抽屉和跳转，不要求全部都有值。

验收：

- `GET /api/v1/discovery-hits?page_size=5` 返回的每条记录都有 `display.title`、`display.type_label`、`display.primary_path`。
- 前端搜索能命中 `display.title` 和 `display.subtitle`。

### T02. 实现 Skill 元数据解析

目标：

- Skill 命中显示 skill 名、描述、版本、路径等人性化字段。

涉及文件：

- `src/assessment/scanning/discovery.py`
- 可新增 `src/assessment/scanning/skill_metadata.py`
- `tests/test_v427_skill_metadata_parser.py`

解析规则：

1. 读取 `SKILL.md`，只读，不执行任何代码。
2. 文件大小上限建议 256 KiB，超限只读取前 256 KiB 并标记 `metadata_truncated=true`。
3. 支持 YAML frontmatter：
   - `name`
   - `description`
   - `version`
   - `author`
   - `tags`
4. 如果没有 frontmatter：
   - `name` 使用第一个一级标题。
   - 没有标题时使用目录名。
   - `description` 使用 frontmatter 描述、标题后的第一段，或前 160 字摘要。
5. `version` 没有时统一显示 `-`。
6. `path` 显示 skill 根目录和 `SKILL.md` 路径。
7. 统计：
   - `files`
   - `scripts`
   - `has_network_keywords`
   - `has_shell_keywords`
   - `has_secret_like_text`
8. 所有摘要必须脱敏。

Skill display 必须包含：

- Skill 名。
- 描述。
- 版本。
- Agent。
- Skill 根路径。
- `SKILL.md` 路径。
- 文件数。
- 脚本数。
- Hash。
- 风险摘要。
- 状态。

验收样例：

```json
{
  "type": "Skill",
  "display": {
    "title": "exploiting-jwt-algorithm-confusion-attack",
    "subtitle": "Demonstrates JWT algorithm confusion testing guidance",
    "version": "-",
    "fields": [
      {"label": "Agent", "value": "Hermes"},
      {"label": "文件", "value": "8"},
      {"label": "脚本", "value": "2"},
      {"label": "路径", "value": "~/AppData/.../SKILL.md"}
    ]
  }
}
```

测试必须覆盖：

- 有 frontmatter。
- 无 frontmatter 但有标题。
- 只有目录名。
- 描述中包含 secret-like 字符串时被脱敏。
- 超大文件截断。
- Windows 路径脱敏。

### T03. 实现 Agent/MCP/Config 类型化展示

目标：

- 不同类型命中展示不同字段。

Agent display：

- 产品名。
- 版本。
- 安装状态：已安装、残留、配置命中、探测命中。
- 可执行路径。
- 探测来源。
- 探测方法。
- 是否命令探测。
- 是否 verified。
- 配置数、MCP 数、Skill 数。
- 最近发现时间。

MCP display：

- Server 名。
- Agent。
- Transport：stdio/http/unknown。
- 命令或 URL，必须脱敏。
- 配置文件路径。
- env key 数量。
- 审批状态。
- 风险等级。
- config sha256 短 hash。

Config display：

- 文件名。
- 产品。
- 配置类型：MCP config、Agent config、VSCode settings、环境文件等。
- 路径。
- 解析器：json/toml/yaml/markdown/env。
- 识别出的 MCP server 数。
- 关联 Agent。
- hash。
- 变化状态。

验收：

- 每种类型至少有一个 fixture 测试。
- 前端列表中不同类型显示不同主要字段。
- 操作按钮按类型变化。

### T04. P04 发现命中 UI 升级

目标：

- 发现列表不再是低语义通用表格，而是企业工具可扫描、可理解、可操作的结果台。

涉及文件：

- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`
- `src/assessment/static/assessment/styles.css`
- `tests/test_v427_discovery_page_static.py`

推荐 UI 结构：

1. 顶部概览：
   - Agent 命中。
   - Skill 命中。
   - MCP 命中。
   - Config 命中。
   - 变化命中。
   - 权限跳过。
2. 类型 tabs：
   - 全部。
   - Agent。
   - Skills。
   - MCP。
   - Config。
   - 已变化。
   - 已忽略。
3. 结果表列：
   - 名称与摘要。
   - 类型/产品。
   - 版本/状态。
   - 关键属性。
   - 路径。
   - 风险/证据。
   - 操作。
4. Skill 行展示：
   - skill 名作为主标题。
   - 描述作为副标题。
   - 版本 chip。
   - 文件数/脚本数 chip。
   - 路径使用单行截断 + tooltip 或详情抽屉。
5. MCP 行展示：
   - server 名。
   - transport badge。
   - command/url 脱敏摘要。
   - env keys count。
   - 审批状态。
6. Agent 行展示：
   - 产品名。
   - 版本。
   - 安装状态。
   - 配置/MCP/Skill 数。
7. Config 行展示：
   - 文件名。
   - 配置类型。
   - 解析状态。
   - 关联 MCP 数。

交互要求：

- 点击行标题打开 discovery hit 详情抽屉。
- 操作按钮按类型显示：
  - Agent：导入 Agent、创建测评、详情。
  - Skill：查看 Skill、扫描 Skill、忽略。
  - MCP：查看 MCP、静态检查、审批。
  - Config：查看配置摘要、解析、忽略。
- 筛选条件要覆盖：
  - 类型。
  - Agent。
  - 状态。
  - 变化状态。
  - 是否含脚本。
  - 是否需审批。
- 搜索覆盖：
  - `display.title`
  - `display.subtitle`
  - skill name。
  - skill description。
  - mcp server name。
  - config filename。
  - path。

验收：

- Skill 行能直接看到“skill名、描述、版本、路径”。
- 没有版本时显示 `-`，不能空白。
- 行内文本不挤压、不重叠。
- 100+ 条 Skill 时列表仍可用。

### T05. Discovery Hit 详情抽屉

目标：

- 用户不离开发现页即可查看命中详情、证据和关联对象。

建议新增状态和方法：

- `selectedDiscoveryHit`
- `discoveryHitDrawerOpen`
- `openDiscoveryHit(hit)`
- `closeDiscoveryHit()`

详情抽屉内容：

- 基础信息：
  - 类型。
  - 标题。
  - 描述。
  - Agent。
  - 状态。
  - 变化状态。
- 路径与证据：
  - 脱敏路径。
  - hash。
  - created_at。
  - updated_at。
  - source。
- 类型化详情：
  - Skill：version、files、scripts、metadata、description、risk_summary。
  - MCP：transport、command/url、env_keys、approval status。
  - Config：parser、mcp count、config type。
  - Agent：version、probe method、verified、details。
- 安全边界：
  - `mutates_installed_agents=false`
  - `stdio_mcp_started=false`
  - `agent_runtime_started=false`
  - `secrets_redacted=true`
- 操作：
  - 导入/查看/扫描/忽略。
  - 复制路径。
  - 下载证据。

验收：

- 点击 Skill 行打开抽屉。
- 抽屉能显示 skill 描述和版本。
- 关闭抽屉后仍停留在原筛选结果。
- 抽屉不展示明文 secret。

### T06. 发现导出包增加 display 摘要

目标：

- 企业客户导出的 discovery inventory 可以直接阅读，不需要理解内部字段。

涉及文件：

- `src/assessment/api/v1.py`
- `src/assessment/store.py` 或导出逻辑所在文件
- `tests/test_v427_discovery_export_display.py`

要求：

- `/api/v1/discovery-hits/export` 中每条 hit 包含 `display`。
- export summary 包含：
  - agent_count。
  - skill_count。
  - mcp_count。
  - config_count。
  - changed_count。
  - ignored_count。
  - skipped_count。
- export validation 检查：
  - 每条 hit 有 display title。
  - 所有路径脱敏。
  - 不含明文 secret。

验收：

- 导出 JSON 中 Skill 能看到 name、description、version、path。
- 导出包仍包含 SHA-256 和安全边界。

### T07. P04/P05/P06/P02/D09 核心链路 E2E

目标：

- 让核心本地测评路径有自动验收证明。

建议新增测试：

- `tests/test_v427_core_local_assessment_flow.py`

覆盖路径：

1. 干净或隔离 DB 启动。
2. 运行本机发现，或用 fixture 注入 discovery result。
3. 验证 P04 discovery API 返回类型化 display。
4. 导入 Agent。
5. P05 Agent 资产可查询导入结果。
6. P06 Agent 详情可查询配置/MCP/Skill 关联。
7. P02 快速扫描可基于发现资产创建真实任务。
8. 任务生成 finding/evidence/report。
9. D09 报告预览可打开证据详情抽屉或 API 详情。
10. 全流程不修改已安装 Agent，不启动 stdio MCP。

推荐加入 E2E manifest 的页面：

- P02 快速扫描
- P04 本机发现
- P05 Agent 资产
- P06 Agent 详情
- P16 风险列表
- P17 证据中心
- P20 报告中心
- D09 报告预览

完成后目标：

```text
e2e_passed >= 18
```

验收：

- `/api/v1/completeness` 中上述页面变为 `e2e=PASS`。
- manifest 中每个 PASS 页面都有真实 test_file/test_name。
- 不允许硬编码 E2E PASS。

### T08. 修复 P04/P49-P54/D19-D22 原型质量

目标：

- 文档/原型不只是存在，而是足以指导第三方 AI 继续开发。

本轮最低要求：

- 升级 `prototype/pages/P04_discovery.html`，体现类型化发现结果。
- 升级 `specs/pages/P04_discovery.md`，加入 display contract、Skill 字段、详情抽屉和 E2E 验收点。
- 对 P49-P54/D19-D22 单行 prototype 至少补充结构化 DOM：
  - 页面标题。
  - 核心 API。
  - 关键表格或详情区域。
  - 空态/错误态。
  - 安全边界。

验收：

- P04 prototype 包含 Skill 类型化行样例。
- P04 spec 明确 Skill 展示字段。
- 新增文档不再是一行占位。

### T09. 修复验证文档命令错误

目标：

- 文档里的验收命令可复制执行。

涉及文件：

- `doc/SPEC_VALIDATION.md`
- `doc/OPERATIONS_DEPLOYMENT.md`
- `doc/USER_GUIDE.md`

要求：

- 修复 `tools<vertical-tab>erify_v426_acceptance.ps1` 控制字符。
- 新增 v4.2.7 验收命令。
- 所有 Python inline 命令使用 PowerShell here-string：

```powershell
$env:PYTHONPATH='src'
@'
print("ok")
'@ | python -
```

验收：

- 文档内不出现 Bash 风格 `@'
# python here-string
'@ | python -`。
- 文档内不出现控制字符路径。

### T10. 历史 self-project 命中治理

目标：

- 满足“本项目源码/文档不应作为扫描对象”的要求，同时处理旧数据残留。

现象：

- 当前 `/api/v1/discovery-hits` 样例中仍可能出现历史记录，例如 `<target>/assessment/scanning/mcp_static.py`。
- 这可能是旧显式扫描留下的持久化记录，不代表 v4.2.6 新扫描仍会产生，但 UI 上会让用户误解。

要求：

1. discovery hit 查询时可标记：
   - `is_self_project=true`
   - `self_project_policy=hidden|test_asset|legacy_stale`
2. 默认列表隐藏普通 self-project legacy hit。
3. 如果是允许的测试 fixture/MCP/Skill，显示为“测试资产”。
4. 导出时保留审计说明，但不把普通 self-project 记录作为真实风险资产。
5. 提供清理或归档历史 self-project 命中的安全操作：
   - 只修改本系统 SQLite。
   - 不删除真实文件。

验收：

- 默认 P04 列表不展示本项目普通源码/文档命中。
- 测试性 MCP/Skill fixture 仍可展示。
- 查询 API 返回明确 skip/hide reason。

## 7. 测试计划

### 7.1 新增测试文件

必须新增：

- `tests/test_v427_skill_metadata_parser.py`
- `tests/test_v427_discovery_display_contract.py`
- `tests/test_v427_discovery_page_static.py`
- `tests/test_v427_discovery_export_display.py`
- `tests/test_v427_core_local_assessment_flow.py`

可选但建议：

- `tests/test_v427_discovery_self_project_legacy.py`
- `tests/test_v427_frontend_discovery_drawer.py`

### 7.2 测试重点

Skill metadata parser：

- frontmatter name/description/version。
- markdown heading fallback。
- directory fallback。
- secret 脱敏。
- 文件大小截断。

Discovery display contract：

- Agent/MCP/Config/Skill 都有 display。
- Skill display 有 title/subtitle/version/path/files/scripts。
- MCP display 有 server/transport/config/env_keys。
- Config display 有 parser/config_type/mcp_count。
- Agent display 有 version/install_status/probe_method。

Frontend static：

- P04 DOM 包含类型 tabs。
- P04 DOM 包含 discovery hit drawer。
- P04 DOM 包含 Skill 字段标题：Skill 名、描述、版本、路径。
- 搜索 haystack 包含 display 字段。

Core flow：

- 发现 -> 导入 -> Agent 详情 -> 快速扫描 -> Finding/Evidence/Report -> 报告证据详情。
- 安全不变量：
  - `mutates_installed_agents=false`
  - `stdio_mcp_started=false`
  - `agent_runtime_started=false`
  - 不保存明文 secret。
  - 不扫描本项目普通源码/文档。

## 8. 验收命令

第三方 AI 完成后必须执行：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest tests\test_v427_skill_metadata_parser.py -q
python -m pytest tests\test_v427_discovery_display_contract.py -q
python -m pytest tests\test_v427_discovery_page_static.py -q
python -m pytest tests\test_v427_discovery_export_display.py -q
python -m pytest tests\test_v427_core_local_assessment_flow.py -q
python -m pytest -q
```

如果继续使用 `uv`：

```powershell
uv run --with pytest --with httpx python -m pytest -q
```

完整性矩阵验收：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
print(payload['summary'])
required = {'P02','P04','P05','P06','P16','P17','P20','D09'}
for row in payload['items']:
    if row['id'] in required:
        print(row['id'], row['audit'], row['contract'], row['e2e'], row['status'])
'@ | python -
```

预期：

- `e2e_passed >= 18`
- P02/P04/P05/P06/P16/P17/P20/D09 均为 `PASS PASS PASS 已验收`。

Discovery display smoke：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/discovery-hits?page_size=20').json()
items = payload['items'] if isinstance(payload, dict) else payload
for item in items[:10]:
    display = item.get('display') or {}
    print(item.get('type'), display.get('title'), display.get('subtitle'), display.get('version'), display.get('primary_path'))
    assert display.get('title')
    assert display.get('primary_path')
'@ | python -
```

Skill display smoke：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/discovery-hits?page_size=200&type=Skill').json()
items = payload['items'] if isinstance(payload, dict) else payload
skill = next(item for item in items if item.get('type') == 'Skill')
display = skill['display']
print(display)
assert display['title']
assert 'version' in display
assert display['version'] or display['version'] == '-'
assert display['primary_path']
'@ | python -
```

## 9. 验收拒绝条件

出现以下任一情况，v4.2.7 不能通过：

1. `python -m pytest -q` 失败。
2. P04 仍是 `NOT_ASSERTED`。
3. P04 页面中 Skill 行仍只展示路径，不展示 skill 名、描述、版本。
4. `GET /api/v1/discovery-hits` 的记录没有 `display.title`。
5. Skill metadata parser 需要执行 Skill 代码才能解析。
6. 明文 secret 出现在 display、导出包、详情抽屉或测试输出中。
7. 默认发现列表继续展示本项目普通源码/文档历史命中且无说明。
8. 发现详情需要整页跳转，关闭后丢失筛选上下文。
9. E2E manifest 中页面 PASS 没有对应测试文件和测试名。
10. `doc/SPEC_VALIDATION.md` 仍包含不可复制执行的命令。
11. 完成后未更新文档或未提交 Git。

## 10. 建议实施顺序

1. 先实现 Skill metadata parser 和单测。
2. 定义并输出 discovery hit `display` contract。
3. 补 Agent/MCP/Config 类型化 display。
4. 改 P04 UI：类型 tabs、类型化表格、Skill 字段、详情抽屉。
5. 改导出包，加入 display 摘要和验证。
6. 建核心链路 E2E：发现 -> 导入 -> 快扫 -> 风险/证据/报告。
7. 更新 e2e manifest，让 P02/P04/P05/P06/P16/P17/P20/D09 PASS。
8. 治理历史 self-project 命中。
9. 修复验证文档命令和补充使用帮助。
10. 运行完整验收命令并提交 Git。

## 11. 交付物清单

代码：

- Skill metadata parser。
- discovery hit display contract。
- 类型化 P04 本机发现 UI。
- discovery hit 详情抽屉。
- display-aware discovery export。
- self-project legacy hit 标记/隐藏策略。

测试：

- `tests/test_v427_skill_metadata_parser.py`
- `tests/test_v427_discovery_display_contract.py`
- `tests/test_v427_discovery_page_static.py`
- `tests/test_v427_discovery_export_display.py`
- `tests/test_v427_core_local_assessment_flow.py`

文档：

- 更新 `doc/agent_security_assessment_v4_1_full/specs/pages/P04_discovery.md`
- 更新 `doc/agent_security_assessment_v4_1_full/prototype/pages/P04_discovery.html`
- 更新 `doc/USER_GUIDE.md`
- 更新 `doc/OPERATIONS_DEPLOYMENT.md`
- 更新 `doc/SPEC_VALIDATION.md`
- 更新 `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`

验收：

- `tools/verify_v426_acceptance.ps1` 仍通过。
- v4.2.7 新增测试通过。
- 完整测试通过。
- `/api/v1/completeness` 的 `e2e_passed >= 18`。
- P04 本机发现达到可用和可读标准。

## 12. 给第三方 AI 的注意事项

1. 不要为了 UI 好看而把表格改成大面积营销式卡片；这是企业安全工具，应保持紧凑、可扫描、可排序。
2. Skill 描述解析必须只读，不能 import、执行脚本或运行 Skill。
3. 发现命中路径必须继续脱敏。
4. 旧字段要保持兼容，避免破坏现有 API 调用。
5. 新 display 字段应作为增强字段加入，不要删除原始字段。
6. 所有新增按钮必须调用真实 API 或明确 disabled，不允许空按钮。
7. 任何 E2E PASS 必须来自 manifest + 测试文件，不允许硬编码。
8. 完成后必须更新文档并提交 Git。
