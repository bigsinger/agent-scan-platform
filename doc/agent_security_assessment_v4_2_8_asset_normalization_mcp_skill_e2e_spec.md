# Agent Security Assessment v4.2.8 迭代 SPEC：资产归一治理、Discovery 服务端查询与 MCP/Skill 专项 E2E

版本：v4.2.8-iteration-spec  
日期：2026-07-09  
状态：待第三方 AI 开发实施  
角色定位：产品验收、规划设计、企业交付差距收敛  
适用仓库：`F:/bigsinger/agent-scan-platform`

## 1. 本轮背景

v4.2.7 已经完成“本机发现结果人性化展示”和核心本地测评链路的第一轮产品化：Skill 元数据解析、Discovery display contract、P04 UI、导出包、核心链路 E2E 都有了自动化测试。当前 `tools/verify_v427_discovery.ps1` 已通过，完整测试为 `138 passed`。

但系统距离最终企业级交付仍有明显差距。本轮评估发现，v4.2.7 主要完成的是“展示和基本链路”，下一步需要解决“数据治理、服务端查询、资产归一、MCP/Skill 专项测评和真实 UI E2E”：

1. 58 个页面中仍有 40 个页面 `E2E=NOT_ASSERTED`。
2. `GET /api/v1/discovery-hits?type=Skill`、`?q=jwt` 等查询参数当前没有生效，服务端仍返回混合类型前 20/100 条。
3. 本项目历史命中 `<target>/assessment/scanning/mcp_static.py` 仍出现在默认发现列表中，违背“本项目普通源码/文档不应作为被测对象”的产品要求。
4. Agent 资产存在重复和历史残留：Codex/Hermes 多版本、多路径、多次导入记录并列展示，未折叠为一个清晰资产。
5. Agent 名称里出现 `бд` 这类疑似编码/分隔符污染，应该归一为 `·` 或更稳妥的 ASCII 分隔。
6. P10-P14、D05-D07 等 MCP/Skill/agent-scan 专项页面仍未 E2E PASS。
7. 当前核心链路 E2E 主要是 API 和静态 DOM 检查，还没有浏览器级点击、抽屉、过滤、分页、返回上下文的真实交互证明。
8. `doc/SPEC_VALIDATION.md` 的 v4.2.7 验收命令再次出现控制字符路径，文档可复制性需要回归测试。
9. 测试使用全局 TestClient 和当前 SQLite 运行态，已经在本地库留下大量 contract/test 记录。企业验收需要测试数据隔离和清理策略。

v4.2.8 的目标是把“发现到的本机智能体资产”从可展示推进到可治理，把 MCP/Skill 专项测评从页面存在推进到可验收。

## 2. 当前验收事实

### 2.1 Git 与提交

当前最新提交：

```text
59ef00f feat(v4.2.7): productize discovery experience and core E2E
```

本轮评估开始时工作区干净。

### 2.2 v4.2.7 自动验收

执行命令：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v427_discovery.ps1
```

结果摘要：

```text
frontend offline check passed: pages=58
v4.2.7 skill metadata: 3 passed
v4.2.7 discovery display: 2 passed
v4.2.7 discovery page static: 2 passed
v4.2.7 discovery export: 1 passed
v4.2.7 core local assessment flow: 1 passed
full test suite: 138 passed in 229.27s
v4.2.7 discovery acceptance verification passed
```

结论：v4.2.7 自动化验收通过。

### 2.3 完整性矩阵

执行命令：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
print(payload['summary'])
for pid in ['P01','P02','P03','P04','P05','P06','P07','P10','P11','P12','P13','P14','P16','P17','P20','D05','D06','D07','D09']:
    row = next((item for item in payload['items'] if item['id'] == pid), None)
    if row:
        print(pid, row['audit'], row['contract'], row['e2e'], row['status'])
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
e2e_passed=18
gaps=40
```

已 E2E PASS：

- P02 快速扫描
- P04 本机发现
- P05 Agent 资产
- P06 Agent 详情
- P16 风险列表
- P17 证据中心
- P20 报告中心
- D09 报告预览
- P49-P54
- D19-D22

仍 NOT_ASSERTED 的本轮重点：

- P07 ABOM
- P08 Adapter 覆盖
- P10 agent-scan 兼容
- P11 MCP Server
- P12 MCP 审批
- P13 Skills
- P14 Skill 详情
- D05 agent-scan issue 详情
- D06 MCP Server 详情
- D07 Tool 详情

### 2.4 Discovery 查询和数据样例

执行命令：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
for qs in ['?page_size=20&type=Skill', '?page_size=20&filter_type=Skill', '?page_size=20&kind=Skill', '?page_size=20&q=jwt']:
    payload = client.get('/api/v1/discovery-hits' + qs).json()
    items = payload['items'] if isinstance(payload, dict) else payload
    print(qs, len(items), [item.get('type') for item in items[:8]])
'@ | python -
```

当前结果：

```text
?page_size=20&type=Skill 20 ['Agent', 'MCP', 'Agent', 'Agent', 'Agent', 'Config', 'Skill', 'Skill']
?page_size=20&filter_type=Skill 20 ['Agent', 'MCP', 'Agent', 'Agent', 'Agent', 'Config', 'Skill', 'Skill']
?page_size=20&kind=Skill 20 ['Agent', 'MCP', 'Agent', 'Agent', 'Agent', 'Config', 'Skill', 'Skill']
?page_size=20&q=jwt 20 ['Agent', 'MCP', 'Agent', 'Agent', 'Agent', 'Config', 'Skill', 'Skill']
```

结论：服务端发现命中列表的 `type/q/kind/filter_type` 查询参数当前不生效。前端即使有筛选，也只能筛当前页，不能支撑 300+ 命中的真实使用。

### 2.5 本项目历史命中仍默认出现

当前默认列表中仍可见：

```text
hit_f4f4c399c459053b MCP Generic <target>/assessment/scanning/mcp_static.py hidden=False policy=visible
```

这说明当前 `self_project_policy` 没有覆盖 `<target>/assessment/...` 这一类历史路径，导致本项目普通源码仍出现在默认列表中。

### 2.6 Agent 资产重复和编码污染

当前 `/api/v1/agents?page_size=50` 摘要：

```text
Counter({'Codex': 6, 'Hermes': 5, 'Claude Code': 2, 'Generic': 1, 'Cursor': 1})
```

样例：

```text
'Codex бд Local' '<program-files>/OpenAI.Codex_26.623.19656.0.../codex.EXE'
'Codex бд Local' '<program-files>/OpenAI.Codex_26.623.9142.0.../codex.EXE'
'Codex бд Local' '<program-files>/OpenAI.Codex_26.623.9142.0.../Codex.exe'
'Codex бд Local' '<program-files>/OpenAI.Codex_26.616.10790.0.../Codex.exe'
```

问题：

- 同一产品多版本并列成多个 Agent 资产，缺少“当前活跃安装”和“历史版本/残留”的归一视图。
- 相同版本不同 exe casing/path 并列重复。
- 名称中 `бд` 疑似由 `·` 编码污染产生。
- 历史测试/导入记录和真实本机记录混在一起，企业客户难以判断真实资产。

### 2.7 文档命令控制字符

`doc/SPEC_VALIDATION.md` 中仍存在垂直制表控制字符，字节级检查：

```text
doc/SPEC_VALIDATION.md has_vtab=True
```

表现为：

```text
tools<vertical-tab>erify_v427_discovery.ps1
```

必须修复并加入文档控制字符回归测试。

## 3. 本轮目标

v4.2.8 必须完成以下目标：

1. Discovery API 支持服务端筛选、搜索、排序、分页，前端筛选与 API 参数一致。
2. 默认隐藏本项目普通源码/文档历史命中，测试资产仍允许显示。
3. Agent 资产完成产品级归一：Codex/Hermes/Claude/Cursor 等按产品聚合，当前活跃安装清晰，历史版本折叠。
4. 清理或标记历史测试/旧导入/编码污染数据，不再干扰默认企业视图。
5. MCP/Skill 专项页面进入可验收闭环，P10/P11/P12/P13/P14/D05/D06/D07 至少 8 个页面 E2E PASS。
6. 核心 Discovery/MCP/Skill 交互增加浏览器级 E2E，覆盖点击、筛选、详情抽屉、分页和返回上下文。
7. 测试数据使用隔离数据库或可清理命名空间，不能继续污染本地正式 SQLite。
8. 修复验证文档控制字符，建立文档命令可复制性测试。

本轮完成后完整性矩阵目标：

```text
pages=58
audit_passed=58
contract_passed=58
e2e_passed >= 28
gaps <= 30
```

必须新增 E2E PASS：

- P07 ABOM
- P08 Adapter 覆盖
- P10 agent-scan 兼容
- P11 MCP Server
- P12 MCP 审批
- P13 Skills
- P14 Skill 详情
- D05 agent-scan issue 详情
- D06 MCP Server 详情
- D07 Tool 详情

## 4. 非目标与安全边界

本轮不做：

- 不自动启动 stdio MCP Server。
- 不自动修改 Codex/Hermes/Claude/Cursor/Windsurf/Kiro 配置。
- 不自动安装探针。
- 不做全局系统 hook。
- 不把本项目普通源码/文档作为被测对象。
- 不一次性要求 58 页全部 E2E PASS。

所有新增能力必须保持：

- `mutates_installed_agents=false`
- `stdio_mcp_started=false`
- `agent_runtime_started=false`
- secret 脱敏
- 默认只读
- 可回滚、可审计

## 5. 主要差距清单

### G1. Discovery API 过滤和搜索无效

严重级别：P0  
影响：本机发现命中可能超过数百条，前端只筛当前页会漏数据。

当前 `type=Skill`、`q=jwt` 等参数不影响返回结果。需要实现服务端：

- type/kind 过滤。
- status 过滤。
- change_status 过滤。
- self_project_policy 过滤。
- include_hidden。
- q 全文搜索。
- sort/order。
- page/page_size。

### G2. Self-project 历史命中治理不完整

严重级别：P0  
影响：用户明确要求不要扫描/展示本项目普通源码和文档。

当前 `<target>/assessment/scanning/mcp_static.py` 仍默认显示。需要覆盖更多路径形态：

- `<target>/assessment/...`
- `<target>/src/...`
- `<target>/doc/...`
- `<project>/assessment/...`
- `<project>/src/...`
- `<project>/doc/...`
- `F:/bigsinger/agent-scan-platform/...`
- `agent-scan-platform/...`

测试 fixture 和测试 MCP/Skill 例外。

### G3. Agent 资产重复、历史残留和编码污染

严重级别：P0  
影响：企业客户无法判断本机真实安装了几个 Agent。

当前 Codex/Hermes 多版本重复显示，名称含 `бд`。需要建立 canonical asset 模型：

- 一个产品一个默认资产视图。
- 历史版本作为 `installations` 或 `versions` 子列表。
- 当前活跃版本优先显示。
- 残留/旧版本显示为 folded stale installation。
- 编码污染迁移为标准显示名。

### G4. MCP/Skill 专项页面未验收

严重级别：P0  
影响：发现结果能看了，但专项扫描与详情链路还没被证明可用。

当前 P10-P14、D05-D07 都是 `NOT_ASSERTED`。下一轮应让 MCP/Skill 从“发现展示”进入“专项分析、详情、审批、工具流、风险映射”。

### G5. UI E2E 仍偏静态

严重级别：P1  
影响：实际点击体验、抽屉、过滤、分页和返回上下文可能坏了但测试发现不了。

当前 v4.2.7 前端测试主要是静态字符串检查，核心链路是 API TestClient。需要 Playwright 或等价浏览器 E2E。

### G6. 测试污染本地运行态数据库

严重级别：P1  
影响：本地正式评估数据和测试数据混杂，影响企业演示和后续测试。

当前 API smoke 和测试已经在 `/api/v1/agents`、`/api/v1/schedules`、`/api/v1/integrations` 等接口中留下 contract/test 数据。下一轮必须引入隔离数据库或测试命名空间清理。

### G7. 文档命令可复制性缺少回归

严重级别：P1  
影响：企业客户复制命令失败。

`doc/SPEC_VALIDATION.md` 中再次出现控制字符路径，说明文档命令没有自动扫描。

## 6. 具体开发任务

### T01. Discovery 服务端查询 API

目标：

- `/api/v1/discovery-hits` 支持服务端过滤、搜索、排序和隐藏策略。

涉及文件：

- `src/assessment/api/v1.py`
- `src/assessment/static/assessment/app.js`
- `tests/test_v428_discovery_server_query.py`

API 参数要求：

```text
GET /api/v1/discovery-hits
  ?page=1
  &page_size=50
  &type=Skill|Agent|MCP|Config
  &q=jwt
  &status=可导入|已导入|已忽略
  &change_status=NEW|CHANGED|UNCHANGED
  &self_project_policy=visible|test_asset|legacy_stale
  &include_hidden=false
  &sort=updated_at|created_at|type|agent|title
  &order=asc|desc
```

行为要求：

1. `type=Skill` 只返回 Skill。
2. `q=jwt` 搜索 `display.title`、`display.subtitle`、`path`、`agent`、`skill_metadata.description`。
3. 默认 `include_hidden=false`，隐藏 `hidden_by_default=true`。
4. 返回 `total` 为过滤后的总数。
5. 返回 `page/page_size/has_next`。
6. 参数无效时返回 422 或受控错误，不静默忽略。

验收：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/discovery-hits?page_size=20&type=Skill').json()
items = payload['items']
assert items
assert all(item['type'] == 'Skill' for item in items)
payload = client.get('/api/v1/discovery-hits?page_size=20&q=jwt').json()
assert payload['items']
assert any('jwt' in str(item.get('display', {})).lower() for item in payload['items'])
'@ | python -
```

### T02. Discovery 前端接入服务端查询

目标：

- P04 的筛选、搜索、分页、排序和隐藏开关由 API 驱动，不再只筛当前页。

涉及文件：

- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`
- `src/assessment/static/assessment/style.css`
- `tests/test_v428_discovery_frontend_query_static.py`

实现要求：

1. 增加 `loadDiscoveryHits()`。
2. 搜索框、类型 tabs、状态筛选、变化筛选、含脚本筛选变更后调用 API。
3. 支持分页：
   - 上一页。
   - 下一页。
   - 当前页。
   - 总数。
4. 支持排序：
   - 更新时间。
   - 类型。
   - 产品。
   - 标题。
5. 默认不显示隐藏记录。
6. 提供“显示历史/隐藏命中”开关，仅用户显式打开时请求 `include_hidden=true`。
7. 空态要说明当前是“过滤后无结果”还是“尚未发现”。

验收：

- 搜索 `jwt` 后 API 请求包含 `q=jwt`。
- 点击 Skill tab 后 API 请求包含 `type=Skill`。
- 分页不会丢失筛选条件。
- 关闭详情抽屉后筛选条件和页码不变。

### T03. Self-project 历史命中隐藏与清理

目标：

- 默认视图不再展示本项目普通源码/文档历史命中。

涉及文件：

- `src/assessment/api/v1.py`
- `src/assessment/scanning/scope.py`
- `tests/test_v428_self_project_legacy_policy.py`

实现要求：

1. 扩展 `discovery_self_project_policy()` 的路径识别。
2. 覆盖 `<target>/assessment/...`、`<target>/src/...`、`<target>/doc/...` 等历史 display path。
3. 测试 fixture、测试 MCP、测试 Skill 保持 `test_asset`。
4. 默认查询隐藏 `legacy_stale`。
5. 增加只影响本系统 SQLite 的归档接口，建议：

```text
POST /api/v1/discovery-hits/cleanup-self-project
```

请求：

```json
{"dry_run": true}
```

返回：

```json
{
  "dry_run": true,
  "matched": 12,
  "would_mark_ignored": ["hit_x"],
  "mutates_installed_agents": false
}
```

6. 非 dry-run 时只更新 discovery_hit 状态，不删除真实文件。

验收：

- `<target>/assessment/scanning/mcp_static.py` 默认不出现在 `/api/v1/discovery-hits`。
- `include_hidden=true` 时可见，并带 `self_project_policy=legacy_stale`。
- 测试 fixture 仍显示。

### T04. Agent 资产归一与去重

目标：

- `/api/v1/agents` 默认展示产品级资产，不再把 Codex/Hermes 每个历史版本都当独立资产。

涉及文件：

- `src/assessment/scanning/discovery.py`
- `src/assessment/api/v1.py`
- 可能新增 `src/assessment/scanning/agent_identity.py`
- `tests/test_v428_agent_identity_normalization.py`

建议模型：

```json
{
  "id": "agt_codex",
  "name": "Codex Local",
  "adapter": "Codex",
  "version": "26.623.19656.0",
  "install_status": "已安装",
  "path": "<program-files>/OpenAI.Codex_26.623.19656.0.../codex.exe",
  "installations": [
    {
      "version": "26.623.19656.0",
      "path": "...",
      "status": "active",
      "source": "WindowsApps package"
    },
    {
      "version": "26.616.10790.0",
      "path": "...",
      "status": "stale",
      "source": "historical"
    }
  ],
  "aliases": ["codex.exe", "Codex.exe"],
  "duplicate_count": 3
}
```

实现要求：

1. Canonical key：
   - product。
   - normalized executable family。
   - user scope。
2. 版本排序：
   - 能解析 semver/package version 时取最高。
   - 无法解析时取最近 verified。
3. casing/path 差异折叠。
4. 历史 stale 保留在详情，不在列表重复显示。
5. `name` 禁止出现 `бд` 或其他 mojibake。
6. 旧 records 可通过读取时 normalize，不强制破坏性迁移。

验收：

- `/api/v1/agents?page_size=50` 中 Codex 默认最多 1 条产品级资产。
- Hermes 默认最多 1 条产品级资产。
- 详情页能看到历史安装列表。
- 名称只允许 `Codex Local`、`Codex · Local` 或等价正常文本，不允许 `бд`。

### T05. 数据清理和测试隔离

目标：

- 自动化测试不污染本地正式 SQLite。

涉及文件：

- `src/assessment/store.py`
- `tests/conftest.py`
- `tools/verify_v428_asset_mcp_skill.ps1`
- 所有新增 v4.2.8 测试

实现要求：

1. 支持测试环境变量，例如：

```text
ASSESSMENT_DB_PATH=<temp db path>
ASSESSMENT_ARTIFACT_ROOT=<temp artifact path>
ASSESSMENT_STATE_ROOT=<temp state path>
```

2. 新测试默认使用临时 DB。
3. verify 脚本不得向正式 `data/db/app.db` 写 contract/test 记录。
4. 若必须使用正式 DB smoke，必须使用前缀并在 finally 清理：
   - `v428_smoke_`
   - `contract_`
5. 增加测试确认正式 DB 路径未被新测试写入。

验收：

- 跑完 `tools/verify_v428_asset_mcp_skill.ps1` 后，正式 DB 不新增 v428 测试记录。
- 测试 artifact 写入临时目录或可清理目录。

### T06. MCP/Skill API 契约和自然别名

目标：

- P11/P12/P13/P14/D06/D07 所需 API 可按自然路径访问，避免用户猜错接口。

涉及文件：

- `src/assessment/api/v1.py`
- `src/assessment/contracts.py`
- `tests/test_v428_mcp_skill_api_contract.py`

必须确认或新增：

```text
GET /api/v1/mcp-servers
GET /api/v1/mcp-servers/{id}
GET /api/v1/mcp-consents
POST /api/v1/mcp-consents/{id}/approve
POST /api/v1/mcp-consents/{id}/reject
GET /api/v1/tools
GET /api/v1/tools/{id}
GET /api/v1/skills
GET /api/v1/skills/{id}
POST /api/v1/skills/{id}/scan
```

自然别名要求：

- `GET /api/v1/mcp` 应返回 MCP server 列表或 308/明确 JSON 指向 `/api/v1/mcp-servers`，不能是通用 `NOT_IMPLEMENTED`。
- `GET /api/v1/mcp/{id}` 应返回 MCP server 详情或明确别名。

验收：

- P11/P12/P13/P14/D06/D07 的 Page API Map 全部 contract PASS。
- 自然别名测试通过。

### T07. MCP 静态检查和审批 E2E

目标：

- MCP 页面不只是展示配置，还能完成静态风险检查、审批 dry-run 和详情追踪。

涉及页面：

- P11 MCP Server
- P12 MCP 审批
- D06 MCP Server 详情
- D07 Tool 详情

测试文件：

- `tests/test_v428_mcp_static_consent_e2e.py`

测试场景：

1. 使用 fixture `.mcp.json`。
2. 发现 MCP server。
3. 不启动 stdio。
4. 生成 consent 记录。
5. 静态检查 command/args/env/url。
6. 识别危险模式：
   - `npx` remote package。
   - `curl | bash`。
   - broad filesystem access。
   - env secret key。
   - unknown transport。
7. 审批 approve/reject 只更新本系统审批状态。
8. D06 详情返回 server、config、risk、consent、tools。
9. D07 详情返回 tool schema、source/sink、risk。

验收：

- P11/P12/D06/D07 加入 E2E manifest 并 PASS。
- 测试断言 `stdio_mcp_started=false`。
- 审批不执行命令。

### T08. Skill 专项扫描和详情 E2E

目标：

- Skill 从发现展示推进到可扫描、可看证据、可关联风险。

涉及页面：

- P13 Skills
- P14 Skill 详情

测试文件：

- `tests/test_v428_skill_scan_detail_e2e.py`

测试场景：

1. 使用 fixture Skill。
2. 解析 metadata。
3. 执行只读 Skill 静态扫描。
4. 检测：
   - prompt injection。
   - shell command。
   - network access。
   - secret-like content。
   - dangerous file path。
5. 生成 finding/evidence。
6. Skill 详情返回：
   - metadata。
   - files/scripts。
   - risks。
   - evidence。
   - remediation。
7. 不执行 Skill 代码。

验收：

- P13/P14 加入 E2E manifest 并 PASS。
- 扫描结果不含明文 secret。

### T09. agent-scan 兼容页和 issue 详情 E2E

目标：

- P10/D05 不只是兼容展示，而能证明本地规则映射和 issue 详情。

涉及页面：

- P10 agent-scan 兼容
- D05 agent-scan issue 详情

测试文件：

- `tests/test_v428_agent_scan_mapping_e2e.py`

要求：

1. 使用 sample issue。
2. 映射到本地 rule。
3. 展示 severity、rule、target、local_rule、evidence。
4. issue 详情可打开。
5. 导出映射证据。
6. 明确哪些是本地等价实现，哪些只是兼容展示。

验收：

- P10/D05 E2E PASS。
- `/api/v1/agent-scan/issues?page_size=5` 的返回不含未脱敏 secret。

### T10. ABOM 和 Adapter 覆盖 E2E

目标：

- 资产治理链路覆盖 P07/P08。

涉及页面：

- P07 ABOM
- P08 Adapter 覆盖

测试文件：

- `tests/test_v428_abom_adapter_e2e.py`

要求：

1. 基于归一后的 Agent 资产生成 ABOM。
2. ABOM 包含 Agent、MCP、Skill、Config、Finding 关系。
3. Adapter 覆盖显示 Codex/Hermes/Claude/Cursor 等覆盖矩阵。
4. Unknown version 降级为只读 generic。
5. 导出 ABOM 证据包。

验收：

- P07/P08 E2E PASS。
- ABOM 不把本项目普通源码作为被测组件。

### T11. 浏览器级 E2E

目标：

- 覆盖真实 UI 点击，而不只是 API 和静态字符串。

建议工具：

- Playwright。

测试文件：

- `tests/test_v428_browser_discovery_mcp_skill.py`

测试路径：

1. 启动本地测试服务或使用 ASGI/静态 server。
2. 打开 `/assessment/discovery`。
3. 点击 Skill tab。
4. 搜索 `jwt`。
5. 打开 Skill 命中详情抽屉。
6. 关闭抽屉后筛选仍保留。
7. 打开 MCP tab。
8. 打开 MCP 详情。
9. 进入 Skill 专项页。
10. 打开 Skill 详情。

视觉/交互断言：

- 没有空白页。
- 没有明显文本重叠。
- 抽屉可关闭。
- 页面没有 console error。
- 按钮不会静默无效。

验收：

- 浏览器 E2E 纳入 verify 脚本。
- 若 CI/本机缺 Playwright 浏览器，测试必须给出明确 skip reason，不能假 PASS。

### T12. 规则库扩展到 MCP/Skill 企业测评最低集

目标：

- 当前规则数仍为 10，企业测评感知偏弱。本轮至少扩展 MCP/Skill 相关规则。

涉及文件：

- `src/assessment/scanning/rules.py`
- 规则文档/映射文件
- `tests/test_v428_mcp_skill_rules.py`

最低新增规则族：

1. MCP command uses remote package without pin。
2. MCP command uses shell pipeline。
3. MCP env exposes secret-like key。
4. MCP stdio requires approval。
5. MCP broad filesystem path。
6. Tool schema destructive action without confirmation。
7. Tool schema network egress sink。
8. Skill prompt injection instruction。
9. Skill shell command execution。
10. Skill network access。
11. Skill secret-like content。
12. Skill writes outside workspace。
13. Skill package install at runtime。
14. Skill hidden external URL。
15. Config grants always-allow dangerous tool。

验收：

- `/api/v1/completeness` 的 `rules` 数量提升到至少 25。
- 每条新增规则有样本、单测、严重度、修复建议、误报说明。

### T13. 文档命令控制字符回归

目标：

- 文档中的命令可复制执行。

涉及文件：

- `doc/SPEC_VALIDATION.md`
- `doc/OPERATIONS_DEPLOYMENT.md`
- `doc/USER_GUIDE.md`
- `tests/test_v428_docs_command_hygiene.py`

要求：

1. 清理所有垂直制表、不可见控制字符。
2. 文档不得包含 Bash 风格 heredoc 写法。
3. Windows 示例统一使用：

```powershell
$env:PYTHONPATH='src'
@'
print("ok")
'@ | python -
```

4. 所有 verify 脚本路径使用：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v428_asset_mcp_skill.ps1
```

验收：

- 字节级扫描 `doc/*.md` 不含 `0x0B`。
- 文档命令 hygiene 测试通过。

### T14. v4.2.8 验收脚本

目标：

- 一条命令完成本轮验收。

新增：

- `tools/verify_v428_asset_mcp_skill.ps1`

脚本步骤：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest tests\test_v428_discovery_server_query.py -q
python -m pytest tests\test_v428_self_project_legacy_policy.py -q
python -m pytest tests\test_v428_agent_identity_normalization.py -q
python -m pytest tests\test_v428_mcp_skill_api_contract.py -q
python -m pytest tests\test_v428_mcp_static_consent_e2e.py -q
python -m pytest tests\test_v428_skill_scan_detail_e2e.py -q
python -m pytest tests\test_v428_agent_scan_mapping_e2e.py -q
python -m pytest tests\test_v428_abom_adapter_e2e.py -q
python -m pytest tests\test_v428_docs_command_hygiene.py -q
python -m pytest -q
```

若包含浏览器测试：

```powershell
python -m pytest tests\test_v428_browser_discovery_mcp_skill.py -q
```

脚本要求：

- 失败即停止。
- 输出每一步。
- 使用测试 DB 或隔离数据。
- 不修改真实 Agent。

## 7. E2E Manifest 更新要求

更新：

- `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`

新增 PASS 页面：

- P07
- P08
- P10
- P11
- P12
- P13
- P14
- D05
- D06
- D07

每条必须包含：

- `page_id`
- `status`
- `test_file`
- `test_names`
- `command`
- `assertions`
- `safety_invariants`

禁止：

- 没有测试文件就写 PASS。
- 用一个过浅测试覆盖大量无关页面。
- 硬编码 completeness PASS。

## 8. 验收命令

第三方 AI 完成后必须执行：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v428_asset_mcp_skill.ps1
```

完整性检查：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
print(payload['summary'])
required = {'P07','P08','P10','P11','P12','P13','P14','D05','D06','D07'}
for row in payload['items']:
    if row['id'] in required:
        print(row['id'], row['audit'], row['contract'], row['e2e'], row['status'])
'@ | python -
```

预期：

```text
e2e_passed >= 28
P07/P08/P10/P11/P12/P13/P14/D05/D06/D07 均为 PASS PASS PASS 已验收
```

Discovery 查询检查：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
skill = client.get('/api/v1/discovery-hits?page_size=20&type=Skill').json()
assert skill['items']
assert all(item['type'] == 'Skill' for item in skill['items'])
search = client.get('/api/v1/discovery-hits?page_size=20&q=jwt').json()
assert search['items']
hidden = client.get('/api/v1/discovery-hits?page_size=200').json()
assert not any('<target>/assessment/' in str(item.get('path', '')) for item in hidden['items'])
print('discovery-query-ok')
'@ | python -
```

Agent 归一检查：

```powershell
$env:PYTHONPATH='src'
@'
from collections import Counter
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
items = client.get('/api/v1/agents?page_size=100').json()['items']
counts = Counter(item.get('adapter') for item in items)
assert counts.get('Codex', 0) <= 1
assert counts.get('Hermes', 0) <= 1
assert not any('бд' in str(item.get('name')) for item in items)
print('agent-normalization-ok')
'@ | python -
```

文档控制字符检查：

```powershell
@'
from pathlib import Path
bad = []
for path in Path('doc').rglob('*.md'):
    data = path.read_bytes()
    if bytes([11]) in data:
        bad.append(str(path))
if bad:
    raise SystemExit('vertical-tab found: ' + ', '.join(bad))
print('docs-control-chars-ok')
'@ | python -
```

## 9. 验收拒绝条件

出现以下任一情况，v4.2.8 不通过：

1. `tools\verify_v428_asset_mcp_skill.ps1` 失败。
2. 完整测试失败。
3. `e2e_passed < 28`。
4. P10/P11/P12/P13/P14/D05/D06/D07 仍是 `NOT_ASSERTED`。
5. `/api/v1/discovery-hits?type=Skill` 返回非 Skill。
6. `/api/v1/discovery-hits?q=jwt` 不执行服务端搜索。
7. 默认发现列表仍显示 `<target>/assessment/...` 或本项目普通源码/文档。
8. `/api/v1/agents` 中 Codex/Hermes 默认重复多条。
9. Agent 名称中出现 `бд` 或其他明显 mojibake。
10. MCP 审批测试启动了 stdio MCP。
11. Skill 扫描执行了 Skill 代码。
12. 测试污染正式 SQLite 且没有清理。
13. 文档包含垂直制表控制字符或不可复制命令。
14. 完成后未更新文档或未提交 Git。

## 10. 建议实施顺序

1. 先做测试 DB 隔离，避免后续测试继续污染本地数据。
2. 修 Discovery 服务端查询和 self-project 隐藏。
3. 做 Agent canonical identity 和重复资产折叠。
4. 修 P04 前端服务端筛选/分页。
5. 补 MCP/Skill API 契约和自然别名。
6. 做 MCP 静态检查/审批 E2E。
7. 做 Skill 扫描/详情 E2E。
8. 做 agent-scan mapping、ABOM、Adapter E2E。
9. 做浏览器 E2E。
10. 扩展 MCP/Skill 规则库。
11. 修文档控制字符和验证脚本。
12. 更新 E2E manifest、运行完整验收、提交 Git。

## 11. 交付物清单

代码：

- Discovery server-side query。
- Self-project legacy hide/cleanup。
- Agent identity normalization。
- MCP/Skill API contract aliases。
- MCP static consent E2E implementation。
- Skill scan/detail E2E implementation。
- Browser E2E support。
- Test DB isolation。

测试：

- `tests/test_v428_discovery_server_query.py`
- `tests/test_v428_self_project_legacy_policy.py`
- `tests/test_v428_agent_identity_normalization.py`
- `tests/test_v428_mcp_skill_api_contract.py`
- `tests/test_v428_mcp_static_consent_e2e.py`
- `tests/test_v428_skill_scan_detail_e2e.py`
- `tests/test_v428_agent_scan_mapping_e2e.py`
- `tests/test_v428_abom_adapter_e2e.py`
- `tests/test_v428_docs_command_hygiene.py`
- 可选 `tests/test_v428_browser_discovery_mcp_skill.py`

文档：

- 更新 `doc/SPEC_VALIDATION.md`
- 更新 `doc/USER_GUIDE.md`
- 更新 `doc/OPERATIONS_DEPLOYMENT.md`
- 更新 P10/P11/P12/P13/P14/D05/D06/D07 页面 spec/prototype 必要内容
- 更新 `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`

脚本：

- `tools/verify_v428_asset_mcp_skill.ps1`

## 12. 给第三方 AI 的注意事项

1. 不要通过硬编码 completeness PASS 来达成目标。
2. 不要删除用户或历史数据；对历史记录做隐藏、归档、标记优先。
3. 不要启动 stdio MCP。
4. 不要执行 Skill 代码。
5. 不要修改已安装 Agent 配置。
6. 不要把前端筛选只做在当前页，应由 API 查询保证正确。
7. 不要把测试数据写入正式 DB；若必须写入，必须清理。
8. 完成后必须更新文档并提交 Git。
