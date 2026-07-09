# Agent Security Assessment v4.2.5 迭代 SPEC：探针/OTel 可验收闭环与产品化修复

版本：v4.2.5-iteration-spec  
日期：2026-07-09  
状态：待第三方 AI 开发实施  
角色定位：规划设计、产品验收、企业交付差距收敛  
适用仓库：`F:/bigsinger/agent-scan-platform`

## 1. 本轮目标

本轮不是继续堆页面，而是把 v4.2 探针与 OTel 旁路监控从“已有骨架”推进到“可被企业客户实际验收”的最小闭环：

1. 探针事件能够真实上报、脱敏、持久化、查询。
2. OTLP HTTP JSON traces/logs/metrics 能被接收并落库；其中 traces/logs 至少能规范化为 probe event。
3. 行为链能够通过明确 API 重建，且重复执行不产生重复链路。
4. P0 异常规则能够在链重建后稳定产出异常记录，并能从 UI 查看。
5. Codex/Hermes 探针适配器的 dry-run 安装计划来自真实本机配置探测和适配器代码生成，不再由前端传入假步骤。
6. P49-P54/D19-D22 的导航、路由、契约、文档、测试、完整性矩阵一致。
7. 保持非侵入原则：默认不修改 Codex/Hermes 配置，不启动 stdio MCP，不扫描本项目源码/文档。

本轮完成后，企业验收应能按“发送测试事件 -> 运行链重建 -> 查看异常 -> 查看证据/报告联动 -> 完整性矩阵显示真实状态”的路径走通。

## 2. 当前现状评估

### 2.1 已具备能力

当前仓库已经有以下 v4.2 代码骨架：

- `src/assessment/observability/api.py`
  - 已提供 `/api/v1/probes/events`、`/api/v1/probes`、`/api/v1/probe-sessions`、`/api/v1/behavior/chains`、`/api/v1/behavior/anomalies`、`/api/v1/behavior/rules`、`/api/v1/observability/health`、`/api/v1/probes/install-plan`。
- `src/assessment/observability/receiver.py`
  - 已提供独立 OTLP HTTP JSON receiver 骨架，包含 `/healthz`、`/v1/traces`、`/v1/logs`、`/v1/metrics`。
- `src/assessment/observability/storage.py`
  - 已有 `probe_event`、`otel_span`、`otel_log`、`otel_metric_point`、`behavior_edge` 结构化表 DDL。
- `src/assessment/observability/chain_builder.py`
  - 已有按 trace/session/window 分组的行为链重建函数。
- `src/assessment/observability/anomaly_rules.py`
  - 已有 8 条 P0 异常规则实现骨架。
- `src/assessment/probes/codex/codex_probe_hook.py`
  - 已有 Codex hook 事件解析和安装计划生成函数。
- `src/assessment/probes/hermes/hermes_probe_plugin.py`
  - 已有 Hermes hook/plugin 事件解析和安装计划生成函数。
- `src/assessment/scanning/scope.py`
  - 已有本项目源码/文档默认跳过策略，只允许扫描测试 fixture、`.agents`、测试 MCP/Skill 资产。

当前本地核查命令结果：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 48
python -m pytest tests\test_api_contract.py::test_all_spec_pages_have_completeness_rows tests\test_frontend_static.py::test_frontend_seed_fallback_does_not_ship_prototype_runtime_data tests\test_real_scan_pipeline.py::test_discovery_probes_installed_hermes_and_codex -q
```

结果：

- `node --check` 通过。
- 离线页面检查通过，但仍是 `pages=48`，未纳入 v4.2 新页面。
- 目标 pytest 结果为 `1 failed, 2 passed`，失败项是完整性矩阵测试仍断言 48 页，而当前接口返回 58 页。

可观测性 smoke 结果：

```text
GET /api/v1/observability/health -> 200
GET /api/v1/probes -> 200
POST /api/v1/probes/events -> 200 accepted=1
GET /api/v1/probes/events?limit=5 -> 200
GET /api/v1/behavior/chains?limit=5 -> 200 items=[]
POST /api/v1/behavior/chains -> 501 NOT_IMPLEMENTED
```

说明：事件入口已经能写入，但链重建还没有 API 闭环，UI 的“运行链重建”无法真实触发链构建。

### 2.2 当前 Git 状态

当前有第三方开发后的未提交前端改动：

```text
M src/assessment/static/assessment/app.js
M src/assessment/static/assessment/index.html
```

本 SPEC 不覆盖这些改动。第三方 AI 实施本轮开发时必须先阅读当前 diff，按用户变更继续开发，不能回退。

## 3. 主要问题与目标差距

### G1. 完整性矩阵与真实状态不同步

现象：

- `contracts.py` 已加入 P49-P54/D19-D22，`/api/v1/completeness?page_size=200` 返回 58 行。
- summary 显示：
  - `pages=58`
  - `apis=157`
  - `audit_passed=48`
  - `contract_passed=48`
  - `e2e_passed=0`
  - `gaps=58`
- P49-P54/D19-D22 的 `missing_api` 全部非空，因为 v4.2 API 未加入 `API_ROWS`，或契约检查没有识别实际 FastAPI route。
- v4.2 新页面没有对应 `doc/agent_security_assessment_v4_1_full/specs/pages/*.md` 和 `prototype/pages/*.html`，因此 audit 仅 48 页 PASS。
- 现有测试仍断言 48 页，已经和当前产品目标冲突。

目标：

- 完整性矩阵必须如实显示 58 页。
- P49-P54/D19-D22 的文档、契约、E2E 状态必须和真实实现一致。
- 不允许在没有 E2E 测试的情况下把 `e2e` 标为 `PASS`。

### G2. 新前端页面无法形成正式导航闭环

现象：

- `index.html` 已有 P49 探针管理、P50 OTel 接收服务、P51 行为链、P52 异常分析 DOM。
- `seed.json` 的 `navGroups` 未加入“可观测性/运行时监控”导航组。
- `app.js` 的 `routeForKey()`、`keyForPath()` 未加入：
  - `probes -> /assessment/probes`
  - `observability -> /assessment/observability`
  - `behavior-chains -> /assessment/behavior/chains`
  - `behavior-anomalies -> /assessment/behavior/anomalies`
  - `otel-explorer -> /assessment/otel/explorer`
  - `probe-install -> /assessment/probes/install`
  - 详情页 D19-D22
- P51 行为链页面有 `chainAgentFilter`，但当前未提交 diff 把 `filteredChains` 改成了 `(behaviorChains||[])`，筛选失效。
- `runChainBuild()` 当前只刷新列表并提示“已刷新行为链”，不触发真实链重建。

目标：

- 新页面必须在左侧导航、路由、浏览器 URL、前进后退、直接打开 URL 时都能进入。
- P51 “运行链重建”必须调用真实 API。
- 筛选、详情、返回上下文不能退化。

### G3. 行为链重建缺少 API 且不具备幂等性证明

现象：

- `chain_builder.build_chains()` 是内部函数，当前没有公开 POST API。
- `POST /api/v1/behavior/chains` 被通用未实现兜底拦截，返回 501。
- 当前重建函数每次都会新建 `behavior_chain`，没有按 `trace_id/session_id/window` 做 upsert 去重。
- `GET /behavior/chains/{chain_id}` 只沿 `behavior_edge.from_event_id` 取事件，可能漏掉最后一个 `to_event_id`。
- 没有测试证明重建排序、边关系、重复构建、异常触发正确。

目标：

- 新增真实 `POST /api/v1/behavior/chains`。
- 支持 `{"action":"build","since":null,"source_agent":null,"dry_run":false}`。
- 重复运行不重复创建相同链和边。
- 详情页返回链、边、完整事件列表、异常摘要。

### G4. OTel Receiver 仍是 traces-only 部分落库

现象：

- `/v1/traces` 能提取 span 并写入 `otel_span`。
- `/v1/logs` 和 `/v1/metrics` 只增加计数，不持久化。
- `normalizer.py` 只有文件头，没有实现 OTLP span/log/metric 到 probe_event 的转换。
- 没有 `/api/v1/otel/spans`、`/api/v1/otel/logs`、`/api/v1/otel/metrics` 查询 API。
- P53 OTel Explorer 已列入契约，但没有页面和查询闭环。

目标：

- OTLP traces/logs/metrics 都必须落入对应表。
- traces/logs 至少能生成规范化 `probe_event`，用于行为链分析。
- P53 能查询最近 span/log/metric，并能按 trace_id 查看关联事件。

### G5. 探针安装计划接口不可信

现象：

- `POST /api/v1/probes/install-plan` 当前只是保存前端传来的 `steps` 和 `rollback`。
- 前端 `installProbe()` 传入固定假步骤：
  - `backup`
  - `hook_script`
  - `config_modify`
  - `restore`
- API 没有调用 Codex/Hermes 适配器的 `generate_install_plan()`。
- 安装计划没有证明 dry-run 不修改配置。
- 详情页 D22 未实现。

目标：

- 安装计划必须由后端根据 `agent_type=codex|hermes` 调用真实适配器生成。
- 默认 `dry_run=true`，不写文件、不修改配置、不生成 hook 文件。
- 返回 `before_hash`、`target_config_path`、`steps`、`rollback`、`mutates_installed_agents=false`、`requires_confirmation=true`。
- 暂不实现真实安装落盘；如需 install/apply，必须另起迭代。

### G6. Codex/Hermes 生成代码存在运行时风险

现象：

- Codex `generate_hook_script()` 生成脚本内部使用 `datetime.now(timezone.utc)`，但生成脚本 import 行没有导入 `datetime` 和 `timezone`。
- Hermes `generate_hermes_plugin_code()` 生成代码使用 `Path.home()`，但没有导入 `Path`。
- 生成代码没有独立编译测试。
- Hermes/Codex parse payload 的字段兼容性还缺少真实样本测试。

目标：

- 生成脚本必须可 `py_compile`。
- 单个 hook 事件解析失败必须 fail-open，不影响 Agent。
- 所有生成代码默认只上报脱敏摘要，不保存 raw prompt/result。

### G7. 异常规则缺少验证样本，且部分逻辑需要收敛

现象：

- `_check_secret_in_prompt()` 对 `[REDACTED]` 的判断逻辑不稳。
- `_check_approval_mismatch()` 内部直接调用全局 `get_store()`，破坏传入 store 的测试隔离。
- 规则命中依赖 payload 字段，但事件入口会先脱敏，危险命令、敏感读取、网络调用等规则需要明确使用哪些字段。
- 缺少对 8 条 P0 规则的最小样本和单测。

目标：

- 每条 P0 规则至少一个正例和一个负例测试。
- 规则输出必须包含 `rule_id`、`severity`、`title`、`event_id`、`chain_id`、`evidence_json`、`fix`。
- 不保存明文 secret。

### G8. 报告/证据交互仍有割裂感

现象：

- 用户此前反馈：查看测评报告时点击证据详情会跳走，返回报告需要重新找。
- 当前 `reportPreview` 是 modal，但证据详情、行为链详情、异常详情和报告之间没有统一抽屉/返回上下文协议。

目标：

- 本轮至少完成报告 -> 证据 -> 返回报告的交互闭环。
- 新增行为链/异常页也要遵循同一交互模式：优先抽屉/侧栏查看详情，跨页跳转必须带 `returnTo` 并恢复上下文。

## 4. 本轮开发范围

### 4.1 必须做

- S1：修复 v4.2 页面导航、路由、契约、完整性矩阵。
- S2：实现 `POST /api/v1/behavior/chains` 链重建 API。
- S3：完善 OTLP logs/metrics 落库与 traces/logs -> probe_event 规范化。
- S4：实现 Codex/Hermes 真实 dry-run 安装计划 API。
- S5：修复 Codex/Hermes 生成代码可编译和 fail-open 测试。
- S6：补齐 8 条 P0 异常规则的样本与测试。
- S7：补齐 P49-P54/D19-D22 的文档、静态页面验收、API 合同测试。
- S8：完成报告/证据详情的抽屉或 returnTo 交互改进。

### 4.2 本轮不做

- 不实现真实安装/启用探针落盘。
- 不修改用户现有 Codex/Hermes 配置。
- 不启动 stdio MCP server。
- 不接入远程云端 OTLP。
- 不做系统级键盘记录、进程注入、DLL hook。
- 不扫描 `F:/bigsinger/agent-scan-platform` 的源码、文档、运维目录；仅允许测试 fixture、测试 MCP、测试 Skill。

## 5. 详细开发任务

### T01. 完整性矩阵与 v4.2 页面契约同步

改动文件建议：

- `src/assessment/contracts.py`
- `src/assessment/api/v1.py`
- `tests/test_api_contract.py`
- `tests/test_frontend_static.py`
- `doc/agent_security_assessment_v4_2_full/specs/pages/*.md` 或等价 v4.2 specs 目录
- `doc/agent_security_assessment_v4_2_full/prototype/pages/*.html` 或明确由 SPA 页面替代的审计记录

具体要求：

1. `PAGE_ROWS` 保留 58 页，并明确 v4.2 新页面属于“可观测性”分组。
2. `API_ROWS` 或契约检查机制必须纳入以下 API：
   - `GET /api/v1/probes`
   - `POST /api/v1/probes`
   - `GET /api/v1/probes/{probe_id}`
   - `POST /api/v1/probes/events`
   - `GET /api/v1/probes/events`
   - `GET /api/v1/probes/events/{event_id}`
   - `POST /api/v1/probes/install-plan`
   - `GET /api/v1/probes/install-plan/{plan_id}`
   - `GET /api/v1/probe-sessions`
   - `POST /api/v1/behavior/chains`
   - `GET /api/v1/behavior/chains`
   - `GET /api/v1/behavior/chains/{chain_id}`
   - `GET /api/v1/behavior/anomalies`
   - `GET /api/v1/behavior/rules`
   - `GET /api/v1/observability/health`
   - `GET /api/v1/otel/spans`
   - `GET /api/v1/otel/logs`
   - `GET /api/v1/otel/metrics`
3. 完整性矩阵的状态必须来自真实检查：
   - 文档/原型不存在：`audit=MISSING_DOC`
   - API 不在 OpenAPI 或 `API_ROWS`：`contract=MISSING_API`
   - 没有对应测试标记：`e2e=NOT_ASSERTED`
   - 有测试并通过：`e2e=PASS`
4. 更新测试：
   - `test_all_spec_pages_have_completeness_rows` 期望 58 页。
   - P49-P54/D19-D22 在 docs/API/test 完成后不得出现 `missing_api`。
   - summary 中 `pages=58`。
5. 不允许只改测试绕过问题；必须让 `/api/v1/completeness` 返回真实可解释状态。

验收命令：

```powershell
python -m pytest tests\test_api_contract.py::test_all_spec_pages_have_completeness_rows -q
python -m pytest tests\test_api_contract.py::test_openapi_contains_v4_1_contract_endpoints -q
```

验收标准：

- 两条测试通过。
- `/api/v1/completeness?page_size=200` 返回 58 行。
- P49-P54/D19-D22 的 `missing_api=[]`。
- 没有 E2E 的页面不能显示 `e2e=PASS`。

### T02. 前端导航、路由与页面状态修复

改动文件建议：

- `src/assessment/static/assessment/seed.json`
- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`
- `tests/test_frontend_static.py`

具体要求：

1. 在 `seed.json.navGroups` 增加分组“运行时监控”或“可观测性”，包含：
   - `probes`：探针管理
   - `observability`：OTel 接收服务
   - `behavior-chains`：行为链时间线
   - `behavior-anomalies`：异常分析
   - `otel-explorer`：OTel Explorer
   - `probe-install`：探针安装向导
2. 在 `routeForKey()` 增加：
   - `probes:'/assessment/probes'`
   - `observability:'/assessment/observability'`
   - `'behavior-chains':'/assessment/behavior/chains'`
   - `'behavior-anomalies':'/assessment/behavior/anomalies'`
   - `'otel-explorer':'/assessment/otel/explorer'`
   - `'probe-install':'/assessment/probes/install'`
3. 在 `keyForPath()` 增加上述反向路由，且注意路径顺序：
   - `/assessment/probes/install` 必须先于 `/assessment/probes/{id}`。
   - `/assessment/probes/plans/{id}` 映射 D22。
   - `/assessment/behavior/chains/{id}` 映射 D20 或保持 P51 内嵌详情。
   - `/assessment/otel/spans/{id}` 映射 D21。
4. 修复 P51 筛选：
   - `v-for` 必须使用 `filteredChains`。
   - `filteredChains` 需要按 `chainAgentFilter` 过滤。
5. 修复 P51 重建按钮：
   - `runChainBuild()` 必须 `POST /api/v1/behavior/chains`。
   - 成功后刷新 `behaviorChains`、`behaviorAnomalies`、`observabilityHealth`。
   - 失败时展示后端错误，不静默降级。
6. P49/P50/P51/P52 进入页面时应触发相应数据加载，不能只在 dashboard 启动时加载一次。
7. 修复文案 typo：
   - `Recevier 状态` 改为 `Receiver 状态`。

验收命令：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest tests\test_frontend_static.py -q
```

验收标准：

- 静态检查识别 58 页，或测试显式说明 v4.2 新页面由 SPA route 覆盖。
- URL 直接打开 `/assessment/probes`、`/assessment/observability`、`/assessment/behavior/chains`、`/assessment/behavior/anomalies` 不回到 dashboard。
- P51 Agent 过滤生效。
- “运行链重建”真实调用 POST API。

### T03. 行为链重建 API 与幂等性

改动文件建议：

- `src/assessment/observability/api.py`
- `src/assessment/observability/chain_builder.py`
- `src/assessment/observability/storage.py`
- `tests/test_observability_behavior_chains.py`

API 合同：

```http
POST /api/v1/behavior/chains
Content-Type: application/json
```

请求：

```json
{
  "action": "build",
  "since": null,
  "source_agent": null,
  "dry_run": false,
  "limit": 5000
}
```

响应：

```json
{
  "status": "BUILT",
  "created": 1,
  "updated": 0,
  "skipped": 0,
  "chains": [
    {
      "id": "bch_xxx",
      "chain_id": "bch_xxx",
      "root_trace_id": "trace-1",
      "session_id": "session-1",
      "source_agent": "codex",
      "event_count": 4,
      "edge_count": 3,
      "risk_score": 80,
      "anomaly_count": 1
    }
  ],
  "mutates_installed_agents": false
}
```

实现要求：

1. `build_chains()` 支持 `source_agent`、`limit`。
2. 链唯一键建议：
   - 有 trace：`trace:{trace_id}`
   - 无 trace 有 session：`session:{source_agent}:{session_id}`
   - 兜底窗口：`window:{source_agent}:{first_timestamp_rounded}`
3. `behavior_chain` 必须保存 `chain_key` 或等价字段，重复运行时 upsert。
4. `behavior_edge` 必须按 `(chain_id, from_event_id, to_event_id, relation)` 去重。
5. `GET /behavior/chains/{id}` 必须返回：
   - `chain`
   - `edges`
   - `events`，包含所有 from/to 事件且按时间排序
   - `anomalies`
6. `dry_run=true` 只返回将要创建/更新的链，不写库。
7. 任何异常只影响当前链，不能导致整个批次失败；响应中记录 `errors`。

验收测试：

```powershell
python -m pytest tests\test_observability_behavior_chains.py -q
```

测试样例至少覆盖：

- 同一 `trace_id` 的 4 个事件构建 1 条链、3 条边。
- 同一请求重复 `POST /behavior/chains` 不重复创建链。
- 无 trace 但同 session 的事件可构建链。
- 详情返回最后一个 `to_event_id` 对应事件。
- `dry_run=true` 不写入 DB。

### T04. OTLP Receiver 落库与规范化

改动文件建议：

- `src/assessment/observability/receiver.py`
- `src/assessment/observability/normalizer.py`
- `src/assessment/observability/storage.py`
- `src/assessment/observability/api.py`
- `tests/test_observability_receiver.py`

具体要求：

1. `/v1/traces`
   - 持久化 spans 到 `otel_span`。
   - 从 span attributes 中提取并生成 `probe_event`。
   - 支持 OTel JSON `attributes` 数组格式：
     - `{"key":"gen_ai.system","value":{"stringValue":"codex"}}`
     - `{"key":"agent.session_id","value":{"stringValue":"..."}}`
2. `/v1/logs`
   - 持久化 log records 到 `otel_log`。
   - 对 body 和 attrs 做脱敏。
   - 如 attrs 包含 `agent.event_type` 或 `event.name`，生成 `probe_event`。
3. `/v1/metrics`
   - 持久化 datapoints 到 `otel_metric_point`。
   - 不要求生成 probe_event，但 health 需要展示 metric count。
4. `normalizer.py` 必须实现：
   - `attributes_to_dict(attributes: list|dict) -> dict`
   - `span_to_probe_event(span: dict, resource: dict, scope: dict) -> dict | None`
   - `log_to_probe_event(log: dict, resource: dict, scope: dict) -> dict | None`
   - `normalize_agent_name(value) -> codex|hermes|openclaw|unknown`
5. 新增查询 API：
   - `GET /api/v1/otel/spans?trace_id=&limit=`
   - `GET /api/v1/otel/logs?trace_id=&limit=`
   - `GET /api/v1/otel/metrics?metric_name=&limit=`
6. `/api/v1/observability/health` 增加：
   - `otel_logs`
   - `otel_metric_points`
   - `receiver_state`
   - `last_error`

验收命令：

```powershell
python -m pytest tests\test_observability_receiver.py -q
```

手工 smoke：

```powershell
$env:PYTHONPATH='src'
python -m assessment.observability.receiver --host 127.0.0.1 --port 4318
```

另开终端：

```powershell
$body = @{
  resourceSpans = @(@{
    resource = @{ attributes = @(@{ key="service.name"; value=@{ stringValue="codex" } }) }
    scopeSpans = @(@{
      spans = @(@{
        traceId = "11111111111111111111111111111111"
        spanId = "2222222222222222"
        name = "tool.call"
        startTimeUnixNano = "1720000000000000000"
        endTimeUnixNano = "1720000000100000000"
        attributes = @(
          @{ key="agent.event_type"; value=@{ stringValue="tool.call.started" } },
          @{ key="agent.session_id"; value=@{ stringValue="smoke-session" } },
          @{ key="agent.tool_name"; value=@{ stringValue="Bash" } },
          @{ key="agent.tool_type"; value=@{ stringValue="shell" } },
          @{ key="agent.command"; value=@{ stringValue="echo hello" } }
        )
      })
    })
  })
} | ConvertTo-Json -Depth 12
Invoke-RestMethod -Method Post http://127.0.0.1:4318/v1/traces -Body $body -ContentType 'application/json'
```

验收标准：

- `/v1/traces` 返回 200。
- `/api/v1/otel/spans` 能查到 span。
- `/api/v1/probes/events` 能查到对应 `tool.call.started`。
- 明文 secret 不出现在 DB 查询响应中。

### T05. 真实 dry-run 探针安装计划

改动文件建议：

- `src/assessment/observability/api.py`
- `src/assessment/probes/codex/codex_probe_hook.py`
- `src/assessment/probes/hermes/hermes_probe_plugin.py`
- `tests/test_probe_install_plan.py`

具体要求：

1. `POST /api/v1/probes/install-plan` 接收：

```json
{
  "agent_type": "codex",
  "dry_run": true,
  "collector_url": "http://127.0.0.1:8000/api/v1/probes/events"
}
```

2. 当 `agent_type=codex` 时：
   - 调用 `codex_probe_hook.generate_install_plan(dry_run=True)`。
   - 不写 `~/.codex/probe_hook.py`。
   - 不修改 `~/.codex/config.toml`。
   - 如未发现 config，返回 `install_status=not_found`，HTTP 仍为 200。
3. 当 `agent_type=hermes` 时：
   - 调用 `hermes_probe_plugin.generate_install_plan(dry_run=True)`。
   - 不修改 Hermes 配置。
4. 返回字段必须包含：
   - `id`
   - `agent_type`
   - `plan_status=dry_run`
   - `dry_run=true`
   - `target_config_path`
   - `before_hash`
   - `steps`
   - `rollback`
   - `mutates_installed_agents=false`
   - `agent_runtime_started=false`
   - `stdio_mcp_started=false`
   - `requires_confirmation=true`
5. 保存到 `probe_install_plan` 的 `steps_json`、`rollback_json` 必须是合法 JSON，不能用 Python `str(list)`。
6. 前端不得再传固定 steps；只传 `agent_type` 和 `dry_run`。

验收命令：

```powershell
python -m pytest tests\test_probe_install_plan.py -q
```

验收标准：

- fake Codex/Hermes config 文件 hash 在请求前后完全一致。
- plan 中 steps 来自后端生成器。
- 不创建 hook 文件。
- 不修改真实用户 Codex/Hermes 配置。

### T06. Codex/Hermes 探针适配器编译与解析测试

改动文件建议：

- `src/assessment/probes/codex/codex_probe_hook.py`
- `src/assessment/probes/hermes/hermes_probe_plugin.py`
- `src/assessment/probes/common/emitter.py`
- `tests/test_probe_adapters.py`

具体要求：

1. Codex generated hook 脚本必须补齐 import：
   - `from datetime import datetime, timezone`
2. Hermes generated plugin 必须补齐 import：
   - `from pathlib import Path`
3. 生成脚本不得依赖当前项目包路径，除非安装计划明确写入独立脚本依赖。
4. `parse_hook_event()` 必须覆盖：
   - Codex `UserPromptSubmit`
   - Codex `PreToolUse`
   - Codex `PermissionRequest`
   - Codex `PostToolUse`
   - Hermes `pre_llm_call`
   - Hermes `pre_tool_call`
   - Hermes `post_tool_call`
   - Hermes MCP 工具名 `mcp_fetch_fetch`
5. `emit_normalized_event()` fail-open 测试：
   - collector 不可达时写入 JSONL buffer。
   - 返回 `False`。
   - 不抛异常。
6. 所有 payload 解析测试必须断言：
   - `source_agent`
   - `event_type`
   - `session_id`
   - `tool_name`
   - `tool_type`
   - `mcp_server/mcp_tool`
   - `redaction_status=redacted`

验收命令：

```powershell
python -m pytest tests\test_probe_adapters.py -q
```

验收标准：

- 生成脚本能写入临时文件并 `py_compile` 通过。
- 解析结果不含明文 secret。
- collector 失败不影响函数返回。

### T07. P0 异常规则样本与测试

改动文件建议：

- `src/assessment/observability/anomaly_rules.py`
- `tests/test_behavior_anomaly_rules.py`

必须覆盖规则：

- `ANOM-SECRET-IN-PROMPT`
- `ANOM-DANGEROUS-SHELL`
- `ANOM-SENSITIVE-READ-THEN-NETWORK`
- `ANOM-MCP-REPEATED-FAILURE`
- `ANOM-TOOL-LOOP`
- `ANOM-CROSS-WORKSPACE-PATH`
- `ANOM-APPROVAL-MISMATCH`
- `ANOM-RAW-CAPTURE-ENABLED`

具体要求：

1. 每条规则至少 1 个正例、1 个负例。
2. 移除规则函数里的全局 `get_store()` 依赖，统一使用传入 store。
3. 规则命中时必须关联 `chain_id`。
4. 不保存明文 secret；`evidence_json` 中只能出现 `[REDACTED]`、hash、字段名或短摘要。
5. 风险分值需要回写到 chain：
   - high：建议 `risk_score>=70`
   - medium：建议 `risk_score>=40`
   - low：建议 `risk_score>=10`

验收命令：

```powershell
python -m pytest tests\test_behavior_anomaly_rules.py -q
```

验收标准：

- 8 条规则全部有测试。
- 测试中注入的 secret 不出现在响应文本或 DB 明文中。

### T08. 报告/证据/行为链详情交互改进

改动文件建议：

- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`
- `src/assessment/static/assessment/style.css`
- `tests/test_frontend_static.py`

具体要求：

1. 新增统一详情抽屉状态：
   - `detailDrawerOpen`
   - `detailDrawerType`
   - `detailDrawerPayload`
   - `detailDrawerReturnTo`
2. 报告预览中点击证据：
   - 优先打开证据抽屉，不离开报告 modal。
   - 抽屉显示证据 ID、finding、sha256、redaction_status、download。
3. 如果必须跳转：
   - URL 加 `?returnTo=/assessment/reports/{id}/preview`
   - 返回按钮恢复报告预览和滚动位置。
4. 行为链详情：
   - 在 P51 页面内用抽屉或右侧详情，不默认跳页。
   - 事件点击可打开事件抽屉。
5. 异常详情：
   - 点击异常行打开详情抽屉，展示 evidence_json、fix、映射标准、关联 chain/event。

验收标准：

- 从报告预览查看证据后，可以一键回到原报告预览。
- 页面状态不丢失当前筛选条件。
- 无需重新在报告列表里查找原报告。

### T09. 本项目扫描边界回归

改动文件建议：

- `tests/test_real_scan_pipeline.py`
- `tests/test_observability_behavior_chains.py`

具体要求：

1. 增加测试：对 `F:/bigsinger/agent-scan-platform` 或 repo root 发起 path scan 时：
   - `doc/`、`src/`、`data/` 不应被当作客户 Agent 项目扫描。
   - 仅 `tests/fixtures`、`.agents`、测试 MCP/Skill 被纳入。
2. 对可观测性事件中的 workspace/path：
   - 如果 path 指向本项目源码/文档，应标记为 self-project-excluded。
   - 不生成业务风险 finding。
3. Discovery/quick scan 响应中保留 `self_project_scope`，方便企业验收。

验收命令：

```powershell
python -m pytest tests\test_real_scan_pipeline.py::test_self_project_source_and_docs_are_skipped -q
```

验收标准：

- 本项目源码/文档不会出现在扫描文件列表。
- 测试 fixture 仍可扫描。
- 响应明确 `policy=skip-agent-scan-platform-source-and-docs`。

### T10. 文档同步

改动文件建议：

- `doc/USER_GUIDE.md`
- `doc/OPERATIONS_DEPLOYMENT.md`
- `doc/SPEC_VALIDATION.md`
- `doc/agent_security_assessment_v4_2_probe_otel_observability_plan.md`

具体要求：

1. `USER_GUIDE.md` 新增章节：
   - 探针管理如何查看。
   - 如何发送测试事件。
   - 如何启动/验证 OTel receiver。
   - 如何运行链重建。
   - 如何查看异常。
   - 探针 dry-run 安装计划含义。
2. `OPERATIONS_DEPLOYMENT.md` 新增章节：
   - Receiver 启动命令。
   - 端口：`127.0.0.1:4318`、平台 API `127.0.0.1:8000`。
   - 日志与 DB 表。
   - 故障处理：Collector 不可达、DB 锁、事件丢弃、重复链。
   - 安全边界：不修改 Agent、不启动 stdio MCP、不保存 raw。
3. `SPEC_VALIDATION.md` 新增 v4.2.5 验收清单：
   - 命令。
   - 预期输出。
   - 页面检查点。
   - 失败排查。
4. 文档必须说明：
   - 本轮不启用真实安装。
   - 本轮只做 dry-run 安装计划。
   - 本轮默认本机回环地址，不上传云端。

验收标准：

- 企业试点评估人员不读源码也能按文档跑完 smoke。
- 文档命令可以复制到 PowerShell 执行。

## 6. 推荐新增测试文件清单

本轮建议新增或扩展以下测试：

```text
tests/test_observability_receiver.py
tests/test_observability_behavior_chains.py
tests/test_behavior_anomaly_rules.py
tests/test_probe_adapters.py
tests/test_probe_install_plan.py
tests/test_frontend_observability_static.py
tests/test_completeness_v4_2.py
```

最低通过命令：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest tests\test_observability_receiver.py tests\test_observability_behavior_chains.py tests\test_behavior_anomaly_rules.py tests\test_probe_adapters.py tests\test_probe_install_plan.py tests\test_frontend_observability_static.py tests\test_completeness_v4_2.py -q
python -m pytest tests\test_api_contract.py tests\test_real_scan_pipeline.py -q
```

如本轮修改影响通用契约，必须跑全量：

```powershell
python -m pytest -q
```

## 7. 企业验收流程

### 7.1 启动平台

```powershell
$env:PYTHONPATH='src'
python -m uvicorn assessment.main:app --host 127.0.0.1 --port 8000
```

访问：

```text
http://127.0.0.1:8000/assessment
```

### 7.2 启动 OTel Receiver

另开 PowerShell：

```powershell
$env:PYTHONPATH='src'
python -m assessment.observability.receiver --host 127.0.0.1 --port 4318
```

验证：

```powershell
Invoke-RestMethod http://127.0.0.1:4318/healthz
Invoke-RestMethod http://127.0.0.1:8000/api/v1/observability/health
```

### 7.3 发送规范化测试事件

```powershell
$body = @{
  events = @(
    @{
      event_id = "evt-v425-001"
      event_type = "agent.user_input.received"
      timestamp = "2026-07-09T10:00:00Z"
      source_agent = "codex"
      session_id = "sess-v425"
      payload = @{ input = "请检查当前项目"; password = "should-not-appear" }
    },
    @{
      event_id = "evt-v425-002"
      event_type = "tool.call.started"
      timestamp = "2026-07-09T10:00:01Z"
      source_agent = "codex"
      session_id = "sess-v425"
      tool_call_id = "tool-v425-001"
      tool_name = "Bash"
      tool_type = "shell"
      payload = @{ command = "echo hello" }
    },
    @{
      event_id = "evt-v425-003"
      event_type = "tool.call.completed"
      timestamp = "2026-07-09T10:00:02Z"
      source_agent = "codex"
      session_id = "sess-v425"
      tool_call_id = "tool-v425-001"
      tool_name = "Bash"
      tool_type = "shell"
      status = "ok"
      payload = @{ output = "hello" }
    }
  )
} | ConvertTo-Json -Depth 8
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/probes/events -Body $body -ContentType 'application/json'
```

预期：

- 返回 `accepted=3`。
- `password` 字段在查询结果中为 `[REDACTED]`。

### 7.4 运行链重建

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/behavior/chains -Body '{"action":"build"}' -ContentType 'application/json'
Invoke-RestMethod http://127.0.0.1:8000/api/v1/behavior/chains
```

预期：

- 第一条请求返回 `status=BUILT`。
- 链列表至少有 1 条。
- 重复执行不会增加重复链。

### 7.5 查看 UI

打开：

```text
http://127.0.0.1:8000/assessment/probes
http://127.0.0.1:8000/assessment/observability
http://127.0.0.1:8000/assessment/behavior/chains
http://127.0.0.1:8000/assessment/behavior/anomalies
http://127.0.0.1:8000/assessment/completeness
```

预期：

- 四个页面不回落到 dashboard。
- P49 能看到探针状态。
- P50 能看到事件列表。
- P51 能看到链并打开详情。
- P52 能看到异常或明确空态。
- P34 完整性矩阵显示 58 页，P49-P54/D19-D22 状态可解释。

## 8. Definition of Done

本轮完成必须同时满足：

1. Git 工作树只包含本轮相关改动；不回退用户/第三方已有改动。
2. 新增/修改文档已同步。
3. 所有新增测试通过。
4. 目标 smoke 手工命令可跑通。
5. `POST /api/v1/behavior/chains` 不再是 501。
6. P49-P54/D19-D22 不再是“有页面但无导航/无契约/无文档”的状态。
7. Codex/Hermes 配置文件在所有测试前后 hash 不变。
8. 明文 secret 不出现在 API 响应、DB 解码结果、报告/证据导出中。
9. 本项目源码/文档不会被当作客户 Agent 项目扫描。
10. 完成后提交 Git，commit message 建议：

```text
feat(v4.2.5): complete observability probe e2e loop
```

## 9. 本轮验收拒收条件

出现以下任意情况，本轮不得验收：

- 通过修改测试期望来掩盖真实功能缺失。
- 完整性矩阵把未测试页面标为 `PASS`。
- `POST /api/v1/behavior/chains` 仍返回 501。
- P51 “运行链重建”仍只是刷新列表。
- 探针安装计划由前端伪造 steps。
- 生成 hook/plugin 代码无法编译。
- 测试或 smoke 修改了真实 Codex/Hermes 配置。
- 任何响应中出现测试 secret 明文。
- `/assessment/probes` 等新 URL 直接打开仍回到 dashboard。
- 扫描本项目时把 `doc/` 或 `src/` 当客户 Agent 资产扫描。

