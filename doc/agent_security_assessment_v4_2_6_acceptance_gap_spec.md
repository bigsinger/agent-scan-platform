# Agent Security Assessment v4.2.6 迭代 SPEC：验收差距收敛、OTel 真实接入与企业硬化

版本：v4.2.6-iteration-spec  
日期：2026-07-09  
状态：待第三方 AI 开发实施  
角色定位：产品验收、规划设计、企业交付差距收敛  
适用仓库：`F:/bigsinger/agent-scan-platform`

## 1. 本轮目标

v4.2.5 已经把探针、OTel、行为链、异常分析、安装计划等功能推进到可运行骨架，并新增了部分测试。但当前仍不能定义为“目标完成”，原因是完整性矩阵、静态 fallback 数据、E2E 证据、OTel receiver 真实接入、异常规则幂等性、详情页体验和企业安全边界仍存在明显差距。

v4.2.6 的目标不是继续增加大量新页面，而是把已经引入的 v4.2 可观测性能力修到可以被企业客户实际测评：

1. `/api/v1/completeness`、`seed.json`、页面文档、原型、测试证据必须一致，不允许静态 fallback 宣称“已验收”但运行态显示 `NOT_ASSERTED`。
2. P49-P54/D19-D22 必须补齐文档、原型、路由、数据接口和可执行验收。
3. OTel receiver 必须有真实 OTLP HTTP JSON traces/logs/metrics 接收测试，不允许只测内部转换函数。
4. 行为链和异常规则必须可重复执行、幂等、不重复生成异常，并且能证明关键 P0 规则有效。
5. 探针安装计划必须保持默认只读、dry-run、安全可回滚，不修改本机 Codex/Hermes 配置。
6. UI 需要把报告、证据、行为链、OTel span、探针详情做成顺滑的详情抽屉或可返回上下文，减少割裂式跳转。
7. 完整测试套件必须恢复通过，并把当前失败点转化为回归测试。

## 2. 非目标与安全边界

本轮不做以下事项：

- 不自动修改已安装 Codex、Hermes、Claude Code、Cursor、Windsurf、Kiro 等智能体的真实配置。
- 不启动或调用本机已配置的 stdio MCP Server。
- 不扫描本项目 `F:/bigsinger/agent-scan-platform` 的源码和文档作为测评对象；只允许扫描本项目内明确用于测试的 fixture、测试性 MCP、测试性 Skill。
- 不引入内核级、驱动级、全局键盘监听、系统代理强插等可能影响智能体正常使用的 hook。
- 不把 OTel receiver 做成强依赖外部云服务；本地接收、落库和分析必须可独立运行。
- 不用 demo 数据掩盖未实现能力。无法实现的能力必须在接口、文档和 UI 中明确标注为“本阶段不交付”或“只读建议”。

所有新增能力必须满足：

- 默认只读。
- 默认不影响已安装智能体的正常使用。
- 默认不保存明文 Secret。
- 默认不把本项目自身代码/文档作为被测智能体资产。
- 对 Codex/Hermes 的探测和安装计划生成只能读取配置、生成计划、生成代码包或说明，不能直接写入真实配置。

## 3. 当前现状评估

### 3.1 已确认的改进

当前仓库最新实现已经包含以下能力：

- 新增运行时监控导航与 P49-P54 页面骨架。
- 新增 D19-D22 详情页契约记录。
- `src/assessment/observability/receiver.py` 已具备独立 OTel HTTP JSON receiver 骨架：
  - `/healthz`
  - `/v1/traces`
  - `/v1/logs`
  - `/v1/metrics`
- `src/assessment/observability/api.py` 已具备平台 API：
  - `/api/v1/probes`
  - `/api/v1/probes/events`
  - `/api/v1/probe-sessions`
  - `/api/v1/behavior/chains`
  - `/api/v1/behavior/anomalies`
  - `/api/v1/behavior/rules`
  - `/api/v1/observability/health`
  - `/api/v1/otel/spans`
  - `/api/v1/otel/logs`
  - `/api/v1/otel/metrics`
  - `/api/v1/probes/install-plan`
- `tests/test_v425_observability_e2e.py` 新增了 4 个测试，已通过。
- 前端静态检查已支持 58 页。
- 行为链重建 API 已由上一轮的 `501 NOT_IMPLEMENTED` 推进到可返回 `200`。

### 3.2 本轮验收时执行过的命令与结果

前端语法检查：

```powershell
node --check src\assessment\static\assessment\app.js
```

结果：通过。

前端离线页面检查：

```powershell
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
```

结果：通过。

输出要点：

```text
frontend offline check passed: pages=58
```

v4.2.5 新增测试：

```powershell
python -m pytest tests\test_v425_observability_e2e.py -q
```

结果：通过。

输出要点：

```text
4 passed in 2.99s
```

完整测试套件：

```powershell
python -m pytest -q
```

结果：失败。

输出要点：

```text
2 failed, 118 passed in 197.63s
```

失败项：

- `tests/test_api_contract.py::test_all_spec_pages_have_completeness_rows`
  - 仍断言 48 行，但当前 `PAGE_ROWS` 已经是 58 行。
- `tests/test_frontend_static.py::test_frontend_seed_fallback_does_not_ship_prototype_runtime_data`
  - 仍断言 `seed["completeness"] == 48`，但当前 `seed.json` 已经是 58 行。

完整性矩阵运行态检查：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
p = client.get('/api/v1/completeness?page_size=200').json()
print(p['summary'])
print([(r['id'], r['audit'], r['contract'], r['e2e']) for r in p['items'][-10:]])
'@ | python -
```

实际结果要点：

```text
pages=58
apis=175
sqlite_tables=88
rules=10
audit_passed=48
contract_passed=58
e2e_passed=0
gaps=58
```

P49-P54/D19-D22 当前状态：

```text
audit=MISSING_DOC
contract=PASS
e2e=NOT_ASSERTED
```

这说明 v4.2 新页面已经进入契约层，但文档/原型未补齐，且全页面 E2E 仍未形成正式验收证据。

OTel/行为链 smoke：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)

print(client.get('/api/v1/observability/health').status_code)
print(client.post('/api/v1/probes/events', json={
    'events': [{
        'event_id': 'smoke_v426_1',
        'event_type': 'agent.user_input.received',
        'timestamp': '2026-07-09T10:00:00Z',
        'source_agent': 'codex',
        'session_id': 'smoke_v426',
        'payload': {'password': 'topsecret', 'input': 'hello'}
    }]
}).text)
print(client.post('/api/v1/behavior/chains', json={'action': 'build'}).text[:300])
print(client.get('/api/v1/otel/spans?limit=5').text)
print(client.get('/api/v1/otel/logs?limit=5').text)
print(client.get('/api/v1/otel/metrics?limit=5').text)
'@ | python -
```

结果要点：

- `/api/v1/observability/health` 返回 `200`。
- `/api/v1/probes/events` 返回 `accepted=1`。
- `/api/v1/behavior/chains` 返回 `200`。
- `/api/v1/otel/spans`、`/api/v1/otel/logs`、`/api/v1/otel/metrics` 当前均可查询，但 smoke 中为空。

### 3.3 当前结论

当前状态可以判断为“可观测性骨架基本可运行，但企业验收闭环未完成”：

- 不是纯原型，但仍存在 demo/fallback 与运行态真实状态不一致。
- 探针事件 API 可用，但 OTel receiver 的真实 ingestion 还缺少端到端测试证明。
- 行为链 API 可用，但异常规则、幂等性、证据链、UI 详情联动还不够硬。
- 完整性矩阵已经从 48 页扩展到 58 页，但静态测试、seed fallback、文档/原型和 E2E 状态没有统一。
- 完整测试套件当前失败，不能交付给企业客户测评。

## 4. 主要问题与差距清单

### G1. 完整测试套件失败，阻塞交付

严重级别：P0  
影响：任何企业交付前置验收都会失败。

现象：

- `python -m pytest -q` 当前为 `2 failed, 118 passed`。
- 两个失败都来自 48 页旧断言没有更新到 58 页。

根因：

- `PAGE_ROWS` 已新增 P49-P54/D19-D22。
- 旧测试仍把 48 页作为固定真值。
- `seed.json` 也跟着扩到 58 页，但测试未改。

修复方向：

- 测试不能简单把 `48` 改成 `58` 后结束。
- 必须同步检查：
  - `PAGE_ROWS` 行数。
  - `seed.json` 行数。
  - `/api/v1/completeness` 行数。
  - P49-P54/D19-D22 文档存在性。
  - E2E 状态不被误标为 PASS。

验收要求：

- `python -m pytest -q` 必须 100% 通过。
- 新增回归测试防止后续再次出现“契约 58、文档 48、seed 过度宣称”的错配。

### G2. 运行态完整性矩阵与静态 fallback 数据互相矛盾

严重级别：P0  
影响：企业客户打开离线页面或 API 页面时看到不同验收状态，会质疑系统可信度。

现象：

- `/api/v1/completeness` 显示：
  - P49-P54/D19-D22 `audit=MISSING_DOC`
  - 所有页面 `e2e=NOT_ASSERTED`
- `src/assessment/static/assessment/seed.json` 中 completeness fallback 却把 58 行都写成类似“已覆盖/已验收”。
- `src/assessment/contracts.py` 的静态 `completeness_rows()` 仍可能输出过度乐观字段。

修复方向：

- 静态 `seed.json` 只能作为离线展示 fallback，不能宣称未被运行态证据证明的状态。
- 如果无运行态 API，应显示：
  - `audit`: `UNKNOWN` 或与静态文件检查一致。
  - `contract`: `UNKNOWN` 或 `STATIC_DECLARED`。
  - `e2e`: `NOT_ASSERTED`。
  - `status`: `待验证`。
- 最优方案：构建 `seed.json` 时从同一份 contract generator 产出，但默认 E2E 不得 PASS。

验收要求：

- 断网/后端不可用时，前端 fallback 不显示“已验收”。
- `/api/v1/completeness` 与前端在线显示完全一致。
- `seed.json` 中不得出现未证明的 `e2e=PASS` 或 `status=已验收`。

### G3. P49-P54/D19-D22 缺少正式文档和原型文件

严重级别：P0  
影响：运行态 audit 只有 48/58 PASS，新功能无法进入正式验收。

缺失文件：

- `doc/agent_security_assessment_v4_1_full/specs/pages/P49_probes.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P50_observability.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P51_behavior_chains.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P52_behavior_anomalies.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P53_otel_explorer.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P54_probe_install.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D19_probe_detail.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D20_behavior_chain_detail.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D21_otel_span_detail.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D22_probe_install_plan_detail.md`
- 对应 `prototype/pages/*.html` 文件。

修复方向：

- 不能只创建空文件让 audit PASS。
- 每个页面 spec 至少包含：
  - 页面目标。
  - 路由。
  - 主 API。
  - 数据表。
  - 关键交互。
  - 安全边界。
  - 空态/失败态。
  - E2E 验收点。
- 每个 prototype 至少包含：
  - 页面标题。
  - 关键控件。
  - 主要表格/详情区。
  - 空态/错误态。
  - 与当前正式 UI 一致的字段命名。

验收要求：

- `/api/v1/completeness?page_size=200` 的 `audit_passed` 从 48 提升到 58。
- P49-P54/D19-D22 不再出现 `MISSING_DOC`。
- 文档和原型中不得出现“演示数据即可”的描述。

### G4. E2E 状态没有证据映射，`e2e_passed=0`

严重级别：P0  
影响：虽然已有 120 个左右测试，但完整性矩阵无法证明任何页面通过 E2E。

现象：

- `/api/v1/completeness` 的 `e2e_passed=0`。
- `tests/test_v425_observability_e2e.py` 通过，但没有与 P49-P54/D19-D22 形成页面级验收映射。
- 48 个旧页面也没有页面级 E2E 状态证据。

修复方向：

- 引入 E2E 证据清单，例如：
  - `tests/e2e_manifest.json`
  - 或 `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`
  - 或在测试中生成 `artifacts/e2e/e2e_results.json`
- 每条证据至少包含：
  - `page_id`
  - `test_file`
  - `test_name`
  - `last_verified_command`
  - `expected_assertions`
  - `safety_invariants`
  - `updated_at`
- `/api/v1/completeness` 只能在对应测试存在且最近一次本地验证通过时把 `e2e=PASS`。
- 如果没有自动读取 pytest 结果，至少使用静态 manifest 声明“被哪个测试覆盖”，并在 SPEC_VALIDATION 中记录本次验证命令。

验收要求：

- P49-P54/D19-D22 至少有一组可执行测试映射。
- 完整性矩阵的 `e2e` 不能靠手工写死 PASS。
- `doc/SPEC_VALIDATION.md` 必须记录 v4.2.6 的实际命令、时间、结果和未覆盖项。

### G5. OTel receiver 未形成真实端到端接收验收

严重级别：P0  
影响：OTel 旁路数据监控是新增核心需求，不能只停留在转换函数或内部 API。

现象：

- `receiver.py` 具备 `/v1/traces`、`/v1/logs`、`/v1/metrics`。
- 当前测试主要覆盖 `span_to_probe_event`、`log_to_probe_event`、查询 API 存在性。
- 尚未看到对 `create_receiver_app()` 的真实 `POST /v1/traces`、`POST /v1/logs`、`POST /v1/metrics` 测试。
- 平台主 API 的 `/api/v1/observability/health` 返回 `receiver_state=embedded-api-ok`，但这不能证明本地 `127.0.0.1:4318` receiver 真的在运行。

修复方向：

- 新增 receiver ingestion 测试，使用 FastAPI TestClient 直接请求 `create_receiver_app()`：
  - POST OTLP traces JSON。
  - POST OTLP logs JSON。
  - POST OTLP metrics JSON。
  - 验证 `otel_span`、`otel_log`、`otel_metric_point` 落库。
  - 验证 traces/logs 能规范化为 `probe_event`。
  - 验证 secrets 被脱敏。
- 修正 `/api/v1/observability/health`：
  - 明确区分 `platform_api_status` 和 `standalone_receiver_status`。
  - 如果没有探测真实 receiver，不得显示 `receiver.status=ok`。
  - 推荐字段：
    - `platform_api.status=ok`
    - `receiver.configured_endpoint=http://127.0.0.1:4318`
    - `receiver.probed=false|true`
    - `receiver.status=unknown|ok|down`
    - `receiver.last_error`
- 提供本地启动命令和健康检查命令。

验收要求：

- 新增测试文件 `tests/test_v426_otel_receiver_ingestion.py`。
- 至少覆盖 traces/logs/metrics 三类 OTLP JSON。
- `/api/v1/otel/spans`、`/api/v1/otel/logs`、`/api/v1/otel/metrics` 可查到接收数据。
- `/api/v1/observability/health` 不再误导性宣称未启动 receiver 为 `ok`。

### G6. OTel 数据规范化不足，影响检索和分析

严重级别：P1  
影响：OTel Explorer 和行为分析数据质量不稳定。

现象：

- `otel_span.attrs_json` 可能保存 OTLP 原始属性数组，而不是标准 key-value dict。
- `otel_log.timestamp`、`otel_metric_point.timestamp` 可能保存 `timeUnixNano` 原始纳秒字符串。
- 查询 API 返回较多 JSON 字符串，前端需要重复解析。
- 缺少按 `trace_id` 聚合的 trace 详情接口。
- 未知 agent 的 OTel span 可能被转换成 `source_agent=unknown` 的 probe_event，污染智能体行为链。

修复方向：

- 入库前统一规范化：
  - attributes 转 dict。
  - timestamp 转 ISO-8601 UTC。
  - body/payload 脱敏后存储。
  - 保留 `raw_ref` 或 `raw_sha256`，不保存原始敏感 payload。
- 增加接口：
  - `GET /api/v1/otel/traces/{trace_id}`
  - 返回 trace 下 spans、logs、metrics、关联 probe_events、关联 behavior_chains。
- 明确 unknown OTel 处理策略：
  - 无 `agent.*`、`ai.agent.*`、`service.name` 或 `session_id` 的 OTel 记录，只存 OTel 表，不生成 probe_event。
  - 有明确智能体属性时，才规范化为 probe_event。

验收要求：

- OTel 查询返回结构化 attributes，不要求前端自行解析 JSON 字符串。
- OTel Explorer 支持从 span 跳到 trace 详情。
- 行为链中不出现大量 `source_agent=unknown` 噪声。

### G7. 行为链和异常规则缺少幂等与规则正确性证明

严重级别：P0  
影响：重复点击“运行链重建”可能重复生成异常，风险列表失真。

现象：

- 行为链重建已能返回 `200`。
- `behavior_chain` 基本具备幂等键，但 `behavior_edge` 通过删除重建实现，边 ID 会 churn。
- `behavior_anomaly` 未看到明确唯一键或去重策略。
- 反复运行链构建时，可能重复插入相同异常。
- P0 异常规则目前缺少逐条单测。

重点规则问题：

- Secret 规则在 API 先脱敏后可能失去“用户尝试输入 secret”的检测信号。
- 危险命令规则的 `command_preview` 需要脱敏，否则可能把 secret 或敏感路径写入异常证据。
- “敏感文件读取后网络外连”规则需要校验时间顺序和时间窗口，不能只看同链路内存在两类事件。
- Windows 路径、Unix 路径、大小写、斜杠方向需要统一。

修复方向：

- 为 `behavior_anomaly` 引入稳定去重键：
  - `rule_id`
  - `chain_id`
  - `event_id`
  - `evidence_sha256`
- 重复构建时更新已有异常，不重复插入。
- `probe_event` 存储脱敏 payload，同时保存非敏感的 `redaction_summary`：
  - `redacted_fields`
  - `secret_like_detected=true|false`
  - `secret_pattern_types`
  - `payload_sha256`
- 8 条 P0 规则必须逐条单测。
- 规则输出必须包含：
  - `rule_id`
  - `severity`
  - `confidence`
  - `chain_id`
  - `event_id`
  - `evidence`
  - `recommendation`
  - `false_positive_guidance`

验收要求：

- 新增测试文件 `tests/test_v426_behavior_anomaly_rules.py`。
- 连续运行两次 `/api/v1/behavior/chains` 后，异常数量不增加。
- 所有异常证据中不得出现测试 secret 明文。
- “敏感读后外连”测试必须包含时间窗口内命中、窗口外不命中、顺序反转不命中。

### G8. D19-D22 详情页可能只是契约，不是完整 UI

严重级别：P1  
影响：用户从列表进入详情后体验割裂，无法顺滑回到报告、证据、行为链。

现象：

- contracts 中已有：
  - D19 探针详情 `/assessment/probes/{id}`
  - D20 行为链详情 `/assessment/behavior/chains/{id}`
  - D21 OTel Span 详情 `/assessment/otel/spans/{id}`
  - D22 探针安装计划详情 `/assessment/probes/plans/{id}`
- 前端存在 detail drawer，但 D19-D22 是否支持直接 URL 打开、刷新保持上下文、返回上级列表仍需验证。
- 报告查看证据时存在跳转割裂体验：点击证据详情后离开报告，再回到报告需要重新找。

修复方向：

- D19-D22 优先做成“列表页 + 详情抽屉 + 可复制深链”的模式。
- 直接访问详情 URL 时：
  - 主区域仍显示对应父级列表或上下文摘要。
  - 右侧/弹层打开详情。
  - 关闭详情后回到父级路由。
- 报告预览中的证据详情不得整页跳走：
  - 证据详情在报告内抽屉打开。
  - 可从证据跳转到 finding、probe_event、behavior_chain、otel_span。
  - 提供“返回报告上下文”或不离开报告。
- 对所有详情抽屉增加统一字段：
  - 来源。
  - 时间。
  - 风险等级。
  - 证据 hash。
  - 脱敏说明。
  - 关联对象。

验收要求：

- 新增前端静态或 Playwright 测试，验证 D19-D22 路由存在对应 DOM。
- 从报告打开证据详情不改变主页面上下文。
- 详情抽屉中不展示明文 secret。

### G9. 探针安装计划安全证明不足

严重级别：P0  
影响：新增探针/hook 需求必须证明“不会影响智能体正常使用”。

现象：

- 当前已有 install plan dry-run。
- 测试主要验证生成代码能 compile。
- 尚未看到“真实/伪造 Codex/Hermes 配置 hash 前后一致”的测试。
- 尚未看到“未显式安装时不创建、不写入、不修改任何 agent 配置”的测试。

修复方向：

- 新增 fake Codex/Hermes home fixture：
  - fake config。
  - fake skills/plugin 目录。
  - fake MCP 配置。
- 运行 install plan dry-run：
  - 记录 config hash。
  - 调用 API。
  - 再次记录 hash。
  - 断言完全一致。
- install plan 返回：
  - 计划步骤。
  - 需要用户手工执行的命令。
  - 回滚步骤。
  - 影响范围。
  - 是否会修改文件：dry-run 必须 `false`。
  - 预计生成文件位置：必须在本项目 artifact 或用户指定导出目录，不得写入真实 agent 目录。

验收要求：

- 新增测试文件 `tests/test_v426_probe_install_safety.py`。
- dry-run 安装计划不修改任何 fake agent 文件。
- UI 探针安装向导明确显示“默认只读、未安装、未接入、不影响现有智能体”。

### G10. 本项目跳过策略需要形成回归证明

严重级别：P1  
影响：用户明确要求不要扫描 `F:/bigsinger/agent-scan-platform` 项目文档或代码。

现象：

- `src/assessment/scanning/scope.py` 已有本项目跳过策略。
- `tests/test_v425_observability_e2e.py` 有相关测试，但覆盖范围仍需扩充到新增扫描入口和 UI。

修复方向：

- 所有扫描入口统一调用同一套 scope policy：
  - 快速扫描 path 模式。
  - machine 模式资产枚举。
  - mcp 模式。
  - skill 模式。
  - probe/observability 测试事件分析。
- 如果用户选择本项目根目录：
  - UI 明确提示“本项目源码/文档默认跳过，仅扫描测试 fixture/测试 MCP/测试 Skill”。
  - API 返回 `skipped_paths` 和 `allowed_test_assets`。

验收要求：

- 新增测试覆盖：
  - path=`F:/bigsinger/agent-scan-platform` 时不扫描普通源码/文档。
  - path 指向本项目测试 fixture 时允许扫描。
  - 扫描结果包含跳过原因。

### G11. 文档和运维部署未完全同步 v4.2.5/v4.2.6

严重级别：P1  
影响：企业客户无法按文档独立跑通。

现象：

- `doc/USER_GUIDE.md`、`doc/OPERATIONS_DEPLOYMENT.md`、`doc/SPEC_VALIDATION.md` 已有 v4.2.5 增量。
- 但还缺少：
  - receiver 单独启动命令。
  - OTLP curl/PowerShell 样例。
  - 行为链重建样例。
  - 异常分析样例。
  - 探针安装计划安全说明。
  - 58 页完整性验收说明。
  - 当前已知限制。

修复方向：

- 更新 `doc/OPERATIONS_DEPLOYMENT.md`：
  - 本地 API 启动。
  - OTel receiver 启动。
  - 健康检查。
  - 数据库备份。
  - 日志/数据保留。
  - 升级回滚。
- 更新 `doc/USER_GUIDE.md`：
  - 探针管理。
  - OTel Explorer。
  - 行为链时间线。
  - 异常分析。
  - 报告内证据详情。
  - 探针安装计划 dry-run。
- 更新 `doc/SPEC_VALIDATION.md`：
  - v4.2.6 实际执行命令。
  - 完整测试结果。
  - 页面完整性结果。
  - 未覆盖项。

验收要求：

- 文档中的命令能在本机 PowerShell 直接运行。
- 文档不宣称未实现能力。
- 文档包含失败排查。

### G12. 企业级管理口保护仍需收敛

严重级别：P2  
影响：企业测评会关注 API 暴露面。

现象：

- 项目主要面向本地运行，但 API 涉及扫描结果、证据、探针事件、OTel 数据。
- 如果监听非 localhost 或被其他进程访问，需要最小保护。

修复方向：

- 保持默认监听 `127.0.0.1`。
- 增加本地管理口安全说明。
- 如果已有 token/auth 能力，确保文档覆盖；如果没有，至少增加：
  - `ASSESSMENT_BIND_HOST=127.0.0.1` 默认。
  - 启动日志提示。
  - 非 localhost 绑定必须显式配置。
  - CORS 默认限制。

验收要求：

- 运维文档明确默认暴露面。
- 健康检查不泄露敏感配置。
- OTel payload 查询默认脱敏。

## 5. v4.2.6 具体开发任务

### T01. 修复完整性矩阵和静态 fallback 一致性

目标：

- 58 页成为唯一真值。
- 不允许 seed fallback 和 runtime API 给出矛盾状态。

涉及文件：

- `src/assessment/contracts.py`
- `src/assessment/api/v1.py`
- `src/assessment/static/assessment/seed.json`
- `tests/test_api_contract.py`
- `tests/test_frontend_static.py`

实现要求：

1. 将 completeness 行数期望从硬编码 48 改为从 `PAGE_ROWS` 或 contract 生成器读取。
2. `seed.json` 中 completeness fallback 不得把未 E2E 验证的页面标为 `已验收`。
3. `completeness_rows()` 输出不应包含误导性的 `e2e=已覆盖`。
4. API runtime 状态仍以真实文档、契约、E2E 证据计算。
5. 加测试验证 runtime 和 seed 至少在以下字段上不冲突：
   - `id`
   - `route`
   - `prototype`
   - `spec`
   - `e2e`
   - `status`

完成标准：

- 旧两个失败测试修复。
- `python -m pytest tests/test_api_contract.py tests/test_frontend_static.py -q` 通过。
- `python -m pytest -q` 不再因 48/58 断言失败。

### T02. 补齐 P49-P54/D19-D22 文档和原型

目标：

- 10 个新页面从 `MISSING_DOC` 变成 `PASS`。

新增文件：

- `doc/agent_security_assessment_v4_1_full/specs/pages/P49_probes.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P50_observability.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P51_behavior_chains.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P52_behavior_anomalies.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P53_otel_explorer.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/P54_probe_install.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D19_probe_detail.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D20_behavior_chain_detail.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D21_otel_span_detail.md`
- `doc/agent_security_assessment_v4_1_full/specs/pages/D22_probe_install_plan_detail.md`
- 对应 `prototype/pages/*.html`

每个 spec 必须包含：

- 页面编号和名称。
- 路由。
- 目标用户和使用场景。
- 主 API。
- 数据来源。
- 关键交互。
- 空态、加载态、失败态。
- 安全与脱敏要求。
- 不影响已安装 Agent 的约束。
- E2E 验收点。

完成标准：

- `/api/v1/completeness?page_size=200` 中 `audit_passed=58`。
- 新页面 prototype/spec 均存在。
- 文档内容与真实 API 名称一致。

### T03. 建立页面级 E2E 证据映射

目标：

- 完整性矩阵的 E2E 状态有证据来源。

推荐新增文件：

- `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`

推荐结构：

```json
{
  "schema": "agent-security-e2e-manifest@4.2.6",
  "updated_at": "2026-07-09T00:00:00Z",
  "items": [
    {
      "page_id": "P49",
      "status": "PASS",
      "test_file": "tests/test_v426_observability_pages.py",
      "test_names": ["test_probe_page_routes_and_api_contract"],
      "command": "python -m pytest tests/test_v426_observability_pages.py -q",
      "assertions": [
        "GET /api/v1/probes returns persisted probe adapters",
        "POST /api/v1/probes/events redacts secrets",
        "probe detail can be opened from route"
      ]
    }
  ]
}
```

实现要求：

1. `/api/v1/completeness` 读取 manifest。
2. 只有 manifest 中 `status=PASS` 且测试文件存在时，页面才可显示 `e2e=PASS`。
3. manifest 中缺失的页面继续显示 `NOT_ASSERTED`。
4. `doc/SPEC_VALIDATION.md` 记录最近一次实际命令结果。

完成标准：

- P49-P54/D19-D22 至少有真实测试映射。
- 旧 48 页可以保持 `NOT_ASSERTED`，但不能被误标 PASS。
- `e2e_passed` 数量与 manifest PASS 数量一致。

### T04. 补齐 OTel receiver 真实接收链路

目标：

- 从 OTLP HTTP JSON 请求到数据库再到查询 API 的链路可验收。

涉及文件：

- `src/assessment/observability/receiver.py`
- `src/assessment/observability/normalizer.py`
- `src/assessment/observability/storage.py`
- `src/assessment/observability/api.py`
- `tests/test_v426_otel_receiver_ingestion.py`

测试必须覆盖：

1. `POST /v1/traces`
   - 输入 OTLP JSON。
   - 写入 `otel_span`。
   - 有 agent/session 属性时生成 `probe_event`。
   - 无 agent/session 属性时不生成污染性 `unknown` probe_event。
2. `POST /v1/logs`
   - 写入 `otel_log`。
   - body 脱敏。
   - 有 agent/session 属性时生成 `probe_event`。
3. `POST /v1/metrics`
   - 写入 `otel_metric_point`。
   - timestamp 为 ISO-8601 或可排序标准格式。
4. 查询 API：
   - `/api/v1/otel/spans`
   - `/api/v1/otel/logs`
   - `/api/v1/otel/metrics`

完成标准：

- `python -m pytest tests/test_v426_otel_receiver_ingestion.py -q` 通过。
- 数据库能看到 spans/logs/metrics。
- 测试 secret 不以明文出现在查询响应。

### T05. 修正 observability health 的真实语义

目标：

- 健康检查不再误导用户。

涉及文件：

- `src/assessment/observability/api.py`
- `doc/OPERATIONS_DEPLOYMENT.md`

实现要求：

1. `/api/v1/observability/health` 返回至少两个层次：
   - `platform_api`
   - `receiver`
2. 如果未探测独立 receiver，不得返回 `receiver.status=ok`。
3. 如果配置了本地 receiver 端点，可做短超时探测：
   - 成功：`status=ok`
   - 失败：`status=down`
   - 未探测：`status=unknown`
4. 返回数据库计数：
   - `total_probe_events`
   - `otel_spans`
   - `otel_logs`
   - `otel_metric_points`
   - `behavior_chains`
   - `behavior_anomalies`

完成标准：

- 无独立 receiver 运行时，health 不宣称 receiver ok。
- 独立 receiver 启动后，文档提供的健康检查可返回 ok。

### T06. OTel 数据规范化和 Trace 详情

目标：

- OTel Explorer 能查看结构化数据和 trace 详情。

涉及文件：

- `src/assessment/observability/storage.py`
- `src/assessment/observability/api.py`
- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`

实现要求：

1. attributes 入库前统一转 dict。
2. timestamp 统一转 ISO-8601 UTC。
3. 查询 API 返回结构化字段，不要求前端手动 parse JSON 字符串。
4. 新增：
   - `GET /api/v1/otel/traces/{trace_id}`
5. Trace 详情包含：
   - spans。
   - logs。
   - metrics。
   - related probe_events。
   - related behavior_chains。

完成标准：

- P53 OTel Explorer 能从 span 进入 trace 详情。
- D21 OTel Span 详情可直接打开。
- API 输出无明文 secret。

### T07. 行为链和异常规则幂等硬化

目标：

- 重复构建不会重复插入链路或异常。

涉及文件：

- `src/assessment/observability/chain_builder.py`
- `src/assessment/observability/anomaly_rules.py`
- `src/assessment/observability/storage.py`
- `tests/test_v426_behavior_anomaly_rules.py`

实现要求：

1. `behavior_anomaly` 引入稳定 dedupe key。
2. 重复运行 `/api/v1/behavior/chains` 时：
   - chain count 不重复增长。
   - anomaly count 不重复增长。
3. P0 规则逐条测试：
   - prompt injection。
   - secret in prompt。
   - sensitive read then network egress。
   - dangerous shell command。
   - MCP tool privilege escalation。
   - unexpected cross-agent handoff。
   - high volume tool calls。
   - policy bypass marker。
4. 规则证据必须脱敏。
5. `secret_like_detected` 在脱敏前计算，明文不落库。

完成标准：

- `python -m pytest tests/test_v426_behavior_anomaly_rules.py -q` 通过。
- 连续两次链构建不会增加重复异常。
- 所有规则都有 severity、confidence、recommendation。

### T08. 详情页和报告证据交互优化

目标：

- 减少割裂式跳转，报告、证据、行为链、OTel Span、探针详情能顺滑联动。

涉及文件：

- `src/assessment/static/assessment/app.js`
- `src/assessment/static/assessment/index.html`
- `src/assessment/static/assessment/styles.css`
- 可能涉及 API detail endpoints。

实现要求：

1. P49-P54 列表页的详情点击默认打开统一详情抽屉。
2. D19-D22 直接路由打开时显示父级上下文和详情抽屉。
3. 报告预览中点击证据：
   - 不离开报告页面。
   - 在报告内打开证据详情抽屉。
   - 可继续跳到关联 finding、behavior_chain、probe_event、otel_span。
4. 抽屉支持：
   - 关闭回到原上下文。
   - 复制深链。
   - 下载证据。
   - 展示脱敏说明。
5. 所有按钮在 API 失败时显示错误态，不静默失败。

完成标准：

- 新增前端测试或 Playwright smoke 覆盖：
  - 打开报告 -> 点击证据 -> 抽屉显示 -> 关闭后仍在报告。
  - 直接打开 `/assessment/behavior/chains/{id}` 能看到详情。
  - 直接打开 `/assessment/otel/spans/{id}` 能看到详情。

### T09. 探针安装计划安全验收

目标：

- 证明 dry-run 不影响已安装智能体。

涉及文件：

- `src/assessment/probes/codex/codex_probe_hook.py`
- `src/assessment/probes/hermes/hermes_probe_plugin.py`
- `src/assessment/observability/api.py`
- `tests/test_v426_probe_install_safety.py`

实现要求：

1. 使用 fake Codex/Hermes home 测试安装计划。
2. 调用 `/api/v1/probes/install-plan` 前后计算 fake config SHA-256。
3. 断言 dry-run 不写入、不删除、不移动任何 fake agent 文件。
4. 计划必须包含：
   - prerequisites。
   - generated_files。
   - manual_steps。
   - rollback_steps。
   - safety_notes。
   - mutates_installed_agents=false。
5. UI 不允许显示“已安装”除非有真实安装状态证据。

完成标准：

- dry-run 测试通过。
- 安装计划详情 D22 展示回滚步骤和安全边界。
- 文档明确默认不自动安装。

### T10. 本项目扫描跳过策略回归

目标：

- 满足用户明确要求：不要扫描本项目源码/文档。

涉及文件：

- `src/assessment/scanning/scope.py`
- 快速扫描相关 API。
- `tests/test_v426_scan_scope_policy.py`

实现要求：

1. 对 `F:/bigsinger/agent-scan-platform` 根路径扫描时，普通源码/文档被跳过。
2. 对本项目测试 fixture、测试 MCP、测试 Skill 路径扫描时允许。
3. 扫描结果中返回：
   - `skipped_paths`
   - `skip_reason`
   - `allowed_test_assets`
4. UI 在用户选择本项目根目录时显示清晰提示。

完成标准：

- 新增测试通过。
- 快速扫描不会把本项目自身文件作为风险样本污染结果。

### T11. 文档同步

目标：

- 企业客户能按文档独立启动、测试、验收。

必须更新：

- `doc/OPERATIONS_DEPLOYMENT.md`
- `doc/USER_GUIDE.md`
- `doc/SPEC_VALIDATION.md`

必须新增或补充内容：

1. OTel receiver 本地启动命令。
2. PowerShell 发送 traces/logs/metrics 样例。
3. 探针事件上报样例。
4. 行为链重建样例。
5. 异常查看样例。
6. 报告内证据详情交互说明。
7. 探针安装计划 dry-run 安全说明。
8. 当前不交付能力和限制。
9. 完整性矩阵 58 页验收说明。
10. 常见失败排查。

完成标准：

- 文档命令可直接复制到 PowerShell 执行。
- 文档与真实 API route 一致。
- 文档不宣称未通过 E2E 的页面“已验收”。

### T12. 一键验收脚本

目标：

- 三方 AI 完成开发后，用户和验收方可以一条命令跑核心验收。

推荐新增：

- `tools/verify_v426_acceptance.ps1`

脚本应执行：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
python -m pytest tests\test_v426_otel_receiver_ingestion.py -q
python -m pytest tests\test_v426_behavior_anomaly_rules.py -q
python -m pytest tests\test_v426_probe_install_safety.py -q
python -m pytest tests\test_v426_scan_scope_policy.py -q
python -m pytest -q
```

脚本要求：

- 失败时停止并返回非 0 exit code。
- 输出每一步命令。
- 不修改真实 Codex/Hermes 配置。
- 不启动真实 stdio MCP。
- 使用临时测试数据库或隔离测试数据，避免污染本机正式 SQLite。

完成标准：

- `powershell -ExecutionPolicy Bypass -File tools\verify_v426_acceptance.ps1` 通过。
- 脚本输出纳入 `doc/SPEC_VALIDATION.md`。

## 6. 验收命令

第三方 AI 完成 v4.2.6 后，至少必须执行以下命令并把结果写入 `doc/SPEC_VALIDATION.md`。

基础静态检查：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
```

新增专项测试：

```powershell
python -m pytest tests\test_v426_otel_receiver_ingestion.py -q
python -m pytest tests\test_v426_behavior_anomaly_rules.py -q
python -m pytest tests\test_v426_probe_install_safety.py -q
python -m pytest tests\test_v426_scan_scope_policy.py -q
```

完整测试：

```powershell
python -m pytest -q
```

完整性矩阵检查：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
print(payload['summary'])
for row in payload['items']:
    if row['id'] in {'P49','P50','P51','P52','P53','P54','D19','D20','D21','D22'}:
        print(row['id'], row['audit'], row['contract'], row['e2e'], row['status'])
'@ | python -
```

预期：

- `pages=58`
- `audit_passed=58`
- `contract_passed=58`
- `e2e_passed` 与 manifest PASS 数量一致。
- P49-P54/D19-D22 不再是 `MISSING_DOC`。
- 没有被真实测试覆盖的页面仍是 `NOT_ASSERTED`，不得伪造 PASS。

OTel receiver ingestion smoke：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.observability.receiver import create_receiver_app

client = TestClient(create_receiver_app())
resp = client.post('/v1/traces', json={
    'resourceSpans': [{
        'resource': {
            'attributes': [
                {'key': 'service.name', 'value': {'stringValue': 'codex'}}
            ]
        },
        'scopeSpans': [{
            'spans': [{
                'traceId': '11111111111111111111111111111111',
                'spanId': '2222222222222222',
                'name': 'agent.tool.call',
                'startTimeUnixNano': '1780000000000000000',
                'endTimeUnixNano': '1780000001000000000',
                'attributes': [
                    {'key': 'agent.name', 'value': {'stringValue': 'codex'}},
                    {'key': 'session.id', 'value': {'stringValue': 'v426-smoke'}},
                    {'key': 'tool.name', 'value': {'stringValue': 'shell'}}
                ]
            }]
        }]
    }]
})
print(resp.status_code, resp.text)
'@ | python -
```

预期：

- 返回 `200`。
- 至少 accepted span 数量为 1。
- 后续 `/api/v1/otel/spans` 可查询到 span。
- 如果属性中包含 secret，查询响应不得出现明文。

## 7. 验收拒绝条件

出现以下任一情况，v4.2.6 不能通过验收：

1. `python -m pytest -q` 仍失败。
2. `/api/v1/completeness` 仍显示 P49-P54/D19-D22 `MISSING_DOC`。
3. `seed.json` 或离线页面把未 E2E 验证的页面显示为“已验收”。
4. `/api/v1/observability/health` 在 receiver 未启动时仍返回 receiver ok。
5. OTel traces/logs/metrics 没有真实 ingestion 测试。
6. 连续两次行为链重建会重复插入相同异常。
7. 异常证据、probe event、OTel 查询中出现明文 secret。
8. 探针安装计划 dry-run 修改了 Codex/Hermes 配置或测试 fixture 配置。
9. 快速扫描把 `F:/bigsinger/agent-scan-platform` 普通源码/文档作为被测资产扫描。
10. 报告证据详情仍必须整页跳走，且无法顺滑回到报告上下文。
11. 文档中的命令无法在 PowerShell 本地执行。
12. 完成开发后未更新文档或未提交 Git。

## 8. 建议实施顺序

1. 先修复当前全量测试失败和 completeness/seed 一致性。
2. 补齐 P49-P54/D19-D22 文档和原型，让 audit 达到 58/58。
3. 建立 E2E manifest，让矩阵有证据映射。
4. 补 OTel receiver ingestion 测试和 health 真实语义。
5. 做行为链/异常规则幂等与 8 条 P0 规则测试。
6. 做 D19-D22 和报告证据抽屉体验优化。
7. 做探针安装计划 dry-run 安全验收。
8. 做本项目扫描跳过策略回归。
9. 更新运维部署、使用帮助、验证文档。
10. 运行一键验收脚本和完整 pytest，最后提交 Git。

## 9. 交付物清单

代码交付：

- 完整性矩阵与 seed fallback 一致性修复。
- OTel receiver ingestion 真实链路。
- OTel 数据规范化和 trace detail。
- 行为链/异常规则幂等硬化。
- D19-D22 详情路由和报告证据抽屉体验。
- 探针安装计划 dry-run 安全验证。
- 本项目扫描跳过策略回归。

测试交付：

- `tests/test_v426_otel_receiver_ingestion.py`
- `tests/test_v426_behavior_anomaly_rules.py`
- `tests/test_v426_probe_install_safety.py`
- `tests/test_v426_scan_scope_policy.py`
- `tests/test_v426_observability_pages.py`
- 必要时更新旧测试，移除 48 页硬编码。

文档交付：

- P49-P54/D19-D22 spec 文件。
- P49-P54/D19-D22 prototype 文件。
- `doc/agent_security_assessment_v4_1_full/e2e_manifest.json`
- 更新 `doc/OPERATIONS_DEPLOYMENT.md`
- 更新 `doc/USER_GUIDE.md`
- 更新 `doc/SPEC_VALIDATION.md`
- 新增或更新一键验收脚本说明。

验收交付：

- `python -m pytest -q` 完整通过。
- `tools/verify_v426_acceptance.ps1` 通过。
- `/api/v1/completeness` 输出 58 页一致状态。
- Git 提交包含代码、测试、文档和验证记录。

## 10. 给第三方 AI 的执行约束

1. 开发前必须先运行 `git status --short`，确认用户或其他 AI 的未提交改动。
2. 不得回退用户已有改动。
3. 不得用 demo 数据替代真实 API。
4. 不得为了测试通过把 E2E 状态硬编码为 PASS。
5. 所有新增 API 必须有测试。
6. 所有新增 UI 按钮必须调用真实 API，并处理 loading/error/empty 状态。
7. 所有涉及 secret、token、password、api key、cookie 的字段必须脱敏。
8. 所有涉及 Codex/Hermes 的操作默认 dry-run。
9. 完成后必须更新文档并提交 Git。
