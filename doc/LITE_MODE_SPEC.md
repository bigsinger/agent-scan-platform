# Agent 安全检查轻量模式 SPEC

> 状态：已实现  
> 适用版本：v4.2.10 lite-first 增量  
> 默认入口：`http://127.0.0.1:8000/assessment`  
> 专业入口：`http://127.0.0.1:8000/assessment/advanced`

## 1. 背景与目标

平台已经具备本机发现、扫描任务、Finding、Evidence、报告、Guard、Probe、OTel、调度、集成和运维能力，但将全部能力同时暴露给首次使用者会产生明显认知负担。轻量模式不删除既有专业能力，而是把默认产品收敛成一条可立即使用的本机检查路径。

本增量的目标只有四项：

1. 用户打开页面后无需理解模板、规则包、执行中心或 OTel 即可开始检查。
2. 一次点击完成本机 Agent 发现、只读静态扫描、风险摘要和报告生成。
3. 默认运行只需要 FastAPI 主平台和 SQLite，不要求启动 OTel Receiver。
4. 保持现有专业工作台、API、SQLite 数据和企业安全边界不变。

## 2. 产品范围

### 2.1 默认轻量模式

轻量模式只提供以下用户功能：

| 功能 | 用户动作 | 真实能力 |
| --- | --- | --- |
| 一键检查 | 点击“开始检查” | 当前用户本机发现 + `machine` 只读扫描 + Task 轮询 + Finding/Report 展示 |
| 仅发现资产 | 点击“仅发现资产” | 发现 Agent、配置、MCP、Skill，不启动 Agent/MCP |
| 结果摘要 | 扫描完成后自动展示 | P0/P1/P2/其他、文件数、证据数、前 10 条真实 Finding |
| 查看报告 | 点击“查看报告” | 打开本次扫描生成的本地 HTML 报告 |
| 最近记录 | 页面自动读取 | 最近 5 次 SQLite 扫描记录 |
| 专业模式 | 点击“专业模式” | 进入原完整工作台 |

轻量快检固定使用：

- `scope=current-user`
- `mode=machine`
- `execution_mode=readonly`
- `remote_analysis=false`
- `max_files=150`
- 不启动 Agent runtime
- 不启动 stdio MCP
- 不修改已安装 Agent 配置

当发现 stdio MCP 时，后台任务可以保持 `WAITING_CONSENT` 真实状态；轻量页按“静态检查完成”展示，因为轻量流程只承诺配置静态分析，不提供 MCP 启动审批。原始任务状态和审批操作仍在专业模式中可见。

### 2.2 专业模式

以下能力不进入默认流程，但继续保留在 `/assessment/advanced` 和原专业路由：

- 指定目录或单个 MCP 扫描
- 完整测评向导与模板
- MCP 启动审批
- Skill 专项扫描
- 动态红队 dry-run
- Guard、沙箱和执行中心
- Probe、OTel、行为链和异常分析
- 攻击路径、复测、规则、扫描器、调度和集成
- SQLite 维护、许可证、完整性矩阵和 API 调试

本增量禁止删除这些 API、表、制品或历史数据，也禁止复制一套轻量数据库。

## 3. 页面与交互

### 3.1 默认入口

`GET /` 和 `GET /assessment` 返回独立的 `lite.html`。该页面使用原生 HTML/CSS/JavaScript，不加载 Vue、`seed.js` 或 `/api/v1/bootstrap`。

首次加载只请求：

1. `GET /api/v1/version`
2. `GET /api/v1/quick-scans/recent?page_size=5`

只有用户点击操作后才请求发现和扫描接口。

### 3.2 一键检查状态

```text
READY
  -> DISCOVERING
  -> DISCOVERED
  -> QUEUED / RUNNING
  -> COMPLETED / PARTIAL_COMPLETED / WAITING_CONSENT
  -> RESULT
```

页面必须展示当前阶段、进度、耗时和错误。扫描任务关闭页面后仍由后台状态机继续执行；重新打开页面可从最近记录查看结果。

### 3.3 资产展示

轻量页只展示顶层 Agent，不把数百个 Skill 直接铺到首屏。每个 Agent 展示：

- 名称
- 类型/Adapter
- 版本，没有则显示 `-`
- 脱敏路径
- 发现状态

配置、MCP、Skill 只展示数量；详细列表进入专业模式查看。

### 3.4 结果展示

结果来源必须是当前 Assessment 的 SQLite/Report 快照，不使用 seed 或固定数字。Finding 列表先按 `assessment_id` 从 API 结果过滤；历史 Finding 超过分页上限时，从本次 Report snapshot 回读，避免误显示空结果。

## 4. 运行模式

### 4.1 轻量启动

```powershell
powershell -ExecutionPolicy Bypass -File .\start_services.ps1 -Lite
```

轻量启动只占用 `127.0.0.1:8000`。`data/run/services.json` 必须记录：

```json
{"mode":"lite","services":[{"name":"main","listen_port":8000}]}
```

### 4.2 完整启动

```powershell
powershell -ExecutionPolicy Bypass -File .\start_services.ps1
```

完整启动继续运行主平台和 `127.0.0.1:4318` OTel Receiver。两种模式使用相同 SQLite、API 和安全边界。

## 5. 验收条件

### 5.1 功能验收

1. `/assessment` 返回轻量页，且不加载 Vue、seed 或 bootstrap。
2. `/assessment/advanced` 和所有原专业路由继续返回完整工作台。
3. “仅发现资产”返回真实本机 Agent，展示名称、版本、路径和状态。
4. “开始检查”能生成真实 Assessment、Finding、Evidence 和 Report。
5. 异步任务可轮询到终态，结果页至少显示风险摘要和报告入口。
6. 最近记录来自 `/api/v1/quick-scans/recent`，空库显示空态。

### 5.2 安全验收

1. Codex/Hermes 配置扫描前后 SHA-256 一致。
2. `mutates_installed_agents=false`。
3. `remote_analysis=false`。
4. 不产生外部网络请求。
5. 不启动 Agent runtime 或 stdio MCP。
6. Lite 启动不监听 4318，且停止脚本仍只处理 manifest 中本产品拥有的进程。

### 5.3 前端验收

1. 1366/1440 桌面和 390px 移动端无根级横向溢出。
2. 页面无 JavaScript console error 或 page error。
3. 主按钮、专业模式链接、资产卡片、风险列表和报告链接可操作。
4. 移动端按钮不截断，Agent 路径使用省略显示，不撑宽页面。

## 6. 定向测试

```powershell
node --check src\assessment\static\assessment\lite.js
python -m pytest tests\test_lite_mode.py tests\test_v4210_service_script_safety.py -q
python -m pytest tests\browser\test_enterprise_journeys.py::test_j01_first_start_empty_dashboard -q
```

完整发布前仍可运行原企业门禁；轻量模式不会降低或替换专业模式的既有验收要求。
