# Agent 安全测评能力模块 V4.1

本仓库按 `doc/agent_security_assessment_v4_1_full` 的全页面原型与 SPEC 实现为可独立运行的本地模块：

- FastAPI REST/SSE API，Base Path 为 `/api/v1`。
- SQLite 本地数据库，默认位置 `data/db/app.db`。
- 正式前端静态资源：`/static/vendor/vue.global.prod.js`、`/static/assessment/app.js`、`/static/assessment/style.css`。
- 48 个页面/详情视图入口与 122 个 V4.1 SPEC API 契约均可访问，并注入 FastAPI OpenAPI。
- 前端不依赖 CDN，Vue 已 vendoring 到本地并登记 `vendor-manifest.json`。
- 本地只读扫描：Agent 发现、MCP 配置解析、Skill 扫描、规则命中、脱敏证据、HTML/JSON 报告。
- stdio MCP Server 默认只生成审批记录，不自动启动。
- 运行时页面优先读取 SQLite 真实扫描记录；seed 数据仅作为无后端/无数据时的离线兜底。
- 只读 Guard 防御监测：对已发现 Agent 配置、MCP、Skill 做哈希基线与变化检测，只写本系统 SQLite，不修改已安装 Agent。

文档：

- 运维部署：`doc/OPERATIONS_DEPLOYMENT.md`
- 使用帮助：`doc/USER_GUIDE.md`

运行：

```powershell
$env:PYTHONPATH='src'
python -m uvicorn assessment.main:app --reload --host 127.0.0.1 --port 8000
```

打开：

```text
http://127.0.0.1:8000/assessment
```

验证：

```powershell
$env:PYTHONPATH='src'
python tools/check_frontend_offline.py --html src/assessment/static/assessment/index.html --expect-pages 48
pytest
```

本机快速扫描：

```powershell
$body = @{
  mode = "machine"
  adapter = "自动识别"
  max_files = 500
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/quick-scans -Body $body -ContentType "application/json"
```

回归样本快速扫描：

```powershell
$body = @{
  mode = "path"
  target_path = "tests\fixtures\sample_agent_project"
  adapter = "Codex"
  max_files = 200
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/quick-scans -Body $body -ContentType "application/json"
```

本机只读防御检查：

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/guard/check
Invoke-RestMethod http://127.0.0.1:8000/api/v1/guard/status
```

报告与 SQLite 运维：

```powershell
$report = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/reports -Body (@{ type = "Standard" } | ConvertTo-Json) -ContentType "application/json"
Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/v1/reports/$($report.report.id)/download" -OutFile report.html

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/sqlite/integrity-check
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/sqlite/backup
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/sqlite/checkpoint
```

能力管理操作：

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/scanners/scanner.local-analysis/self-test
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/rules/SECRET-KEY-001/test -Body (@{ sample = "sk-test-value" } | ConvertTo-Json) -ContentType "application/json"
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/schedules -Body (@{ name = "本机变化扫描"; type = "本机发现"; status = "ACTIVE" } | ConvertTo-Json) -ContentType "application/json"
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/integrations/runtime-platform/test
Invoke-RestMethod -Method Put -Uri http://127.0.0.1:8000/api/v1/settings -Body (@{ default_profile = "standard-complete"; timezone = "Asia/Shanghai" } | ConvertTo-Json) -ContentType "application/json"
```
