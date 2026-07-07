# P05 Agent 资产 · 页面 SPEC

> 文件：`prototype/pages/P05_agents.html`  
> Route：`/assessment/agents`  
> 页面分组：资产  
> 页面类型：asset_list

## 1. 页面目标

统一查看 OpenClaw、Hermes、Claude Code、Codex 和 agent-scan 兼容 Agent。

该页面必须作为独立 HTML 原型存在，并且正式开发时必须保留独立路由、加载状态、空状态、错误状态、权限/禁用状态和审计事件映射。不得只在总览页中以局部卡片替代。

## 2. 页面区域

- 搜索筛选
- 资产表
- 组件计数
- 最近测评
- 适配器覆盖
- 资产详情

## 3. 用户动作

- 查看详情
- 重新探测
- 创建测评
- 生成 ABOM
- 归档

每个动作必须满足：

1. 前端有明确按钮、菜单或链接入口。
2. 点击后有 loading 或禁用态。
3. 成功后刷新当前视图或跳转到明确页面。
4. 失败时展示错误信息、`correlation_id` 和重试入口。
5. 写操作必须记录 `audit_event`。

## 4. API 契约

- `GET /api/v1/agents`
- `GET /api/v1/agents/{id}`
- `POST /api/v1/agents/{id}/probe`

接口返回必须统一包装：

```json
{
  "code": 0,
  "message": "ok",
  "data": {},
  "correlation_id": "req_xxx"
}
```

错误返回必须包含：

```json
{
  "code": 422,
  "message": "validation failed",
  "validation_errors": [{"field":"target.path","message":"路径不存在或无权限"}],
  "correlation_id": "req_xxx"
}
```

## 5. 主要实体

`agent_instance, component, adapter`

当前本地实现中，Agent 资产页的搜索框、Agent 类型、支持级别和探测状态下拉直接过滤当前 `agentAssets` 运行态数据。筛选字段覆盖名称、ID、路径、Adapter、版本、支持级别、探测状态和安装来源；筛选只改变页面视图，不触发重新探测、不写 SQLite、不启动或修改已安装 Agent。

正式实现时，实体字段应与 SQLite 表、Pydantic Schema、API 响应和前端字段保持一致。页面不得使用未定义字段。

## 6. 必须覆盖状态

- 可测评
- 需重探测
- 部分支持
- 归档

除此之外，所有页面还必须覆盖：

- loading；
- empty；
- success；
- partial_success；
- failed；
- forbidden；
- disabled_by_host_platform；
- sqlite_readonly；
- offline_mode。

## 7. 前端原型要求

- 原型文件：`prototype/pages/P05_agents.html`。
- 必须通过本地 `../assets/vendor/vue.global.prod.js` 加载 Vue，不得依赖公网 CDN。
- 必须保留 `boot-status` 启动提示和错误兜底。
- 必须有本页专属标题、Route、API、主要实体、状态覆盖说明。
- 本页所有按钮必须可点击并给出原型反馈，不允许点击无响应。
- 本页链接到其他详情页时必须指向真实存在的 HTML 文件。

## 8. 后端实现要求

- 使用 FastAPI Router 独立注册本页相关 API。
- 所有写操作使用事务，失败回滚。
- 长任务不得在请求线程中直接执行；必须创建 task 后由本地任务执行器处理。
- 查询接口必须支持分页、排序和筛选。
- 所有返回数据必须经过脱敏，尤其是环境变量、Token、Authorization Header、绝对路径和命令参数。

## 9. SQLite 数据要求

本页至少涉及实体：`agent_instance, component, adapter`。

开发时必须确认：

1. 表字段可支持页面展示的全部列。
2. 列表筛选字段已建立必要索引。
3. 详情页通过 ID 查询时不存在 N+1 查询。
4. 删除或归档操作不得物理删除证据，除非证据保留策略明确允许。

## 10. 审计事件

建议事件命名：

- `P05_agents.view`
- `P05_agents.create`
- `P05_agents.update`
- `P05_agents.run`
- `P05_agents.cancel`
- `P05_agents.export`
- `P05_agents.error`

每个事件必须包含：`actor`、`tenant_id`、`assessment_id`、`target_id`、`correlation_id`、`created_at`、`payload_redacted`。

## 11. 验收清单

- [ ] 页面可从 `prototype/index.html` 进入。
- [ ] 页面可本地双击打开，无公网依赖。
- [ ] 页面 Console 无 Error。
- [ ] 页面不存在空白首屏。
- [ ] 页面主按钮、详情按钮、弹窗、抽屉均可交互。
- [ ] 页面中展示的 API、实体、状态与本 SPEC 一致。
- [ ] E2E 覆盖成功、空状态、API 失败、权限不足。
- [ ] AI 编码代理未删除错误兜底、未引入 CDN、未新增未定义字段。

## 12. AI 开发特别约束

AI 编码代理实现本页时不得：

1. 将本页面合并到其他页面导致路由缺失；
2. 删除原型中的状态面板、API 提示、错误兜底；
3. 使用模拟字段替代后端 Schema；
4. 默认允许启动 stdio MCP Server；
5. 省略审计事件；
6. 将敏感值写入日志、证据或报告；
7. 只实现正常路径，不实现失败路径。
