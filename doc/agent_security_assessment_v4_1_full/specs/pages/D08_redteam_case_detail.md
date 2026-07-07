# D08 红队用例详情 · 页面 SPEC

> 文件：`prototype/pages/D08_redteam_case_detail.html`  
> Route：`/assessment/redteam-cases/{id}`  
> 页面分组：详情页  
> 页面类型：case_detail

## 1. 页面目标

细化单个红队用例的变量、步骤、多轮对话、判定规则、适用 Agent 和安全授权。

该页面必须作为独立 HTML 原型存在，并且正式开发时必须保留独立路由、加载状态、空状态、错误状态、权限/禁用状态和审计事件映射。不得只在总览页中以局部卡片替代。

当前正式应用实现为 `/assessment/redteam-cases/{id}` 深链页面 `case-detail`，进入页面后读取 `GET /api/v1/redteam-cases/{id}`，并复用 `POST /api/v1/redteam-cases/{id}/validate` 与 `/dry-run` 完成校验和本地 deterministic dry-run。页面不得展示固定样例变量；dry-run 不调用外部模型、不启动 MCP Server 或真实 Tool，不修改已安装 Agent。

## 2. 页面区域

- 元信息
- 变量
- Prompt 步骤
- 判定器
- 示例输出
- 安全限制
- 测试历史

## 3. 用户动作

- 试运行
- 复制
- 编辑
- 禁用
- 加入模板

每个动作必须满足：

1. 前端有明确按钮、菜单或链接入口。
2. 点击后有 loading 或禁用态。
3. 成功后刷新当前视图或跳转到明确页面。
4. 失败时展示错误信息、`correlation_id` 和重试入口。
5. 写操作必须记录 `audit_event`。

## 4. API 契约

- `GET /api/v1/redteam-cases/{id}`
- `POST /api/v1/redteam-cases/{id}/dry-run`

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

`redteam_case, payload_template, judge_rule`

正式实现时，实体字段应与 SQLite 表、Pydantic Schema、API 响应和前端字段保持一致。页面不得使用未定义字段。

## 6. 必须覆盖状态

- 草稿
- 可运行
- 危险需授权
- 判定失败

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

- 原型文件：`prototype/pages/D08_redteam_case_detail.html`。
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

本页至少涉及实体：`redteam_case, payload_template, judge_rule`。

开发时必须确认：

1. 表字段可支持页面展示的全部列。
2. 列表筛选字段已建立必要索引。
3. 详情页通过 ID 查询时不存在 N+1 查询。
4. 删除或归档操作不得物理删除证据，除非证据保留策略明确允许。

## 10. 审计事件

建议事件命名：

- `D08_redteam_case_detail.view`
- `D08_redteam_case_detail.create`
- `D08_redteam_case_detail.update`
- `D08_redteam_case_detail.run`
- `D08_redteam_case_detail.cancel`
- `D08_redteam_case_detail.export`
- `D08_redteam_case_detail.error`

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
