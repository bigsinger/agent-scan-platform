# V4.1 全量开发总规范

## 1. 本次交付范围

本包将 V4.1 原先的单页原型拆分为 **48 个独立页面/详情页**。每个页面均包含：

- 独立 HTML 原型；
- 独立页面 SPEC；
- 独立 Route；
- API、实体、状态、审计事件和验收清单。

## 2. 技术栈

- 后端：Python 3.12 + FastAPI + Pydantic + SQLAlchemy 2.x。
- 数据库：SQLite 3，WAL 模式。
- 前端：原生 HTML/CSS/JavaScript + Vue 3 Global Build。
- 原型：允许本地 Vue vendoring；禁止运行时使用外网 CDN。
- 任务：本地 asyncio + multiprocessing spawn + subprocess。
- 报告：Jinja2 HTML；Playwright PDF 可选。

## 3. 与现有运行时防护平台关系

本模块不是独立企业平台。账号、登录、IAM、主审计、全局报告归档、策略中心等能力由现有 Agent 运行时防护平台承载。本模块负责：

1. Agent/MCP/Skill/ABOM 发现；
2. agent-scan 本地适配；
3. Prompt/MCP/Skill/SCA/红队测评；
4. 风险、证据、攻击路径、报告和复测核心能力；
5. 通过集成接口将资产、风险、报告和策略建议回写主平台。

## 4. AI 编码代理开发顺序

1. 先实现 SQLite schema 和 Pydantic schema；
2. 再实现 API 契约；
3. 再实现扫描器插件和 agent-scan bridge；
4. 再实现页面路由与 Vue 前端；
5. 最后实现报告、复测和平台集成。

不得先做 UI 再反推后端字段。

## 5. 禁止事项

- 禁止删除任一页面或将页面合并导致 Route 缺失；
- 禁止引入 Go、Redis、PostgreSQL、MinIO、Celery、RabbitMQ、Kafka；
- 禁止依赖 unpkg、jsdelivr、cdnjs、Google Fonts 等公网资源；
- 禁止默认静默启动 stdio MCP Server；
- 禁止将 Snyk 云分析作为私有化必需依赖；
- 禁止将 Token、Authorization、Cookie、绝对路径明文写入日志或报告；
- 禁止只有正常路径，没有失败路径和空状态。

## 6. 验收方式

- 打开 `prototype/index.html`，确认所有页面入口可达。
- 执行链接完整性检查，所有 `prototype/pages/*.html` 和 `specs/pages/*.md` 存在。
- 断网打开任一页面，页面应正常渲染。
- Console 不得出现 Error。
- 所有页面应展示 Route、API、实体和状态覆盖。
