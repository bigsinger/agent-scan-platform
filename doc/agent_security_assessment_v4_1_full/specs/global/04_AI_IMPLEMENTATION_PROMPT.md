# 给 AI 编码代理的一次性开发提示词

你将实现 Agent 安全测评能力模块 V4.1。请严格读取本目录：

1. `specs/global/00_GLOBAL_SPEC.md`
2. `specs/PAGE_INDEX.md`
3. `specs/pages/*.md`
4. `prototype/pages/*.html`

必须实现全部 48 个页面，不得只实现主页。

开发约束：

- 后端只用 Python + FastAPI。
- 数据库只用 SQLite。
- 前端用原生 HTML/CSS/JavaScript + Vue，本地静态资源，不使用 CDN。
- 不使用 Go、Redis、Celery、PostgreSQL、MinIO。
- 不默认启动 stdio MCP Server，必须审批。
- 所有页面必须有加载、空、成功、失败、无权限/禁用状态。
- 所有写操作必须审计。
- 所有敏感字段必须脱敏。

开发完成后，必须提供：

- FastAPI 服务启动命令；
- SQLite 初始化脚本；
- OpenAPI 文档；
- 前端访问地址；
- 单元测试；
- E2E 验收结果；
- 页面实现覆盖矩阵。
