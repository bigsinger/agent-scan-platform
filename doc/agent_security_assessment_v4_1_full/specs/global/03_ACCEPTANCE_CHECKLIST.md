# 全量验收清单

## 文件数量

- HTML 页面：48 个，位于 `prototype/pages/`。
- 页面 SPEC：48 个，位于 `specs/pages/`。
- 全局 SPEC：位于 `specs/global/`。

## 前端验收

- [ ] `prototype/index.html` 可打开。
- [ ] 所有页面链接存在。
- [ ] 所有页面无 CDN 依赖。
- [ ] 所有页面本地 Vue 加载成功。
- [ ] 所有页面有 `boot-status` 兜底。
- [ ] 所有页面至少有一个按钮可交互。
- [ ] 所有页面有 API、实体、状态覆盖说明。

## 后端验收

- [ ] OpenAPI 包含全部页面 API。
- [ ] SQLite schema 支持全部页面展示字段。
- [ ] 任务状态机支持等待 MCP 审批、取消、重试、部分完成。
- [ ] agent-scan bridge 可在离线模式运行。
- [ ] Snyk 云分析为可选连接器，不是默认依赖。

## AI 开发验收

- [ ] AI 未删除页面。
- [ ] AI 未引入 Go 或外部队列。
- [ ] AI 未默认启动 stdio MCP。
- [ ] AI 未省略错误态和空状态。
