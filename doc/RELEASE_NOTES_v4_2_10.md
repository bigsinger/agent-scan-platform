# Release Notes v4.2.10

## Enterprise Release Gate

v4.2.10 将 v4.2.9 的最终交付闭环升级为企业发布门禁：验收结果必须绑定当前 commit、真实浏览器截图和测试结果，不能再依赖手工 PASS 标记。

## 关键变化

| 领域 | 变化 |
|---|---|
| E2E 完整性 | `e2e_manifest.json` 只声明映射，`latest-e2e-result.json` 绑定当前 commit、测试名和截图 SHA |
| 浏览器验收 | 新增真实 Chromium Playwright 旅程，检查 console error、page error、外网请求和 PNG 截图 |
| 敏感数据 | 新增 `SensitiveDataGuard`，统一 SQLite、artifact、audit、probe/OTel 的脱敏与持久化守门 |
| 服务启停 | `start_services.ps1` / `stop_services.ps1` 改为 PID manifest 所有权模型，不再按端口杀任意进程 |
| Probe | Codex 保持 `DRY_RUN_ONLY`；Hermes 交付真实 user plugin、计划 ID 二次确认、备份、合成自测、禁用/修复/卸载/回滚和 UI/API 生命周期 |
| OTel | Receiver 增加 loopback/token 边界、JSON-only、体积限制、批量限制、ID 校验、幂等与 retention |
| Finding | 顶层 Finding 按逻辑风险 rollup，命中明细写入 `finding_instance` |
| 扫描与状态机 | machine 默认 HTTP 202；有界 worker 持久化 Task/Job/Process/Event，支持取消、重试、中断恢复，以及无变化文件分析/Evidence 复用 |
| 数据迁移与维护 | 新增 `001`-`003` 事务迁移、校验和漂移阻断、升级前备份、retention 计划绑定、artifact 完整性和引用感知 GC |
| API 安全 | 未知路由统一 `404 ROUTE_NOT_FOUND`；请求关联 ID 贯穿审计；请求体、解压数据和 artifact 下载均有实际字节上限 |
| 前端与交互 | API/runtime 状态拆入 `runtime.js`；本机发现类型化展示；报告风险返回上下文；桌面/移动端布局和可访问名称进入浏览器门禁 |
| 发布包 | 生成 wheel/sdist/SBOM/OpenAPI/迁移清单/依赖漏洞审计/manifest/zip，可离线 SHA 与全新 venv 校验 |
| 本机门禁 | 真实发现当前机器 Codex/Hermes，并对发现配置做有界只读扫描，前后 Hash 必须一致 |
| Probe/OTel 脱敏 | 事件解析、发送、失败缓冲、OTel normalize 和 SQLite 入库均禁止明文 Secret；raw capture API 被拒绝 |

## 回归快照

提交前隔离回归结果为：非浏览器 `209 passed`（含 58 页 manifest 引用文件/函数存在性契约），真实 Chromium 企业旅程 `8 passed`。最终发布结论仍必须由当前提交执行一键门禁后生成的 JUnit、PNG、commit 绑定结果、敏感数据审计和交付包 manifest 决定，不能引用本段文字替代机器证据。

## 验收命令

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v4210_enterprise_release.ps1
```

## 安全承诺

- 不保存原始 Secret。
- 不自动修改 Codex/Hermes 配置。
- Hermes 只有在用户输入精确 `plan_id` 并确认配置变更后才安装 observe-only plugin；该操作先备份并可回滚。
- 不启动 stdio MCP。
- 不停止非本产品拥有的进程。
- 默认只监听 `127.0.0.1`。
