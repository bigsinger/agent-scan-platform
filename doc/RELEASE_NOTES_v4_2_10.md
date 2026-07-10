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
| Probe | Hermes/Codex 能力检测改为诚实状态；Codex 不推测 hook 能力，Hermes fake-home 生命周期可回滚 |
| OTel | Receiver 增加 loopback/token 边界、JSON-only、体积限制、批量限制、ID 校验、幂等与 retention |
| Finding | 顶层 Finding 按逻辑风险 rollup，命中明细写入 `finding_instance` |
| 异步扫描 | `async_scan=true` 返回 QUEUED task/job，不再伪装完成 |
| 发布包 | 生成 wheel/sdist/SBOM/OpenAPI/manifest/zip，可离线 SHA 校验 |

## 验收命令

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v4210_enterprise_release.ps1
```

## 安全承诺

- 不保存原始 Secret。
- 不自动修改 Codex/Hermes 配置。
- 不启动 stdio MCP。
- 不停止非本产品拥有的进程。
- 默认只监听 `127.0.0.1`。
