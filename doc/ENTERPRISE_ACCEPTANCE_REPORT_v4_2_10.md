# Enterprise Acceptance Report v4.2.10

## 结论来源

本报告对应 `agent_security_assessment_v4_2_10_enterprise_release_gate_spec.md`。Markdown 不作为 PASS 来源；最终结论只取 `tools/verify_v4210_enterprise_release.ps1` 为当前 commit 生成的 `latest-e2e-result.json`、`live-machine-readonly.json`、JUnit XML、浏览器 PNG 和交付包 manifest。缺少任一工件时结论为未验收。

## 门禁清单

| ID | 门禁 | 自动证据 |
|---|---|---|
| T01 | 真实 E2E 结果绑定 | JUnit 解析、当前 commit、72 小时有效期、测试名和 PNG SHA/尺寸 |
| T02 | SensitiveDataGuard | SQLite、artifact、audit、Probe/OTel 源头/发送前/持久化前脱敏及只读审计 |
| T03 | 服务所有权启停 | 外部进程保留、伪造 manifest 拒绝、自有主平台/Receiver 精确停止 |
| T04 | Finding rollup | 逻辑 Finding 与 `finding_instance` 命中明细一致性 |
| T05 | 异步扫描状态机 | 真实 worker、Job/Process/Event、取消、重试和启动恢复 |
| T06 | API 管理面安全 | loopback 默认、非 loopback Token、body 限制、安全响应头 |
| T07 | Probe 生命周期 | Codex `DRY_RUN_ONLY`；Hermes 临时 Home apply/self-test/disable/repair/uninstall/rollback |
| T08 | OTel Receiver | OTLP/HTTP JSON、体积/批次/ID/时间戳限制、幂等、retention 和全字段脱敏 |
| T09 | 数据重置/保留/迁移 | SQLite Backup API、运行表白名单、`KeepDiscovery`、事务 migration、retention 计划绑定、引用感知 artifact GC |
| T10 | 最终交付包 | wheel/sdist/SBOM/OpenAPI/迁移清单/依赖审计/文档/样例/验收证据/manifest SHA/全新 venv smoke |
| T11 | 58 页前端 | 离线资源校验和 8 条真实 Chromium 旅程，无 console/page error 和外网请求 |
| T12 | 本机能力 | 真实发现 Codex/Hermes，对其配置做有界只读扫描并验证 Hash 不变 |
| T13 | 范围边界 | 跳过本仓库源码/doc，保留显式 fixture；不启动 Agent/stdio MCP/Skill |
| T14 | 维护性 | Python/Node/PowerShell 语法、完整 pytest、diff check、发布包安装导入 |

## 提交前回归快照

2026-07-10 在隔离 SQLite、state 和 artifact 根目录执行：

```text
non-browser pytest: 208 passed
Chromium enterprise journeys: 8 passed
browser console/page errors: 0
external browser requests: 0
```

该快照用于证明开发收敛，不是发布 PASS 的替代物。最终签收必须重新执行下方一键验收，使结果绑定提交后的 Git HEAD，并由脚本在最后一个门禁完成后才发布 `latest-e2e-result.json`。

## 一键验收

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v4210_enterprise_release.ps1
```

脚本使用隔离 DB、artifact、state 和 E2E result 路径。`/api/v1/completeness` 仅在当前 commit 的机器生成结果全部有效时报告 58/58 E2E PASS。脚本结束时还会比较正式数据库、正式 artifact 与 Codex/Hermes 配置的组合指纹；任何变化都会使门禁失败。
