# Agent Security Assessment v4.2.10 最终验收清单

## 一键命令

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v4210_enterprise_release.ps1
```

## 自动门禁

| 指标 | 目标 |
|---|---:|
| pages / audit / contract / E2E | 58 / 58 / 58 / 58 |
| gaps | 0 |
| Chromium journeys / PNG | 8 / 8 |
| non-browser pytest | 209 passed / 0 failed / 0 skipped |
| JUnit failures / errors / skips | 0 / 0 / 0 |
| 本机 Agent | Codex、Hermes 均真实发现 |
| 配置 Hash 变化 | 0 |
| 敏感数据命中 | 0 |
| 外部进程误停止 | 0 |
| 交付包文件 Hash 错误 | 0 |
| schema migration | 001 / 002 / 003，校验和一致 |
| OTel 批量基准 | 10,000 事件入库、二次提交幂等、Secret 命中 0 |

## 企业试用流程

1. 空库启动，确认运行态为空而非 demo 数据。
2. 发现本机 Agent、Skill、MCP，并导出 inventory 证据。
3. 执行 machine/path/mcp 快速扫描，观察 Task/Job/Event 与取消/重试。
4. 进入 MCP/Skill 专项，核对静态签名、审批过期和 Toxic Flow。
5. 查看 Finding、Evidence、Attack Path；报告内证据使用抽屉，返回时保留报告上下文。
6. 生成 HTML/JSON 报告、证据包和复测 diff。
7. 启动 OTel Receiver，发送脱敏测试事件，重建行为链并查看异常。
8. Hermes 探针先生成只读计划；仅在客户授权时确认安装，并演练合成自测与卸载恢复。Codex 不安装。
9. 执行 SQLite 完整性、备份和 restore drill。
10. 预览 retention 与 artifact GC，确认计划绑定、数据库备份、引用保护和隔离 manifest。
11. 运行一键门禁并离线验证最终 ZIP。

## 安全不变量

- 默认不修改真实 Agent；Hermes 探针修改必须精确计划确认、先备份并可回滚。
- 不启动 stdio MCP，不执行 Skill，不执行未审批命令。
- 不保存明文 Secret、完整 Prompt 或完整 Tool 输出，不允许 raw capture。
- 本项目源码和 `doc` 不进入本机 Agent 扫描，显式 fixture 除外。
- 测试默认使用隔离 SQLite、artifact、state；正式数据与 Agent 配置前后指纹必须一致。
- 服务停止只处理经 manifest 所有权复核的本产品进程。

## 证据位置

验收脚本结束会打印 `acceptance_result`、`live_machine_result`、`delivery_package` 和 `protected_fingerprint`。企业签收应保存这些路径对应工件及 ZIP SHA-256，不能只保存控制台“passed”文本。
