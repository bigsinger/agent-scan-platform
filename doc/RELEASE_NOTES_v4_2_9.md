# Release Notes v4.2.9

## 终局交付收敛

v4.2.9 将 Agent Security Assessment 从核心能力可用推进到企业验收闭环。

## 关键变化

- 58 个页面全部进入 E2E manifest。
- 新增 v429 final acceptance 脚本。
- 测试默认使用隔离 DB、artifact root 和 state root。
- 补齐 `python-exec`、`process-executions`、`processes` 等自然 API 别名。
- 补齐 Dashboard、Profile、Task、Redteam、Finding、Evidence、Report、Retest、Rule、Scanner、Schedule、Integration、Settings、SQLite、License、Completeness、API Debug 等闭环 E2E。
- 新增最终交付包导出和演示状态重置脚本。

## 验收命令

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v429_final_acceptance.ps1
```

## 安全说明

本版本仍坚持本地只读边界：不修改真实 Agent、不启动 stdio MCP、不执行 Skill、不保存明文 Secret。
