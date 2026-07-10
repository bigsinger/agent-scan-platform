# Agent Security Assessment v4.2.9 最终验收清单

## 一键命令

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v429_final_acceptance.ps1
```

## 验收目标

| 指标 | 目标 |
|---|---:|
| pages | 58 |
| audit_passed | 58 |
| contract_passed | 58 |
| e2e_passed | 58 |
| gaps | 0 |
| rules | >=25 |

## 企业试用流程

1. 发现本机 Agent / Skill / MCP。
2. 执行快速扫描。
3. 进入 MCP/Skill 专项静态检查。
4. 查看 Finding、Evidence、Attack Path。
5. 生成报告。
6. 创建复测。
7. 导出最终交付包。

## 安全边界

- 不修改真实 Agent 配置。
- 不启动 stdio MCP。
- 不执行 Skill 代码。
- 不保存明文 Secret。
- 测试默认使用隔离 SQLite、artifact root 和 state root。
