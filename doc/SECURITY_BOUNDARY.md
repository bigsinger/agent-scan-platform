# Agent Security Assessment v4.2.9 安全边界

## 默认部署边界

- 默认监听 `127.0.0.1`。
- 非 localhost 绑定需要主平台托管或显式 `ASSESSMENT_ADMIN_TOKEN`。
- CORS 默认限制本地来源。

## 只读原则

| 项目 | 承诺 |
|---|---|
| Agent 配置 | 不自动修改 |
| stdio MCP | 不自动启动 |
| Skill 代码 | 不执行 |
| Secret | 不保存明文 |
| 测试数据 | 默认隔离 DB/artifact/state |

## 环境变量

```text
ASSESSMENT_DB_PATH
ASSESSMENT_ARTIFACT_ROOT
ASSESSMENT_STATE_ROOT
ASSESSMENT_DISABLE_BACKGROUND_JOBS=true
ASSESSMENT_ADMIN_TOKEN
```

## 管理口保护

写接口可在托管模式下接入 token 校验。本地独立模式以 localhost 绑定和危险配置拒绝作为默认保护。
