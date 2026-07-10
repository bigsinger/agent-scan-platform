# Agent Security Assessment v4.2.10 安全边界

## 默认部署边界

- 默认监听 `127.0.0.1`。
- 非 localhost 绑定需要主平台托管或显式 `ASSESSMENT_ADMIN_TOKEN`。
- CORS 默认限制本地来源。

## 只读原则

| 项目 | 承诺 |
|---|---|
| Agent 配置 | 默认不修改；仅 Hermes 探针在精确计划 ID + 显式确认后可写，且先备份、可回滚 |
| stdio MCP | 不自动启动 |
| Skill 代码 | 不执行 |
| Secret | 不保存明文 |
| Probe 原始数据 | 禁止 raw capture；仅保存脱敏 preview、长度和 SHA-256 |
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

## v4.2.10 强化边界

- `SensitiveDataGuard` 统一 SQLite、artifact、audit、probe/OTel 脱敏。
- Admin Token 开启后写接口与导出/下载受 `X-Assessment-Token` 保护。
- 未登记 API 不再进入通用业务分发器，统一返回 `404 ROUTE_NOT_FOUND`；脱敏审计携带请求关联 ID。
- 主 API 实际读取请求体并限制为 2 MiB；artifact 下载只允许 state/artifact 根目录内文件且限制为 64 MiB。
- OTel Receiver 仅支持 loopback 或 token，限制 JSON/body/batch/event 大小。
- gzip 使用有界解压，压缩后小但解压超限的请求会被拒绝；10,000 条 Probe 事件使用单事务批量落库。
- Receiver 当前支持 OTLP/HTTP JSON traces/logs/metrics；不宣称支持 OTLP protobuf 或 gRPC。
- Hermes 探针为 observe-only、fail-open、回调入队；200ms 网络超时只发生在后台线程，Collector 不可达时写入 1MiB 有界轮转缓冲。
- Codex 探针能力为 `DRY_RUN_ONLY`，系统不会向 `~/.codex/config.toml` 写入猜测的 Hook schema。
- Hermes 生命周期写操作必须同时提交持久化计划的 `plan_id` 和 `acknowledge_agent_config_change=true`；配置 Hash 漂移后原计划失效。
- 服务停止只认产品 PID manifest，不按端口杀进程。
- Retention 和 artifact GC 必须先 dry-run，再提交未漂移计划 ID 与显式确认；只处理本系统状态并在删除前备份/隔离，不进入 Agent 目录。
