# P53 OTel Explorer

## 页面目标
为 Agent 安全测评 v4.2.6 提供「OTel Explorer」正式验收页面，不使用演示数据掩盖未实现能力。

## 路由
`/assessment/otel/explorer`

## 目标用户和使用场景
企业安全测评人员在本地只读模式下查看可观测性数据、证据链和探针状态。

## 主 API
GET /api/v1/otel/spans；GET /api/v1/otel/logs；GET /api/v1/otel/metrics；GET /api/v1/otel/traces/{trace_id}

## 数据来源
otel_span, otel_log, otel_metric_point, probe_event

## 关键交互
查询 span/log/metric，从 span 进入 trace 详情。所有详情优先在抽屉中打开，关闭后返回原上下文。

## 空态、加载态、失败态
- 空态：显示「暂无数据」和下一步操作。
- 加载态：按钮禁用并显示等待状态。
- 失败态：展示 API 错误，不静默失败。

## 安全与脱敏要求
- 默认只读，不启动或修改已安装 Agent。
- 不启动 stdio MCP。
- Secret、Token、Password、Cookie、Authorization 等必须脱敏为 `[REDACTED]` 或仅保存 hash。

## E2E 验收点
- 路由可打开且不回落 dashboard。
- 主 API 返回 200 或受控空态。
- 页面不展示明文 secret。
- 安全边界字段 `mutates_installed_agents=false`。
