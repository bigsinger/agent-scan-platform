# P04 本机发现

## 页面目标
本机发现是本地 Agent 安全测评的核心入口。页面以只读方式发现 Agent、Skill、MCP 与 Config，并通过 `display` contract 输出可读字段。

## Display Contract
每条 discovery hit 必须包含 `display.title`、`display.subtitle`、`display.type_label`、`display.version`、`display.primary_path`、`display.fields`、`display.risk_summary` 和 `display.safety_summary`。

## Skill 展示字段
- Skill 名
- 描述
- 版本（无版本显示 `-`）
- Agent
- Skill 根路径 / SKILL.md 路径
- 文件数 / 脚本数
- Hash
- 风险摘要

## 交互
- 类型 tabs：全部 / Agent / Skills / MCP / Config
- 搜索覆盖名称、描述、路径、MCP、配置摘要
- 点击行标题打开 discovery hit 详情抽屉
- 关闭抽屉后保留筛选上下文

## 安全边界
只读发现；不修改已安装 Agent；不启动 stdio MCP；不执行 Skill；所有 secret 脱敏。

## E2E 验收
`tests/test_v427_core_local_assessment_flow.py::test_v427_core_local_assessment_flow` 和 `tests/test_v427_discovery_page_static.py`。
