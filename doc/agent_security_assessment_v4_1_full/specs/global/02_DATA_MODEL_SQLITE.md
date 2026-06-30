# SQLite 数据模型总览

正式实现至少包含以下表，字段可在开发中扩展，但不得删除页面需要展示的字段。

## 核心表

- `agent_instance`
- `component`
- `component_relation`
- `config_snapshot`
- `assessment`
- `assessment_scope`
- `assessment_profile`
- `task`
- `task_stage`
- `task_event`
- `discovery_run`
- `discovery_hit`
- `mcp_server`
- `mcp_tool`
- `mcp_prompt`
- `mcp_resource`
- `mcp_consent`
- `skill`
- `skill_file`
- `scanner_plugin`
- `scanner_run`
- `redteam_case`
- `redteam_run`
- `redteam_message`
- `finding`
- `evidence`
- `attack_path`
- `report`
- `retest_run`
- `rule`
- `issue_mapping`
- `schedule`
- `integration`
- `audit_event`
- `database_backup`
- `third_party_component`

## SQLite 运行要求

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
```

子进程不得直接并发写库；扫描子进程写 JSON 结果，父进程统一入库。
