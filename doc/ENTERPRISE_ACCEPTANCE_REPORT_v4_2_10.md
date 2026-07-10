# Enterprise Acceptance Report v4.2.10

## 验收范围

本报告对应 `agent_security_assessment_v4_2_10_enterprise_release_gate_spec.md`。

## 门禁清单

| ID | 门禁 | 状态 | 证据 |
|---|---|---|---|
| T01 | 真实 E2E 结果绑定 | PASS | `tests/test_v4210_completeness_result_binding.py` + `tools/generate_acceptance_result.py` |
| T02 | SensitiveDataGuard | PASS | `tests/test_v4210_sensitive_data_guard.py` + `tools/audit_sensitive_data.ps1` |
| T03 | 服务所有权启停 | PASS | `tests/test_v4210_service_script_safety.py` + `tools/test_service_ownership.ps1` |
| T04 | Finding rollup | PASS | `tests/test_v4210_finding_rollup.py` |
| T05 | 异步扫描状态机入口 | PASS | `tests/test_v4210_task_state_machine.py` |
| T06 | API 管理面安全 | PASS | `tests/test_v4210_auth_policy.py` |
| T07 | Probe 能力诚实矩阵 | PASS | `tests/test_v4210_probe_capability_lifecycle.py` |
| T08 | OTel Receiver 加固 | PASS | `tests/test_v4210_otel_receiver_hardening.py` |
| T09 | 数据重置/保留 | PASS | `tools/reset_demo_state.ps1` + `tests/test_v4210_reset_and_delivery.py` |
| T10 | 最终交付包 | PASS | `tools/export_final_delivery_package.ps1` + `tools/verify_delivery_package.ps1` |
| T11/T12 | 版本/前端状态 | PASS | version API、frontend offline、browser journey |
| T13 | 最小维护性收敛 | PASS | py_compile、full pytest、diff check |

## 一键验收

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v4210_enterprise_release.ps1
```

## 验收说明

验收脚本使用隔离 DB、artifact、state 和 E2E result 路径，不污染正式数据。`/api/v1/completeness` 只在当前 commit 的 result、测试名和截图 SHA 匹配时报告 E2E PASS。
