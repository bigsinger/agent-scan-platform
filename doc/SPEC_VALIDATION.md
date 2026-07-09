# V4.1 SPEC 生成与校验记录

生成时间：2026-06-26

## 文件

- `agent_security_assessment_v4_1_spec.md`
- `agent_security_assessment_v4_1_prototype.html`
- `agent_security_assessment_v4_1_deliverables.zip`

## 版本定位

V4.1 是 V4.0 的完整整合版开发规范，不是补丁文档。它保留 V4.0 的 Python + FastAPI + SQLite + 原生 HTML + Vue 技术路线，并合并前端离线运行、Vue 本地化、空白页防护、模板编译验收、AI 编码代理前端修改规则。

## 已纳入 V4.1 的新增规范

1. 原型必须在断网、file://、无后端服务环境下运行。
2. 原型允许内嵌 Vue Global Build；正式产品必须使用本地 `/static/vendor/vue.global.prod.js`。
3. 禁止运行时依赖 unpkg、jsdelivr、cdnjs、Google Fonts 等公网资源。
4. 使用 v-cloak 必须配套 boot-status / boot-error。
5. 必须捕获 window error 与 unhandledrejection。
6. 必须进行 Vue 模板编译、Console、导航点击、离线打开专项验收。
7. AI 编码代理修改前端时必须执行前端专项自检。

## 静态校验

- SPEC 行数：2912 行
- SPEC 文件大小：约 141 KiB
- 已包含完整 V4.0 主体内容
- 已新增附录 C：V4.1 前端防空白页验收清单
- 已新增附录 D：V4.1 与 V4.0 差异追踪

## v4.2.5 SPEC 验收清单

必跑命令：

```powershell
node --check src\assessment\static\assessment\app.js
python tools\check_frontend_offline.py --html src\assessment\static\assessment\index.html --expect-pages 58
```

当前环境若未安装 pytest，可直接执行：

```powershell
$env:PYTHONPATH='src'
@'
# python here-string
'@ | python -
from tests.test_v425_observability_e2e import (
    test_v425_behavior_chain_build_is_idempotent,
    test_v425_otlp_normalizer_and_query_api,
    test_v425_probe_install_plan_and_generated_code_compile,
)
test_v425_behavior_chain_build_is_idempotent()
test_v425_otlp_normalizer_and_query_api()
test_v425_probe_install_plan_and_generated_code_compile()
print('direct-v425-tests-ok')
PY
```

页面检查：`/assessment/probes`、`/assessment/observability`、`/assessment/behavior/chains`、`/assessment/behavior/anomalies`、`/assessment/otel/explorer`、`/assessment/probes/install` 均不能回落 dashboard。

## v4.2.6 验收结果（2026-07-09）

执行命令：

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify_v426_acceptance.ps1
```

实际输出摘要：

```text
frontend offline check passed: pages=58
v4.2.6 otel receiver ingestion: 2 passed
v4.2.6 behavior anomaly rules: 2 passed
v4.2.6 probe install safety: 1 passed
v4.2.6 scan scope policy: 2 passed
v4.2.6 observability pages: 2 passed
legacy 48/58 regression tests: 2 passed
full test suite: 129 passed in 193.12s
v4.2.6 acceptance verification passed
```

完整性矩阵期望：58 页；P49-P54/D19-D22 文档、原型、契约、E2E manifest 均已映射。未在 manifest 中覆盖的旧页面保持 `NOT_ASSERTED`，不伪造 PASS。

## v4.2.7 Discovery Experience 验收

```powershell
powershell -ExecutionPolicy Bypass -File toolserify_v427_discovery.ps1
```

核心检查：

```powershell
$env:PYTHONPATH='src'
@'
from fastapi.testclient import TestClient
from assessment.main import app
client = TestClient(app)
payload = client.get('/api/v1/completeness?page_size=200').json()
print(payload['summary'])
required = {'P02','P04','P05','P06','P16','P17','P20','D09'}
for row in payload['items']:
    if row['id'] in required:
        print(row['id'], row['audit'], row['contract'], row['e2e'], row['status'])
'@ | python -
```

预期：`e2e_passed >= 18`，P02/P04/P05/P06/P16/P17/P20/D09 均为 `PASS PASS PASS 已验收`。
