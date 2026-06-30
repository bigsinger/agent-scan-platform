# Agent 安全测评能力模块 V4.1 · 全页面原型与 SPEC 交付包

本交付包修复了“只有主页面”的问题，改为每个页面和子页面均独立生成。

## 目录结构

```text
prototype/
  index.html                 # 全页面索引
  pages/                     # 48 个独立页面 HTML
  assets/css/app.css         # 共享样式
  assets/js/app.js           # 共享 Vue 启动与交互逻辑
  assets/vendor/vue.global.prod.js # 本地 Vue，无 CDN
specs/
  PAGE_INDEX.md              # 页面索引
  pages/                     # 48 个页面 SPEC
  global/                    # 全局开发规范
  agent_security_assessment_v4_1_full_spec.md # 合并版 SPEC
VALIDATION.md                # 生成与校验记录
```

## 使用方式

直接双击打开：

```text
prototype/index.html
```

或打开任一页面：

```text
prototype/pages/P01_dashboard.html
```

## 交付原则

- 所有页面本地离线可打开。
- 所有页面均指向真实存在的页面 SPEC。
- 所有页面均显示 Route、API、实体、状态。
- 可直接交给 AI 编码代理逐页实现。
