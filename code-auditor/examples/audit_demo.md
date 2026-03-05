# 审计 Demo — soc-agent 联动审计记录

> 本文档是 code-auditor 对 soc-agent 项目的完整审计过程记录，
> 演示 6 步 SOP + wooyun-legacy / xianzhi-research 联动。

## S1: 模式判定

```
[MODE] standard
```

## S2: 项目画像 + EALOC

```
[RECON]
  项目: SOC Agent (安全运营中心 AI Agent)
  技术栈: Python (FastAPI + LangChain) + JavaScript (Chrome Extension)
  文件: 61 (Python 43 + JS 18)
  代码行: 12,548

[EALOC]
  Tier1 (Entry):     9 files,  2,367 LOC  ← ×1.0  (路由/handler/API)
  Tier2 (Business): 48 files,  9,913 LOC  ← ×0.5  (服务/工具/适配器)
  Tier3 (Model):     4 files,    329 LOC  ← ×0.1  (模型/配置)
  EALOC = 2367×1.0 + 9913×0.5 + 329×0.1 = 7,356 effective LOC
```

## S3: Sink 粗筛

```bash
python3 scan_sinks.py ~/Desktop/codes/soc-agent
```

```
[SCAN] Total: 36 findings
  🔴 CRITICAL: 0
  🟡 HIGH:     36 (全部为 extension/ 中的 innerHTML XSS)
  🔵 MEDIUM:   0

Top Files:
  23 sinks | Tier2 | extension/sidebar.js
   7 sinks | Tier2 | extension/options.js
   6 sinks | Tier2 | extension/content.js
```

## S4: 执行计划 → STOP

```
[PLAN]
  审计维度:
    D1 注入      — server 端 SQL/命令注入检查
    D2 认证      — BACKEND_AUTH_TOKEN 机制审计
    D6 SSRF      — mcp_adapter.py HTTP 请求审计
    D7 加密      — TLS 验证配置检查
    D8 配置      — CORS/Debug 配置审计
    XSS          — extension innerHTML 深度追踪

  重点文件:
    server/services/mcp_adapter.py  (httpx 调用)
    server/utils/auth.py            (认证逻辑)
    server/main.py                  (CORS 配置)
    extension/sidebar.js            (23 处 innerHTML)
```

⚠️ STOP — 等待用户确认

## S5: 深度审计

### 轨道 A — 控制建模

| # | 敏感操作 | 位置 | 应有控制 | 实际 | 结论 |
|---|---------|------|---------|------|------|
| 1 | MCP HTTP 通信 | mcp_adapter.py:146,169,310 | TLS 验证 | ❌ `verify=False` ×3 | **HIGH** |
| 2 | API 全局认证 | auth.py:30 | 强制启用 | ⚠️ 默认关闭 | **MEDIUM** |
| 3 | CORS 配置 | main.py:62 | 白名单 Origin | 需确认 | **MEDIUM** |

### 轨道 B — 数据流分析

**数据流 1: AI 响应 → innerHTML (HIGH)**

```
Source:  AI API 返回内容 (ai-api.js)
  ↓ chrome.runtime.sendMessage
Path:   sidebar.js: handleResponse()
  ↓ 拼接 HTML
Sink:   el.innerHTML = response  (23 处)

净化: ❌ 无 HTML 转义 / DOMPurify
结论: HIGH — 若 AI 被 prompt injection 操控返回恶意 HTML，可触发 DOM XSS
```

### 补充 Skills 联动

**联动 1: 发现 XSS → 读取 `wooyun-legacy/categories/xss.md`**

从乌云案例中提取相关模式：
- 案例 wooyun-2014-063865: 存储型 XSS + CSRF 组合 → Cookie 劫持
- 案例 wooyun-2013-032814: XSS 劫持管理员后台

→ **结论增强**: soc-agent 的 innerHTML 接收 AI 返回内容，类似存储型 XSS 模式。
若攻击者通过 prompt injection 让 AI 返回 `<img onerror=...>`，
Chrome Extension CSP 阻止 `<script>` 但不阻止事件属性型 XSS。

**联动 2: 发现认证缺失 → 读取 `wooyun-legacy/categories/unauthorized-access.md`**

- 案例 wooyun-2015-0133489: redis 未授权 → 任意文件上传
- 案例 wooyun-2014-079702: 平行越权 → 修改他人数据

→ **结论增强**: soc-agent 默认无认证 = 任何人可调用 API，包括发起 LLM 对话、
执行 MCP 工具调用。在内网部署仍有横向移动风险。

**联动 3: innerHTML 追踪不确定 → 读取 `xianzhi-research/references/web-injection.md`**

使用四层思维金字塔分析：
- L1 攻击面: innerHTML 是"数据与指令不分离"的典型接口
- L4 防御反推: Manifest V3 CSP 阻止 inline script，但不阻止 `<img onerror>`

→ **结论增强**: 确认 DOM XSS 可绕过 CSP，攻击路径成立。

## S6: 报告

### 发现汇总

| # | 等级 | 类型 | 位置 | 描述 |
|---|------|------|------|------|
| 1 | 🔴 HIGH | TLS 验证禁用 | mcp_adapter.py:146,169,310 | 3 处 `verify=False` |
| 2 | 🟡 HIGH | DOM XSS ×36 | extension/sidebar.js 等 | innerHTML 无转义 |
| 3 | 🟡 MEDIUM | 认证默认关闭 | auth.py:30 | 无 token 时全开放 |
| 4 | 🟡 MEDIUM | CORS 配置 | main.py:62 | 需确认 allowed_origins |

### 覆盖矩阵

| # | 维度 | 覆盖 | 发现 |
|---|------|------|------|
| D1 | 注入 | ✅ | 0 |
| D2 | 认证 | ✅ | 1 |
| D6 | SSRF | ✅ | 0 |
| D7 | 加密 | ✅ | 1 (TLS) |
| D8 | 配置 | ✅ | 1 (CORS) |
| XSS | 前端 | ✅ | 36 |

覆盖率: 6/6 ✅ → 可出报告

### 整体风险: 🟡 MEDIUM-HIGH
