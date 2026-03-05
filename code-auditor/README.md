# 🔍 Code Auditor — AI 驱动的专业代码安全审计 Skill

> **让 AI Agent 像资深安全专家一样审计代码**
>
> 9 语言 · EALOC 智能权重 · 双轨并行框架 · LSP 深度追踪

---

## 项目概述

Code Auditor 是一个面向 AI Agent 的代码安全审计技能（Skill），它不是一个传统的 SAST 工具，而是一套**标准化的审计 SOP**——教会 AI"先看什么、后查什么、查到什么程度"。

### 核心理念

```
传统工具思路:    代码 → 正则匹配 → 告警列表（误报率高）
Code Auditor:   代码 → AI 理解语义 → SOP 引导审计 → 精准漏洞报告
```

AI 不缺代码理解能力，缺的是"章法"。Code Auditor 提供了这套章法。

### 目标平台

任何支持 Skill/Agent 的 IDE 或平台：

| 平台 | LSP 支持 | 备注 |
|------|---------|------|
| VS Code (Gemini / Copilot) | ✅ 完整 | 推荐环境 |
| Cursor | ✅ 完整 | 推荐环境 |
| Claude Code | ✅ 完整 | 原生支持 |
| Windsurf / Trae | ✅ 完整 | |
| CLI Agent | ⚠️ 降级 | 回退到 grep + read |

---

## 系统架构

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Code Auditor                              │
│                                                                     │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────────┐  │
│  │  SKILL.md   │    │ scan_sinks   │    │    references/         │  │
│  │  (主 SOP)   │    │   .py        │    │                        │  │
│  │             │    │              │    │  sinks_{lang}.md ×9    │  │
│  │ 执行控制器  │───▶│ 自动粗筛     │    │  coverage_matrix.md    │  │
│  │ EALOC 权重  │    │ EALOC 分层   │    │  report_template.md    │  │
│  │ 双轨框架   │    │ 9 语言正则   │    │                        │  │
│  │ 反幻觉规则  │    └──────────────┘    └────────────────────────┘  │
│  └──────┬──────┘           │                       │                │
│         │                  │                       │                │
│         ▼                  ▼                       ▼                │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │              AI Agent Runtime (IDE 环境)                     │    │
│  │                                                             │    │
│  │  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐  │    │
│  │  │  Grep   │  │   Read   │  │  LSP   │  │ External Tool │  │    │
│  │  │ 模式搜索 │  │ 文件读取  │  │ 语义跳转│  │ semgrep/bandit│  │    │
│  │  └─────────┘  └──────────┘  └────────┘  └───────────────┘  │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   目标代码项目      │
                    │  (任意语言/框架)    │
                    └───────────────────┘
```

### 审计流水线（6 步执行控制器）

```
S1 模式判定          S2 项目画像            S3 Sink 粗筛
┌──────────┐      ┌──────────────┐      ┌──────────────┐
│ standard │      │ 技术栈识别   │      │ scan_sinks   │
│   or     │─────▶│ EALOC 分层   │─────▶│   .py 自动   │
│  deep    │      │ 攻击面枚举   │      │   扫描+分层   │
└──────────┘      └──────────────┘      └──────┬───────┘
                                               │
S4 执行计划 ← STOP   S5 深度审计              S6 报告
┌──────────────┐   ┌──────────────┐      ┌──────────────┐
│ 审计维度选择  │   │ 轨道A: 控制法│      │ 覆盖矩阵自检 │
│ 等待用户确认  │──▶│ 轨道B: 数据流│─────▶│ 标准化报告   │
│              │   │ LSP 深度追踪 │      │              │
└──────────────┘   └──────────────┘      └──────────────┘
```

---

## 核心技术亮点

### 1. EALOC 智能资源分配（Effective Analysis LOC）

**问题**：AI Agent 的 Token 有限，不可能对每一行代码都投入同等注意力。

**解法**：根据代码层级自动分配审计权重。

```
                    注意力分配
  Tier 1 ██████████████████████████████████████ ×1.0
  (入口层: Controller / Filter / Handler / Router)
  → API 入口、身份认证逻辑、参数接收

  Tier 2 ██████████████████                     ×0.5
  (业务层: Service / DAO / Repository / Manager)
  → 数据流转、数据库操作、业务逻辑

  Tier 3 ████                                   ×0.1
  (模型层: Entity / DTO / Model / POJO / Config)
  → 仅模式匹配，关注信息泄露和硬编码
```

**公式**：`EALOC = T1_LOC × 1.0 + T2_LOC × 0.5 + T3_LOC × 0.1`

**效果**：相比均匀分配，削减约 **67%** 无效计算成本，将资源集中在最容易出问题的入口层。

#### 各语言的层级映射

| 层级 | Java | Python | Go | PHP | JS/Node |
|------|------|--------|----|-----|---------|
| **Tier 1** | `*Controller` `*Filter` | `views.py` `routes.py` | `*handler.go` | `*Controller.php` | `*router.*` `*controller.*` |
| **Tier 2** | `*Service` `*DAO` `*Mapper` | `*service.py` `models.py` | `*service.go` `*repo.go` | `*Service.php` `*Repository.php` | `*service.*` `*model.*` |
| **Tier 3** | `*Entity` `*DTO` `*VO` | `*serializer.py` `*schema.py` | `*model.go` `*entity.go` | `*Entity.php` `*Request.php` | `*dto.*` `*entity.*` |

### 2. 双轨并行审计框架

传统审计只关注"注入"，但逻辑漏洞（认证缺失、IDOR、竞态条件）同样致命。双轨并行确保两类漏洞都不遗漏：

```
┌─────────────────────────────────────────────────────────────────┐
│                      双轨并行审计框架                            │
│                                                                 │
│  ┌──────────────────┐          ┌──────────────────┐             │
│  │  轨道 A (50%)    │          │  轨道 B (40%)    │             │
│  │  控制建模法       │          │  数据流分析法     │             │
│  │                  │          │                  │             │
│  │  发现"缺失"类漏洞 │          │  发现"注入"类漏洞 │             │
│  │                  │          │                  │             │
│  │  公式:           │          │  公式:           │             │
│  │  漏洞 = 敏感操作  │          │  漏洞 = Source   │             │
│  │       - 应有控制  │          │   → [无净化]     │             │
│  │                  │          │   → Sink         │             │
│  │  ● 认证缺失      │          │  ● SQL 注入      │             │
│  │  ● 授权缺失      │          │  ● 命令注入      │             │
│  │  ● IDOR         │          │  ● 反序列化 RCE  │             │
│  │  ● 竞态条件      │          │  ● SSRF/XXE     │             │
│  │  ● 重放攻击      │          │  ● XSS/SSTI     │             │
│  └──────────────────┘          └──────────────────┘             │
│                                                                 │
│  ┌──────────────────────────────────────────────────┐           │
│  │  补充轨道 (10%): 配置审计 + 依赖审计              │           │
│  │  硬编码密钥 · Debug 模式 · CORS · CVE 依赖        │           │
│  └──────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### 3. LSP 增强污点追踪

传统 SAST 用 grep 搜索效率低且噪音大。Code Auditor 指导 AI 使用 IDE 内置的 LSP 实现**语义级**代码跳转：

```
传统方式:  grep "executeQuery" → 500 个匹配 → 逐个人工判断
LSP 方式:  findReferences(executeQuery) → 仅返回 8 个实际代码引用 → 精确

节省约 40% 的 Token 消耗
```

**追踪示例——SQL 注入**：

```
Step 1: Grep 定位 Sink
   └─ stmt.executeQuery(sql)           ← UserDao.java:45

Step 2: LSP goToDefinition(sql)
   └─ sql = buildQuery(userId)         ← UserDao.java:42

Step 3: LSP goToDefinition(buildQuery)
   └─ 跳转到 QueryHelper.java:20      ← 发现字符串拼接

Step 4: LSP incomingCalls(executeQuery)
   └─ 找到 5 个调用点                   ← 2 个来自 Controller（HTTP 入口）

Step 5: 确认攻击路径
   └─ Controller → Service → DAO → executeQuery()
   └─ userId 来自 @RequestParam        ← 确认 Source，报告漏洞
```

### 4. 辅助扫描脚本（scan_sinks.py）

零依赖的 Python 脚本，在 S3 阶段自动完成粗筛：

```bash
$ python3 scan_sinks.py /path/to/project

[EALOC 分层统计]
  Tier 1 (入口层):  23 文件,  2,450 LOC
  Tier 2 (业务层):  67 文件,  8,300 LOC
  Tier 3 (模型层):  45 文件,  3,200 LOC
  EALOC = 23×1.0 + 67×0.5 + 45×0.1 = 61 (有效分析单元)

[Sink 扫描结果]
  🔴 CRITICAL (3)
    UserController.java:45    | SQL-CONCAT    | Tier1 | stmt.executeQuery("..." + param)
    FileService.java:78       | PATH-TRAVERSE | Tier2 | new File(basePath + fileName)
    ConfigLoader.java:23      | DESERIALIZE   | Tier2 | ObjectInputStream.readObject()

  🟡 HIGH (7)
    ...

  Total: 18 sinks in 135 files (9 Tier1, 6 Tier2, 3 Tier3)
```

### 5. 10 维度覆盖矩阵（审后自检）

确保审计不遗漏关键维度：

```
D1  注入        D2  认证        D3  授权        D4  反序列化     D5  文件操作
 ┌─────┐         ┌─────┐         ┌─────┐         ┌─────┐         ┌─────┐
 │ ✅  │         │ ✅  │         │ ⚠️  │         │ ✅  │         │ ❌  │
 └─────┘         └─────┘         └─────┘         └─────┘         └─────┘

D6  SSRF        D7  加密        D8  配置        D9  业务逻辑     D10 供应链
 ┌─────┐         ┌─────┐         ┌─────┐         ┌─────┐         ┌─────┐
 │ ✅  │         │ ⚠️  │         │ ✅  │         │ ⚠️  │         │ ✅  │
 └─────┘         └─────┘         └─────┘         └─────┘         └─────┘

终止判定: ≥8/10 覆盖 + D1-D3 全覆盖 → 可出报告
```

### 6. 反幻觉 / 反确认偏差机制

AI 审计最大的风险是"编造漏洞"。Code Auditor 内置双重防护：

```
反幻觉规则:
  ✗ 禁止猜测文件路径
  ✗ 禁止凭记忆编造代码
  ✗ 禁止报告未读取过的文件中的漏洞
  ✓ 必须用 Read/Glob 验证文件存在
  ✓ 必须引用 Read 工具返回的实际代码
  → 宁可漏报也不误报

反确认偏差规则:
  ✗ 禁止"基于经验重点关注某类漏洞"
  ✗ 禁止跳过 checklist 中"不太可能"的项目
  ✓ 必须枚举所有敏感操作，逐一验证
  ✓ 必须完成每种漏洞类型的完整检查清单
  → 方法论驱动，而非经验驱动
```

---

## 支持的语言与框架

| 语言 | 主要框架 | 重点漏洞类型 |
|------|---------|-------------|
| **Java** | Spring Boot, MyBatis, Shiro | SQL注入(${}), 反序列化, JNDI, XXE, SpEL |
| **Python** | Django, Flask, FastAPI | Pickle RCE, SSTI, 命令注入, Django ORM注入 |
| **Go** | Gin, Echo, Fiber | 竞态条件, SSRF, SQL拼接, 不安全的 template |
| **PHP** | Laravel, ThinkPHP, WordPress | 反序列化POP链, 文件包含, SQL注入 |
| **JavaScript** | Express, Koa, NestJS | 原型污染, XSS, child_process, eval |
| **C#** | ASP.NET Core, Blazor | BinaryFormatter, ViewState, SQL拼接 |
| **C/C++** | - | 缓冲区溢出, 格式化字符串, UAF, 整数溢出 |
| **Ruby** | Rails, Sinatra | ERB注入, Marshal反序列化, mass assignment |
| **Rust** | Actix, Rocket | unsafe块, FFI边界, panic路径, 逻辑漏洞 |

---

## 技术栈

| 组件 | 技术 | 说明 |
|------|------|------|
| 主 SOP | Markdown (SKILL.md) | AI Agent 的"操作手册" |
| 方法论 | Markdown (core/) | 污点分析、控制建模、反幻觉等 |
| 语言知识 | Markdown (languages/) | 9 语言 Source/Sink + 框架专项 |
| 安全领域 | Markdown (security/) | 认证/API/密码学/竞态等 8 领域 |
| 扫描脚本 | Python 3 (stdlib only) | 零依赖，任何环境可运行 |
| 代码导航 | LSP (IDE 内置) | 语义级跳转与追踪 |
| 模式匹配 | grep/ripgrep | 快速 Sink 点定位 |
| 外部工具 | semgrep/bandit (可选) | 专业 SAST 补充 |

---

## 项目文件结构

```
code-auditor/                            29 个文件，结构化组织
├── SKILL.md              (175行)   主 SOP — 执行控制器 + EALOC + 双轨框架
├── core/                (1,151行)   核心方法论
│   ├── taint_analysis.md              污点追踪 + LSP + Slot 类型
│   ├── security_controls.md           控制建模方法论（轨道 A）
│   ├── data_flow_methodology.md       数据流分析（轨道 B）
│   ├── anti_hallucination.md          反幻觉 + 反确认偏差
│   ├── poc_generation.md              PoC 生成模板
│   └── external_tools_guide.md        外部工具集成
├── languages/           (1,480行)   9 语言 Sink 深度模块
│   ├── java.md / python.md            含框架专项 + Gadget 链
│   └── go / php / js / csharp / c_cpp / ruby / rust
├── security/              (714行)   8 安全领域专项
│   ├── authentication_authorization   认证 + 授权
│   ├── api_security / cryptography    API + 密码学
│   └── file_operations / race_conditions / business_logic / ...
├── checklists/            (102行)   覆盖矩阵 + 通用检查清单
├── reporting/             (125行)   报告模板
└── scripts/
    └── scan_sinks.py      (486行)   零依赖 Sink 粗筛 + EALOC 分层
```

---

## 与同类方案对比

| 特性 | Code Auditor | code-audit (3stonebrother) | irify-sast (yaklang) | 传统 SAST |
|------|-------------|---------------------------|---------------------|-----------|
| 定位 | AI SOP + 脚本辅助 | AI SOP 百科全书 | SSA 引擎 Skill | 独立工具 |
| 文件规模 | 29 文件, 4,569 行 | 109 文件, 67,543 行 | 3 文件 | N/A |
| 语言支持 | 9 语言 | 9 语言 | 7 语言 | 视工具 |
| EALOC 权重 | ✅ | ❌ | ❌ | ❌ |
| 辅助脚本 | ✅ scan_sinks | ❌ | ✅ SSA 引擎 | 独立运行 |
| 外部依赖 | 无 (Python stdlib) | 无 | yaklang MCP | 视工具 |
| 双轨审计 | ✅ | ✅ | ❌ | ❌ |
| 覆盖矩阵 | ✅ | ✅ | ❌ | 部分 |
| 反幻觉机制 | ✅ | ✅ | ✅ | N/A |
| LSP 追踪指导 | ✅ | ✅ | 引擎替代 | N/A |

---

## 设计哲学

> **"不是教 AI 什么是漏洞，而是教它先看什么、后查什么、查到什么程度。"**

1. **SOP 驱动而非规则驱动** — AI 已经"知道"什么是 SQL 注入，它缺的是系统化的审计流程
2. **结构化而非堆砌** — 29 文件按 5 层组织（方法论/语言/安全域/检查/工具），比 109 文件更易维护
3. **权重而非平均** — EALOC 让 AI 把 80% 精力花在入口层和业务层
4. **宁漏勿误** — 反幻觉机制确保每个发现都基于实际代码
5. **渐进式加载** — 只在需要时读取对应语言模块，节省上下文窗口
6. **生态组合** — 与 wooyun-legacy（案例库）和 xianzhi-research（思维框架）搭配使用效果更佳

---

## 推荐搭配 Skills

Code Auditor 专注于"怎么执行审计"。搭配以下 Skills 可获得更完整的安全审计体验：

| Skill | 定位 | 说明 | 安装 |
|-------|------|------|------|
| [wooyun-legacy](https://github.com/tanweai/wooyun-legacy) | 案例库 (WHAT) | 88,636 个真实漏洞案例，覆盖 15 种类型 | `git clone` 到 Skills 目录 |
| [xianzhi-research](https://github.com/tanweai/xianzhi-research) | 思维框架 (HOW TO THINK) | 四层思维金字塔 + 跨域攻击链方法论 | `git clone` 到 Skills 目录 |

```
xianzhi-research  →  HOW TO THINK  (思维框架层)
code-auditor      →  HOW TO DO     (执行层)
wooyun-legacy     →  WHAT TO FIND  (案例库层)
```

---

## 许可证

MIT License

## 作者

zhangchengli
