---
name: code-auditor
description: |
  AI-driven professional code security auditing skill. 9 languages,
  EALOC-weighted analysis, dual-track framework, LSP-enhanced tracking.
  Languages: Java, Python, Go, PHP, JavaScript, C#, C/C++, Ruby, Rust.
  Frameworks: Spring Boot, Django, Flask, FastAPI, Gin, Express, NestJS,
  Laravel, Rails, ASP.NET Core, Actix, and more.
tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Task
  - LSP
---

# Code Auditor — 专业代码安全审计

> 9语言 · EALOC 权重 · 双轨并行 · LSP 深度追踪

## When to Use

- 用户请求 **代码审计 / 安全审计 / 漏洞扫描**
- 用户说 **/audit** 或 **审计这个项目**
- 用户要求 **安全评审** 或 **渗透测试准备**

---

## Execution Controller（6 步必经路径）

> ⚠️ 不是建议，是必须。每步有强制输出。

### S1: 模式判定

| 关键词 | 模式 |
|--------|------|
| "审计" "扫描" "安全检查" | **standard** |
| "深度审计" "deep" "全面审计" | **deep** |
| 无法判定 | **问用户，不得假设** |

**必须在对话/思考流中明确打印以下内容后才能进入 S2**:

```text
[MODE] {standard|deep}
理由: {判定依据}
```
*(注意：严格遵守，不可省略此步骤的显式声明)*

### S2: 项目画像 + EALOC

执行攻击面测绘和 EALOC 分层。

**必须输出以下所有条目**（留空需标注"未识别"）:

```
[RECON]
  项目名: ___
  技术栈: ___ (框架/ORM/模板引擎)
  入口点: 必须详细列出所有 Controller/Router 文件的具体路径或路由列表，禁止只填数字。
  鉴权机制: ___ (Spring Security/JWT/Session/无)
  CORS 配置: ___ (白名单/通配符/无)
  公开端点(无鉴权): 明确列出免鉴权的 API 路径列表。

[EALOC]
  Tier1: ___ files, ___ LOC
  Tier2: ___ files, ___ LOC
  Tier3: ___ files, ___ LOC
  EALOC = ___
```

#### EALOC 层级映射

| 层级 | Java | Python | Go | PHP | JS/Node | C# | C/C++ | Ruby | Rust |
|------|------|--------|----|-----|---------|-----|-------|------|------|
| **T1** ×1.0 | `*Controller` `*Filter` | `views` `routes` `api` | `*handler` `*router` | `*Controller` | `*router` `*controller` | `*Controller` | `main` `*server` | `*controller` | `*handler` |
| **T2** ×0.5 | `*Service` `*DAO` `*Mapper` | `*service` `models` | `*service` `*repo` | `*Service` `*Model` | `*service` `*model` | `*Service` `*Repository` | `*util` `*lib` | `*model` `*service` | `*service` |
| **T3** ×0.1 | `*Entity` `*DTO` `*VO` | `*serializer` `*schema` | `*model` `*config` | `*Entity` `config` | `*dto` `*config` | `*Entity` `*DTO` | `*types` | `*serializer` | `*model` |

### S3: Sink 粗筛

```bash
python3 "$SKILL_DIR/scripts/scan_sinks.py" "$PROJECT_ROOT"
```

→ 输出: `[SCAN]` Sink 数量 + EALOC 分布 + Top 高危文件

### S4: 执行计划 → STOP

→ 输出: `[PLAN]` 审计维度 + 重点文件

> ⛔ **STOP — 强制物理停止点 (CRITICAL)**
>
> 输出 PLAN 后，**绝对禁止**立刻连贯进入 S5 深度代码阅读！
> 你必须通过 `notify_user` 工具（将 BlockedOnUser 设为 true）或其他同等能中断执行流的工具，向用户展示计划，并**强制等待用户的明确审批**。
>
> 以下情况也**不得跳过**此停止点：
> - 用户在初始请求中说了"完整审计"、"输出完整报告"或"不用确认直接做"
>
> **这是一个框架级防爆冲机制，如果不等待直接进行后续审计，视为严重违规！**

### S5: 深度审计

用户确认后执行。

**执行过程强制声明**:
进入 S5 时，你必须在回答中显式打印：
1. `【已加载语言模块】: 正在应用 languages/{lang}.md`
2. `【执行轨道A】: 进行控制建模...` 或 `【执行轨道B】: 进行数据流分析...`

> **S5 前置条件 — 未完成以下 Read 操作前不得开始审计：**
>
> 1. **Read** `languages/{lang}.md` （S2 识别出的主要语言，最多 2 个）
> 2. **Read** `core/security_controls.md` （轨道 A 方法论）
> 3. **Read** `core/taint_analysis.md` （轨道 B 方法论）
> 4. **Read** `core/anti_hallucination.md` （反幻觉规则）
> 5. **Read** `core/poc_generation.md` （PoC 模板，发现漏洞时使用）
>
> 如因上下文长度限制无法全部加载，至少加载第 1 项（语言模块）和第 4 项。

**轨道 A — 控制建模法 (50%)**:
> 详见 `core/security_controls.md`

缺失类: 敏感操作 − 应有控制 = 漏洞
- 枚举敏感操作 → 推导应有控制 → 验证存在性

**轨道 B — 数据流分析 (40%)**:
> 详见 `core/data_flow_methodology.md` + `core/taint_analysis.md`

注入类: Source → [无净化] → Sink = 漏洞
- Sink 排序(EALOC) → 反向追踪 → 净化检查

**补充 (10%)**: 配置审计 + 依赖审计

**补充 Skills 联动**（若已安装）：

> 以下为**条件触发的强制动作**。发现对应漏洞时**必须执行 Read**，不可跳过或假装已读。

**wooyun-legacy — 发现漏洞后必须 Read 对应案例文件**:

| 发现的漏洞类型 | **必须 Read** 的文件 | 在报告中必须引用 |
|--------------|---------|------|
| SQL 注入 | `wooyun-legacy/categories/sql-injection.md` | 至少 1 个案例编号 |
| XSS | `wooyun-legacy/categories/xss.md` | 至少 1 个案例编号 |
| 命令执行/RCE | `wooyun-legacy/categories/command-execution.md` 或 `rce.md` | 至少 1 个案例编号 |
| 文件上传/路径遍历 | `wooyun-legacy/categories/file-upload.md` 或 `file-traversal.md` | 至少 1 个案例编号 |
| SSRF | `wooyun-legacy/categories/ssrf.md` | 至少 1 个案例编号 |
| XXE | `wooyun-legacy/categories/xxe.md` | 至少 1 个案例编号 |
| 未授权访问 | `wooyun-legacy/categories/unauthorized-access.md` | 至少 1 个案例编号 |
| 逻辑漏洞/IDOR | `wooyun-legacy/categories/logic-flaws.md` | 至少 1 个案例编号 |

**约束规则**：
- 未发现对应漏洞时**不得读取**。单个审计最多查阅 **2-3 个分类**
- ⛔ **禁止虚报联动 (反幻觉核心)**：你必须在工具调用记录中真实执行了 `view_file` 或读取命令去读取 `~/.agents/skills/wooyun-legacy/...` 中的具体文件。如果工具调用历史中没有真实读取记录就在报告里声称参考了，这是极其严重的幻觉 (Hallucination) 违规！

**xianzhi-research — 思维卡住时必须 Read 对应文件**:

| 触发场景 | **必须 Read** 的文件 |
|---------|------|
| 轨道 B Sink→Source 追踪中断 | `xianzhi-research/references/web-injection.md` |
| 轨道 A 控制建模后无法确认漏洞影响 | `xianzhi-research/references/privilege-bypass.md` |
| deep 模式需要跨域攻击链推导 | `xianzhi-research/references/case-index.md` |

⛔ **同样禁止虚报**：必须真实调用工具读取了 `xianzhi-research` 目录下的文件，否则绝对禁止在报告中声明"参考了 xianzhi 方法论"。

### S6: 报告输出

验证覆盖率后按 `reporting/report_template.md` 输出综合审计报告。

🛡️ **强制规则 (PoC 生成)**:
报告中的 PoC 小节**必须**遵循 `core/poc_generation.md`，使用 ` ```http ` 完整数据包格式，禁止使用普通文本或代码段来描述 PoC 步骤。

| 前置条件 | standard | deep |
|---------|----------|------|
| D1-D3 全覆盖 | ✅ | ✅ |
| 高危 Sink 全追踪 | ✅ | ✅ |
| ≥ 8/10 维度覆盖 | — | ✅ |

---

## Anti-Hallucination Rules

> 详见 `core/anti_hallucination.md`

```
✗ 不猜测文件路径  ✗ 不编造代码  ✗ 不报告未读取文件的漏洞
✓ Read 验证存在   ✓ 引用实际代码  ✓ 匹配项目技术栈
核心: 宁漏勿误
```

## Anti-Confirmation-Bias Rules

```
✗ 不从经验出发   ✗ 不跳过低概率项  ✗ 不只查熟悉漏洞
✓ 枚举并逐一验证  ✓ 完成全部检查   ✓ 同等严谨
核心: 方法论驱动
```

---

## Reference Navigation

### 核心方法论（S5 开始前加载）

| 文件 | 用途 | 何时加载 |
|------|------|---------|
| `core/taint_analysis.md` | 污点追踪 + LSP | 轨道 B 开始前 |
| `core/security_controls.md` | 控制建模 | 轨道 A 开始前 |
| `core/data_flow_methodology.md` | 数据流分析 | 轨道 B 开始前 |
| `core/anti_hallucination.md` | 反幻觉详细规则 | S5 开始前 |
| `core/poc_generation.md` | PoC 生成 | 发现漏洞后 |
| `core/external_tools_guide.md` | 外部工具 | 需要工具辅助时 |

### 语言模块（按 S2 技术栈加载）

| 语言 | 文件 |
|------|------|
| Java | `languages/java.md` |
| Python | `languages/python.md` |
| Go | `languages/go.md` |
| PHP | `languages/php.md` |
| JavaScript | `languages/javascript.md` |
| C# | `languages/csharp.md` |
| C/C++ | `languages/c_cpp.md` |
| Ruby | `languages/ruby.md` |
| Rust | `languages/rust.md` |

### 安全领域（按审计维度加载）

| 维度 | 文件 |
|------|------|
| D2-D3 认证/授权 | `security/authentication_authorization.md` |
| D1 输入验证/XSS | `security/input_validation.md` |
| D5 文件操作 | `security/file_operations.md` |
| D7 加密 | `security/cryptography.md` |
| D9 竞态条件 | `security/race_conditions.md` |
| D9 业务逻辑 | `security/business_logic.md` |
| D10 供应链 | `security/dependencies.md` |
| API 安全 | `security/api_security.md` |

### 检查清单 & 报告

| 文件 | 用途 | 何时加载 |
|------|------|---------|
| `checklists/coverage_matrix.md` | 覆盖自检 | S6 前 |
| `checklists/universal_checklist.md` | 通用检查清单 | S5 补充 |
| `reporting/report_template.md` | 报告模板 | S6 |

### 推荐补充 Skills（可选，独立安装）

| Skill | 用途 | 安装 |
|-------|------|------|
| [wooyun-legacy](https://github.com/tanweai/wooyun-legacy) | 88,636 真实漏洞案例库 | `git clone` 到 Skills 目录 |
| [xianzhi-research](https://github.com/tanweai/xianzhi-research) | 安全研究元思考方法论 | `git clone` 到 Skills 目录 |
