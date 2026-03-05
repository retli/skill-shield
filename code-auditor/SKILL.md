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

→ 输出: `[MODE] {standard|deep}`

### S2: 项目画像 + EALOC

执行攻击面测绘和 EALOC 分层。

→ 输出: `[RECON]` 技术栈+入口点 + `[EALOC]` 三层统计

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

**⚠️ STOP — 等待用户确认后才进入 S5。**

### S5: 深度审计

用户确认后执行。**必须先加载核心方法论和对应语言模块。**

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

> 以下为**条件触发**，仅在发现对应漏洞时读取，不要无差别加载。

**wooyun-legacy — 按发现类型查阅案例**:

| 发现的漏洞类型 | 读取文件 | 用途 |
|--------------|---------|------|
| SQL 注入 | `wooyun-legacy/categories/sql-injection.md` | 确认绕过方式、二次注入模式 |
| XSS | `wooyun-legacy/categories/xss.md` | 确认存储型/DOM型利用链 |
| 命令执行/RCE | `wooyun-legacy/categories/command-execution.md` + `rce.md` | 确认利用可行性 |
| 文件上传/路径遍历 | `wooyun-legacy/categories/file-upload.md` + `file-traversal.md` | 绕过方式参考 |
| SSRF | `wooyun-legacy/categories/ssrf.md` | 协议绕过、内网探测 |
| XXE | `wooyun-legacy/categories/xxe.md` | 确认 OOB 利用 |
| 未授权访问/认证缺失 | `wooyun-legacy/categories/unauthorized-access.md` | 真实未授权案例 |
| 逻辑漏洞/IDOR | `wooyun-legacy/categories/logic-flaws.md` | 业务逻辑绕过模式 |

⚠️ **不要查阅**：未发现对应漏洞时不读取案例文件。单个审计最多查阅 2-3 个分类。

**xianzhi-research — 思维卡住时调用**:

仅在以下场景读取 `xianzhi-research/references/` 对应文件：
- 轨道 B **Sink→Source 追踪中断**（净化函数不确定）→ 读 `web-injection.md`（边界探索方法）
- 轨道 A **控制建模后无法确认漏洞影响** → 读 `privilege-bypass.md`（提权/绕过思路）
- deep 模式下需要 **跨域攻击链推导** → 读 `case-index.md`（CVE 组合利用参考）

### S6: 报告输出

验证覆盖率后按 `reporting/report_template.md` 输出。

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
