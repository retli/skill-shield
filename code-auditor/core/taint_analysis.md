# 污点分析模块 — Taint Analysis Guide

> 污点分析是代码审计的核心方法论，追踪不可信数据从进入系统到触发危险操作的完整路径。

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Taint Analysis Flow                        │
│                                                                 │
│   Source ──→ Propagation ──→ Sanitizer? ──→ Sink               │
│   (污点源)    (传播路径)      (净化检查)     (汇聚点)            │
│                                                                 │
│   用户输入    变量赋值         过滤/转义      危险函数            │
│              函数参数          验证/编码      执行操作            │
│              返回值            白名单                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 与 EALOC 的集成

污点追踪应按 EALOC 层级分配精力：

| EALOC 层级 | 追踪策略 | 说明 |
|-----------|----------|------|
| **Tier1 (入口层)** ×1.0 | **完整正反向追踪** | Controller/Handler 是 Source 所在层，必须逐一确认每个参数的流向 |
| **Tier2 (业务层)** ×0.5 | **Sink 反向追踪** | 从 Sink 反向追到 Source，确认传播路径 |
| **Tier3 (模型层)** ×0.1 | **仅模式匹配** | 只用 grep 搜索敏感模式（硬编码密钥等），不做链路追踪 |

---

## 追踪策略

### 函数级 vs 变量级追踪

| 策略 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| **变量级追踪** | 精确、能识别净化点 | 易断链(反射/线程/回调) | 简单数据流 |
| **函数级追踪** | 稳定、不易断链 | 可能有误报 | 复杂调用关系 |

**推荐**: 先用函数级追踪建立调用链，再用变量级验证污点传播。

### BFS 反向追溯算法

```
算法: Sink 到 Source 的广度优先搜索

输入: sink_method, max_depth
输出: 所有到达 Source 的调用链

procedure TRACE_BACK(sink_method):
    queue = [(sink_method, [sink_method], 0)]
    visited = set()
    results = []

    while queue not empty:
        current, path, depth = queue.pop(0)

        if current in visited or depth > max_depth:
            continue
        visited.add(current)

        if is_source_method(current):  // 到达外部入口点
            results.append(path)
            continue

        for caller in get_callers(current):
            if not has_parameters(caller):
                continue  // 无参方法无法接收污点
            queue.append((caller, path + [caller], depth + 1))

    return results
```

---

## LSP 增强追踪

### 为什么 LSP 优于 Grep

| 方法 | 搜索 `sanitize` | 结果 |
|------|-----------------|------|
| **Grep** | `grep "sanitize"` | 匹配字符串、注释、变量名 (噪音大) |
| **LSP** | `findReferences(sanitize)` | **仅返回实际代码引用** (精确) |

### LSP 操作与审计场景

| LSP 操作 | 审计场景 | 使用示例 |
|----------|----------|----------|
| `goToDefinition` | **污点溯源** | 追踪变量来自哪里 |
| `findReferences` | **影响面分析** | 危险函数被哪些地方调用 |
| `goToImplementation` | **多态穿透** | 接口背后的实际实现 |
| `incomingCalls` | **攻击面映射** | 谁调用了 `executeQuery()` |
| `outgoingCalls` | **污点传播** | 该函数又调用了什么 |
| `documentSymbol` | **入口点枚举** | Controller 的所有方法 |
| `workspaceSymbol` | **全局搜索** | 找所有 `*Handler` 类 |

### 实战工作流：追踪 SQL 注入

```
Step 1: Grep 定位 Sink
  └─ grep "executeQuery" → UserDao.java:45 stmt.executeQuery(sql)

Step 2: LSP goToDefinition(sql)
  └─ 跳转到 sql 变量定义 → sql = buildQuery(userId) at line 42

Step 3: LSP goToDefinition(buildQuery)
  └─ 跳转到函数定义 → QueryHelper.java:20 发现字符串拼接

Step 4: LSP incomingCalls(executeQuery)
  └─ 找到 5 个调用点，2 个来自 Controller 层 (HTTP入口)

Step 5: 确认攻击路径
  └─ Controller → Service → DAO → executeQuery()
  └─ userId 来自 @RequestParam → 确认 Source
```

### LSP 与 Grep 协同策略

```
Phase 1: Grep 广度搜索
  ├─ 快速发现潜在危险点
  └─ 适用于: 初始侦察、模式匹配

Phase 2: LSP 深度分析
  ├─ 精确追踪数据流
  ├─ 分析调用关系
  └─ 适用于: 验证漏洞、追踪污点

回退策略: LSP 不可用时，使用 Grep + Read 组合
```

### 常见追踪模式

**模式 1: 危险函数调用点枚举**
```
1. Grep 快速定位一个调用点
2. LSP goToDefinition 跳转到定义
3. LSP findReferences 获取所有调用点
4. 对每个调用点进行污点分析
```

**模式 2: 数据验证函数有效性**
```
1. LSP findReferences(sanitize) 找到所有调用点
2. 对比 LSP findReferences(dangerousSink) 的调用点
3. 检查是否每个 Sink 调用前都有 sanitize
```

**模式 3: 接口实现全覆盖**
```
1. LSP goToImplementation(UserService.getUser)
2. 返回: UserServiceImpl, AdminUserService, CacheUserService
3. 对每个实现进行独立审计
```

---

## Sink Slot 类型分类

> 不同 Sink 位置需要不同的防护措施。

### SQL Sink Slot

| Slot | 代码特征 | 正确防护 | 无效防护 |
|------|----------|----------|----------|
| **SQL-val** | `WHERE col = ?` | 参数绑定 | — |
| **SQL-like** | `WHERE col LIKE ?` | 参数绑定 + 转义 `%_` | 仅参数绑定 |
| **SQL-num** | `LIMIT ?` | parseInt/类型转换 | 字符串绑定 |
| **SQL-ident** | `ORDER BY ${col}` | **白名单** | 参数绑定无效! |
| **SQL-table** | `FROM ${table}` | **白名单** | 参数绑定无效! |

### Command Slot

| Slot | 代码特征 | 正确防护 | 无效防护 |
|------|----------|----------|----------|
| **CMD-argument** | `cmd [arg]` | shell=False + 数组 | 黑名单 |
| **CMD-string** | `"cmd ${input}"` | shlex.quote/白名单 | 简单转义 |

### File Slot

| Slot | 代码特征 | 正确防护 | 无效防护 |
|------|----------|----------|----------|
| **FILE-path** | 路径拼接 | resolve() + 边界检查 | `../` 黑名单 |
| **FILE-include** | 动态包含 | 白名单路径 | 协议过滤 |

### Template Slot

| Slot | 代码特征 | 正确防护 | 无效防护 |
|------|----------|----------|----------|
| **TMPL-content** | 模板渲染 | autoescape | — |
| **TMPL-expr** | `{{ expr }}` | 沙箱 | 简单过滤 |

### 审计时的 Slot 检查流程

```
1. 识别 Sink 点
2. 确定 Slot 类型 (val/ident/argument/path/...)
3. 检查实际使用的防护措施
4. 验证防护措施是否匹配 Slot 类型
5. 不匹配 → 报告潜在漏洞
```

---

## 净化后拼接检测

### 反模式

"净化后拼接"指: 数据经过净化后，在到达 sink 之前又与**未净化数据**拼接。

### 检测流程

```
1. 定位 sanitizer 调用: escape(), htmlspecialchars()
2. 标记净化后变量为 "sanitized"
3. 追踪到 sink 路径
4. 检查路径上是否有字符串拼接
5. 若拼接引入未净化数据 → 报告漏洞
6. 若净化上下文不匹配 → 报告漏洞
```

### 危险模式示例

**净化后与未净化数据拼接**:
```python
user_id = escape_sql(request.args.get('id'))   # sanitized
table = request.args.get('table')               # NOT sanitized!
query = f"SELECT * FROM {table} WHERE id = {user_id}"  # 危险!
```

**净化上下文不匹配**:
```python
user_input = html_escape(request.args.get('data'))  # HTML sanitized
script = f"<script>var data = '{user_input}';</script>"  # JS 上下文!
```

### 审计检查点

- [ ] 追踪**所有**到达 sink 的变量，不仅仅是用户输入
- [ ] 检查每个拼接操作是否引入未净化数据
- [ ] 验证净化函数与 sink 上下文是否匹配
- [ ] 检查净化后是否有破坏性的二次处理

---

## 污点分析报告模板

```markdown
## [严重程度] 漏洞类型 - 文件名:行号

### Source (污点源)
位置: `file:行号`
类型: [HTTP参数 / Cookie / Header / 文件读取]
代码: (引用实际代码)

### Taint Propagation (传播路径)
[Step 1] file:行号 → 污点引入
    ↓
[Step 2] file:行号 → 污点传递 (未净化)
    ↓
[Step 3] file:行号 → 污点到达 Sink

传播链: X 行代码 / X 个函数 / X 个文件

### Sink (汇聚点)
位置: `file:行号`
类型: [SQL执行 / 命令执行 / 反序列化]
Slot 类型: [SQL-val / SQL-ident / CMD-arg / ...]

### 分析结论
| 分析项 | 结果 |
|--------|------|
| 污点源可控性 | 完全可控 / 部分可控 / 需特定条件 |
| 净化措施 | 无 / 有但可绕过 / 有效 |
| Slot 匹配 | 防护匹配 / 防护不匹配 |
| 利用复杂度 | 简单 / 中等 / 复杂 |
| 需要认证 | 是 / 否 |
```

---

## 函数上下文分析

### Caller 分析 (谁调用了目标函数)

```
对每个调用点:
1. 调用参数是什么?
   - 硬编码常量 → 安全
   - 局部变量 → 继续追踪来源
   - 函数参数 → 继续追踪调用者
   - 用户输入 → 找到 Source!

2. 调用上下文:
   - Controller/Handler → 可能是入口点
   - Service/Util → 继续追踪
   - 测试代码 → 通常可忽略
```

### Callee 分析 (目标函数调用了谁)

```
1. 读取函数完整代码
2. 提取所有函数调用
3. 分类:
   ├─ 危险函数 (Sink) → 标记风险
   ├─ 数据处理 → 分析是否传递污点
   ├─ 验证函数 → 检查是否有效净化
   └─ 工具函数 → 递归分析
```

### 使用 Grep 追踪

```bash
# 查找变量定义
grep -n "variableName\s*=" file.ext
# 查找函数调用
grep -rn "functionName(" --include="*.ext"
# 查找函数定义
grep -rn "def functionName\|function functionName" *.ext
```

### 使用 LSP 追踪

```
1. goToDefinition: 跳转到变量/函数定义
2. findReferences: 查找所有引用位置
3. incomingCalls: 查找调用者
4. outgoingCalls: 查找被调用函数
```
