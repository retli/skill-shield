# 数据流分析方法论 — 轨道 B

> 数据流分析发现的是"注入类"漏洞: Source → [无净化] → Sink = 漏洞

## 核心公式

```
注入类漏洞 = Source → [无有效净化] → Sink

1. 定位所有 Sink 点 (scan_sinks.py 粗筛 + grep 补充)
2. 按 EALOC 权重排序 Sink
3. 从 Sink 反向追踪数据流到 Source
4. 在传播路径上检查净化措施
5. 无净化 / 可绕过 / slot 类型不匹配 → 报告漏洞
```

## 与 EALOC 的集成

```
Sink 处理优先级:
  1. Tier1 中的 Sink → 直接接触用户输入，最可能有漏洞
  2. Tier2 中的 Sink → 需确认上游是否传入用户数据
  3. Tier3 中的 Sink → 仅粗扫，极少有可利用漏洞
```

---

## Step 1: Sink 定位

### 自动粗筛

```bash
python3 "$SKILL_DIR/scripts/scan_sinks.py" "$PROJECT_ROOT"
```

### 手动补充 (按语言加载对应 languages/*.md)

根据 S2 识别的技术栈，加载对应语言模块中的 grep 命令进行补充扫描。

### Sink 分类优先级

| 优先级 | Sink 类型 | 原因 |
|--------|----------|------|
| P0 | RCE (命令执行/反序列化/JNDI) | 服务器完全沦陷 |
| P1 | SQL 注入 | 数据泄露/操纵 |
| P2 | 任意文件读写 | 信息泄露/代码执行 |
| P3 | SSRF | 内网穿透 |
| P4 | XSS/SSTI | 客户端攻击/服务端 RCE |
| P5 | 信息泄露 | 敏感数据暴露 |

---

## Step 2: 反向追踪

### 追踪流程

```
给定 Sink: stmt.executeQuery(sql) at UserDao.java:45

1. 提取 Sink 变量: sql
2. 在当前函数内向上搜索 sql 的定义
   → String sql = buildQuery(userId) at line 42
3. 追踪 buildQuery 函数定义
   → 在 QueryHelper.java:20 发现拼接
4. 追踪 userId 参数来源
   → 来自 Service.getUserById(id)
5. 继续追踪到 Controller
   → @RequestParam String id → 确认为 Source
```

### 追踪操作

**使用 LSP (优先)**:
```
1. LSP goToDefinition(sql) → 变量定义
2. LSP goToDefinition(buildQuery) → 函数定义
3. LSP incomingCalls(executeQuery) → 所有调用者
```

**使用 Grep (回退)**:
```bash
grep -n "sql\s*=" UserDao.java
grep -rn "buildQuery(" --include="*.java"
grep -rn "executeQuery(" --include="*.java"
```

---

## Step 3: 净化检查

### 净化有效性判定

| 检查项 | 有效 | 无效/可绕过 |
|--------|------|------------|
| SQL 参数化 | `PreparedStatement + ?` | `Statement + 拼接` |
| SQL 列名/表名 | 白名单验证 | 参数绑定 (无效!) |
| 命令注入 | `shell=False + 数组参数` | 黑名单过滤 |
| 路径遍历 | `resolve() + startsWith()` | `../` 黑名单 |
| XSS | 自动转义模板 | 手动 `html_escape` 后拼 JS |
| SSRF | IP 白名单 + 协议白名单 | 仅 hostname 检查 (DNS rebinding) |

### 净化后拼接检测（关键）

参见 `core/taint_analysis.md` — "净化后拼接检测"章节。

---

## Step 4: 攻击链推导 (仅 deep 模式)

```
对每个 Critical/High 漏洞，执行链式推导:
1. 前置条件 → 需要认证? → 有无认证绕过可串联?
2. 利用结果 → 信息泄露/代码执行/权限提升?
3. 结果转化 → 该结果能否作为下一个漏洞的输入?
4. 迭代延伸 → 重复 2-3 直到无法扩展
5. 整体评估 → 组合影响 > 单个漏洞影响?

优先级: RCE > 任意文件读写 > 认证绕过 > 注入 > 信息泄漏
```

---

## Source 速查 (通用)

| 语言 | 主要 Source |
|------|-----------|
| Java | `request.getParameter()`, `@RequestParam`, `@RequestBody` |
| Python | `request.args`, `request.form`, `request.json` |
| Go | `r.URL.Query()`, `c.Query()`, `c.PostForm()` |
| PHP | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` |
| Node.js | `req.query`, `req.body`, `req.params` |
| C# | `Request.Query`, `[FromBody]`, `[FromQuery]` |

## Sink 速查 (通用)

| 类型 | 严重程度 | 典型函数 |
|------|---------|---------|
| RCE | Critical | `exec()`, `system()`, `eval()` |
| 反序列化 | Critical | `readObject()`, `pickle.loads()`, `unserialize()` |
| SQL注入 | Critical | `executeQuery()`, `cursor.execute()`, `db.Query()` |
| SSRF | High | `HttpClient`, `requests.get()`, `http.Get()` |
| XXE | High | `DocumentBuilder.parse()`, `SAXParser.parse()` |
| 路径遍历 | High | `new File()`, `open()`, `os.Open()` |
| XSS | Medium | `response.write()`, `innerHTML`, `echo` |
