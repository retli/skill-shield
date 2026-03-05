# Go Security Audit — Complete Reference

> 适用: Go 1.16+, Gin, Echo, Fiber, Chi, net/http

---

## Source
```go
// net/http
r.URL.Query().Get("param")    // Query
r.FormValue("param")           // Form
r.PostFormValue("param")       // POST Form
r.Body                         // Body
r.Header.Get("X-Custom")      // Header
r.Cookie("name")               // Cookie

// Gin
c.Query("param")               // Query
c.PostForm("param")            // Form
c.Param("id")                  // Path
c.GetHeader("X-Custom")       // Header
c.ShouldBindJSON(&body)        // JSON Body

// Echo
c.QueryParam("param")
c.FormValue("param")
c.Param("id")
c.Bind(&body)
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险函数 |
|----------|-----|---------|----------|
| SQL注入 | 89 | Critical | db.Query/Exec + fmt.Sprintf |
| 命令执行 | 78 | Critical | exec.Command |
| SSRF | 918 | High | http.Get/Post, http.NewRequest |
| 路径遍历 | 22 | High | os.Open, filepath.Join |
| 模板注入 | 79 | High | template.HTML |
| 竞态条件 | 362 | High | goroutine 无同步 |
| 反序列化 | 502 | Medium | json/xml/gob.Unmarshal |

## Sink 检测命令

```bash
# SQL 注入 — Go 最常见漏洞
grep -rn "db\.\(Query\|QueryRow\|Exec\)\|Sprintf.*SELECT\|Sprintf.*INSERT\|Sprintf.*UPDATE\|Sprintf.*DELETE\|Sprintf.*WHERE\|Sprintf.*ORDER" --include="*.go"
# 安全: db.Query("SELECT ... WHERE id = ?", id)
# 危险: db.Query(fmt.Sprintf("SELECT ... WHERE id = %s", id))

# 命令执行
grep -rn "exec\.Command\|exec\.CommandContext\|os\.StartProcess" --include="*.go"

# SSRF
grep -rn "http\.\(Get\|Post\|Head\)\|http\.NewRequest\|client\.Do\|client\.Get" --include="*.go"

# 文件操作
grep -rn "os\.Open\|os\.Create\|os\.ReadFile\|os\.WriteFile\|ioutil\.ReadFile\|ioutil\.WriteFile" --include="*.go"
grep -rn "filepath\.Join\|path\.Join" --include="*.go" | grep -E "param\|query\|input\|c\.\|r\."

# 竞态条件
grep -rn "go\s\+func\|go\s\+\w" --include="*.go"
grep -rn "sync\.Mutex\|sync\.RWMutex\|sync\.WaitGroup\|atomic\.\|sync\.Map" --include="*.go"
# 运行检测: go build -race ./...

# 模板安全
grep -rn "template\.HTML\|template\.JS\|template\.URL\|template\.CSS" --include="*.go"
# template.HTML() 跳过转义 — 若参数可控则 XSS

# 反序列化
grep -rn "json\.Unmarshal\|json\.NewDecoder\|gob\.NewDecoder\|xml\.Unmarshal\|yaml\.Unmarshal" --include="*.go"

# defer 缺失
grep -rn "os\.Open\|sql\.Open\|net\.Dial" --include="*.go" -A 5 | grep -v "defer"
```

## Gin/Echo 框架专项

```bash
# 路由列表
grep -rn "r\.\(GET\|POST\|PUT\|DELETE\)\|g\.\(GET\|POST\)" --include="*.go"
grep -rn "e\.\(GET\|POST\|PUT\|DELETE\)" --include="*.go"

# 认证中间件
grep -rn "middleware\|authMiddleware\|JWTAuth\|BasicAuth\|AuthRequired" --include="*.go"

# CORS 配置
grep -rn "cors\.\|Access-Control-Allow-Origin\|AllowOrigins\|AllowAllOrigins" --include="*.go"
```

## Go 特有漏洞

### 竞态条件 (高频)
```
检测: go build -race ./...
重点:
  1. 共享变量无锁访问 (特别是 map)
  2. goroutine 内修改全局状态
  3. channel 使用不当导致死锁
```

### 整数溢出
```bash
grep -rn "int32\|int16\|int8\|uint" --include="*.go" | grep -E "strconv\.Atoi\|parseInt"
# Go 的 strconv.Atoi 返回 int (平台相关), 转 int32 可能溢出
```

## 审计清单

### 🔴 Critical
- [ ] SQL 使用 fmt.Sprintf 拼接
- [ ] exec.Command 参数可控

### 🟡 High
- [ ] http.Get URL 可控（SSRF）
- [ ] filepath.Join 路径遍历
- [ ] goroutine 竞态条件
- [ ] template.HTML 非转义输出
- [ ] 整数溢出 (int → int32)

### 🔵 配置
- [ ] CORS 配置
- [ ] TLS 配置
- [ ] defer 缺失（资源泄露）
