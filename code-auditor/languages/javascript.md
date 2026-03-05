# JavaScript/Node.js Security Audit — Complete Reference

> 适用: Node.js, Express, Koa, NestJS, Fastify, React, Vue, Angular

---

## Source
```javascript
// Express
req.query.param      // GET 参数
req.body.param        // POST body
req.params.id         // 路径参数
req.headers['x-custom']
req.cookies.name
req.file / req.files  // multer

// NestJS
@Query('param'), @Body(), @Param('id'), @Headers('x-custom')

// Koa
ctx.query.param, ctx.request.body, ctx.params.id

// 前端
location.search, location.hash, document.cookie
window.name, document.referrer, postMessage data
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险函数 |
|----------|-----|---------|----------|
| 代码执行 | 94 | Critical | eval, Function(), vm.runInContext |
| 命令执行 | 78 | Critical | child_process.exec/spawn |
| 原型污染 | 1321 | Critical | merge, defaultsDeep, Object.assign |
| XSS | 79 | High | innerHTML, dangerouslySetInnerHTML |
| SQL注入 | 89 | Critical | query + 模板字符串拼接 |
| 路径遍历 | 22 | High | fs.readFile + user input |
| 反序列化 | 502 | Critical | node-serialize, js-yaml |
| SSRF | 918 | High | axios, fetch, http.request |
| Regex DoS | 1333 | Medium | 恶意正则 + 用户输入 |

## Sink 检测命令

```bash
# 代码执行
grep -rn "\beval\s*(\|\bFunction\s*(\|vm\.run\|vm\.createContext\|new Function" --include="*.js" --include="*.ts"

# 命令执行
grep -rn "child_process\.\(exec\|execSync\|execFile\|spawn\|spawnSync\|fork\)\|require.*child_process\|execSync\|spawnSync" --include="*.js" --include="*.ts"

# 原型污染 — Node.js 特有高危
grep -rn "__proto__\|constructor\[.*\]\|Object\.assign\|\.merge\s*(\|defaultsDeep\|extend\s*(\|deepmerge\|\.\.\.\s*req\.body\|spread\s*(" --include="*.js" --include="*.ts"
# 攻击: {"__proto__": {"isAdmin": true}}
# 危险的库: lodash < 4.17.21, merge-deep, minimist < 1.2.6

# XSS
grep -rn "\.innerHTML\s*=\|\.outerHTML\s*=\|dangerouslySetInnerHTML\|document\.write\s*(\|v-html\|\[innerHTML\]" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.vue"

# SQL 注入
grep -rn "query\s*(.*\$\{\|query\s*(.*\+\|execute\s*(.*\+\|raw\s*(.*\+" --include="*.js" --include="*.ts"
# 安全: query('SELECT * WHERE id = ?', [id])
# 安全: query('SELECT * WHERE id = $1', [id])

# 文件操作
grep -rn "fs\.\(readFile\|writeFile\|readFileSync\|writeFileSync\|unlink\|createReadStream\|createWriteStream\|existsSync\)" --include="*.js" --include="*.ts" | grep -E "req\.|user|param|query|body"

# SSRF
grep -rn "axios\.\(get\|post\|put\|delete\|request\)\|fetch\s*(\|http\.request\|https\.request\|got\s*(\|node-fetch\|undici" --include="*.js" --include="*.ts" | grep -E "req\.|user|param|body|query"

# 反序列化
grep -rn "serialize\|unserialize\|node-serialize\|js-yaml\.load\b" --include="*.js" --include="*.ts"
# YAML: 安全用 js-yaml.load(data, { schema: js-yaml.FAILSAFE_SCHEMA })

# Regex DoS
grep -rn "new RegExp\s*(\|\.match\s*(\|\.replace\s*(\|\.test\s*(" --include="*.js" --include="*.ts" | grep -E "req\.|user|param|input"
```

## Express/NestJS 专项

```bash
# 路由列表
grep -rn "app\.\(get\|post\|put\|delete\|patch\)\|router\.\(get\|post\|put\|delete\)" --include="*.js" --include="*.ts"

# 无认证路由
grep -rn "router\.\(post\|put\|delete\)" --include="*.js" --include="*.ts" | grep -v "auth\|passport\|jwt\|guard\|middleware"

# 安全中间件
grep -rn "helmet\|cors\|csurf\|express-rate-limit\|hpp\|express-validator" --include="*.js" --include="*.ts" --include="package.json"

# NestJS Guards
grep -rn "@UseGuards\|@Public\|AuthGuard\|RolesGuard" --include="*.ts"

# JWT 配置
grep -rn "jwt\|jsonwebtoken\|sign\|verify\|JwtModule\|JwtStrategy" --include="*.js" --include="*.ts"
```

## React/Vue 前端专项

```bash
# React XSS
grep -rn "dangerouslySetInnerHTML\|__html" --include="*.jsx" --include="*.tsx"
grep -rn "href=\s*{" --include="*.jsx" --include="*.tsx" | grep -v "sanitize\|encodeURI"

# Vue XSS
grep -rn "v-html" --include="*.vue"

# 前端敏感信息
grep -rn "API_KEY\|SECRET\|TOKEN\|api[_-]key" --include="*.js" --include="*.ts" --include="*.env"
```

## 审计清单

### 🔴 Critical
- [ ] eval/Function 执行用户输入
- [ ] child_process.exec 命令注入
- [ ] 原型污染（merge/assign + 用户输入）
- [ ] SQL 模板字符串注入
- [ ] node-serialize 反序列化

### 🟡 High
- [ ] innerHTML/dangerouslySetInnerHTML XSS
- [ ] fs 操作路径遍历
- [ ] HTTP 请求 SSRF
- [ ] Regex DoS (ReDoS)
- [ ] JWT secret 硬编码

### 🔵 配置
- [ ] Helmet 安全头
- [ ] CORS 配置
- [ ] CSRF 防护
- [ ] Rate Limiting
- [ ] 前端无硬编码 API Key
