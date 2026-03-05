# API 安全

> 覆盖 REST API / GraphQL / gRPC 安全审计

---

## REST API 安全

### 审计要点

| 检查项 | 风险 | 检测 |
|--------|------|------|
| 认证机制 | API Key/JWT/OAuth 安全性 | 见 authentication_authorization.md |
| 限流 | 暴力破解/DoS | Rate limit 配置 |
| 输入验证 | 注入/非法数据 | Schema 验证 |
| 批量赋值 | Mass Assignment | 白名单字段 |
| 错误泄露 | 堆栈/内部信息 | Error handler |
| CORS | 跨域资源泄露 | CORS 配置 |
| 版本管理 | 老版本无修复 | 版本路由 |

### 检测命令

```bash
# CORS 配置
grep -rn "Access-Control-Allow-Origin\|@CrossOrigin\|cors\|CORS" --include="*.java" --include="*.py" --include="*.js" --include="*.go"
# 危险: Allow-Origin: * + Allow-Credentials: true

# Rate Limiting
grep -rn "RateLimit\|rate.?limit\|throttle\|bucket\|limiter" --include="*.java" --include="*.py" --include="*.js" --include="*.go"

# 错误处理
grep -rn "printStackTrace\|traceback\|stack.?trace\|e\.message\|err\.Error" --include="*.java" --include="*.py" --include="*.js" --include="*.go"

# 输入大小限制
grep -rn "maxBodySize\|MAX.*SIZE\|content.?length\|upload.*limit" --include="*.java" --include="*.py" --include="*.js"

# API Key 管理
grep -rn "api.?key\|API_KEY\|apiKey\|x-api-key" --include="*.java" --include="*.py" --include="*.js" --include="*.yml" --include="*.properties"
```

### 批量赋值检测

```bash
# Java — Spring
grep -rn "@RequestBody\|@ModelAttribute" --include="*.java"
# 检查: 是否使用 DTO 还是直接实体?
# 危险: 用户可传递 role/isAdmin 等敏感字段

# Python — Django
grep -rn "request\.POST\|request\.data\|serializer\.\(is_valid\|save\)" --include="*.py"
# 检查: Serializer 是否限制 fields?
# 危险: fields = '__all__'

# Node.js
grep -rn "Object\.assign\|spread.*req\.body\|\.create.*req\.body\|{.*\.\.\.req\.body" --include="*.js" --include="*.ts"
```

---

## GraphQL 安全

### 审计要点

| 检查项 | 风险 | CWE |
|--------|------|-----|
| 内省开启 | Schema 泄露 | 200 |
| 深度无限 | 查询拒绝服务 | 400 |
| 批量查询 | 性能拒绝服务 | 400 |
| 字段级权限 | 未授权数据访问 | 862 |
| N+1 问题 | 性能放大 | 400 |

```bash
# 查找 GraphQL 配置
grep -rn "graphql\|GraphQL\|gql\|schema\|Query\|Mutation\|Resolver" --include="*.java" --include="*.py" --include="*.js" --include="*.ts"

# 内省检查
grep -rn "introspection\|__schema\|schemaDirective" --include="*.java" --include="*.py" --include="*.js" --include="*.yml"

# 深度限制
grep -rn "maxDepth\|depthLimit\|queryDepth\|maxComplexity" --include="*.java" --include="*.py" --include="*.js"
```

---

## 审计清单

- [ ] CORS 配置非 `*`（或有 Credentials 时非 `*`）
- [ ] 有速率限制
- [ ] 错误响应不包含堆栈跟踪
- [ ] 使用 DTO/Schema 防批量赋值
- [ ] GraphQL 生产环境禁用内省
- [ ] GraphQL 有查询深度限制
- [ ] 大型列表接口有分页
