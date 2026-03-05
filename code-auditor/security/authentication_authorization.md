# 认证与授权安全

> 覆盖矩阵: D2 认证 + D3 授权

---

## 认证安全

### 审计要点

| 检查项 | 风险 | grep 关键词 |
|--------|------|------------|
| 密码存储 | 明文/弱哈希 | `MD5\|SHA1\|password.*=\|encode\|encrypt` |
| 密码策略 | 弱密码放行 | `minLength\|password.*length\|validate.*password` |
| 登录限流 | 暴力破解 | `loginAttempt\|lockout\|rateLimit\|throttle` |
| Session 管理 | 会话固定/劫持 | `session\|JSESSIONID\|cookie\|httpOnly\|secure` |
| JWT 安全 | 签名绕过/泄露 | `jwt\|jsonwebtoken\|sign\|verify\|HS256\|RS256\|none` |
| 多因素认证 | 缺失/可绕过 | `mfa\|totp\|2fa\|two.?factor\|otp` |
| 记住我 | 令牌可预测 | `remember\|persistent\|auto.?login` |
| 密码重置 | 令牌可预测/不过期 | `reset.*password\|forgot.*password\|token.*expir` |
| OAuth/OIDC | state缺失/redirect绕过 | `oauth\|oidc\|redirect_uri\|state\|authorization_code` |

### 密码存储审计

```bash
# 查找密码相关代码
grep -rn "password\|passwd\|credential\|secret" --include="*.java" --include="*.py" --include="*.go" --include="*.php"

# 弱哈希算法
grep -rn "MD5\|SHA-?1\b\|DES\b\|Base64.*password" --include="*.java" --include="*.py"

# 安全哈希 (应该看到这些)
grep -rn "BCrypt\|Argon2\|PBKDF2\|scrypt\|bcrypt\|pbkdf2" --include="*.java" --include="*.py" --include="*.go"
```

### JWT 审计

```bash
# JWT 配置
grep -rn "jwt\|JsonWebToken\|JwtUtil\|JwtHelper" --include="*.java" --include="*.py" --include="*.js"

# 算法选择 (检查是否允许 none)
grep -rn "algorithm\|HS256\|RS256\|alg.*none" --include="*.java" --include="*.py" --include="*.js"

# Secret 密钥 (是否硬编码)
grep -rn "secret\|signing.?key\|jwt.?key" --include="*.java" --include="*.py" --include="*.properties" --include="*.yml"

# 常见漏洞
# 1. 允许 alg: "none"
# 2. HS256 secret 太短 (< 32 bytes)
# 3. RS256 → HS256 混淆攻击
# 4. JWT 不设过期时间
# 5. 敏感信息存储在 payload 中
```

### Session 管理审计

```bash
# Session 配置
grep -rn "session\|Session\|setMaxInactiveInterval\|SESSION_COOKIE\|session_lifetime" --include="*.java" --include="*.py" --include="*.properties" --include="*.yml" --include="*.php"

# Cookie 安全属性
grep -rn "httpOnly\|secure\|sameSite\|HttpOnly\|Secure\|SameSite" --include="*.java" --include="*.py" --include="*.js" --include="*.php"

# 检查项:
# 1. Session ID 是否足够随机 (>= 128 bit)
# 2. 登录后是否重新生成 Session ID
# 3. Cookie 是否设置 HttpOnly + Secure + SameSite
# 4. Session 超时是否合理 (建议 <= 30min)
```

---

## 授权安全

### 审计要点

| 检查项 | 漏洞 | CWE | 检测方法 |
|--------|------|-----|---------|
| 垂直越权 | 低权限访问高权限功能 | 285 | 检查授权注解/中间件 |
| 水平越权 (IDOR) | 访问他人资源 | 639 | 检查资源归属验证 |
| 功能级权限 | 前端隐藏后端无保护 | 862 | 对比路由与权限配置 |
| 角色层级 | 角色继承不当 | 269 | 检查角色模型 |

### 授权遗漏检测

```bash
# Java — 查找无认证注解的敏感方法
grep -rn "@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java" -B 5 | grep -v "@PreAuthorize\|@Secured\|@RolesAllowed"

# Python — 查找无装饰器的视图
grep -rn "def post\|def put\|def delete" --include="*.py" -B 5 | grep -v "@login_required\|@permission_required\|@admin_required"

# Go — 查找无中间件的路由
grep -rn "\.POST\|\.PUT\|\.DELETE" --include="*.go" | grep -v "auth\|Auth\|middleware"

# Node.js — 查找无中间件的路由
grep -rn "router\.\(post\|put\|delete\)\|app\.\(post\|put\|delete\)" --include="*.js" --include="*.ts" | grep -v "auth\|passport\|jwt\|guard"
```

### IDOR 检测

```bash
# 查找 ID 参数接口
grep -rn "@PathVariable\|@RequestParam.*[Ii]d\|params\[:id\]\|req\.params\.id" --include="*.java" --include="*.py" --include="*.rb" --include="*.js"

# 重点检查:
# 1. 数据库查询是否加了 owner/user_id 条件
# 2. Service 层是否验证资源归属
# 3. 是否存在可猜测的顺序 ID (应使用 UUID)
```

### 常见授权绕过手法

| 手法 | 说明 | 检测 |
|------|------|------|
| HTTP 方法绕过 | GET 有检查 POST 没有 | 对比同路由不同方法的权限 |
| 路径大小写 | `/Admin` vs `/admin` | 检查路由匹配是否大小写敏感 |
| 参数覆盖 | `role=admin` 参数注入 | 检查 Mass Assignment |
| API 版本 | `/v1/admin` 无检查 | 检查老版本 API 路由 |
| 直接对象引用 | 改 URL 中的 ID | IDOR 检测 |

---

## 审计清单

### 认证
- [ ] 密码使用 Bcrypt/Argon2/PBKDF2 存储
- [ ] 登录接口有速率限制
- [ ] Session ID 登录后重新生成
- [ ] Cookie 设置 HttpOnly + Secure + SameSite
- [ ] JWT 不允许 alg: none
- [ ] JWT secret 足够强（≥32 bytes）
- [ ] 密码重置 token 有时效且一次性

### 授权
- [ ] 所有敏感端点有认证检查
- [ ] 数据访问操作有归属验证（防 IDOR）
- [ ] 管理功能有角色检查
- [ ] 前端隐藏的功能后端也有权限控制
