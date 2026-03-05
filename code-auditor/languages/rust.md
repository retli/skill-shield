# Rust Security Audit — Complete Reference

> 适用: Rust, Actix-web, Rocket, Axum, Warp, Tokio

---

## Source
```rust
// Actix-web
web::Query::<Params>::from_query(&req)
web::Json::<Body>::extract(&req)
web::Path::<(String,)>::extract(&req)
req.headers().get("X-Custom")

// Axum
Query(params): Query<Params>
Json(body): Json<Body>
Path(id): Path<String>
headers: HeaderMap
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险模式 |
|----------|-----|---------|----------|
| unsafe 代码 | 787 | High | unsafe {} 块 |
| 命令执行 | 78 | High | Command::new |
| FFI 边界 | 119 | High | extern "C", CString |
| panic 路径 | — | Medium | unwrap(), expect(), 直接索引 |
| SQL注入 | 89 | Critical | format!() + query |
| 路径遍历 | 22 | High | PathBuf + user input |
| 整数溢出 | 190 | Medium | as 转换 (release mode) |
| SSRF | 918 | High | reqwest + user URL |

## Sink 检测命令

```bash
# unsafe 块 — Rust 审计重点
grep -rn "\bunsafe\s*{" --include="*.rs"
# unsafe 块内需要人工审计:
# 1. 原始指针解引用
# 2. FFI 调用
# 3. 可变引用别名
# 4. 内存布局假设

# 命令执行
grep -rn "Command::new\|std::process::Command" --include="*.rs"
# 检查: arg() 参数是否来自用户输入

# FFI 边界
grep -rn 'extern\s*"C"' --include="*.rs"
grep -rn "CString\|CStr\|from_raw\|into_raw\|as_ptr\|from_raw_parts" --include="*.rs"
# FFI 调用跳过 Rust 所有权系统 — 是安全审计重点

# panic 路径
grep -rn "\.unwrap()\|\.expect(" --include="*.rs"
grep -rn "\[.*\]" --include="*.rs" | grep -v "\.get(\|\.get_mut("
# 生产代码应使用 ? 或 match/if let 替代 unwrap

# SQL 注入
grep -rn "format!\|query\s*(" --include="*.rs" | grep "format!"
grep -rn "execute\s*(" --include="*.rs" | grep "format!"
# 安全: sqlx::query("SELECT ... WHERE id = $1").bind(id)
# 危险: sqlx::query(&format!("SELECT ... WHERE id = {}", id))

# 文件操作
grep -rn "File::open\|File::create\|std::fs::\|tokio::fs::" --include="*.rs" | grep -E "format!|user|param|input"

# 原始指针
grep -rn "\*const\s\|\*mut\s\|NonNull\|Box::into_raw\|Box::from_raw" --include="*.rs"

# 整数转换
grep -rn "\bas\s\+u\|as\s\+i\|as\s\+usize\|as\s\+isize" --include="*.rs"
# release mode 不检查溢出! debug mode 会 panic

# SSRF
grep -rn "reqwest::\|hyper::\|surf::" --include="*.rs" | grep -E "format!\|user\|param\|input"

# Send/Sync 自定义实现
grep -rn "unsafe impl\s\+Send\|unsafe impl\s\+Sync" --include="*.rs"
# 不正确的实现可能导致数据竞态
```

## Rust 特有安全点

### unsafe 审计清单
```
□ 原始指针是否验证了非 null？
□ 原始指针是否验证了对齐？
□ FFI 函数的参数边界是否正确？
□ 可变引用是否有别名？
□ 内存是否正确释放？(不重复释放)
□ 生命周期假设是否正确？
```

### 安全替代

| 危险 | 安全替代 |
|------|----------|
| `.unwrap()` | `.unwrap_or()`, `.unwrap_or_default()`, `?`, `if let` |
| `arr[i]` | `arr.get(i)`, `arr.get(i).ok_or(err)?` |
| `as u32` | `.try_into()?.`, `u32::try_from()?` |
| `*const T` | `&T` 引用 |
| `*mut T` | `&mut T` 可变引用 |
| `Box::from_raw` | `Arc`, `Rc`, 智能指针 |

## Actix-web / Axum 专项

```bash
# 路由列表
grep -rn "\.route\|\.resource\|Router::new\|get\|post\|put\|delete" --include="*.rs" | grep -E "web::|axum::|\.route"

# 认证中间件
grep -rn "middleware\|from_fn\|layer\|Extension\|Claims\|auth\|jwt\|bearer" --include="*.rs"

# CORS
grep -rn "Cors::\|CorsLayer\|cors\|allow_origin" --include="*.rs"

# 速率限制
grep -rn "RateLimit\|rate_limit\|throttle\|Governor" --include="*.rs"
```

## 审计清单

### 🔴 Critical
- [ ] SQL format! 拼接
- [ ] Command::new 参数可控

### 🟡 High
- [ ] unsafe 块使用合理性
- [ ] FFI 边界内存安全
- [ ] .unwrap()/.expect() 在生产路径
- [ ] 文件路径用户可控
- [ ] Send/Sync 自定义实现正确性

### 🔵 Medium
- [ ] as 类型转换溢出（release mode）
- [ ] 原始指针使用
- [ ] 正确的错误处理
