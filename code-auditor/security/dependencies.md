# 依赖与供应链安全

> 覆盖矩阵: D10 供应链

---

## 审计要点

| 检查项 | 风险 | 检测 |
|--------|------|------|
| 已知 CVE | 利用已公开漏洞 | 版本对照 |
| 废弃依赖 | 无安全维护 | 最后更新时间 |
| 过度依赖 | 攻击面过大 | 依赖数量 |
| 内部包 | 名称抢注 | 私有包源配置 |
| 锁文件 | 版本不固定 | lock 文件检查 |
| 仓库源 | 不安全的源 | 配置检查 |

## 检测命令

### 依赖文件定位

```bash
# 各语言依赖文件
find . -maxdepth 3 -name "pom.xml" -o -name "build.gradle" -o -name "requirements*.txt" -o -name "Pipfile" -o -name "pyproject.toml" -o -name "go.mod" -o -name "package.json" -o -name "composer.json" -o -name "Gemfile" -o -name "Cargo.toml" -o -name "*.csproj"
```

### 内置工具检查

```bash
# Python
pip-audit                           # 推荐
safety check                       # 备选
pip install pip-audit && pip-audit

# Node.js
npm audit                          # 内置
npx audit-ci                      # CI 集成

# Go
go list -m -json all | go-mod-audit  # 第三方
govulncheck ./...                    # 官方 (Go 1.20+)

# Ruby
bundle-audit check                  # gem install bundler-audit

# PHP
composer audit                      # Composer 2.4+

# Rust
cargo audit                        # cargo install cargo-audit

# Java (OWASP Dependency-Check)
mvn org.owasp:dependency-check-maven:check
```

### 锁文件检查

```bash
# 检查锁文件存在
ls -la package-lock.json yarn.lock pnpm-lock.yaml Pipfile.lock poetry.lock Gemfile.lock go.sum Cargo.lock 2>/dev/null

# 危险: 无锁文件 = 版本不确定
```

## 高危依赖速查

### Java

| 组件 | 危险版本 | CVE/漏洞 |
|------|----------|---------|
| Log4j2 | < 2.17.0 | Log4Shell RCE |
| Fastjson | < 1.2.83 | @type RCE |
| Shiro | < 1.7.1 | 认证绕过 |
| Spring | < 5.3.18 (Framework) | SpringShell |
| Jackson | enableDefaultTyping | 反序列化 |
| Commons-Collections | 3.1-3.2.1, 4.0 | CC链 RCE |
| XStream | < 1.4.18 | XML RCE |

### Python

| 组件 | 危险版本 | CVE/漏洞 |
|------|----------|---------|
| Django | 视具体版本 | 多个 SQLi/XSS |
| Pillow | < 9.0 | 多个 RCE |
| PyYAML | < 6.0 (yaml.load) | 代码执行 |
| Jinja2 | < 3.1.0 | 沙箱逃逸 |
| requests | < 2.32.0 | SSRF 相关 |

### Node.js

| 组件 | 危险版本 | CVE/漏洞 |
|------|----------|---------|
| lodash | < 4.17.21 | 原型污染 |
| express | 检查最新安全公告 | 多种 |
| minimist | < 1.2.6 | 原型污染 |
| jsonwebtoken | < 9.0 | 签名绕过 |

## 审计清单

- [ ] 有锁文件且在版本控制中
- [ ] 运行语言内置审计工具（npm audit / pip-audit / etc）
- [ ] 检查高危组件版本对照表
- [ ] 私有包源配置正确（防 dependency confusion）
- [ ] 无废弃/无维护的关键依赖
