# 外部工具集成指南

> AI 审计可借助专业 SAST 工具补充能力，但工具结果必须人工验证，不可直接采信。

---

## 工具使用原则

```
1. 工具是辅助，不是替代 — 工具结果仍需人工确认
2. 先 AI 审计后工具补充 — 不要一开始就跑工具
3. 关注高危结果 — 忽略 info/low 级别输出
4. 去重 — 与 AI 发现去重，不重复报告
```

## 推荐工具

### Python: Bandit
```bash
# 安装
pip install bandit

# 扫描
bandit -r . -f json -o bandit_report.json
bandit -r . -ll -ii    # 仅 High+，High confidence

# 重点关注
# B101: assert used
# B301-B303: pickle/marshal/yaml
# B501-B502: SSL verification disabled
# B601-B607: OS commands
# B608: SQL injection
```

### Java: SpotBugs + Find Security Bugs
```bash
# Maven
mvn com.github.spotbugs:spotbugs-maven-plugin:check

# 重点关注
# SQL_INJECTION, COMMAND_INJECTION
# XXE_PROCESSING, DESERIALIZATION
# PATH_TRAVERSAL, UNVALIDATED_REDIRECT
```

### 多语言: Semgrep
```bash
# 安装
pip install semgrep

# 使用官方安全规则
semgrep --config "p/security-audit" .
semgrep --config "p/owasp-top-ten" .

# 语言专项
semgrep --config "p/java" .
semgrep --config "p/python" .
semgrep --config "p/javascript" .
semgrep --config "p/golang" .
semgrep --config "p/php" .

# 仅高危
semgrep --config "p/security-audit" --severity ERROR .
```

### Go: Gosec
```bash
# 安装
go install github.com/securego/gosec/v2/cmd/gosec@latest

# 扫描
gosec -fmt json ./...
gosec -exclude=G104 ./...  # 排除未检查错误

# 重点关注
# G201-G203: SQL injection
# G301-G307: File operations
# G401-G407: Cryptography
# G501-G505: Blocklist imports
```

### 密钥泄露: Gitleaks
```bash
# 安装
brew install gitleaks  # macOS

# 扫描当前代码
gitleaks detect --source .

# 扫描 Git 历史
gitleaks detect --source . --log-opts="--all"

# JSON 输出
gitleaks detect --source . -f json -r gitleaks_report.json
```

### PHP: Psalm (taint analysis)
```bash
# 安装
composer require --dev vimeo/psalm

# 生成配置
./vendor/bin/psalm --init

# 污点分析
./vendor/bin/psalm --taint-analysis
```

### .NET: Security Code Scan
```bash
# NuGet 安装
dotnet add package SecurityCodeScan.VS2019

# 集成到 build
dotnet build /p:RunAnalyzers=true
```

### 依赖检查: OWASP Dependency-Check
```bash
# Java
mvn org.owasp:dependency-check-maven:check

# 通用
dependency-check --project "project" --scan .

# Node.js
npm audit --json
npx audit-ci --config audit-ci.json

# Python
pip-audit
safety check
```

---

## 工具结果集成流程

```
1. AI 完成 Phase 5 审计
2. 根据技术栈选择工具运行
3. 收集工具输出 (JSON 格式)
4. 去重: 与 AI 发现比对
5. 验证: 对工具新发现进行人工确认
6. 合并: 经确认的工具发现纳入报告
7. 标注: 在报告中注明发现来源 (AI / 工具)
```

---

## 工具对比

| 工具 | 语言 | 优势 | 局限 |
|------|------|------|------|
| Semgrep | 多语言 | 规则丰富，速度快 | 不做数据流追踪 |
| Bandit | Python | 专精 Python | 仅模式匹配 |
| SpotBugs | Java | 字节码分析 | 需编译 |
| Gosec | Go | Go 专精 | 规则较少 |
| Gitleaks | 通用 | 密钥检测全面 | 仅检测密钥 |
| Psalm | PHP | 污点分析 | 需类型注解 |
