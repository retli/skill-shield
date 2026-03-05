# 输入验证安全

> 覆盖矩阵: D1 注入（通用防御层）

---

## 审计要点

| 检查项 | 风险 | 检测 |
|--------|------|------|
| 无输入验证 | 各类注入 | 直接使用请求参数 |
| 客户端验证 | 可绕过 | 仅前端 JS 校验 |
| 黑名单验证 | 可绕过 | 替代不安全字符 |
| 类型不匹配 | 类型混淆 | 字符串当数字用 |
| 长度无限制 | DoS/溢出 | 超长输入 |
| 编码绕过 | 双重编码 | URL/HTML/Unicode |

## 检测命令

```bash
# 输入验证框架/注解
grep -rn "@Valid\|@NotNull\|@Size\|@Pattern\|@Min\|@Max\|@Email" --include="*.java"
grep -rn "validators\|ValidationError\|validate\|clean\|wtforms" --include="*.py"
grep -rn "Joi\|yup\|zod\|class-validator\|express-validator" --include="*.js" --include="*.ts"

# 正则验证
grep -rn "Pattern\.compile\|re\.compile\|regexp\|regex\|match\|test(" --include="*.java" --include="*.py" --include="*.js" --include="*.go"

# 黑名单方式 (危险)
grep -rn "replace.*<script\|replace.*SELECT\|replace.*\\.\\." --include="*.java" --include="*.py" --include="*.js"

# 白名单方式 (推荐)
grep -rn "allowList\|whitelist\|permit\|enum\.\(values\|contains\)" --include="*.java" --include="*.py" --include="*.js"
```

## XSS 专项

### 检测

```bash
# 输出编码
grep -rn "htmlEscape\|htmlspecialchars\|encodeForHTML\|escapeHtml\|DOMPurify\|sanitize" --include="*.java" --include="*.py" --include="*.js" --include="*.php"

# 非转义输出 (危险)
grep -rn "th:utext\|Html\.Raw\|innerHTML\|dangerouslySetInnerHTML\|{!!.*!!}\|\|safe\|autoescape.*false" --include="*.java" --include="*.py" --include="*.js" --include="*.html" --include="*.php" --include="*.cs"

# DOM XSS
grep -rn "document\.write\|eval\|setTimeout.*\+\|location\.hash\|location\.search\|window\.name" --include="*.js" --include="*.ts"
```

### XSS 上下文

| 上下文 | 危险输出 | 正确编码 |
|--------|---------|---------|
| HTML Body | `<div>USER</div>` | HTML Entity 编码 |
| HTML Attribute | `<input value="USER">` | HTML Attribute 编码 |
| JavaScript | `var x = 'USER';` | JavaScript 编码 |
| URL | `<a href="USER">` | URL 编码 + 协议白名单 |
| CSS | `style="color:USER"` | CSS 编码 |

### 净化器绕过

| 绕过方式 | 示例 |
|---------|------|
| 大小写 | `<ScRiPt>` |
| 双写 | `<scr<script>ipt>` |
| 编码 | `&#60;script&#62;` |
| 事件 | `<img onerror=alert(1)>` |
| 协议 | `javascript:alert(1)` |
| 模板注入 | `{{constructor.constructor('alert(1)')()}}` |

## 审计清单

- [ ] 所有输入有服务端验证（非仅客户端）
- [ ] 使用白名单而非黑名单
- [ ] 有输入长度/大小限制
- [ ] HTML 输出自动编码（autoescape 开启）
- [ ] 非转义输出有充分理由且已审查
- [ ] URL 参数有协议白名单（防 javascript:）
- [ ] 文件名/路径有合法字符白名单
