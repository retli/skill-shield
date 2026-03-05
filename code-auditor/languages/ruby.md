# Ruby Security Audit — Complete Reference

> 适用: Ruby 2.x/3.x, Rails 6+, Sinatra, Hanami

---

## Source
```ruby
params[:name]                 # Rails 参数
request.headers["X-Custom"]   # 请求头
cookies[:session]              # Cookie
request.body.read              # Raw body
request.env["QUERY_STRING"]    # 查询字符串
params.permit(:name, :email)   # Strong Parameters
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险函数 |
|----------|-----|---------|----------|
| 代码执行 | 94 | Critical | eval, instance_eval, class_eval |
| 命令执行 | 78 | Critical | system, exec, %x{}, backtick |
| 反序列化 | 502 | Critical | Marshal.load, YAML.unsafe_load |
| SQL注入 | 89 | Critical | where("#{var}"), find_by_sql |
| ERB注入 | 79 | High | ERB.new(user_input) |
| 文件操作 | 22 | High | File.read, send_file + user path |
| SSRF | 918 | High | open(url), Net::HTTP, URI.open |
| Mass Assignment | 915 | High | 未 permit 的 params |
| 动态调用 | 94 | High | send(user_input) |

## Sink 检测命令

```bash
# 代码执行
grep -rn "\beval\s*[\(\"]\|instance_eval\|class_eval\|module_eval\|binding\.eval" --include="*.rb"

# 命令执行
grep -rn "\bsystem\s*(\|\bexec\s*(\|%x[\[{(]\|\`" --include="*.rb"
grep -rn "Open3\.\|IO\.popen\|Kernel\.open\|Kernel\.system\|Kernel\.exec" --include="*.rb"

# 反序列化
grep -rn "Marshal\.load\|Marshal\.restore\|YAML\.load\b\|YAML\.unsafe_load" --include="*.rb"
grep -rn "Oj\.load\|Psych\.unsafe_load" --include="*.rb"
# 安全: YAML.safe_load / Psych.safe_load

# SQL 注入
grep -rn "where\s*(\".*#{\|where\s*('.*#\{" --include="*.rb"
grep -rn "find_by_sql\|execute\s*(\|select_all\|connection\.exec" --include="*.rb"
grep -rn "order\s*(\".*#{\|group\s*(\".*#{" --include="*.rb"
# 安全: where(name: params[:name])
# 危险: where("name = '#{params[:name]}'")

# ERB / 模板注入
grep -rn "ERB\.new\s*(" --include="*.rb"
grep -rn "\.html_safe\|raw\s*(" --include="*.rb" --include="*.erb"

# 文件操作
grep -rn "File\.\(read\|write\|open\|delete\|exist\)\|send_file\|send_data" --include="*.rb" | grep -E "params|user|input"

# 动态方法调用
grep -rn "\.send\s*(\|\.public_send\s*(\|\.method\s*(" --include="*.rb" | grep -E "params|user|input"
grep -rn "const_get\|constantize\|safe_constantize" --include="*.rb"

# Mass Assignment
grep -rn "params\.permit\|params\.require" --include="*.rb"
grep -rn "attr_accessible\|attr_protected" --include="*.rb"
```

## Rails 专项

```bash
# 路由
cat config/routes.rb | grep -E "resources|get|post|put|delete|patch"

# 认证
grep -rn "before_action.*authenticate\|skip_before_action.*authenticate\|devise" --include="*.rb"

# 授权
grep -rn "authorize\|can\?\|cannot\?\|pundit\|cancancan\|ability" --include="*.rb"

# CSRF
grep -rn "protect_from_forgery\|skip_forgery_protection\|verify_authenticity_token" --include="*.rb"

# Strong Parameters
grep -rn "params\.permit\|params\.require" --include="*.rb"
# 检查: 是否有未经 permit 就使用的 params

# 安全头
grep -rn "force_ssl\|config\.ssl_options\|SecureHeaders\|content_security_policy" --include="*.rb"
```

## 审计清单

### 🔴 Critical
- [ ] eval/send 接收用户输入
- [ ] system/exec 命令注入
- [ ] Marshal.load/YAML.load 反序列化
- [ ] where("#{var}") SQL注入

### 🟡 High
- [ ] ERB.new(user_input) 模板注入
- [ ] .html_safe XSS
- [ ] send_file 路径遍历
- [ ] params 未 permit (Mass Assignment)
- [ ] constantize 动态类加载

### 🔵 配置
- [ ] CSRF 保护开启
- [ ] force_ssl 开启
- [ ] Strong Parameters 使用
