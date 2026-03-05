# C#/.NET Security Audit — Complete Reference

> 适用: ASP.NET Core, ASP.NET MVC, Blazor, WPF, .NET 6+

---

## Source
```csharp
Request.Query["param"], Request.Form["param"]
Request.Headers["X-Custom"], Request.Cookies["name"]
[FromQuery] string param, [FromBody] Model body
[FromRoute] int id, [FromForm] string field
HttpContext.Request.Body, Request.ReadFormAsync()
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险函数 |
|----------|-----|---------|----------|
| SQL注入 | 89 | Critical | SqlCommand + 拼接, FromSqlRaw |
| 命令执行 | 78 | High | Process.Start |
| 反序列化 | 502 | Critical | BinaryFormatter, TypeNameHandling.All |
| XSS | 79 | High | @Html.Raw, Response.Write |
| 路径遍历 | 22 | High | File操作 + 拼接 |
| XPath注入 | 643 | High | SelectNodes + 拼接 |
| LDAP注入 | 90 | High | DirectorySearcher + 拼接 |
| SSRF | 918 | High | HttpClient + 用户URL |

## Sink 检测命令

```bash
# SQL 注入
grep -rn "SqlCommand\|ExecuteReader\|ExecuteNonQuery\|ExecuteScalar\|SqlDataAdapter" --include="*.cs" | grep -E "\+|String\.Format|\$\""
grep -rn "FromSqlRaw\|FromSqlInterpolated\|ExecuteSqlRaw\|ExecuteSqlInterpolated" --include="*.cs"
# 安全: new SqlCommand("SELECT ... WHERE id = @id", conn), cmd.Parameters.AddWithValue("@id", id)
# 安全: context.Users.FromSqlInterpolated($"SELECT ... WHERE id = {id}")
# 危险: context.Users.FromSqlRaw($"SELECT ... WHERE id = {id}")

# 命令执行
grep -rn "Process\.Start\|ProcessStartInfo\|Process\.GetProcesses" --include="*.cs"

# 反序列化
grep -rn "BinaryFormatter\|ObjectStateFormatter\|SoapFormatter\|NetDataContractSerializer\|LosFormatter\|DataContractJsonSerializer" --include="*.cs"
grep -rn "TypeNameHandling\.\(All\|Auto\|Objects\|Arrays\)" --include="*.cs"
grep -rn "JavaScriptSerializer\|DataContractSerializer.*KnownType" --include="*.cs"
# 安全: System.Text.Json (默认安全)

# XSS
grep -rn "@Html\.Raw\|Response\.Write\|HtmlString" --include="*.cs" --include="*.cshtml"

# 文件操作
grep -rn "File\.\(ReadAllText\|WriteAllText\|Open\|Delete\|Copy\|Move\)" --include="*.cs" | grep -E "\+|\$\""
grep -rn "StreamReader\|StreamWriter\|FileStream\|Directory\.\(GetFiles\|Delete\)" --include="*.cs" | grep -E "\+|\$\""
grep -rn "IFormFile\|ContentDisposition\|SaveAsAsync" --include="*.cs"

# SSRF
grep -rn "HttpClient\|WebClient\|HttpWebRequest\|RestClient" --include="*.cs" | grep -E "\+|\$\"|user|param"

# LDAP 注入
grep -rn "DirectorySearcher\|SearchFilter\|DirectoryEntry" --include="*.cs" | grep -E "\+|\$\""

# XPath 注入
grep -rn "SelectNodes\|SelectSingleNode\|XPathNavigator\|Evaluate" --include="*.cs" | grep -E "\+|\$\""
```

## ASP.NET Core 专项

```bash
# 认证配置
grep -rn "\[Authorize\]\|\[AllowAnonymous\]\|AuthorizationPolicy\|RequireAuthorization" --include="*.cs"
# 无认证 Controller
grep -rn "class.*Controller" --include="*.cs" -B 3 | grep -v "\[Authorize\]"

# 中间件配置
grep -rn "UseAuthentication\|UseAuthorization\|UseHttpsRedirection\|UseHsts\|UseCors" --include="*.cs"

# CORS
grep -rn "AddCors\|WithOrigins\|AllowAnyOrigin\|SetIsOriginAllowed" --include="*.cs"

# 反伪造令牌
grep -rn "ValidateAntiForgeryToken\|IgnoreAntiforgeryToken\|AddAntiforgery" --include="*.cs"

# 数据保护
grep -rn "IDataProtector\|DataProtectionProvider\|Protect\|Unprotect" --include="*.cs"

# Kestrel 配置
grep -rn "UseKestrel\|ListenAnyIP\|Limits\.\|MaxRequestBodySize" --include="*.cs"
```

## 审计清单

### 🔴 Critical
- [ ] SqlCommand/FromSqlRaw 字符串拼接
- [ ] BinaryFormatter/SoapFormatter 反序列化
- [ ] TypeNameHandling.All (JSON.NET)

### 🟡 High
- [ ] @Html.Raw XSS
- [ ] Process.Start 命令执行
- [ ] 文件路径拼接遍历
- [ ] HttpClient SSRF
- [ ] [AllowAnonymous] 敏感端口

### 🔵 配置
- [ ] HTTPS Redirection 开启
- [ ] CORS 非 AllowAnyOrigin
- [ ] Anti-Forgery Token 配置
- [ ] 日志不含敏感数据
