# Java Security Audit — Complete Reference

> 适用: Java 8+, Spring Boot, MyBatis/MyBatis-Plus, Shiro, Struts2

---

## Source（污点源）

### HTTP 参数
```java
// Servlet
request.getParameter("name")
request.getParameterValues("names")
request.getParameterMap()
request.getInputStream()    // raw body
request.getReader()

// Spring MVC
@RequestParam String param
@PathVariable String id
@RequestBody Object body
@RequestHeader String header
@CookieValue String cookie
@MatrixVariable Map<String, String> vars

// JAX-RS
@QueryParam("name") String name
@FormParam("name") String name
@HeaderParam("X-Custom") String header
```

### 文件上传
```java
MultipartFile.getOriginalFilename()
MultipartFile.getInputStream()
MultipartFile.getBytes()
Part.getSubmittedFileName()
```

### 其他 Source
```java
System.getProperty("key")
System.getenv("KEY")
Properties.load(inputStream)
```

---

## Sink 分类表

| Sink类型 | 漏洞 | CWE | 严重程度 | 危险函数 |
|----------|------|-----|---------|----------|
| SQL执行 | SQL注入 | 89 | Critical | Statement.execute, ${}, createQuery |
| 命令执行 | RCE | 78 | Critical | Runtime.exec, ProcessBuilder |
| 反序列化 | RCE | 502 | Critical | readObject, parseObject, XStream |
| XML解析 | XXE | 611 | High | DocumentBuilder, SAXParser |
| JNDI | RCE | 74 | Critical | InitialContext.lookup |
| HTTP请求 | SSRF | 918 | High | HttpClient, RestTemplate |
| 文件操作 | 路径遍历 | 22 | High | new File, FileInputStream |
| 表达式 | RCE | 917 | High | SpEL, OGNL, MVEL, EL |
| HTML输出 | XSS | 79 | Medium | response.getWriter, th:utext |
| LDAP | 注入 | 90 | High | DirContext.search |
| 反射 | RCE | 470 | High | Method.invoke, Class.forName |

---

## Sink 检测命令

### SQL 注入 (重点)

```bash
# MyBatis ${} 注入 — 最高优先级
grep -rn "\$\{" --include="*.xml" --include="*.java"
# 重要: ${} 不走参数绑定，直接拼接!
# 安全: #{} 走 PreparedStatement

# MyBatis-Plus 危险方法
grep -rn "\.apply\s*(\|\.last\s*(\|\.exists\s*(\|\.having\s*(" --include="*.java"
# apply("date_format(field, '%Y') = {0}", userInput) — 可注入

# Statement 拼接
grep -rn "Statement\|executeQuery\|executeUpdate\|executeBatch" --include="*.java" | grep -E "\+|String\.format|concat"

# Spring Data JPA @Query
grep -rn "@Query.*nativeQuery.*true" --include="*.java" -A 3
# 检查: 是否使用 ?1 参数绑定

# HQL/JPQL 拼接
grep -rn "createQuery\s*(" --include="*.java" -A 3 | grep -E "\+|String\.format|concat"

# JdbcTemplate
grep -rn "JdbcTemplate\|NamedParameterJdbcTemplate" --include="*.java" -A 5 | grep -E "\+|String\.format"
```

**Sink Slot 类型 (关键知识)**:

| Slot 类型 | 代码特征 | 正确防护 | 无效防护 |
|-----------|----------|----------|----------|
| SQL-val | `WHERE col = #{val}` | #{} 参数绑定 | — |
| SQL-like | `WHERE col LIKE #{val}` | #{} + CONCAT('%', #{val}, '%') | `LIKE '%${val}%'` |
| SQL-ident | `ORDER BY ${col}` | **白名单验证** | #{} 无效! 会加引号 |
| SQL-table | `FROM ${table}` | **白名单验证** | #{} 无效! |
| SQL-in | `WHERE id IN (${ids})` | 动态生成 `<foreach>` | `${ids}` 直接拼接 |

### 反序列化 (高危)

```bash
# 原生反序列化
grep -rn "ObjectInputStream\|readObject\|readUnshared\|enableDefaultTyping" --include="*.java"

# Fastjson (< 1.2.83 高危)
grep -rn "JSON\.parse\|JSON\.parseObject\|JSON\.parseArray\|@type" --include="*.java"
# 检查: autoType 是否开启, 版本是否 < 1.2.83

# XStream
grep -rn "XStream\|fromXML\|toXML" --include="*.java"

# Jackson 不安全配置
grep -rn "enableDefaultTyping\|DefaultTyping\|OBJECT_AND_NON_CONCRETE\|activateDefaultTyping" --include="*.java"
# 检查: ObjectMapper 是否开启多态类型

# Hessian
grep -rn "HessianInput\|HessianOutput\|Hessian2Input" --include="*.java"

# SnakeYAML
grep -rn "Yaml\.load\|new Yaml()" --include="*.java"
# 安全: new Yaml(new SafeConstructor())
```

**Java 反序列化 Gadget 链速查**:

| Gadget | 依赖 | 危险版本 | 利用方式 |
|--------|------|----------|---------|
| CommonsCollections 1-7 | commons-collections | 3.1-3.2.1, 4.0 | InvokerTransformer 链 |
| CommonsBeanutils | commons-beanutils | 1.8.3-1.9.4 | TemplatesImpl |
| C3P0 | c3p0 | 全版本 | JNDI + URLClassLoader |
| JDK7u21 | JDK | 7u21 | AnnotationInvocationHandler |
| Spring | spring-core | <5.2.20 | MethodInvokeTypeProvider |
| Rome | rome | 1.0-1.12 | ObjectBean |

### JNDI 注入

```bash
grep -rn "\.lookup\s*(\|InitialContext\|JdbcRowSetImpl\|JMXConnectorFactory" --include="*.java"
# Log4j2 JNDI: ${jndi:ldap://...}
grep -rn "jndi\|ldap://\|rmi://" --include="*.java" --include="*.xml" --include="*.properties"

# 防御检查:
grep -rn "JndiLookup\|log4j2\.formatMsgNoLookups" --include="*.properties" --include="*.xml"
```

### XXE

```bash
grep -rn "DocumentBuilder\|SAXParser\|SAXReader\|SAXBuilder\|XMLInputFactory\|TransformerFactory\|SchemaFactory\|Validator" --include="*.java"

# 防御检查:
grep -rn "disallow-doctype-decl\|external-general-entities\|SUPPORT_DTD\|IS_SUPPORTING_EXTERNAL_ENTITIES" --include="*.java"

# 安全配置示例:
# dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
# dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
```

### 命令执行

```bash
grep -rn "Runtime\.getRuntime\|ProcessBuilder\|\.exec\s*(" --include="*.java"
# 检查: 参数是否来自用户输入
# 安全: 使用数组参数, 不要拼接字符串
```

### SSRF

```bash
grep -rn "new URL\|openConnection\|HttpClient\|OkHttpClient\|RestTemplate\|WebClient\|HttpURLConnection\|AsyncHttpClient" --include="*.java"
# 检查: URL 是否用户可控
# 防御: URL 白名单 + IP 黑名单 + 协议白名单
```

### 表达式注入

```bash
# SpEL
grep -rn "SpelExpressionParser\|parseExpression\|@Value.*#\{" --include="*.java"

# OGNL (Struts2)
grep -rn "OgnlUtil\|getValue.*OgnlContext\|ActionContext" --include="*.java"

# MVEL
grep -rn "MVEL\.eval\|MVEL\.compileExpression" --include="*.java"

# EL
grep -rn "ELProcessor\|ELManager\|ValueExpression\|MethodExpression" --include="*.java"
```

### 文件操作

```bash
grep -rn "new File(.*\+\|FileInputStream\s*(\|FileOutputStream\s*(\|Paths\.get\s*(\|Files\.\(read\|write\|copy\|move\|delete\)" --include="*.java"
grep -rn "MultipartFile\|transferTo\|getOriginalFilename" --include="*.java"
```

### 反射调用

```bash
grep -rn "\.invoke\s*(\|getDeclaredMethod\|Class\.forName\|getMethod\|getDeclaredConstructor\|newInstance" --include="*.java"
# 检查: 类名/方法名是否用户可控
```

---

## Spring Boot 专项

### 安全配置

```bash
# Spring Security 配置
grep -rn "WebSecurityConfigurerAdapter\|SecurityFilterChain\|HttpSecurity\|@EnableWebSecurity" --include="*.java"
grep -rn "permitAll\|authenticated\|hasRole\|hasAuthority" --include="*.java"

# Actuator 端点暴露
grep -ri "management\.endpoints\|management\.server\|actuator" --include="*.yml" --include="*.properties"
# 危险: management.endpoints.web.exposure.include=*

# CORS 配置
grep -rn "CorsMapping\|@CrossOrigin\|CorsFilter\|CorsConfigurationSource\|allowedOrigins" --include="*.java"
# 危险: allowedOrigins("*") + allowCredentials(true)

# CSRF 配置
grep -rn "csrf\(\)\.disable\|CsrfFilter\|csrfTokenRepository" --include="*.java"

# 密钥/敏感配置
grep -ri "secret\|password\|key\|token\|credential" --include="*.yml" --include="*.properties" | grep -v "^#"
```

### 常见漏洞模式

#### Spring Data @Query 注入
```java
// 危险: 拼接
@Query(value = "SELECT * FROM user WHERE name = '" + name + "'", nativeQuery = true)
// 安全: 参数绑定
@Query(value = "SELECT * FROM user WHERE name = ?1", nativeQuery = true)
```

#### Actuator 信息泄露
```yaml
# 危险配置
management:
  endpoints:
    web:
      exposure:
        include: "*"  # 暴露所有端点
```

### MyBatis / MyBatis-Plus 专项

```bash
# ${} vs #{} 审计
find . -name "*.xml" -exec grep -l "\$\{" {} \;

# Mapper 接口与 XML 映射
grep -rn "@Select\|@Update\|@Insert\|@Delete" --include="*.java" | grep "\$\{"

# MyBatis-Plus Wrapper 注入
grep -rn "QueryWrapper\|LambdaQueryWrapper\|UpdateWrapper" --include="*.java" -A 5 | grep "apply\|last\|exists\|having"

# 安全用法:
# wrapper.apply("date_format(create_time, '%Y') = {0}", year)  ← {0} 安全
# wrapper.apply("date_format(create_time, '%Y') = " + year)    ← 拼接危险!
```

---

## 危险依赖速查表

| 依赖 | 危险版本 | 漏洞类型 | 检测命令 |
|------|----------|---------|---------|
| log4j-core | < 2.17.0 | JNDI RCE (Log4Shell) | `grep "log4j" pom.xml` |
| fastjson | < 1.2.83 | @type RCE | `grep "fastjson" pom.xml` |
| commons-collections | 3.1-3.2.1, 4.0 | CC链 RCE | `grep "commons-collections" pom.xml` |
| commons-beanutils | 1.8.3-1.9.4 | CB链 RCE | `grep "commons-beanutils" pom.xml` |
| xstream | < 1.4.18 | XML RCE | `grep "xstream" pom.xml` |
| shiro | < 1.7.1 | 认证绕过 | `grep "shiro" pom.xml` |
| spring-framework | < 5.3.18 | SpringShell | `grep "spring" pom.xml` |
| jackson-databind | 2.x enableDefaultTyping | 反序列化 | `grep "jackson" pom.xml` |
| hutool | < 5.8.20 | 多种 | `grep "hutool" pom.xml` |
| snakeyaml | < 2.0 | RCE | `grep "snakeyaml" pom.xml` |

---

## 审计清单

### 🔴 Critical（必查）
- [ ] MyBatis ${} 拼接点
- [ ] MyBatis-Plus apply()/last() 注入
- [ ] 反序列化入口 (ObjectInputStream/Fastjson/XStream/Jackson)
- [ ] JNDI lookup 参数可控
- [ ] Log4j2 < 2.17.0
- [ ] Fastjson < 1.2.83 + autoType
- [ ] XML 解析未禁用外部实体 (XXE)

### 🟡 High
- [ ] Runtime.exec / ProcessBuilder 参数可控
- [ ] SpEL/OGNL/MVEL 表达式注入
- [ ] SSRF: URL 参数用户可控
- [ ] 文件路径遍历
- [ ] 反射调用参数可控
- [ ] Spring Data @Query 拼接

### 🔵 配置
- [ ] Actuator 端点暴露
- [ ] application.yml 硬编码密钥
- [ ] CORS allowedOrigins = "*"
- [ ] CSRF 保护禁用
- [ ] Debug 模式未关闭
- [ ] Swagger/API 文档暴露
