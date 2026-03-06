# 漏洞精细化判定条件表：反序列化与模板注入

> **反幻觉门禁**：
> 当在审计（如 Layer 2）中通过 Sink-driven 追踪到以下核心组件的危险函数时，**严禁直接认定漏洞成立 (CONFIRMED)**。
> 必须依据本条件表进行详细的前置条件确认。无法确认的，一律标记为 `HYPOTHESIS`。

---

## 1. Fastjson 反序列化 (Java)

**触发 Sink：** `JSON.parseObject()`, `JSON.parse()`, `JSON.parseArray()`

**成立判断决策树：**
1. **获取版本号**：在项目的 `pom.xml` 或 `build.gradle` 中查找 fastjson 版本。
   -若找不到版本号，转入 `HYPOTHESIS`。
2. **版本 < 1.2.68**：
   - 漏洞**直接成立** (CONFIRMED)。存在多条公开利用链。
3. **1.2.68 <= 版本 <= 1.2.80**：
   - 需要依赖链绕过。搜索项目依赖（如 Maven）：
     - 若包含 `groovy` -> 成立
     - 若包含 `jython` + `postgresql` -> 成立
     - 若包含 `aspectj` -> 成立
     - 若包含 `commons-io` (>= 2.x) -> 成立
   - 若不包含上述依赖库，则降级为 `HYPOTHESIS`，需验证环境是否有其它隐藏链。
4. **版本 >= 1.2.83**：
   - 必须查找项目中对于 `ParserConfig.getGlobalInstance().setSafeMode()` 的配置调用。
   - 若 `safeMode = true` -> **漏洞不成立 (安全的)**
   - 若未开启 `safeMode` 但未显式开启 `autoType` -> 难以利用，降级为 `HYPOTHESIS`。

---

## 2. JNDI 注入 (Java)

**触发 Sink：** `InitialContext.lookup(userInput)`

**成立判断决策树：**
1. **确认 Source 源头可追溯且未受限过滤**。
2. **判断 JDK 版本上下文** (若能通过文档或 Dockerfile 获取)：
   - **JDK < 8u191**：默认允许远程加载类，漏洞**直接成立** (CONFIRMED)。
   - **JDK >= 8u191**：`trustURLCodebase` 默认为 false。此时必须检查本地 classpath：
     - 若 classpath 有 `Tomcat` (`BeanFactory` + `ELProcessor`) -> 成立
     - 若 classpath 有 `Groovy` -> 成立
   - 若不确定版本，需在报告注明并评定为 `HYPOTHESIS`。

---

## 3. Velocity SSTI 模板注入 (Java)

**触发 Sink：** `Velocity.evaluate(...)`, `VelocityEngine.evaluate(...)`

**成立判断决策树：**
1. **模板内容是否由用户输入？**（如未经过净化或转义的 HTTP 参数/数据库取出值直接当成模板）。
   - 不是用户输入 -> 漏洞不成立
2. **是否配置了 Uberspector 防御机制？** (全局搜索 `runtime.introspector.uberspect` 属性)
   - 若**未配置** -> 可利用反射执行 `Runtime.exec`，漏洞**成立** (CONFIRMED)。
   - 若配置为 `SecureUberspector` -> **漏洞被防御 (不成立)**。
   - 若使用了自定义过滤器，转入 `HYPOTHESIS` 分析自定义类的实现。

---

## 4. Jackson 反序列化 (Java)

**触发 Sink：** `ObjectMapper.readValue(userInput, ...)`

**成立判断决策树：**
1. **检测 DefaultTyping 开启状态：**
   - 搜索 `enableDefaultTyping()` 或 `activateDefaultTyping()` 全局调用配置。
   - **未开启多态反序列化** -> 漏洞**难以利用 / 不成立**。
2. **确认 CVE 补丁情况**：
   - 如果开启了，且 `jackson-databind` 版本极老（如< 2.9） -> 极有可能成立 (CONFIRMED)。
   - 很多类都在黑名单中，建议标为 `HYPOTHESIS` 指向本地寻找可用的 gadget chain。

---

> **给 Agent 的强制指令：**
> 在最终输出 `reporting/report_template.md` 的漏洞详情时，如果在上文中使用了 `CONFIRMED`，则必须在 **“触发条件”** 这一栏，罗列你是如何依据此表中的判断树通过以上所有的环境和版本校验的。如果证据不足（缺版本/缺配置获取），绝对不允许标记为 `CONFIRMED`。
