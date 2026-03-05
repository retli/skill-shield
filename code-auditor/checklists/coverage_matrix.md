# Security Coverage Matrix（审后自检）

> Phase 5（深度审计）完成后，对照此矩阵验证维度覆盖率。
> 未覆盖维度需加载对应 `languages/{lang}.md` 补充审计。

| # | 维度 | 关键问题 | 参考文件 | 已覆盖? | 发现数 |
|---|------|---------|---------|---------|--------|
| D1 | 注入 | SQL/Cmd/LDAP/SSTI/SpEL 执行点？ | `security/input_validation.md` + 语言文件 | [ ] | |
| D2 | 认证 | Token/Session 安全？密钥管理？ | `security/authentication_authorization.md` | [ ] | |
| D3 | 授权 | 用户归属验证？CRUD 权限？ | `security/authentication_authorization.md` | [ ] | |
| D4 | 反序列化 | 不受信数据反序列化？Gadget 链？ | **参见语言文件**: Java(readObject/Fastjson) Python(pickle) PHP(unserialize) | [ ] | |
| D5 | 文件操作 | 路径遍历？上传/下载？ | `security/file_operations.md` | [ ] | |
| D6 | SSRF | URL 用户可控？协议限制？ | **参见语言文件**: 各语言 SSRF 章节 | [ ] | |
| D7 | 加密 | 硬编码密钥？弱算法？ | `security/cryptography.md` | [ ] | |
| D8 | 配置 | 调试暴露？CORS？错误泄露？ | `checklists/universal_checklist.md` | [ ] | |
| D9 | 业务逻辑 | 竞态？金额篡改？IDOR？ | `security/race_conditions.md` + `security/business_logic.md` | [ ] | |
| D10 | 供应链 | 已知 CVE？版本安全？ | `security/dependencies.md` | [ ] | |

## 覆盖标准

### Sink-driven 维度 (D1, D4, D5, D6)
- **已覆盖 ✅** = 核心 Sink 类别均被搜索 + 有数据流追踪
- **浅覆盖 ⚠️** = 搜索过但 Sink 类别有遗漏 / 仅 Grep 未追踪
- **未覆盖 ❌** = 该维度未被搜索

### Control-driven 维度 (D3, D9)
- **已覆盖 ✅** = 端点审计率 ≥ 50%(deep) / ≥ 30%(standard) + CRUD 权限对比
- **浅覆盖 ⚠️** = 仅 Grep 搜索但未系统枚举端点
- **未覆盖 ❌** = 未执行控制建模审计

### Config-driven 维度 (D2, D7, D8, D10)
- **已覆盖 ✅** = 核心配置项均已检查 + 版本/算法对比安全基线
- **浅覆盖 ⚠️** = 仅检查部分配置
- **未覆盖 ❌** = 未检查

## 终止判定

- ≥ 8/10 维度覆盖 → 可进入报告
- D1-D3 任一未覆盖 → **不可**出报告（注入+认证+授权是核心三角）
- < 5/10 维度覆盖 → 必须补充审计
