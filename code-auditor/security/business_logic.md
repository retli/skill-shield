# 业务逻辑安全

> 覆盖矩阵: D9 业务逻辑

---

## 审计要点

| 漏洞模式 | 影响 | 检测思路 |
|---------|------|---------|
| 流程跳过 | 绕过必需步骤 | 多步流程完整性 |
| 金额篡改 | 修改价格/金额 | 前端传参 vs 后端计算 |
| IDOR | 操作他人资源 | ID 参数归属验证 |
| 重放攻击 | 重复提交 | 幂等性/去重机制 |
| 逻辑滥用 | 合法功能恶意使用 | 频率/额度限制 |
| 状态篡改 | 非法状态转换 | 状态机完整性 |

## 检测命令

```bash
# 价格/金额相关
grep -rn "price\|amount\|total\|cost\|fee\|discount\|coupon\|quantity" --include="*.java" --include="*.py" --include="*.go" --include="*.js"

# 关键: 价格是否从前端传入？
grep -rn "request.*price\|body.*amount\|params.*cost\|input.*total" --include="*.java" --include="*.py" --include="*.js"

# 状态转换
grep -rn "status\|state\|step\|stage\|phase\|workflow" --include="*.java" --include="*.py" --include="*.go"

# 幂等性控制
grep -rn "idempotent\|nonce\|request.?id\|transaction.?id\|dedup" --include="*.java" --include="*.py" --include="*.go" --include="*.js"

# 优惠/折扣逻辑
grep -rn "coupon\|voucher\|discount\|promotion\|reward\|bonus\|referral" --include="*.java" --include="*.py" --include="*.js"
```

## 高风险模式

### 金额篡改
```
危险: 前端传递价格到后端
POST /api/order
{"productId": 1, "quantity": 1, "price": 0.01}  ← 价格应从后端查询

检查: 价格/金额是否从数据库获取而非前端参数
```

### 流程跳过
```
正常流程: 下单 → 支付 → 确认
攻击: 直接调用确认接口跳过支付

检查: 每个步骤是否验证前置状态
```

### 状态机

```
合法: pending → paid → shipped → completed
非法: pending → completed (跳过支付)
非法: completed → pending (状态回退)

检查: 状态转换是否有白名单验证
```

## 审计清单

- [ ] 价格/金额从后端数据库获取，非前端参数
- [ ] 多步流程有状态完整性检查
- [ ] 状态转换有合法路径白名单
- [ ] 关键操作有幂等性/去重控制
- [ ] 优惠券/折扣在后端验证有效性和使用条件
- [ ] 批量操作有数量/频率限制
