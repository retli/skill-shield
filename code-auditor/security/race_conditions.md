# 竞态条件安全

> 覆盖矩阵: D9 业务逻辑（并发部分）

---

## 审计要点

| 漏洞模式 | 影响 | 常见场景 |
|---------|------|---------|
| TOCTOU | 检查与使用之间被篡改 | 文件操作、权限检查 |
| 余额竞态 | 多次扣款/透支 | 支付、提现、兑换 |
| 库存竞态 | 超卖 | 秒杀、抢购 |
| 限流竞态 | 绕过频率限制 | 验证码、登录尝试 |
| 唯一性竞态 | 重复注册/创建 | 用户名、订单号 |
| 文件竞态 | 符号链接攻击 | 临时文件创建 |

## 检测命令

```bash
# 并发原语
grep -rn "synchronized\|ReentrantLock\|AtomicInteger\|volatile" --include="*.java"
grep -rn "threading\|Lock\|Semaphore\|async.*await\|asyncio" --include="*.py"
grep -rn "sync\.Mutex\|sync\.RWMutex\|atomic\.\|chan\s" --include="*.go"
grep -rn "lock\|mutex\|Interlocked\|ConcurrentDictionary" --include="*.cs"

# SELECT FOR UPDATE (乐观/悲观锁)
grep -rn "FOR UPDATE\|LOCK IN SHARE MODE\|@Version\|optimistic.?lock\|pessimistic" --include="*.java" --include="*.py" --include="*.go" --include="*.xml"

# 事务边界
grep -rn "@Transactional\|BEGIN\|COMMIT\|ROLLBACK\|transaction\|atomic" --include="*.java" --include="*.py" --include="*.go"

# 关键业务操作 (重点检查并发安全)
grep -rn "balance\|amount\|stock\|inventory\|quantity\|counter\|credit\|debit" --include="*.java" --include="*.py" --include="*.go"
```

## 高风险模式

### 检查后执行 (TOCTOU)
```
// 危险模式:
balance = getBalance(userId)     // 检查
if balance >= amount:            // 判断
    debit(userId, amount)        // 执行  ← 此时 balance 可能已变

// 安全模式:
BEGIN TRANSACTION
SELECT balance FROM account WHERE id = ? FOR UPDATE  // 加锁
IF balance >= amount THEN
    UPDATE account SET balance = balance - ? WHERE id = ?
COMMIT
```

### 余额/库存竞态
```
攻击方式: 同时发送多个相同请求
触发条件: 读取-判断-更新 不在同一事务内
检测方法: 搜索余额/库存操作，检查是否有事务 + 行锁
```

## 防御验证

| 防御手段 | 验证方法 |
|---------|---------|
| 数据库行锁 | 检查 SELECT FOR UPDATE |
| 乐观锁 | 检查 @Version / WHERE version = ? |
| 分布式锁 | 检查 Redis SETNX / Redisson |
| 幂等性 | 检查唯一事务 ID / 幂等键 |

## 审计清单

- [ ] 余额/库存操作在事务内 + 行锁
- [ ] 支付/转账有幂等性控制
- [ ] 限流使用原子操作（非读-判-写分离）
- [ ] 文件操作避免 TOCTOU
- [ ] 唯一性约束在数据库层（非应用层 if-check）
