# Security Coverage Tracker（运行期覆盖跟踪表）

> 此表格用于在 **Phase 2.5 审计阶段** 进行强制进度追踪。
> 每一轮审计后，Agent 必须将读过的文件在这里勾选！**未达 100% 必须强制触发补扫**。

## 使用指引

1. S3 阶段结束时，通过 `python3 scripts/scan_sinks.py "$PROJECT_ROOT" --coverage` 生成初始文件列表覆盖到下表。
2. 每完成一批文件（或单 Agent 结束时），将对应的状态改为 `[x] 已审阅`，并填入发现问题数。
3. 进入 Phase 3 前，必须检查本文件是否所有行均为 `[x]`。

---

### [COVERAGE_MATRIX_TODO]
*(请在开始审计前，用 `scan_sinks.py --coverage` 的真实输出替换下列示例表格)*

| 行号 | 文件路径 | Tier | Agent 审核状态 | 发现问题数 |
|---|---------|------|------|-------|
| 1 | `src/main/java/com/example/controller/AuthController.java` | Tier1 | [ ] 待审阅 | 0 |
| 2 | `src/main/java/com/example/service/UserService.java` | Tier2 | [ ] 待审阅 | 0 |
| 3 | `src/main/java/com/example/entity/User.java` | Tier3 | [ ] 待审阅 | 0 |
