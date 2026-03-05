# C/C++ Security Audit — Complete Reference

> 适用: C, C++, 嵌入式, 系统编程, 服务端

---

## Source
```c
argv[N]                       // 命令行参数
getenv("VAR")                 // 环境变量
fgets(buf, size, stdin)       // 标准输入
read(fd, buf, count)          // 文件/socket 读取
recv(sock, buf, len, flags)   // 网络接收
getline(&line, &len, fp)      // 行读取
scanf("%s", buf)              // 格式化输入
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险函数 |
|----------|-----|---------|----------|
| 缓冲区溢出 | 120 | Critical | strcpy, strcat, gets, sprintf |
| 命令执行 | 78 | Critical | system, popen, exec* |
| 格式化字符串 | 134 | Critical | printf(user_input) |
| 整数溢出 | 190 | High | malloc(size * count) |
| UAF | 416 | Critical | free() 后使用 |
| 双重释放 | 415 | Critical | free() 两次 |
| 空指针解引用 | 476 | High | malloc 未检查 |
| 竞态条件 | 362 | High | 信号处理/文件操作 |

## Sink 检测命令

```bash
# 缓冲区溢出 — C 最常见
grep -rn "\bgets\s*(" --include="*.c" --include="*.cpp" --include="*.h"
# gets() 无任何边界检查 — 必须消除

grep -rn "\bstrcpy\s*(\|\bstrcat\s*(\|\bsprintf\s*(\|\bvsprintf\s*(" --include="*.c" --include="*.cpp"
# 安全替代: strncpy / strncat / snprintf

grep -rn "\bscanf\s*(\|sscanf\s*(" --include="*.c" --include="*.cpp" | grep "%s" | grep -v "%[0-9]*s"
# 危险: scanf("%s", buf)  安全: scanf("%63s", buf)

# 命令执行
grep -rn "\bsystem\s*(\|\bpopen\s*(\|\bexecl\s*(\|\bexeclp\s*(\|\bexecv\s*(\|\bexecvp\s*(" --include="*.c" --include="*.cpp"

# 格式化字符串
grep -rn "printf\s*(\s*[a-z_]" --include="*.c" --include="*.cpp" | grep -v 'printf\s*("'
grep -rn "fprintf\s*(\s*\w*\s*,\s*[a-z_]" --include="*.c" --include="*.cpp" | grep -v 'fprintf\s*(\s*\w*\s*,\s*"'
grep -rn "syslog\s*(\s*\w*\s*,\s*[a-z_]" --include="*.c" --include="*.cpp" | grep -v 'syslog\s*(\s*\w*\s*,\s*"'
# 危险: printf(buf)  安全: printf("%s", buf)

# 整数溢出
grep -rn "malloc\s*(\|calloc\s*(\|realloc\s*(" --include="*.c" --include="*.cpp"
# 检查: malloc(n * sizeof(T)) — n 溢出时分配很小的缓冲区

# 内存安全
grep -rn "\bfree\s*(" --include="*.c" --include="*.cpp"
# 检查: free 后是否将指针置 NULL
# 检查: 是否有多次 free 同一指针

grep -rn "= NULL\|== NULL\|!= NULL" --include="*.c" --include="*.cpp"
```

## 安全函数替代

| 危险 | 安全替代 | 说明 |
|------|----------|------|
| `gets()` | `fgets(buf, sizeof(buf), stdin)` | 必须替换 |
| `strcpy()` | `strncpy()` / `strlcpy()` | 限制长度 |
| `strcat()` | `strncat()` / `strlcat()` | 限制长度 |
| `sprintf()` | `snprintf()` | 限制长度 |
| `scanf("%s")` | `scanf("%63s")` | 限制宽度 |
| `printf(buf)` | `printf("%s", buf)` | 防格式化 |

## 内存安全审计模式

### UAF 检测
```
1. 搜索所有 free() 调用
2. 检查 free 后同一指针是否被使用
3. 检查多个指针指向同一内存时的 free
```

### 双重 free 检测
```
1. 搜索 free() 调用
2. 检查同一变量是否 free 两次
3. 检查错误处理路径中的重复 free
```

### 整数溢出检测
```
1. 搜索 malloc/calloc 调用
2. 检查参数是否包含乘法
3. size * count 溢出时结果很小
4. 检查 size 来源是否可控
```

## 审计清单

### 🔴 Critical
- [ ] gets() 使用（必定溢出）
- [ ] strcpy/strcat/sprintf 无边界
- [ ] printf(user_input) 格式化字符串
- [ ] system/popen 命令注入
- [ ] free 后使用 (UAF)

### 🟡 High
- [ ] malloc 返回值未检查
- [ ] 整数溢出导致小缓冲区
- [ ] 数组越界访问
- [ ] 双重 free
- [ ] 信号处理竞态

### 🔵 配置
- [ ] 编译启用保护 (-fstack-protector, -D_FORTIFY_SOURCE=2)
- [ ] ASLR/PIE 启用
- [ ] NX/DEP 启用
