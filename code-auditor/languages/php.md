# PHP Security Audit — Complete Reference

> 适用: PHP 7.x/8.x, Laravel, ThinkPHP, WordPress, Symfony, CodeIgniter

---

## Source
```php
$_GET['param'], $_POST['param'], $_REQUEST['param']
$_COOKIE['name'], $_SERVER['HTTP_*'], $_SERVER['REQUEST_URI']
$_FILES['file'], $_ENV['KEY']
file_get_contents('php://input')     // raw body
$request->input('param')             // Laravel
$request->param('param')             // ThinkPHP
$request->query->get('param')        // Symfony
```

## Sink 分类表

| Sink类型 | CWE | 严重程度 | 危险函数 |
|----------|-----|---------|----------|
| 代码执行 | 94 | Critical | eval, assert, preg_replace /e |
| 命令执行 | 78 | Critical | system, exec, passthru, shell_exec, popen |
| SQL注入 | 89 | Critical | mysql_query, ->query, DB::raw |
| 文件包含 | 98 | Critical | include, require + $变量 |
| 反序列化 | 502 | Critical | unserialize, phar:// |
| 文件操作 | 22 | High | file_get_contents, fopen + $变量 |
| SSRF | 918 | High | curl_exec, file_get_contents + $url |
| XSS | 79 | Medium | echo, print + 未过滤变量 |

## Sink 检测命令

```bash
# 代码/命令执行
grep -rn "\beval\s*(\|assert\s*(\|system\s*(\|exec\s*(\|passthru\s*(\|shell_exec\s*(\|popen\s*(\|proc_open\s*(" --include="*.php"
grep -rn "preg_replace\s*(.*\/e" --include="*.php"
grep -rn "call_user_func\|call_user_func_array\|array_map\|array_filter.*ARRAY_FILTER_USE" --include="*.php"

# SQL 注入
grep -rn "mysql_query\|mysqli_query\|->query\s*(\|pg_query" --include="*.php" | grep -E "\\\$|\."
grep -rn "->where\s*(.*\\\$\|->whereRaw\s*(\|DB::raw\s*(\|DB::select\s*(.*\\\$\|->selectRaw\s*(" --include="*.php"

# 文件包含
grep -rn "\b\(include\|require\|include_once\|require_once\)\s*(\?\s*\\\$" --include="*.php"

# 反序列化
grep -rn "\bunserialize\s*(" --include="*.php"
grep -rn "phar://" --include="*.php"

# 文件操作
grep -rn "file_get_contents\|file_put_contents\|fopen\|readfile\|unlink\|move_uploaded_file\|copy\|rename" --include="*.php" | grep "\\\$"

# SSRF
grep -rn "curl_exec\|curl_setopt.*CURLOPT_URL\|file_get_contents\s*(\s*\\\$\|fopen\s*(\s*\\\$" --include="*.php"

# XSS
grep -rn "echo\s*\\\$\|print\s*\\\$\|<\?=\s*\\\$" --include="*.php" | grep -v "htmlspecialchars\|htmlentities\|e(\)"
```

## Laravel 专项

```bash
# Eloquent 注入
grep -rn "DB::raw\|whereRaw\|selectRaw\|orderByRaw\|havingRaw\|groupByRaw" --include="*.php"
# 安全: whereRaw('col = ?', [$val])
# 危险: whereRaw("col = $val")

# Mass Assignment
grep -rn "\\\$fillable\|\\\$guarded" --include="*.php"
# 危险: $guarded = [] (无保护)
# 安全: $fillable = ['name', 'email'] (白名单)

# 路由认证
grep -rn "Route::" routes/*.php | grep -v "middleware.*auth"

# Blade XSS
grep -rn "{!!\s\|@php\|Str::limit" --include="*.blade.php"
# {!! $var !!} 不转义!  安全: {{ $var }}
```

## PHP 反序列化 POP 链

```bash
# 查找魔术方法入口
grep -rn "__destruct\|__wakeup\|__toString\|__call\|__get\|__set\|__invoke" --include="*.php"

# Phar 反序列化触发
# 以下函数可触发 Phar 元数据反序列化:
grep -rn "file_exists\|is_dir\|is_file\|file_get_contents\|fopen\|file\|copy\|unlink\|stat\|filetype\|filesize\|realpath\|rename\|md5_file\|sha1_file\|filemtime" --include="*.php" | grep "\\\$"
```

## 审计清单

### 🔴 Critical
- [ ] eval/system/exec 接收用户输入
- [ ] SQL 字符串拼接 / DB::raw 无参数绑定
- [ ] include/require 动态路径
- [ ] unserialize 不受信数据
- [ ] Phar 反序列化链

### 🟡 High
- [ ] file_get_contents 路径/URL 可控
- [ ] curl_exec SSRF
- [ ] echo 未转义 XSS
- [ ] Laravel Mass Assignment ($guarded = [])
- [ ] preg_replace /e 修饰符
- [ ] Blade {!! !!} 未过滤

### 🔵 配置
- [ ] display_errors = On
- [ ] allow_url_include = On
- [ ] 缺少 CSRF token
