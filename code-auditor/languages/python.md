# Python Security Audit — Complete Reference

> 适用: Python 2.x/3.x, Django, Flask, FastAPI, Tornado, Sanic

---

## Source（污点源）

### Flask
```python
request.args.get('name')         # GET 参数
request.form.get('name')         # POST 表单
request.json                     # JSON body
request.data                     # Raw body
request.values.get('name')       # GET + POST 合并
request.headers.get('X-Custom')  # 请求头
request.cookies.get('session')   # Cookie
request.files['file']            # 文件上传
request.environ.get('PATH_INFO') # WSGI 环境
```

### Django
```python
request.GET.get('name')
request.POST.get('name')
request.body / request.data      # DRF
request.META.get('HTTP_X_CUSTOM')
request.COOKIES.get('session')
request.FILES['file']
```

### FastAPI
```python
async def handler(
    param: str = Query(),        # 查询参数
    body: Model = Body(),        # 请求体
    path_id: str = Path(),       # 路径参数
    header: str = Header(),      # 请求头
    cookie: str = Cookie(),      # Cookie
    file: UploadFile = File(),   # 文件上传
):
```

---

## Sink 分类表

| Sink类型 | 漏洞 | CWE | 严重程度 | 危险函数 |
|----------|------|-----|---------|----------|
| 命令执行 | 命令注入 | 78 | Critical | os.system, subprocess, popen |
| 代码执行 | 代码注入 | 94 | Critical | eval, exec, compile |
| SQL执行 | SQL注入 | 89 | Critical | cursor.execute, raw(), extra() |
| 反序列化 | RCE | 502 | Critical | pickle.load, yaml.load, marshal |
| 模板引擎 | SSTI | 97 | Critical | render_template_string, Template |
| 文件操作 | 路径遍历 | 22 | High | open(), send_file, os.path |
| HTTP请求 | SSRF | 918 | High | requests.get, urllib |
| XML解析 | XXE | 611 | High | etree.parse, minidom |
| 动态导入 | RCE | 94 | High | __import__, importlib |

---

## Sink 检测命令

### 命令注入 (重点)

```bash
# os 模块
grep -rn "os\.system\|os\.popen\|os\.exec[lv]" --include="*.py"

# subprocess
grep -rn "subprocess\.\(call\|run\|Popen\|check_output\|check_call\|getoutput\|getstatusoutput\)" --include="*.py"
# 关键: shell=True 是高危标志
grep -rn "shell\s*=\s*True" --include="*.py"

# 其他
grep -rn "commands\.\|pty\.spawn\|paramiko.*exec_command" --include="*.py"
```

### 代码注入

```bash
# eval/exec
grep -rn "\beval\s*(\|\bexec\s*(\|\bcompile\s*(" --include="*.py"

# 动态导入
grep -rn "__import__\|importlib\.import_module\|importlib\.util\|pkgutil" --include="*.py"

# 反射
grep -rn "getattr\s*(\|setattr\s*(" --include="*.py" | grep -E "request|user|input|param"
```

### 反序列化 (高危)

```bash
# Pickle — 最危险
grep -rn "pickle\.\(loads\?\|Unpickler\)\|cPickle\.\(loads\?\)" --include="*.py"
# Pickle 可直接 RCE, 无需 Gadget 链

# YAML
grep -rn "yaml\.load\|yaml\.full_load\|yaml\.unsafe_load" --include="*.py"
# 安全: yaml.safe_load()

# Marshal
grep -rn "marshal\.\(loads\?\)" --include="*.py"

# JsonPickle
grep -rn "jsonpickle\.\(decode\|loads\)" --include="*.py"

# Shelve
grep -rn "shelve\.open" --include="*.py"
```

**Pickle 利用示例**:
```python
# 攻击者构造 payload:
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))
payload = pickle.dumps(Exploit())

# 服务端触发:
pickle.loads(user_uploaded_data)  # 直接 RCE!

# 安全替代:
json.loads(data)          # 仅基本类型
yaml.safe_load(data)      # SafeLoader
msgpack.unpackb(data)     # 二进制序列化
```

### SQL 注入

```bash
# 原生 SQL 拼接
grep -rn "execute\s*(.*%" --include="*.py"
grep -rn "execute\s*(.*\.format" --include="*.py"
grep -rn "execute\s*(.*f['\"]" --include="*.py"

# Django ORM 危险用法
grep -rn "\.raw\s*(" --include="*.py"
grep -rn "\.extra\s*(" --include="*.py"
grep -rn "RawSQL\s*(" --include="*.py"

# Django 字典注入 (高级)
grep -rn "\.filter\s*(\*\*\|\.exclude\s*(\*\*" --include="*.py"
# 攻击: filter(**{"field__regex": ".*"})
# 可悟出任意 ORM Lookup

# SQLAlchemy 拼接
grep -rn "text\s*(\|execute\s*(.*\+" --include="*.py"

# 安全: cursor.execute("SELECT ... WHERE id = %s", (id,))
#        不要: cursor.execute("SELECT ... WHERE id = %s" % id)
```

### SSTI 模板注入

```bash
# Jinja2
grep -rn "render_template_string\s*(" --include="*.py"
grep -rn "Template\s*([^)]*)\.\(render\|generate\|stream\)" --include="*.py"
grep -rn "Environment\s*(\|from_string\s*(" --include="*.py"

# Mako
grep -rn "mako\.template\|Template\s*(.*text\s*=" --include="*.py"

# Tornado
grep -rn "tornado\.template\|RequestHandler.*render\(" --include="*.py"
```

**SSTI Payload 速查**:

| 引擎 | 探测 | 确认 | 利用 |
|------|------|------|------|
| **Jinja2** | `{{7*7}}` → 49 | `{{config}}` | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| **Mako** | `${7*7}` → 49 | `${self.module.__name__}` | `<% import os; os.system('id') %>` |
| **Tornado** | `{{7*7}}` → 49 | `{{handler.settings}}` | `{% import os %}{{os.popen('id').read()}}` |

### 文件操作

```bash
# 文件读写
grep -rn "open\s*(" --include="*.py" | grep -E "request|user|input|param|filename"
grep -rn "send_file\|send_from_directory\|FileResponse\|StreamingResponse" --include="*.py"

# 路径操作
grep -rn "os\.path\.join.*request\|pathlib.*request" --include="*.py"

# 删除
grep -rn "os\.remove\|os\.unlink\|shutil\.rmtree" --include="*.py"

# 压缩包
grep -rn "zipfile\.ZipFile\|tarfile\.open\|\.extractall\|\.extract\(" --include="*.py"
# 检查: Zip Slip — 解压时是否验证路径
```

### SSRF

```bash
grep -rn "requests\.\(get\|post\|put\|delete\|patch\|head\|options\)\|urllib\.request\.urlopen\|urllib\.request\.Request\|httpx\.\|aiohttp\.\(ClientSession\|request\)" --include="*.py"
grep -rn "pycurl\|curl_cffi" --include="*.py"
```

### XXE

```bash
# 危险解析器
grep -rn "etree\.\(parse\|fromstring\|XML\|iterparse\)\|minidom\.parse\|xml\.sax\.parse\|pulldom" --include="*.py"

# 安全: defusedxml
grep -rn "defusedxml\|defused" --include="*.py"
# 若未使用 defusedxml -> 可能有 XXE
```

---

## Django 专项

```bash
# 路由与认证
grep -rn "url\(r\|path\(\|re_path\(" --include="*.py" | head -30  # 路由列表
grep -rn "@login_required\|@permission_required\|LoginRequiredMixin\|PermissionRequiredMixin" --include="*.py"

# 无认证的视图
grep -rn "class.*View\|def\s\+\(get\|post\|put\|delete\)\b" --include="*.py" -B 5 | grep -v "@login_required\|LoginRequired"

# Django ORM 注入
grep -rn "\.raw\s*(\|\.extra\s*(\|RawSQL\|connection\.cursor" --include="*.py"

# 模板安全
grep -rn "\|safe\b\|mark_safe\|autoescape.*off\|{% autoescape false %}" --include="*.py" --include="*.html"

# CSRF
grep -rn "@csrf_exempt\|csrf_protect" --include="*.py"

# Settings 安全
grep -ri "DEBUG\s*=\s*True\|SECRET_KEY\s*=\s*['\"]" --include="*.py" --include="settings*"
grep -ri "ALLOWED_HOSTS\s*=\s*\['\*'\]" --include="*.py"

# 密码存储
grep -rn "make_password\|check_password\|PBKDF2\|BCrypt\|Argon2" --include="*.py"
```

## Flask 专项

```bash
# 路由列表
grep -rn "@app\.route\|@blueprint\.route\|@bp\.route" --include="*.py"

# 无认证路由
grep -rn "@app\.route\|@bp\.route" --include="*.py" | grep -v "@login_required\|@auth"

# Session 配置
grep -rn "secret_key\|SECRET_KEY\|SESSION_COOKIE\|app\.config" --include="*.py"

# 调试模式
grep -rn "debug\s*=\s*True\|FLASK_DEBUG\|app\.run" --include="*.py"

# Jinja2 配置
grep -rn "autoescape\|TEMPLATES_AUTO_RELOAD" --include="*.py"
```

## FastAPI 专项

```bash
# 依赖注入认证
grep -rn "Depends\s*(\|Security\s*(\|OAuth2PasswordBearer\|HTTPBearer" --include="*.py"

# 路由无认证
grep -rn "@app\.\(get\|post\|put\|delete\)\|@router\.\(get\|post\|put\|delete\)" --include="*.py" | grep -v "Depends\|Security"

# Pydantic 验证
grep -rn "class.*BaseModel\|Field\s*(\|validator\|@field_validator" --include="*.py"
```

---

## 危险依赖速查

| 依赖 | 危险场景 | 安全替代 |
|------|----------|---------|
| pickle | 任何 load/loads | json / msgpack |
| PyYAML yaml.load | 默认不安全 | yaml.safe_load |
| Jinja2 render_template_string | 用户输入模板 | render_template + .html 文件 |
| subprocess shell=True | 命令注入 | shell=False + 列表参数 |
| Django .raw() | SQL 注入 | ORM queryset |
| requests verify=False | MITM | 保持 verify=True |
| xml.etree | XXE | defusedxml |
| Pillow < 9.0 | 多个 RCE | 更新到最新 |

---

## 审计清单

### 🔴 Critical（必查）
- [ ] eval()/exec() 接收用户输入
- [ ] os.system/subprocess shell=True 命令注入
- [ ] pickle.load/loads 反序列化
- [ ] SQL 字符串拼接/格式化 (f-string / .format / %)
- [ ] render_template_string SSTI
- [ ] Django .raw()/.extra() SQL 注入
- [ ] yaml.load 未用 SafeLoader

### 🟡 High
- [ ] open() 路径遍历
- [ ] requests/urllib SSRF
- [ ] Django filter(**dict) 字典注入
- [ ] zipfile/tarfile Zip Slip
- [ ] getattr/setattr 接收用户输入
- [ ] __import__ 动态导入

### 🔵 配置
- [ ] Django DEBUG = True
- [ ] Flask debug = True
- [ ] SECRET_KEY 硬编码
- [ ] CORS 配置过宽
- [ ] csrf_exempt 使用
- [ ] ALLOWED_HOSTS = ['*']
