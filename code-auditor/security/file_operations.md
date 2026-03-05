# 文件操作安全

> 覆盖矩阵: D5 文件操作

---

## 审计要点

| 检查项 | 漏洞 | CWE |
|--------|------|-----|
| 路径遍历 | 任意文件读取 | 22 |
| 上传无限制 | WebShell/RCE | 434 |
| 文件名可控 | 覆盖系统文件 | 73 |
| 临时文件 | 竞态条件/权限 | 377 |
| 压缩包解压 | Zip Slip | 22 |
| 符号链接 | 跳出目录 | 59 |

## 检测命令

```bash
# 文件读取操作
grep -rn "File\.read\|FileInputStream\|open\(\|os\.Open\|readFile\|file_get_contents\|IO\.read" --include="*.java" --include="*.py" --include="*.go" --include="*.js" --include="*.php" --include="*.rb"

# 文件写入操作
grep -rn "File\.write\|FileOutputStream\|\.write\(\|os\.Create\|writeFile\|file_put_contents\|IO\.write" --include="*.java" --include="*.py" --include="*.go" --include="*.js" --include="*.php" --include="*.rb"

# 文件上传
grep -rn "MultipartFile\|upload\|@PostMapping.*file\|request\.files\|FormFile\|$_FILES" --include="*.java" --include="*.py" --include="*.go" --include="*.js" --include="*.php"

# 文件下载
grep -rn "download\|send_file\|sendFile\|StreamingResponse\|attachment\|Content-Disposition" --include="*.java" --include="*.py" --include="*.go" --include="*.js" --include="*.php"

# 压缩包操作
grep -rn "ZipFile\|ZipInputStream\|zipfile\|archive\|unzip\|tar\|gzip" --include="*.java" --include="*.py" --include="*.go" --include="*.js"

# 路径拼接 (关键检查点)
grep -rn "Paths\.get.*\+\|os\.path\.join.*request\|filepath\.Join.*param\|path\.join.*req\|\.\./" --include="*.java" --include="*.py" --include="*.go" --include="*.js"
```

## 路径遍历防御验证

```
正确防御:
1. 获取规范路径: resolve() / realpath() / canonicalize()
2. 验证是否在允许目录内: startsWith(baseDir)

无效防御:
✗ 仅替换 "../" (可用 "....//" 绕过)
✗ 仅检查前缀 (符号链接可绕过)
✗ URL 解码后再检查 (双重编码绕过)
```

## 上传安全检查

```
检查项:
1. 文件扩展名白名单 (不是黑名单!)
2. 文件内容 Magic Bytes 验证
3. 文件大小限制
4. 上传目录不在 Web 根目录下
5. 存储使用随机文件名
6. 检查双扩展名 (file.php.jpg)
```

## Zip Slip 检测

```
攻击: 压缩包内路径含 "../../" 可写入任意位置

检查: 解压时是否验证目标路径在预期目录内

安全代码 (Java):
  File destFile = new File(destDir, entry.getName());
  if (!destFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())) {
      throw new Exception("Zip Slip detected");
  }
```

## 审计清单

- [ ] 文件路径使用 resolve() + startsWith() 边界检查
- [ ] 上传使用扩展名白名单 + Magic Bytes 验证
- [ ] 上传目录不可执行 / 不在 Web 根下
- [ ] 下载路径不可遍历
- [ ] 解压操作防 Zip Slip
- [ ] 临时文件安全创建 + 及时删除
