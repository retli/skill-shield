# 密码学安全

> 覆盖矩阵: D7 加密

---

## 审计要点

| 检查项 | 风险 | 检测 |
|--------|------|------|
| 弱算法 | 数据可被解密/伪造 | DES/MD5/SHA1/RC4 |
| 硬编码密钥 | 密钥泄露 | 代码中搜索 |
| ECB 模式 | 明文模式泄露 | 加密模式检查 |
| 弱随机数 | 可预测 | Random vs SecureRandom |
| 证书校验 | MITM | verify=False |
| 填充 | Padding Oracle | PKCS5/7 + CBC |
| IV/Nonce | 重用导致破解 | 固定 IV 检测 |

## 检测命令

```bash
# 弱哈希算法
grep -rn "MD5\|SHA-?1\b\|DES\b\|RC4\|Blowfish\|3DES" --include="*.java" --include="*.py" --include="*.go" --include="*.js" --include="*.cs"

# 弱随机数
grep -rn "java\.util\.Random\|random\.random\|Math\.random\|rand\(\)\|mt_rand" --include="*.java" --include="*.py" --include="*.js" --include="*.php"
# 安全: SecureRandom, secrets, crypto.randomBytes

# 硬编码密钥
grep -rn "secret.?key\|encryption.?key\|AES.?key\|private.?key" --include="*.java" --include="*.py" --include="*.js" --include="*.go" --include="*.properties" --include="*.yml" | grep -E "=\s*['\"]"

# ECB 模式
grep -rn "ECB\|AES/ECB\|mode.*ecb\|MODE_ECB" --include="*.java" --include="*.py" --include="*.go" --include="*.js"

# SSL/TLS 证书校验禁用
grep -rn "verify\s*=\s*False\|VERIFY_NONE\|InsecureSkipVerify\|setHostnameVerifier\|AllowAllHostnameVerifier\|TrustAllCerts\|rejectUnauthorized.*false" --include="*.java" --include="*.py" --include="*.go" --include="*.js"

# 固定 IV
grep -rn "IvParameterSpec\|iv\s*=\s*['\"]" --include="*.java" --include="*.py" | grep -v "random\|Random\|generate"
```

## 安全基线

| 用途 | 推荐算法 | 禁止 |
|------|----------|------|
| 密码存储 | Argon2id / bcrypt / PBKDF2 | MD5 / SHA1 / 明文 |
| 对称加密 | AES-256-GCM | DES / 3DES / AES-ECB |
| 哈希 | SHA-256 / SHA-3 | MD5 / SHA-1 |
| 随机数 | SecureRandom / secrets | Random / Math.random |
| 密钥交换 | ECDH / X25519 | RSA-1024 |
| 签名 | Ed25519 / RSA-2048+ | RSA-1024 / DSA |
| TLS | TLS 1.2+ | SSL / TLS 1.0 / 1.1 |

## 审计清单

- [ ] 无 MD5/SHA1 用于安全目的
- [ ] 无硬编码密钥/IV
- [ ] 加密使用 GCM/CTR 模式（非 ECB/CBC）
- [ ] 使用密码学安全随机数生成器
- [ ] SSL/TLS 证书校验未禁用
- [ ] TLS 版本 ≥ 1.2
- [ ] 密码存储使用自适应哈希
