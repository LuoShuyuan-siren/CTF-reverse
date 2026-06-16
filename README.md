# CTF Reverse 离线密码学工具

本仓库提供 `ctf_crypto_tool.py`：一个面向 CTF / 逆向 / 离线考试环境的 Python 命令行工具。工具的 XOR、Affine、RC4、Hash 和爆破功能只依赖 Python 标准库；AES、DES、SM4 加解密通过系统本地 `openssl` 命令完成，不需要联网或安装 Python 第三方包。

## 快速开始

查看帮助：

```bash
python ctf_crypto_tool.py --help
python ctf_crypto_tool.py convert --help
python ctf_crypto_tool.py crypto --help
python ctf_crypto_tool.py hash --help
python ctf_crypto_tool.py hash-bruteforce --help
```

## 1. 编码转换：`convert`

### 命令格式

```bash
python ctf_crypto_tool.py convert \
  --input-type hex|text|decimal \
  --output-type hex|text|decimal \
  --input <输入内容>
```

### 参数说明

- `--input-type`：输入格式，支持 `hex`、`text`、`decimal`。
- `--output-type`：输出格式，支持 `hex`、`text`、`decimal`。
- `--input`：待转换内容。
- `decimal` 格式支持空格或逗号分隔的字节值，例如 `65 66 67` 或 `65,66,67`。

### 示例命令

```bash
python ctf_crypto_tool.py convert --input-type hex --output-type text --input 68656c6c6f
python ctf_crypto_tool.py convert --input-type text --output-type hex --input hello
python ctf_crypto_tool.py convert --input-type decimal --output-type hex --input "104 101 108 108 111"
python ctf_crypto_tool.py convert --input-type text --output-type decimal --input ABC
```

## 2. 统一加解密接口：`crypto`

`crypto` 子命令要求在 `plaintext`、`ciphertext`、`key` 三者中**恰好提供两个**，工具会尝试推导第三个：

- `plaintext + key => ciphertext`
- `ciphertext + key => plaintext`
- `plaintext + ciphertext => key`（仅部分算法支持）

### 通用命令格式

```bash
python ctf_crypto_tool.py crypto \
  --alg xor|affine|rc4|des|aes|sm4 \
  [--plaintext <明文>] \
  [--plaintext-type hex|text|decimal] \
  [--ciphertext <密文>] \
  [--ciphertext-type hex|text|decimal] \
  [--key <密钥>] \
  [--key-type hex|text|decimal] \
  [--output-type hex|text|decimal] \
  [--mode ecb|cbc] \
  [--iv <初始化向量>] \
  [--padding pkcs7|zero|none]
```

### 通用参数说明

- `--alg`：算法名，支持 `xor`、`affine`、`rc4`、`des`、`aes`、`sm4`。
- `--plaintext` / `--plaintext-type`：明文及其格式，默认明文格式为 `text`。
- `--ciphertext` / `--ciphertext-type`：密文及其格式，默认密文格式为 `hex`。
- `--key` / `--key-type`：密钥及其格式，默认密钥格式为 `text`。
- `--output-type`：输出格式，默认 `hex`。
- `--mode`：分组密码模式，支持 `ecb`、`cbc`，默认 `ecb`。
- `--iv`：CBC 模式初始化向量。
- `--padding`：填充方式，支持 `pkcs7`、`zero`、`none`，默认 `pkcs7`。

> 说明：当前离线版本完整实现了 XOR、Affine、RC4、MD5、SHA256；AES、DES、SM4 使用本机 `openssl` 命令执行 ECB/CBC 加解密，并由工具侧处理 `pkcs7`、`zero`、`none` 填充。对于 AES/DES/SM4，仅凭明文和密文无法唯一恢复密钥，工具会输出 `无法仅凭明文和密文唯一恢复密钥`。

### 2.1 XOR

#### 命令格式

```bash
# 明文 + 密钥 => 密文
python ctf_crypto_tool.py crypto --alg xor --plaintext <明文> --key <密钥> --output-type hex|text|decimal

# 密文 + 密钥 => 明文
python ctf_crypto_tool.py crypto --alg xor --ciphertext <密文> --ciphertext-type hex|text|decimal --key <密钥> --output-type hex|text|decimal

# 明文 + 密文 => 尝试恢复密钥
python ctf_crypto_tool.py crypto --alg xor --plaintext <明文> --ciphertext <密文> --ciphertext-type hex|text|decimal --output-type hex|text|decimal
```

#### 示例命令

```bash
python ctf_crypto_tool.py crypto --alg xor --plaintext hello --key k --output-type hex
python ctf_crypto_tool.py crypto --alg xor --ciphertext 030e070704 --key k --output-type text
python ctf_crypto_tool.py crypto --alg xor --plaintext hello --ciphertext 030e070704 --output-type text
```

XOR 支持通过 `plaintext + ciphertext` 恢复重复密钥流。

### 2.2 Affine 字节仿射密码

Affine 使用字节运算：`cipher = (a * plain + b) mod 256`。密钥格式为两个整数：`"a b"`，其中 `a` 必须与 256 互素。

#### 命令格式

```bash
# 明文 + 密钥 => 密文
python ctf_crypto_tool.py crypto --alg affine --plaintext <明文> --key "<a> <b>" --output-type hex|text|decimal

# 密文 + 密钥 => 明文
python ctf_crypto_tool.py crypto --alg affine --ciphertext <密文> --ciphertext-type hex|text|decimal --key "<a> <b>" --output-type hex|text|decimal

# 明文 + 密文 => 尝试恢复 a、b
python ctf_crypto_tool.py crypto --alg affine --plaintext <明文> --ciphertext <密文> --ciphertext-type hex|text|decimal --output-type text
```

#### 示例命令

```bash
python ctf_crypto_tool.py crypto --alg affine --plaintext ABC --key "5 8" --output-type hex
python ctf_crypto_tool.py crypto --alg affine --ciphertext 4d5257 --key "5 8" --output-type text
python ctf_crypto_tool.py crypto --alg affine --plaintext ABC --ciphertext 4d5257 --output-type text
```

Affine 支持通过爆破合法的 `a` 并计算 `b` 来恢复参数。

### 2.3 RC4

#### 命令格式

```bash
# 明文 + 密钥 => 密文
python ctf_crypto_tool.py crypto --alg rc4 --plaintext <明文> --key <密钥> --output-type hex|text|decimal

# 密文 + 密钥 => 明文
python ctf_crypto_tool.py crypto --alg rc4 --ciphertext <密文> --ciphertext-type hex|text|decimal --key <密钥> --output-type hex|text|decimal
```

#### 示例命令

```bash
python ctf_crypto_tool.py crypto --alg rc4 --plaintext hello --key secret --output-type hex
python ctf_crypto_tool.py crypto --alg rc4 --ciphertext <hex密文> --key secret --output-type text
```

RC4 加密和解密使用同一运算。RC4 不支持仅凭 `plaintext + ciphertext` 唯一恢复密钥。

### 2.4 AES / DES / SM4

AES、DES、SM4 支持 `ECB` / `CBC` 模式以及 `pkcs7` / `zero` / `none` 填充。密钥长度要求：AES 为 16/24/32 字节，DES 为 8 字节，SM4 为 16 字节；CBC 模式必须提供 `--iv`，IV 长度与分组长度一致（DES 为 8 字节，AES/SM4 为 16 字节）。

#### 命令格式

```bash
# 明文 + 密钥 => 密文
python ctf_crypto_tool.py crypto --alg aes|des|sm4 --plaintext <明文> --key <密钥> --mode ecb|cbc --iv <IV> --padding pkcs7|zero|none --output-type hex

# 密文 + 密钥 => 明文
python ctf_crypto_tool.py crypto --alg aes|des|sm4 --ciphertext <密文> --ciphertext-type hex --key <密钥> --mode ecb|cbc --iv <IV> --padding pkcs7|zero|none --output-type text

# 明文 + 密文 => 密钥：不可唯一恢复
python ctf_crypto_tool.py crypto --alg aes|des|sm4 --plaintext <明文> --ciphertext <密文> --ciphertext-type hex
```

#### 示例命令

```bash
python ctf_crypto_tool.py crypto --alg aes --plaintext hello --key 00112233445566778899aabbccddeeff --key-type hex --mode ecb --padding pkcs7 --output-type hex
python ctf_crypto_tool.py crypto --alg des --ciphertext <hex密文> --key 0123456789abcdef --key-type hex --mode ecb --padding pkcs7 --output-type text
python ctf_crypto_tool.py crypto --alg sm4 --plaintext hello --ciphertext <hex密文> --ciphertext-type hex
```

AES/DES/SM4 已支持使用本机 `openssl` 执行加解密；如果运行环境没有 `openssl` 命令，工具会明确报错。密钥恢复仍会报错说明无法仅凭明文和密文唯一恢复。

## 3. Hash 计算：`hash`

### 命令格式

```bash
python ctf_crypto_tool.py hash \
  --alg md5|sha256 \
  --input <输入内容> \
  --input-type hex|text|decimal
```

### 示例命令

```bash
python ctf_crypto_tool.py hash --alg md5 --input hello --input-type text
python ctf_crypto_tool.py hash --alg sha256 --input 68656c6c6f --input-type hex
python ctf_crypto_tool.py hash --alg md5 --input "104 101 108 108 111" --input-type decimal
```

支持的 Hash 算法：`md5`、`sha256`。

## 4. Hash 爆破：`hash-bruteforce`

爆破时工具会按指定长度和字符集生成候选字符串，计算 MD5/SHA256 后与目标 hash 比对。找到后输出第一个匹配结果；未找到则输出 `NOT FOUND` 并返回非零退出码。

### 命令格式

```bash
python ctf_crypto_tool.py hash-bruteforce \
  --alg md5|sha256 \
  --hash <目标hash> \
  [--length <待爆破输入的字节数>] \
  [--charset ascii_lowercase|digits|hex|printable|自定义字符集]
```

如果没有提供 `--length`，程序会交互式询问：

```text
请输入待爆破输入的字节数:
```

### 字符集说明

- `ascii_lowercase`：小写英文字母 `a-z`。
- `digits`：数字 `0-9`。
- `hex`：十六进制字符 `0-9a-f`。
- `printable`：Python `string.printable` 中的可打印字符。
- 自定义字符集：例如 `--charset abc123`。

### 示例命令

```bash
python ctf_crypto_tool.py hash-bruteforce --alg md5 --hash 900150983cd24fb0d6963f7d28e17f72 --length 3 --charset ascii_lowercase
python ctf_crypto_tool.py hash-bruteforce --alg sha256 --hash <目标hash> --length 4 --charset digits
python ctf_crypto_tool.py hash-bruteforce --alg md5 --hash <目标hash> --length 5 --charset abc123
```

## 5. 明文 + 密文 推导密钥支持情况

| 算法 | 明文 + 密钥 => 密文 | 密文 + 密钥 => 明文 | 明文 + 密文 => 密钥 |
| --- | --- | --- | --- |
| XOR | 支持 | 支持 | 支持 |
| Affine | 支持 | 支持 | 支持，爆破/恢复 `a b` |
| RC4 | 支持 | 支持 | 不支持，无法唯一恢复 |
| AES | 支持，依赖本机 `openssl` | 支持，依赖本机 `openssl` | 不支持，无法唯一恢复 |
| DES | 支持，依赖本机 `openssl` | 支持，依赖本机 `openssl` | 不支持，无法唯一恢复 |
| SM4 | 支持，依赖本机 `openssl` | 支持，依赖本机 `openssl` | 不支持，无法唯一恢复 |
