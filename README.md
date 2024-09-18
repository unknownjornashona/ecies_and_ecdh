```markdown
# ECC Encryption and Decryption


## 简介

此项目实现了基于椭圆曲线密码学（ECC）的加密和解密工具。使用 OpenSSL 库生成密钥对，通过公钥加密数据，并通过私钥解密数据。主要用于保护敏感信息的传输。

## 特性

- 生成 ECC 密钥对（公钥和私钥）。
- 使用公钥加密数据并保存到文件。
- 使用私钥解密数据并保存到文件。
- 支持从文件中加载明文进行加密。
- 支持将生成的密文和解密后的明文保存到指定文件。

## 环境要求

- C++ 11 或更高版本
- OpenSSL 库

## 编译和安装

1. 确保您已安装 OpenSSL。可以通过包管理工具（如 apt、brew 等）安装。
   
   ```bash
   # 示例（Ubuntu）
   sudo apt-get install libssl-dev
   ```

2. 创建一个构建目录并进入该目录：

   ```bash
   mkdir build
   cd build
   ```

3. 编译源代码：

   ```bash
   g++ -o ecc_encryption ../ecc_encryption.cpp -lssl -lcrypto
   ```

   请确保将 `../ecc_encryption.cpp` 替换为 `.cpp` 文件的实际路径。

## 使用方法

运行程序时传递三个参数：

```bash
./ecc_encryption <plaintext_file> <ciphertext_file> <decrypted_file>
```

- `<plaintext_file>`: 要加密的明文文件路径。
- `<ciphertext_file>`: 要保存生成的密文文件路径。
- `<decrypted_file>`: 要保存解密后的明文文件路径。

### 示例命令

```bash
./ecc_encryption plaintext.txt ciphertext.bin decrypted_text.txt
```

## 示例

1. 创建一个名为 `plaintext.txt` 的文件，在其中写入您要加密的内容。
2. 运行加密程序生成密文 `ciphertext.bin`。
3. 运行解密程序将密文还原为明文并保存为 `decrypted_text.txt`。

## 许可证

此项目遵循 MIT 许可证。可自由使用和修改，但请在分发时注明原作者。

## 贡献

欢迎任何贡献！提交问题、建议或合并请求都非常欢迎。

**💰 Donation Links:**
#### Donate Links

<b>BTC</b>: <code>39yp6fdcCiSn4v7d9JQAN27DffnMnUknwJ</code></br>
<b>BTC</b>: <code>bc1q80kznf4nzt2ratzctc6m3d8xw8avxw7rlq06rh</code></br>
<b>BTC</b>: <code>36EojEJBkLuEMC8hpNFhJJ8tuBtaX8vU3m</code></br></br>

```

### 使用说明