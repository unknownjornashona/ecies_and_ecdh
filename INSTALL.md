```markdown
# 安装指南

此文档提供有关如何安装和配置 ECC 加密与解密工具的说明。

## 先决条件

在开始安装之前，请确保您的系统上已安装以下软件：

- **C++ 编译器**: 例如 g++ 或 clang++
- **OpenSSL**: 确保安装了开发版本的 OpenSSL，以便使用其加密库。

### 安装 OpenSSL

#### 在 Linux 上

对于基于 Debian 的系统（如 Ubuntu）：

```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

对于基于 Red Hat 的系统（如 Fedora 或 CentOS）：

```bash
sudo dnf install openssl-devel
```

#### 在 macOS 上

使用 Homebrew 安装 OpenSSL：

```bash
brew install openssl
```

请注意安装完成后，您可能需要设置环境变量：

```bash
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
```

#### 在 Windows 上

1. 下载预编译的 OpenSSL DLLs 和头文件（[OpenSSL 官网](https://slproweb.com/products/Win32OpenSSL.html)）。
2. 按照说明进行安装，确认将 OpenSSL 的 `bin` 目录添加到系统的 `PATH` 环境变量中。

## 克隆项目

确保您已安装 Git。然后您可以使用以下命令从 GitHub 克隆项目：

```bash
git clone <项目的 Git 地址>
cd <项目目录>
```

替换 `<项目的 Git 地址>` 和 `<项目目录>` 为实际地址和目录。

## 编译项目

1. **创建构建目录**：

   ```bash
   mkdir build
   cd build
   ```

2. **编译源代码**：

   ```bash
   g++ -o ecc_encryption ../ecc_encryption.cpp -lssl -lcrypto
   ```

   请确保将 `../ecc_encryption.cpp` 替换为您的源文件实际路径。

## 运行程序

一旦编译成功，您就能够在 `build` 目录中找到可执行文件 `ecc_encryption`。按照以下方式运行程序：

```bash
./ecc_encryption <plaintext_file> <ciphertext_file> <decrypted_file>
```

确保替换 `<plaintext_file>`、`<ciphertext_file>` 和 `<decrypted_file>` 为您实际使用的文件名。

## 遇到的问题

如果在安装或使用过程中遇到问题，请参考开源社区的支持和文档，或在项目的 issue 页面提出问题。

```

### 使用说明