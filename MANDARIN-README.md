# 后量子加密 - 自述文件

[![构建状态](https://github.com/GuckertDev/post-quantum-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/GuckertDev/post-quantum-encryption/actions)
[![Codecov](https://codecov.io/gh/GuckertDev/post-quantum-encryption/branch/main/graph/badge.svg)](https://codecov.io/gh/GuckertDev/post-quantum-encryption)
[![记分卡](https://api.securityscorecards.dev/projects/github.com/GuckertDev/post-quantum-encryption/badge)](https://api.securityscorecards.dev/projects/github.com/GuckertDev/post-quantum-encryption)
[![许可证：MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

一个强大的 CLI 工具，用于使用混合加密方案（ML-KEM-1024 用于密钥封装、HKDF-SHA256 用于密钥派生、AES-256-GCM 用于数据加密、可选 Argon2 用于密码强化）对后量子文件和文件夹进行加密/解密。

## 功能
- **后量子安全**: 符合 NIST 的 ML-KEM-1024 (FIPS 203) 量子抗性加密。
- **混合加密**: 将 ML-KEM-1024 与 AES-256-GCM 结合，提供强大的数据保护。
- **密码模式**: 可选 Argon2 用于安全密钥派生。
- **文件夹支持**: 使用 `rayon` 进行递归加密/解密并行处理。
- **灵活模式**: 文件和文件夹操作的 `代替` 或 `复制` 模式。
- **跨平台**: 通过 GitHub Actions 在 Windows、macOS 和 Linux 上测试。
- **全面测试**: >98% 测试覆盖率，包括单元测试、模糊测试和基准测试。
- **CI/CD**: 通过 GitHub Actions 进行自动化测试、代码检查和安全审计。

## 安装

### 通过 Cargo 安装

此命令使用 Cargo 直接从 GitHub 存储库安装该工具。
```bash
cargo install post-quantum-encryption
```
## 手动克隆和构建

#### 此命令将存储库克隆到您的本地机器。
```bash
git clone https://github.com/GuckertDev/post-quantum-encryption.git
```
#### 此命令以发布模式构建项目。
```bash
cargo build --release
```
#### 此命令在本地安装构建的工具。
```bash
cargo install --path .
```

## 用法
### 交互模式
#### 此命令启动交互式菜单，您可以按照提示加密或解密文件和文件夹。
```bash
post-quantum-encryption
```
## 命令行模式
### 加密文件
#### 此命令使用可选密码加密指定文件。
```bash
post-quantum-encryption encrypt --file secret.txt --mode copy --passphrase
```
### 解密文件
#### 此命令使用可选密码解密指定的加密文件。
```bash
post-quantum-encryption decrypt --file secret.txt.mlkem --mode copy --passphrase
```
### 加密文件夹（递归）
#### 此命令递归加密指定文件夹中的所有文件。
```bash
post-quantum-encryption encrypt --folder my_folder --mode copy
```
### 解密文件夹
#### 此命令递归解密指定加密文件夹中的所有文件。
```bash
post-quantum-encryption decrypt --folder my_folder_encrypted --mode copy
```
### 自定义扩展
#### 此命令使用用户定义的扩展名而不是默认的 .mlkem 来加密文件。
```bash
post-quantum-encryption encrypt --file secret.txt --extension pqe
```
#### 有关详细示例，请参阅 docs/guide.md。

## 威胁模型 (NIST IR 8545) 
- **量子攻击**: ML-KEM 抵御 Shor/ Grover 算法.
- **侧信道**: 恒定时间操作 (subtle, oqs 实现).
- **暴力破解**: Argon2 (时间/内存密集) 用于密码强化.
- **数据损坏**: GCM 认证确保解密在篡改数据时失败.
- **存储**: 使用临时密钥；生产环境中建议使用硬件钱包进行密钥管理.

## 安全
请参阅 SECURITY.md 获取漏洞报告和详细威胁模型。请将漏洞报告至 security@guckert.dev。

## 贡献
请参阅 CONTRIBUTING.md 指南。保持 98% 以上的测试覆盖率，确保代码简洁干净。

## 更新日志
有关详细的发行说明，请参阅 CHANGELOG.md。

