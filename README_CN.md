# 🔒 Web Security Toolkit - 网络安全工具包

[![GitHub](https://img.shields.io/badge/GitHub-M0onc%2Fweb--security--skill-blue?logo=github)](https://github.com/M0onc/web-security-skill)
[![ClawHub](https://img.shields.io/badge/ClawHub-Published-orange?logo=openclaw)](https://clawhub.ai)

一个全面的安全测试工具包，涵盖 Web、云、容器、IoT、无线、二进制分析和恶意软件分析。

## 📊 功能特性 (38个工具)

### 🌐 Web 漏洞扫描器 (12个)
- **SQL 注入**: `sql_scanner.py` - 检测 SQL 注入漏洞
- **XSS 跨站脚本**: `xss_scanner.py` - 检测反射型和存储型 XSS
- **命令注入**: `cmdi_scanner.py` - 检测命令执行漏洞
- **LFI/RFI**: `lfi_tester.py` - 本地/远程文件包含测试
- **SSRF**: `ssrf_scanner.py` - 服务器端请求伪造检测
- **XXE**: `xxe_scanner.py` - XML 外部实体攻击检测
- **SSTI**: `ssti_scanner.py` - 服务端模板注入检测
- **反序列化**: `deserialization_scanner.py` - 检测不安全的反序列化
- **CORS**: `cors_scanner.py` - 跨域资源共享配置检查
- **开放重定向**: `open_redirect_scanner.py` - 检测开放重定向漏洞
- **API 安全**: `api_scanner.py` - REST/GraphQL API 安全测试
- **HTTP 头检查**: `header_checker.py` - 安全头配置检查

### 🔍 信息收集 (3个)
- **子域名扫描**: `subdomain_scanner.py`
- **目录扫描**: `dir_scanner.py`
- **Nmap 自动化**: `nmap_automation.py`

### ☁️ 云安全 (1个)
- **AWS 安全扫描**: `aws_security_scanner.py` (S3, EC2, IAM, RDS)

### 🐳 容器安全 (2个)
- **Docker 安全扫描**: `docker_security_scanner.py`
- **Kubernetes 安全扫描**: `kubernetes_scanner.py`

### 🔧 二进制与逆向工程 (3个)
- **二进制分析**: `binary_analyzer.py` (PE/ELF)
- **固件分析**: `firmware_analyzer.py`
- **加密分析**: `crypto_analyzer.py`

### 📡 无线与 IoT (4个)
- **WiFi 分析**: `wifi_analyzer.py`
- **蓝牙扫描**: `ble_scanner.py`
- **RF 分析**: `rf_analyzer.py`

### 🦠 恶意软件分析 (2个)
- **恶意软件分析**: `malware_analyzer.py`
- **YARA 扫描**: `yara_scanner.py`

### 💥 漏洞利用 (2个)
- **漏洞利用框架**: `exploit_framework.py` (Log4j, Shellshock, Heartbleed)
- **反向 Shell 生成**: `revshell_gen.py`

### 🛠️ 实用工具 (8个)
- **JWT 工具**: `jwt_tool.py`
- **编码器**: `encoder.py`
- **哈希破解**: `hash_cracker.py`
- **字典生成**: `wordlist_gen.py`
- **PCAP 分析**: `pcap_analyzer.py`
- **请求工具**: `request_util.py`

## 🚀 快速开始

```bash
# 通过 ClawHub 安装
npx clawhub@latest install web-security

# 或从 GitHub 克隆
git clone https://github.com/M0onc/web-security-skill.git
```

## 📖 使用示例

```bash
# SQL 注入扫描
python3 scripts/sql_scanner.py -u "http://target.com/page.php?id=1"

# XSS 测试
python3 scripts/xss_scanner.py -u "http://target.com/search" -p q

# 生成反向 Shell
python3 scripts/revshell_gen.py --type bash --host your.ip --port 4444

# AWS 安全扫描
python3 scripts/aws_security_scanner.py -p default

# 分析恶意软件
python3 scripts/malware_analyzer.py -f suspicious_file.exe
```

## 📦 内容清单

- 38 个 Python 脚本
- 2 个 Payload 库 (XSS, SQLi)
- 4 个参考文档
- 全部语法验证通过 ✅

## 🎯 适用场景

- Web 渗透测试
- CTF 比赛
- 安全评估
- 漏洞研究
- 恶意软件分析
- IoT 安全测试

## ⚠️ 免责声明

本工具包仅用于授权的安全测试。在测试任何系统之前，请务必获得适当的授权。

## 📄 许可证

MIT-0 - 可自由使用、修改和再分发。无需署名。

## 🔗 相关链接

- [GitHub 仓库](https://github.com/M0onc/web-security-skill)
- [ClawHub 页面](https://clawhub.ai)
- [OpenClaw](https://openclaw.ai)
