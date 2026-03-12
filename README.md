# 🔒 Web Security Toolkit

[![GitHub](https://img.shields.io/badge/GitHub-M0onc%2Fweb--security--skill-blue?logo=github)](https://github.com/M0onc/web-security-skill)
[![ClawHub](https://img.shields.io/badge/ClawHub-Published-orange?logo=openclaw)](https://clawhub.ai)

A comprehensive security testing toolkit for OpenClaw covering web, cloud, containers, IoT, wireless, binary analysis, and malware analysis.

## 📊 Features (38 Tools)

### 🌐 Web Vulnerability Scanners (12)
- **SQL Injection**: `sql_scanner.py`
- **XSS**: `xss_scanner.py`
- **Command Injection**: `cmdi_scanner.py`
- **LFI/RFI**: `lfi_tester.py`
- **SSRF**: `ssrf_scanner.py`
- **XXE**: `xxe_scanner.py`
- **SSTI**: `ssti_scanner.py`
- **Deserialization**: `deserialization_scanner.py`
- **CORS**: `cors_scanner.py`
- **Open Redirect**: `open_redirect_scanner.py`
- **API Security**: `api_scanner.py`
- **Header Checker**: `header_checker.py`

### 🔍 Information Gathering (3)
- **Subdomain Scanner**: `subdomain_scanner.py`
- **Directory Scanner**: `dir_scanner.py`
- **Nmap Automation**: `nmap_automation.py`

### ☁️ Cloud Security (1)
- **AWS Security Scanner**: `aws_security_scanner.py` (S3, EC2, IAM, RDS)

### 🐳 Container Security (2)
- **Docker Security Scanner**: `docker_security_scanner.py`
- **Kubernetes Security Scanner**: `kubernetes_scanner.py`

### 🔧 Binary & Reverse Engineering (3)
- **Binary Analyzer**: `binary_analyzer.py` (PE/ELF)
- **Firmware Analyzer**: `firmware_analyzer.py`
- **Crypto Analyzer**: `crypto_analyzer.py`

### 📡 Wireless & IoT (4)
- **WiFi Analyzer**: `wifi_analyzer.py`
- **BLE Scanner**: `ble_scanner.py`
- **RF Analyzer**: `rf_analyzer.py`

### 🦠 Malware Analysis (2)
- **Malware Analyzer**: `malware_analyzer.py`
- **YARA Scanner**: `yara_scanner.py`

### 💥 Exploitation (2)
- **Exploit Framework**: `exploit_framework.py` (Log4j, Shellshock, Heartbleed)
- **Reverse Shell Generator**: `revshell_gen.py`

### 🛠️ Utilities (8)
- **JWT Tool**: `jwt_tool.py`
- **Encoder**: `encoder.py`
- **Hash Cracker**: `hash_cracker.py`
- **Wordlist Generator**: `wordlist_gen.py`
- **PCAP Analyzer**: `pcap_analyzer.py`
- **Request Utilities**: `request_util.py`

## 🚀 Quick Start

```bash
# Install via ClawHub
npx clawhub@latest install web-security

# Or clone from GitHub
git clone https://github.com/M0onc/web-security-skill.git
```

## 📖 Usage Examples

```bash
# SQL Injection Scan
python3 scripts/sql_scanner.py -u "http://target.com/page.php?id=1"

# XSS Testing
python3 scripts/xss_scanner.py -u "http://target.com/search" -p q

# Generate Reverse Shell
python3 scripts/revshell_gen.py --type bash --host your.ip --port 4444

# AWS Security Scan
python3 scripts/aws_security_scanner.py -p default

# Analyze Malware
python3 scripts/malware_analyzer.py -f suspicious_file.exe
```

## 📦 Contents

- 38 Python scripts
- 2 Payload libraries (XSS, SQLi)
- 4 Reference documents
- All syntax validated ✅

## 🎯 Use Cases

- Web penetration testing
- CTF competitions
- Security assessments
- Vulnerability research
- Malware analysis
- IoT security testing

## ⚠️ Disclaimer

This toolkit is for authorized security testing only. Always obtain proper authorization before testing any system.

## 📄 License

MIT-0 - Free to use, modify, and redistribute. No attribution required.

## 🔗 Links

- [GitHub Repository](https://github.com/M0onc/web-security-skill)
- [ClawHub Page](https://clawhub.ai)
- [OpenClaw](https://openclaw.ai)
