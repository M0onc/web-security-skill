---
name: web-security
version: 1.0.0
description: Comprehensive security testing toolkit for web, cloud, containers, IoT, wireless, binary analysis, malware analysis, and CTF automation. Covers SQL injection, XSS, command injection, file upload vulnerabilities, authentication bypass, SSRF, XXE, LFI, AWS security, Docker/Kubernetes security, binary analysis, firmware analysis, wireless security, malware analysis, and common exploitation techniques. Includes automated scanners, exploit generators, payload libraries, and CTF automation tools.
---

# Web Security Toolkit

A comprehensive security testing toolkit covering web, cloud, containers, IoT, wireless, binary analysis, and malware analysis.

## Quick Start

### Common Tasks

**Scan for SQL Injection:**
```bash
python3 scripts/sql_scanner.py -u "http://target.com/page.php?id=1"
```

**Test for XSS:**
```bash
python3 scripts/xss_scanner.py -u "http://target.com/search" -p q
```

**Generate Reverse Shell:**
```bash
python3 scripts/revshell_gen.py --type bash --host your.ip --port 4444
```

**Check Headers Security:**
```bash
python3 scripts/header_checker.py -u "http://target.com"
```

**Enumerate Subdomains:**
```bash
python3 scripts/subdomain_scanner.py -d target.com
```

**Scan with Nmap:**
```bash
python3 scripts/nmap_automation.py -t 192.168.1.1 -p comprehensive
```

**Analyze Binary:**
```bash
python3 scripts/binary_analyzer.py -f /path/to/binary
```

**Scan AWS Security:**
```bash
python3 scripts/aws_security_scanner.py -p default
```

**Scan Docker Security:**
```bash
python3 scripts/docker_security_scanner.py
```

**Analyze Malware:**
```bash
python3 scripts/malware_analyzer.py -f suspicious_file.exe
```

## Vulnerability Categories

### Web Vulnerabilities
- **SQL Injection**: `scripts/sql_scanner.py`
- **XSS**: `scripts/xss_scanner.py` + `assets/xss_payloads.txt`
- **Command Injection**: `scripts/cmdi_scanner.py`
- **LFI/RFI**: `scripts/lfi_tester.py`
- **SSRF**: `scripts/ssrf_scanner.py`
- **XXE**: `scripts/xxe_scanner.py`
- **SSTI**: `scripts/ssti_scanner.py`
- **Deserialization**: `scripts/deserialization_scanner.py`
- **CORS**: `scripts/cors_scanner.py`
- **Open Redirect**: `scripts/open_redirect_scanner.py`
- **File Upload**: See references

### Cloud Security
- **AWS Scanner**: `scripts/aws_security_scanner.py` - S3, EC2, IAM, RDS

### Container Security
- **Docker Scanner**: `scripts/docker_security_scanner.py` - Images, containers, Dockerfile
- **Kubernetes Scanner**: `scripts/kubernetes_scanner.py` - Pods, RBAC, secrets

### Binary & Reverse Engineering
- **Binary Analyzer**: `scripts/binary_analyzer.py` - PE/ELF analysis, protections
- **Firmware Analyzer**: `scripts/firmware_analyzer.py` - IoT firmware extraction
- **Crypto Analyzer**: `scripts/crypto_analyzer.py` - Password/entropy analysis

### Wireless & IoT
- **WiFi Analyzer**: `scripts/wifi_analyzer.py` - Network scanning
- **BLE Scanner**: `scripts/ble_scanner.py` - Bluetooth devices
- **RF Analyzer**: `scripts/rf_analyzer.py` - Radio frequency analysis

### Malware Analysis
- **Malware Analyzer**: `scripts/malware_analyzer.py` - Static analysis
- **YARA Scanner**: `scripts/yara_scanner.py` - Rule-based detection

### Exploitation Framework
- **Exploit Framework**: `scripts/exploit_framework.py` - Log4j, Shellshock, Heartbleed, etc.

## Tools Reference

### Web Scanners (12)
| Tool | Purpose | Usage |
|------|---------|-------|
| `sql_scanner.py` | SQLi detection | `python3 scripts/sql_scanner.py -u URL` |
| `xss_scanner.py` | XSS detection | `python3 scripts/xss_scanner.py -u URL` |
| `cmdi_scanner.py` | Command injection | `python3 scripts/cmdi_scanner.py -u URL` |
| `lfi_tester.py` | LFI/RFI testing | `python3 scripts/lfi_tester.py -u URL` |
| `ssrf_scanner.py` | SSRF detection | `python3 scripts/ssrf_scanner.py -u URL` |
| `xxe_scanner.py` | XXE detection | `python3 scripts/xxe_scanner.py -u URL` |
| `ssti_scanner.py` | SSTI detection | `python3 scripts/ssti_scanner.py -u URL` |
| `deserialization_scanner.py` | Deserialization | `python3 scripts/deserialization_scanner.py -u URL` |
| `cors_scanner.py` | CORS misconfig | `python3 scripts/cors_scanner.py -u URL` |
| `open_redirect_scanner.py` | Open redirect | `python3 scripts/open_redirect_scanner.py -u URL` |
| `api_scanner.py` | API security | `python3 scripts/api_scanner.py -u URL` |
| `header_checker.py` | Security headers | `python3 scripts/header_checker.py -u URL` |

### Information Gathering (3)
| Tool | Purpose | Usage |
|------|---------|-------|
| `subdomain_scanner.py` | Subdomain enum | `python3 scripts/subdomain_scanner.py -d domain.com` |
| `dir_scanner.py` | Directory brute | `python3 scripts/dir_scanner.py -u URL` |
| `nmap_automation.py` | Nmap automation | `python3 scripts/nmap_automation.py -t IP` |

### Cloud Security (1)
| Tool | Purpose | Usage |
|------|---------|-------|
| `aws_security_scanner.py` | AWS security | `python3 scripts/aws_security_scanner.py -p PROFILE` |

### Container Security (2)
| Tool | Purpose | Usage |
|------|---------|-------|
| `docker_security_scanner.py` | Docker security | `python3 scripts/docker_security_scanner.py -f Dockerfile` |
| `kubernetes_scanner.py` | K8s security | `python3 scripts/kubernetes_scanner.py` |

### Binary & Reverse Engineering (3)
| Tool | Purpose | Usage |
|------|---------|-------|
| `binary_analyzer.py` | Binary analysis | `python3 scripts/binary_analyzer.py -f BINARY` |
| `firmware_analyzer.py` | Firmware analysis | `python3 scripts/firmware_analyzer.py -f FIRMWARE` |
| `crypto_analyzer.py` | Crypto analysis | `python3 scripts/crypto_analyzer.py -d DATA` |

### Wireless & IoT (4)
| Tool | Purpose | Usage |
|------|---------|-------|
| `wifi_analyzer.py` | WiFi scanning | `python3 scripts/wifi_analyzer.py` |
| `ble_scanner.py` | BLE scanning | `python3 scripts/ble_scanner.py` |
| `rf_analyzer.py` | RF analysis | `python3 scripts/rf_analyzer.py` |
| `firmware_analyzer.py` | Firmware analysis | `python3 scripts/firmware_analyzer.py -f FIRMWARE` |

### Malware Analysis (2)
| Tool | Purpose | Usage |
|------|---------|-------|
| `malware_analyzer.py` | Static analysis | `python3 scripts/malware_analyzer.py -f FILE` |
| `yara_scanner.py` | YARA scanning | `python3 scripts/yara_scanner.py -f FILE` |

### Exploitation (2)
| Tool | Purpose | Usage |
|------|---------|-------|
| `exploit_framework.py` | Exploit framework | `python3 scripts/exploit_framework.py -t TARGET --log4j CB` |
| `revshell_gen.py` | Reverse shell gen | `python3 scripts/revshell_gen.py --list` |

### Utilities (8)
| Tool | Purpose | Usage |
|------|---------|-------|
| `jwt_tool.py` | JWT manipulation | `python3 scripts/jwt_tool.py -t TOKEN` |
| `encoder.py` | Payload encoding | `python3 scripts/encoder.py -d DATA -t base64` |
| `hash_cracker.py` | Hash cracking | `python3 scripts/hash_cracker.py -H HASH` |
| `wordlist_gen.py` | Custom wordlists | `python3 scripts/wordlist_gen.py -w word -o out.txt` |
| `pcap_analyzer.py` | PCAP analysis | `python3 scripts/pcap_analyzer.py -f FILE.pcap` |
| `request_util.py` | HTTP utilities | Import as module |

## Payload Libraries

Located in `assets/`:
- `xss_payloads.txt` - XSS payloads by context
- `sqli_payloads.txt` - SQL injection payloads

## References

Located in `references/`:
- `sqli.md` - SQL Injection techniques
- `xss.md` - XSS techniques
- `command_injection.md` - Command injection
- `file_upload.md` - File upload vulnerabilities

## Total Tools: 38 Scripts

- 12 Web Vulnerability Scanners
- 3 Information Gathering
- 1 Cloud Security
- 2 Container Security
- 3 Binary/Reverse Engineering
- 4 Wireless/IoT
- 2 Malware Analysis
- 2 Exploitation
- 8 Utilities
- 2 Payload Libraries
- 4 Reference Documents

## Tips

1. Always get authorization before testing
2. Use proxy flags to route traffic through Burp/ZAP
3. Check `references/` for detailed exploitation techniques
4. Customize payloads in `assets/` for specific targets
5. Combine multiple tools for comprehensive testing
6. Update tools regularly for latest vulnerabilities
