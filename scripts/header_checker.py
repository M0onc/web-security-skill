#!/usr/bin/env python3
"""
Security Headers Checker
Analyzes HTTP security headers and provides recommendations
"""

import requests
import sys
import argparse
from urllib.parse import urlparse

# Security headers and their recommended values
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "recommended": "max-age=31536000; includeSubDomains",
        "description": "Forces HTTPS connections",
        "severity": "High"
    },
    "Content-Security-Policy": {
        "recommended": "default-src 'self'",
        "description": "Prevents XSS and data injection",
        "severity": "High"
    },
    "X-Content-Type-Options": {
        "recommended": "nosniff",
        "description": "Prevents MIME type sniffing",
        "severity": "Medium"
    },
    "X-Frame-Options": {
        "recommended": "DENY or SAMEORIGIN",
        "description": "Prevents clickjacking",
        "severity": "High"
    },
    "X-XSS-Protection": {
        "recommended": "1; mode=block",
        "description": "Legacy XSS filter (deprecated but still useful)",
        "severity": "Low"
    },
    "Referrer-Policy": {
        "recommended": "strict-origin-when-cross-origin",
        "description": "Controls referrer information",
        "severity": "Medium"
    },
    "Permissions-Policy": {
        "recommended": "geolocation=(), microphone=(), camera=()",
        "description": "Controls browser features",
        "severity": "Medium"
    },
    "Cross-Origin-Embedder-Policy": {
        "recommended": "require-corp",
        "description": "Prevents cross-origin resource loading",
        "severity": "Medium"
    },
    "Cross-Origin-Opener-Policy": {
        "recommended": "same-origin",
        "description": "Isolates browsing context",
        "severity": "Medium"
    },
    "Cross-Origin-Resource-Policy": {
        "recommended": "same-origin",
        "description": "Controls cross-origin resource access",
        "severity": "Low"
    },
}

# Headers that should NOT be present
DANGEROUS_HEADERS = {
    "Server": "Reveals server software information",
    "X-Powered-By": "Reveals technology stack",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
}


def check_headers(url):
    """Check security headers for a URL"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        results = {
            "missing": [],
            "present": [],
            "dangerous": [],
            "cookies": []
        }
        
        print(f"[*] Checking: {response.url}")
        print(f"[*] Status: {response.status_code}")
        print(f"[*] Server: {headers.get('Server', 'Not disclosed')}\n")
        
        # Check security headers
        print("="*60)
        print("SECURITY HEADERS CHECK")
        print("="*60)
        
        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                value = headers[header]
                results["present"].append({
                    "header": header,
                    "value": value,
                    "recommended": info["recommended"]
                })
                print(f"[✓] {header}")
                print(f"    Value: {value}")
                print(f"    Recommended: {info['recommended']}")
            else:
                results["missing"].append({
                    "header": header,
                    "severity": info["severity"],
                    "description": info["description"],
                    "recommended": info["recommended"]
                })
                severity_icon = "[!]" if info["severity"] == "High" else "[-]"
                print(f"{severity_icon} {header} - MISSING ({info['severity']})")
                print(f"    Description: {info['description']}")
        
        # Check dangerous headers
        print("\n" + "="*60)
        print("INFORMATION DISCLOSURE")
        print("="*60)
        
        for header, description in DANGEROUS_HEADERS.items():
            if header in headers:
                results["dangerous"].append({
                    "header": header,
                    "value": headers[header],
                    "description": description
                })
                print(f"[!] {header}: {headers[header]}")
                print(f"    Risk: {description}")
        
        if not results["dangerous"]:
            print("[✓] No information disclosure headers found")
        
        # Check cookies
        print("\n" + "="*60)
        print("COOKIE SECURITY")
        print("="*60)
        
        if response.cookies:
            for cookie in response.cookies:
                cookie_issues = []
                
                if not cookie.secure:
                    cookie_issues.append("Missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_issues.append("Missing HttpOnly flag")
                if not cookie.has_nonstandard_attr('SameSite'):
                    cookie_issues.append("Missing SameSite flag")
                
                if cookie_issues:
                    print(f"[!] {cookie.name}")
                    for issue in cookie_issues:
                        print(f"    - {issue}")
                    results["cookies"].append({
                        "name": cookie.name,
                        "issues": cookie_issues
                    })
                else:
                    print(f"[✓] {cookie.name} - Secure")
        else:
            print("[-] No cookies set")
        
        # SSL/TLS check
        print("\n" + "="*60)
        print("SSL/TLS CHECK")
        print("="*60)
        
        parsed = urlparse(response.url)
        if parsed.scheme == "https":
            print("[✓] HTTPS enabled")
            if "Strict-Transport-Security" in headers:
                print("[✓] HSTS enabled")
            else:
                print("[!] HSTS not enabled")
        else:
            print("[!] HTTPS not enforced")
        
        return results
        
    except requests.exceptions.SSLError as e:
        print(f"[!] SSL Error: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection Error: {e}")
        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def generate_report(results):
    """Generate a summary report"""
    if not results:
        return
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    total_headers = len(SECURITY_HEADERS)
    present = len(results["present"])
    missing = len(results["missing"])
    
    score = (present / total_headers) * 100
    
    print(f"\nSecurity Score: {score:.1f}% ({present}/{total_headers})")
    
    high_missing = [h for h in results["missing"] if h["severity"] == "High"]
    if high_missing:
        print(f"\n[!] Critical missing headers:")
        for h in high_missing:
            print(f"    - {h['header']}")
    
    if results["dangerous"]:
        print(f"\n[!] Information disclosure issues: {len(results['dangerous'])}")
    
    if results["cookies"]:
        print(f"\n[!] Cookie security issues: {len(results['cookies'])}")


def main():
    parser = argparse.ArgumentParser(description="Security Headers Checker")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--proxy", help="Proxy URL")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    results = check_headers(args.url)
    generate_report(results)


if __name__ == "__main__":
    main()
