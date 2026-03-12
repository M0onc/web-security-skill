#!/usr/bin/env python3
"""
API Security Scanner
Scan REST APIs for common security issues
"""

import requests
import argparse
import json
import urllib.parse

# Common API endpoints to test
COMMON_ENDPOINTS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/graphql",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/api-docs",
    "/api/docs",
    "/v1",
    "/v2",
    "/v3",
    "/internal",
    "/internal/api",
    "/admin/api",
    "/dev/api",
    "/test/api",
    "/debug",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/metrics",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/actuator/heapdump",
    "/actuator/httptrace",
    "/actuator/mappings",
    "/actuator/scheduledtasks",
    "/actuator/jolokia",
    "/jolokia",
    "/env",
    "/configprops",
    "/metrics",
    "/health",
    "/info",
    "/trace",
    "/dump",
    "/mappings",
]

# Common API vulnerabilities to check
VULNERABILITY_CHECKS = {
    "missing_auth": {
        "description": "Missing authentication",
        "check": lambda r: r.status_code == 200
    },
    "verbose_error": {
        "description": "Verbose error messages",
        "check": lambda r: any(x in r.text.lower() for x in ['error', 'exception', 'traceback', 'stacktrace'])
    },
    "cors_misconfig": {
        "description": "CORS misconfiguration",
        "check": lambda r: r.headers.get('Access-Control-Allow-Origin') == '*'
    },
    "sensitive_data": {
        "description": "Sensitive data exposure",
        "check": lambda r: any(x in r.text.lower() for x in ['password', 'secret', 'key', 'token', 'api_key', 'private'])
    },
}


def discover_endpoints(base_url):
    """Discover API endpoints"""
    print(f"[*] Discovering API endpoints...\n")
    
    discovered = []
    
    for endpoint in COMMON_ENDPOINTS:
        url = urllib.parse.urljoin(base_url, endpoint)
        
        try:
            response = requests.get(url, timeout=5)
            
            if response.status_code != 404:
                print(f"[+] Found: {url} ({response.status_code})")
                discovered.append({
                    "url": url,
                    "status": response.status_code,
                    "content_type": response.headers.get('Content-Type', 'Unknown'),
                    "size": len(response.content)
                })
        except:
            pass
    
    return discovered


def test_http_methods(url):
    """Test different HTTP methods"""
    print(f"[*] Testing HTTP methods on {url}...")
    
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD']
    results = {}
    
    for method in methods:
        try:
            if method == 'GET':
                response = requests.get(url, timeout=5)
            elif method == 'POST':
                response = requests.post(url, timeout=5)
            elif method == 'PUT':
                response = requests.put(url, timeout=5)
            elif method == 'DELETE':
                response = requests.delete(url, timeout=5)
            elif method == 'PATCH':
                response = requests.patch(url, timeout=5)
            elif method == 'OPTIONS':
                response = requests.options(url, timeout=5)
            elif method == 'TRACE':
                response = requests.request('TRACE', url, timeout=5)
            elif method == 'HEAD':
                response = requests.head(url, timeout=5)
            
            results[method] = {
                "status": response.status_code,
                "allowed": 'Allow' in response.headers.get('Access-Control-Allow-Methods', '')
            }
            
            if response.status_code not in [404, 405, 501]:
                print(f"    {method}: {response.status_code}")
        
        except Exception as e:
            pass
    
    return results


def test_idor(url):
    """Test for IDOR (Insecure Direct Object Reference)"""
    print(f"[*] Testing for IDOR...")
    
    # Common ID patterns
    id_patterns = [
        ("/1", "/2"),
        ("/user/1", "/user/2"),
        ("/account/1", "/account/2"),
        ("/order/1", "/order/2"),
        ("/item/1", "/item/2"),
    ]
    
    results = []
    
    for pattern1, pattern2 in id_patterns:
        try:
            url1 = urllib.parse.urljoin(url, pattern1)
            url2 = urllib.parse.urljoin(url, pattern2)
            
            r1 = requests.get(url1, timeout=5)
            r2 = requests.get(url2, timeout=5)
            
            if r1.status_code == 200 and r2.status_code == 200:
                if r1.text != r2.text:
                    print(f"    [+] Potential IDOR: {pattern1} vs {pattern2}")
                    results.append({
                        "type": "IDOR",
                        "urls": [url1, url2]
                    })
        except:
            pass
    
    return results


def test_mass_assignment(url):
    """Test for mass assignment vulnerability"""
    print(f"[*] Testing for mass assignment...")
    
    # Try to set admin flag
    test_data = {
        "admin": True,
        "is_admin": True,
        "role": "admin",
        "user_role": "administrator",
    }
    
    try:
        response = requests.post(url, json=test_data, timeout=5)
        
        if response.status_code == 200:
            print(f"    [!] Potential mass assignment - accepted admin fields")
            return True
    except:
        pass
    
    return False


def scan_api(base_url):
    """Scan API for vulnerabilities"""
    print(f"[*] Scanning API: {base_url}\n")
    
    # Discover endpoints
    endpoints = discover_endpoints(base_url)
    
    if not endpoints:
        print("[!] No API endpoints discovered")
        return []
    
    print(f"\n[*] Discovered {len(endpoints)} endpoint(s)")
    
    vulnerabilities = []
    
    for endpoint in endpoints:
        print(f"\n[*] Testing endpoint: {endpoint['url']}")
        
        # Test HTTP methods
        methods = test_http_methods(endpoint['url'])
        
        # Check for vulnerabilities
        try:
            response = requests.get(endpoint['url'], timeout=5)
            
            for vuln_name, vuln_check in VULNERABILITY_CHECKS.items():
                if vuln_check['check'](response):
                    print(f"    [!] {vuln_check['description']}")
                    vulnerabilities.append({
                        "endpoint": endpoint['url'],
                        "type": vuln_name,
                        "description": vuln_check['description']
                    })
        except:
            pass
        
        # Test IDOR
        idor_results = test_idor(endpoint['url'])
        vulnerabilities.extend(idor_results)
        
        # Test mass assignment
        if test_mass_assignment(endpoint['url']):
            vulnerabilities.append({
                "endpoint": endpoint['url'],
                "type": "mass_assignment",
                "description": "Potential mass assignment vulnerability"
            })
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Base API URL")
    parser.add_argument("--proxy", help="Proxy URL")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_api(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} potential issue(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Endpoint: {vuln['endpoint']}")
            print(f"     Type: {vuln['type']}")
            print(f"     Description: {vuln['description']}")
            print()
    else:
        print("\n[+] No obvious vulnerabilities detected")
    
    if args.output and vulnerabilities:
        with open(args.output, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
