#!/usr/bin/env python3
"""
Binary Analyzer
Analyze binary files for security issues
"""

import argparse
import subprocess
import os
import re
import json
from pathlib import Path


class BinaryAnalyzer:
    """Binary security analyzer"""
    
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.results = {}
        
    def check_file_type(self):
        """Check file type using file command"""
        try:
            result = subprocess.run(
                ['file', self.binary_path],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def check_protection_mechanisms(self):
        """Check binary protection mechanisms"""
        protections = {}
        
        # Check if checksec is available
        try:
            result = subprocess.run(
                ['checksec', '--file=' + self.binary_path, '--output=json'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                protections = json.loads(result.stdout)
        except:
            # Manual checks
            protections = self._manual_protection_check()
        
        return protections
    
    def _manual_protection_check(self):
        """Manual protection checks"""
        protections = {}
        
        # Check NX (No-eXecute)
        try:
            result = subprocess.run(
                ['readelf', '-l', self.binary_path],
                capture_output=True,
                text=True
            )
            protections['NX'] = 'GNU_STACK' in result.stdout and 'RWE' not in result.stdout
        except:
            protections['NX'] = 'Unknown'
        
        # Check PIE (Position Independent Executable)
        try:
            result = subprocess.run(
                ['readelf', '-h', self.binary_path],
                capture_output=True,
                text=True
            )
            protections['PIE'] = 'DYN' in result.stdout
        except:
            protections['PIE'] = 'Unknown'
        
        # Check Canary (Stack protection)
        try:
            result = subprocess.run(
                ['readelf', '-s', self.binary_path],
                capture_output=True,
                text=True
            )
            protections['Canary'] = '__stack_chk_fail' in result.stdout
        except:
            protections['Canary'] = 'Unknown'
        
        # Check RELRO
        try:
            result = subprocess.run(
                ['readelf', '-d', self.binary_path],
                capture_output=True,
                text=True
            )
            if 'BIND_NOW' in result.stdout:
                protections['RELRO'] = 'Full'
            elif 'GNU_RELRO' in result.stdout:
                protections['RELRO'] = 'Partial'
            else:
                protections['RELRO'] = 'None'
        except:
            protections['RELRO'] = 'Unknown'
        
        return protections
    
    def check_strings(self):
        """Extract interesting strings"""
        interesting = []
        
        try:
            result = subprocess.run(
                ['strings', '-n', '8', self.binary_path],
                capture_output=True,
                text=True
            )
            
            strings = result.stdout.split('\n')
            
            patterns = {
                'password': r'password|passwd|pwd',
                'key': r'secret|api_key|private_key',
                'url': r'https?://[^\s]+',
                'email': r'[\w\.-]+@[\w\.-]+',
                'ip': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                'path': r'/[\w\-/]+\.[\w]+',
            }
            
            for s in strings:
                for category, pattern in patterns.items():
                    if re.search(pattern, s, re.IGNORECASE):
                        interesting.append({
                            'category': category,
                            'string': s
                        })
                        break
        
        except Exception as e:
            print(f"[!] Error extracting strings: {e}")
        
        return interesting[:50]  # Return top 50
    
    def check_symbols(self):
        """Check for dangerous functions"""
        dangerous = []
        
        dangerous_functions = [
            'gets', 'strcpy', 'strcat', 'sprintf', 'scanf',
            'system', 'exec', 'popen', 'eval', 'memcpy',
            'strncpy', 'strncat', 'snprintf', 'vsprintf',
            'malloc', 'free', 'realloc', 'alloca',
            'printf', 'fprintf', 'dprintf',
        ]
        
        try:
            result = subprocess.run(
                ['nm', '-D', self.binary_path],
                capture_output=True,
                text=True
            )
            
            for func in dangerous_functions:
                if func in result.stdout:
                    dangerous.append(func)
        
        except:
            pass
        
        return dangerous
    
    def analyze(self):
        """Run full analysis"""
        print(f"[*] Analyzing: {self.binary_path}\n")
        
        self.results['file_type'] = self.check_file_type()
        print(f"[+] File type: {self.results['file_type']}")
        
        self.results['protections'] = self.check_protection_mechanisms()
        print(f"\n[+] Protection mechanisms:")
        for protection, status in self.results['protections'].items():
            status_str = str(status)
            if status_str.lower() in ['true', 'full', 'yes']:
                print(f"    ✓ {protection}: Enabled")
            elif status_str.lower() in ['false', 'none', 'no']:
                print(f"    ✗ {protection}: Disabled")
            else:
                print(f"    ? {protection}: {status}")
        
        self.results['dangerous_functions'] = self.check_symbols()
        if self.results['dangerous_functions']:
            print(f"\n[!] Dangerous functions found:")
            for func in self.results['dangerous_functions']:
                print(f"    - {func}")
        
        self.results['strings'] = self.check_strings()
        if self.results['strings']:
            print(f"\n[+] Interesting strings found:")
            for item in self.results['strings'][:20]:
                print(f"    [{item['category']}] {item['string'][:80]}")
        
        return self.results


def main():
    parser = argparse.ArgumentParser(description="Binary Analyzer")
    parser.add_argument("-b", "--binary", required=True, help="Binary file to analyze")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"[!] File not found: {args.binary}")
        return
    
    analyzer = BinaryAnalyzer(args.binary)
    results = analyzer.analyze()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
