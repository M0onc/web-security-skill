#!/usr/bin/env python3
"""
YARA Scanner
Simple YARA rule scanner for malware detection
"""

import argparse
import json
import os
import re


class YaraScanner:
    """Simple YARA-like scanner"""
    
    # Built-in rules
    BUILT_IN_RULES = {
        'ransomware': {
            'description': 'Ransomware indicators',
            'strings': [
                b'your files have been encrypted',
                b'bitcoin', b'btc', b'wallet',
                b'ransom', b'decrypt', b'payment',
                b'.locked', b'.encrypted', b'.crypto',
                b'tor browser', b'onion',
            ],
            'condition': '2 of them'
        },
        'trojan': {
            'description': 'Trojan indicators',
            'strings': [
                b'backdoor', b'reverse shell', b'connect back',
                b'keylogger', b'stealer', b'grabber',
                b'credential', b'password', b'cookie',
            ],
            'condition': '2 of them'
        },
        'miner': {
            'description': 'Cryptocurrency miner',
            'strings': [
                b'stratum+tcp', b'stratum+ssl',
                b'xmrig', b'cpuminer', b'miner',
                b'monero', b'xmr', b'pool',
                b'hashrate', b'difficulty',
            ],
            'condition': '2 of them'
        },
        'packed': {
            'description': 'Packed/Obfuscated',
            'strings': [
                b'UPX', b'ASPack', b'PECompact',
                b'VMProtect', b'Themida', b'Enigma',
                b'packed', b'compressed',
            ],
            'condition': '1 of them'
        },
        'webshell': {
            'description': 'Web Shell',
            'strings': [
                b'eval($_POST', b'eval($_GET', b'eval($_REQUEST',
                b'system($_POST', b'exec($_POST', b'shell_exec',
                b'passthru', b'popen', b'proc_open',
                b'base64_decode', b'gzinflate', b'str_rot13',
                b'c99', b'r57', b'wso', b'b374k',
            ],
            'condition': '2 of them'
        },
        'powershell_malware': {
            'description': 'PowerShell Malware',
            'strings': [
                b'powershell -ep bypass', b'-executionpolicy bypass',
                b'invoke-expression', b'iex',
                b'invoke-mimikatz', b'invoke-shellcode',
                b'downloadstring', b'downloadfile',
                b'frombase64string', b'convert]::tobyte',
                b'bitsadmin', b'certutil -decode',
            ],
            'condition': '2 of them'
        },
        'macro_malware': {
            'description': 'Macro Malware',
            'strings': [
                b'autoopen', b'autoclose', b'autoexec',
                b'shell(', b'createobject', b'wscript.shell',
                b'powershell', b'cmd.exe', b'rundll32',
                b'document_open', b'workbook_open',
            ],
            'condition': '2 of them'
        },
    }
    
    def __init__(self, rules_file=None):
        self.rules = self.BUILT_IN_RULES.copy()
        self.matches = []
        
        if rules_file:
            self.load_rules(rules_file)
    
    def load_rules(self, rules_file):
        """Load custom rules from file"""
        try:
            with open(rules_file, 'r') as f:
                custom_rules = json.load(f)
                self.rules.update(custom_rules)
            print(f"[+] Loaded custom rules from {rules_file}")
        except Exception as e:
            print(f"[!] Error loading rules: {e}")
    
    def scan_file(self, file_path):
        """Scan a single file"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            return self.scan_content(content, file_path)
        
        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}")
            return None
    
    def scan_content(self, content, file_path):
        """Scan content against rules"""
        matches = []
        
        for rule_name, rule in self.rules.items():
            matched_strings = []
            
            for string in rule.get('strings', []):
                if string in content:
                    matched_strings.append(string.decode('utf-8', errors='ignore'))
            
            # Check condition
            condition = rule.get('condition', '1 of them')
            threshold = int(re.search(r'(\d+)', condition).group(1))
            
            if len(matched_strings) >= threshold:
                matches.append({
                    'rule': rule_name,
                    'description': rule.get('description', ''),
                    'file': file_path,
                    'matches': matched_strings[:5],  # Limit matches shown
                    'count': len(matched_strings)
                })
        
        return matches
    
    def scan_directory(self, directory):
        """Scan all files in a directory"""
        print(f"[*] Scanning directory: {directory}\n")
        
        all_matches = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                print(f"  Scanning: {file_path}")
                
                matches = self.scan_file(file_path)
                if matches:
                    all_matches.extend(matches)
        
        return all_matches
    
    def generate_report(self, matches):
        """Generate scan report"""
        print("\n" + "="*60)
        print("YARA SCAN REPORT")
        print("="*60)
        
        if not matches:
            print("\n[+] No matches found")
            return
        
        print(f"\n[!] Found {len(matches)} match(es):\n")
        
        for match in matches:
            print(f"Rule: {match['rule']}")
            print(f"Description: {match['description']}")
            print(f"File: {match['file']}")
            print(f"Matches: {match['count']}")
            print(f"Strings found:")
            for s in match['matches']:
                print(f"  - {s[:50]}...")
            print()


def main():
    parser = argparse.ArgumentParser(description="YARA Scanner")
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument("-d", "--directory", help="Directory to scan")
    parser.add_argument("-r", "--rules", help="Custom rules file (JSON)")
    parser.add_argument("-l", "--list-rules", action="store_true", help="List built-in rules")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    scanner = YaraScanner(rules_file=args.rules)
    
    if args.list_rules:
        print("[+] Built-in rules:")
        for name, rule in scanner.rules.items():
            print(f"  - {name}: {rule['description']}")
        return
    
    matches = []
    
    if args.file:
        print(f"[*] Scanning file: {args.file}\n")
        matches = scanner.scan_file(args.file)
        if matches:
            scanner.generate_report(matches)
        else:
            print("\n[+] No matches found")
    
    elif args.directory:
        matches = scanner.scan_directory(args.directory)
        scanner.generate_report(matches)
    
    else:
        parser.print_help()
    
    if args.output and matches:
        with open(args.output, 'w') as f:
            json.dump(matches, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
