#!/usr/bin/env python3
"""
Firmware Analyzer
Analyze IoT firmware for security issues
"""

import argparse
import os
import subprocess
import json
import re
from pathlib import Path


class FirmwareAnalyzer:
    """IoT Firmware security analyzer"""
    
    def __init__(self, firmware_path):
        self.firmware_path = firmware_path
        self.extracted_path = None
        self.results = {}
    
    def identify_firmware(self):
        """Identify firmware type"""
        try:
            result = subprocess.run(
                ['file', self.firmware_path],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return "Unknown"
    
    def extract_firmware(self):
        """Extract firmware using binwalk"""
        print("[*] Attempting to extract firmware...")
        
        try:
            # Create extraction directory
            extract_dir = f"{self.firmware_path}_extracted"
            os.makedirs(extract_dir, exist_ok=True)
            
            # Run binwalk
            result = subprocess.run(
                ['binwalk', '-e', '-C', extract_dir, self.firmware_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.extracted_path = extract_dir
                print(f"[+] Firmware extracted to: {extract_dir}")
                return True
            else:
                print(f"[!] Extraction failed: {result.stderr}")
                return False
        
        except subprocess.TimeoutExpired:
            print("[!] Extraction timed out")
            return False
        except FileNotFoundError:
            print("[!] binwalk not found. Install with: apt install binwalk")
            return False
    
    def find_files(self):
        """Find interesting files in extracted firmware"""
        if not self.extracted_path:
            return []
        
        interesting_files = []
        
        patterns = {
            'config': r'.*\.(conf|config|cfg|ini|xml|json|yaml)$',
            'credentials': r'.*(passwd|shadow|htpasswd|credentials|secret|key).*',
            'binaries': r'.*\.(elf|bin|so|dll|exe)$',
            'scripts': r'.*\.(sh|py|pl|rb|lua)$',
            'web': r'.*\.(html|htm|js|php|asp|jsp)$',
        }
        
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                for category, pattern in patterns.items():
                    if re.match(pattern, file, re.IGNORECASE):
                        interesting_files.append({
                            'category': category,
                            'path': file_path,
                            'size': os.path.getsize(file_path)
                        })
                        break
        
        return interesting_files
    
    def check_backdoors(self):
        """Check for potential backdoors"""
        if not self.extracted_path:
            return []
        
        backdoor_indicators = []
        
        # Known backdoor signatures
        signatures = [
            r'backdoor|backd00r',
            r'telnetd.*-l.*sh',
            r'nc.*-e.*(/bin/sh|/bin/bash)',
            r'python.*-c.*socket.*subprocess',
            r'useradd.*admin.*password',
            r'echo.*root:.*\/etc\/passwd',
        ]
        
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        
                        for sig in signatures:
                            if re.search(sig, content.decode('utf-8', errors='ignore'), re.IGNORECASE):
                                backdoor_indicators.append({
                                    'file': file_path,
                                    'signature': sig
                                })
                except:
                    pass
        
        return backdoor_indicators
    
    def check_default_credentials(self):
        """Check for default credentials"""
        if not self.extracted_path:
            return []
        
        credentials = []
        
        # Common default credentials
        default_creds = [
            (r'admin:admin', 'admin/admin'),
            (r'root:root', 'root/root'),
            (r'root:password', 'root/password'),
            (r'admin:password', 'admin/password'),
            (r'guest:guest', 'guest/guest'),
        ]
        
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                if 'passwd' in file.lower() or 'shadow' in file.lower():
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                            for pattern, cred in default_creds:
                                if re.search(pattern, content, re.IGNORECASE):
                                    credentials.append({
                                        'file': file_path,
                                        'credential': cred
                                    })
                    except:
                        pass
        
        return credentials
    
    def analyze(self):
        """Run full firmware analysis"""
        print(f"[*] Analyzing firmware: {self.firmware_path}\n")
        
        # Identify firmware
        self.results['firmware_type'] = self.identify_firmware()
        print(f"[+] Firmware type: {self.results['firmware_type']}")
        
        # Extract firmware
        if self.extract_firmware():
            # Find interesting files
            self.results['files'] = self.find_files()
            print(f"\n[+] Found {len(self.results['files'])} interesting files")
            
            # Group by category
            by_category = {}
            for f in self.results['files']:
                cat = f['category']
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(f)
            
            for cat, files in by_category.items():
                print(f"    {cat}: {len(files)} files")
            
            # Check for backdoors
            self.results['backdoors'] = self.check_backdoors()
            if self.results['backdoors']:
                print(f"\n[!] Potential backdoors found:")
                for backdoor in self.results['backdoors']:
                    print(f"    - {backdoor['file']}")
                    print(f"      Signature: {backdoor['signature']}")
            
            # Check for default credentials
            self.results['default_credentials'] = self.check_default_credentials()
            if self.results['default_credentials']:
                print(f"\n[!] Default credentials found:")
                for cred in self.results['default_credentials']:
                    print(f"    - {cred['credential']} in {cred['file']}")
        
        return self.results


def main():
    parser = argparse.ArgumentParser(description="Firmware Analyzer")
    parser.add_argument("-f", "--firmware", required=True, help="Firmware file to analyze")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.firmware):
        print(f"[!] File not found: {args.firmware}")
        return
    
    analyzer = FirmwareAnalyzer(args.firmware)
    results = analyzer.analyze()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
