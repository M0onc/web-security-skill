#!/usr/bin/env python3
"""
BLE Scanner
Bluetooth Low Energy device scanner
"""

import argparse
import subprocess
import json
import sys


class BLEScanner:
    """Bluetooth Low Energy scanner"""
    
    def __init__(self):
        self.devices = []
    
    def check_bluetooth(self):
        """Check if Bluetooth is available"""
        try:
            result = subprocess.run(
                ['hciconfig'],
                capture_output=True,
                text=True
            )
            return 'hci' in result.stdout
        except:
            return False
    
    def scan_ble(self, duration=10):
        """Scan for BLE devices"""
        print(f"[*] Scanning for BLE devices ({duration}s)...")
        
        try:
            # Using hcitool
            result = subprocess.run(
                ['timeout', str(duration), 'hcitool', 'lescan'],
                capture_output=True,
                text=True
            )
            
            devices = self._parse_hcitool_output(result.stdout)
            return devices
        
        except Exception as e:
            print(f"[!] Scan error: {e}")
            return []
    
    def _parse_hcitool_output(self, output):
        """Parse hcitool lescan output"""
        devices = []
        seen = set()
        
        for line in output.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                mac = parts[0]
                name = ' '.join(parts[1:]) if len(parts) > 1 else 'Unknown'
                
                if mac not in seen:
                    seen.add(mac)
                    devices.append({
                        'mac': mac,
                        'name': name
                    })
        
        return devices
    
    def get_device_info(self, mac):
        """Get detailed device information"""
        print(f"[*] Getting info for {mac}...")
        
        try:
            # Try to connect and get info
            result = subprocess.run(
                ['hcitool', 'lecc', mac],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return {
                'mac': mac,
                'connection': result.returncode == 0
            }
        
        except:
            return {
                'mac': mac,
                'connection': False
            }
    
    def analyze_device(self, device):
        """Analyze device for security issues"""
        issues = []
        
        # Check for common device names that might indicate test/dev devices
        dev_indicators = ['test', 'dev', 'debug', 'temp', 'example']
        if any(ind in device.get('name', '').lower() for ind in dev_indicators):
            issues.append({
                'severity': 'INFO',
                'issue': 'Development Device',
                'description': 'Device name suggests development/test environment'
            })
        
        # Check for devices without names
        if not device.get('name') or device.get('name') == 'Unknown':
            issues.append({
                'severity': 'LOW',
                'issue': 'Anonymous Device',
                'description': 'Device is not broadcasting a name'
            })
        
        return issues
    
    def generate_report(self):
        """Generate scan report"""
        print("\n" + "="*60)
        print("BLE SCAN RESULTS")
        print("="*60)
        
        if not self.devices:
            print("\n[!] No BLE devices found")
            return
        
        print(f"\n[*] Found {len(self.devices)} device(s)\n")
        
        for device in self.devices:
            print(f"Device: {device.get('name', 'Unknown')}")
            print(f"  MAC: {device.get('mac')}")
            
            issues = self.analyze_device(device)
            if issues:
                print(f"  Notes:")
                for issue in issues:
                    print(f"    [{issue['severity']}] {issue['issue']}")
            print()
    
    def run(self, duration=10):
        """Run BLE scan"""
        print("[*] BLE Security Scanner\n")
        
        if not self.check_bluetooth():
            print("[!] Bluetooth not available")
            print("[*] Make sure Bluetooth is enabled and you have proper permissions")
            return
        
        print("[+] Bluetooth is available")
        
        # Scan for devices
        self.devices = self.scan_ble(duration)
        
        # Generate report
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description="BLE Scanner")
    parser.add_argument("-t", "--time", type=int, default=10,
                        help="Scan duration in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    scanner = BLEScanner()
    scanner.run(args.time)
    
    if args.output and scanner.devices:
        with open(args.output, 'w') as f:
            json.dump(scanner.devices, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
