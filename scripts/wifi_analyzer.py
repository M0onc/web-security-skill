#!/usr/bin/env python3
"""
WiFi Security Analyzer
Analyze WiFi networks for security issues
"""

import argparse
import subprocess
import re
import json
import os


class WiFiAnalyzer:
    """WiFi security analyzer"""
    
    def __init__(self):
        self.interfaces = []
        self.networks = []
    
    def get_interfaces(self):
        """Get wireless interfaces"""
        try:
            result = subprocess.run(
                ['iw', 'dev'],
                capture_output=True,
                text=True
            )
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split()[-1]
                    interfaces.append(iface)
            
            return interfaces
        except:
            # Fallback to iwconfig
            try:
                result = subprocess.run(
                    ['iwconfig'],
                    capture_output=True,
                    text=True
                )
                
                interfaces = []
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        iface = line.split()[0]
                        interfaces.append(iface)
                
                return interfaces
            except:
                return []
    
    def scan_networks(self, interface):
        """Scan for WiFi networks"""
        print(f"[*] Scanning with interface: {interface}")
        
        try:
            # Put interface in monitor mode or just scan
            result = subprocess.run(
                ['iwlist', interface, 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            networks = self._parse_iwlist_output(result.stdout)
            return networks
        
        except subprocess.TimeoutExpired:
            print("[!] Scan timed out")
            return []
        except Exception as e:
            print(f"[!] Scan error: {e}")
            return []
    
    def _parse_iwlist_output(self, output):
        """Parse iwlist scan output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            # New cell (network)
            if line.startswith('Cell '):
                if current_network:
                    networks.append(current_network)
                current_network = {}
            
            # ESSID (Network name)
            elif 'ESSID:' in line:
                essid = line.split('ESSID:')[1].strip('"')
                current_network['essid'] = essid
            
            # MAC Address
            elif 'Address:' in line:
                mac = line.split('Address:')[1].strip()
                current_network['bssid'] = mac
            
            # Encryption
            elif 'Encryption key:' in line:
                current_network['encrypted'] = 'on' in line.lower()
            
            # Security protocols
            elif 'IE: IEEE 802.11i/WPA2' in line:
                current_network['security'] = 'WPA2'
            elif 'IE: WPA Version 1' in line:
                current_network['security'] = 'WPA'
            elif 'WEP' in line:
                current_network['security'] = 'WEP'
            
            # Signal level
            elif 'Signal level=' in line or 'Quality=' in line:
                match = re.search(r'Signal level[=:](-?\d+)', line)
                if match:
                    current_network['signal'] = int(match.group(1))
            
            # Channel
            elif 'Channel:' in line:
                match = re.search(r'Channel[:=](\d+)', line)
                if match:
                    current_network['channel'] = int(match.group(1))
            
            # Frequency
            elif 'Frequency:' in line:
                match = re.search(r'Frequency:([\d.]+)', line)
                if match:
                    current_network['frequency'] = float(match.group(1))
        
        if current_network:
            networks.append(current_network)
        
        return networks
    
    def analyze_security(self, network):
        """Analyze network security"""
        issues = []
        
        # Check for open network
        if not network.get('encrypted', True):
            issues.append({
                'severity': 'HIGH',
                'issue': 'Open Network',
                'description': 'Network has no encryption'
            })
        
        # Check for WEP
        elif network.get('security') == 'WEP':
            issues.append({
                'severity': 'HIGH',
                'issue': 'WEP Encryption',
                'description': 'WEP is easily cracked and should not be used'
            })
        
        # Check for WPA
        elif network.get('security') == 'WPA':
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'WPA Only',
                'description': 'WPA is outdated, WPA2 or WPA3 recommended'
            })
        
        # Check for hidden SSID
        if network.get('essid') == '' or network.get('essid') == '\x00':
            issues.append({
                'severity': 'LOW',
                'issue': 'Hidden SSID',
                'description': 'SSID hiding provides minimal security'
            })
        
        # Check for common/default SSID
        common_essids = ['linksys', 'netgear', 'dlink', 'tp-link', 'default', 'admin']
        if any(common in network.get('essid', '').lower() for common in common_essids):
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Default/Common SSID',
                'description': 'May indicate default configuration'
            })
        
        return issues
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n" + "="*60)
        print("WIFI SECURITY ANALYSIS REPORT")
        print("="*60)
        
        if not self.networks:
            print("\n[!] No networks found")
            return
        
        print(f"\n[*] Found {len(self.networks)} networks\n")
        
        for network in self.networks:
            print(f"Network: {network.get('essid', 'Hidden')}")
            print(f"  BSSID: {network.get('bssid', 'Unknown')}")
            print(f"  Security: {network.get('security', 'Unknown')}")
            print(f"  Channel: {network.get('channel', 'Unknown')}")
            print(f"  Signal: {network.get('signal', 'Unknown')} dBm")
            
            issues = self.analyze_security(network)
            if issues:
                print(f"  Issues:")
                for issue in issues:
                    print(f"    [{issue['severity']}] {issue['issue']}")
                    print(f"    {issue['description']}")
            else:
                print(f"  Status: Secure")
            
            print()
    
    def run(self):
        """Run WiFi analysis"""
        print("[*] WiFi Security Analyzer\n")
        
        # Get interfaces
        self.interfaces = self.get_interfaces()
        
        if not self.interfaces:
            print("[!] No wireless interfaces found")
            print("[*] Make sure you have a wireless adapter and proper permissions")
            return
        
        print(f"[+] Found interfaces: {', '.join(self.interfaces)}")
        
        # Scan with first interface
        for interface in self.interfaces:
            print(f"\n[*] Scanning with {interface}...")
            networks = self.scan_networks(interface)
            self.networks.extend(networks)
        
        # Generate report
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(description="WiFi Security Analyzer")
    parser.add_argument("-i", "--interface", help="Wireless interface to use")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        print("[*] Run with: sudo python3 wifi_analyzer.py")
        return
    
    analyzer = WiFiAnalyzer()
    
    if args.interface:
        analyzer.interfaces = [args.interface]
    
    analyzer.run()
    
    if args.output and analyzer.networks:
        with open(args.output, 'w') as f:
            json.dump(analyzer.networks, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
