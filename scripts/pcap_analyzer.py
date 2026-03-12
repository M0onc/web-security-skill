#!/usr/bin/env python3
"""
PCAP Analyzer
Analyze network capture files for security issues
"""

import argparse
import sys


class PCAPAnalyzer:
    """PCAP file analyzer"""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        
        # Try to import scapy
        try:
            from scapy.all import rdpcap
            self.scapy_available = True
        except ImportError:
            print("[!] Scapy not installed")
            print("[*] Install with: pip install scapy")
            self.scapy_available = False
    
    def load_pcap(self):
        """Load PCAP file"""
        if not self.scapy_available:
            return False
        
        try:
            from scapy.all import rdpcap
            print(f"[*] Loading {self.pcap_file}...")
            self.packets = rdpcap(self.pcap_file)
            print(f"[+] Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"[!] Error loading PCAP: {e}")
            return False
    
    def analyze_protocols(self):
        """Analyze protocols in capture"""
        if not self.packets:
            return {}
        
        from collections import Counter
        
        protocols = Counter()
        
        for pkt in self.packets:
            if pkt.haslayer('TCP'):
                protocols['TCP'] += 1
            elif pkt.haslayer('UDP'):
                protocols['UDP'] += 1
            elif pkt.haslayer('ICMP'):
                protocols['ICMP'] += 1
            elif pkt.haslayer('ARP'):
                protocols['ARP'] += 1
            
            # Application protocols
            if pkt.haslayer('HTTP'):
                protocols['HTTP'] += 1
            if pkt.haslayer('DNS'):
                protocols['DNS'] += 1
            if pkt.haslayer('DHCP'):
                protocols['DHCP'] += 1
        
        return dict(protocols)
    
    def find_cleartext_passwords(self):
        """Find cleartext passwords in traffic"""
        if not self.packets:
            return []
        
        passwords = []
        
        # Common password patterns
        patterns = [
            b'password=',
            b'passwd=',
            b'pwd=',
            b'pass=',
            b'user=',
            b'username=',
            b'login=',
            b'Authorization: Basic',
        ]
        
        for pkt in self.packets:
            if pkt.haslayer('Raw'):
                data = bytes(pkt['Raw'])
                
                for pattern in patterns:
                    if pattern in data:
                        # Extract context
                        idx = data.find(pattern)
                        context = data[max(0, idx-20):min(len(data), idx+50)]
                        passwords.append({
                            'pattern': pattern.decode(),
                            'context': context
                        })
        
        return passwords
    
    def detect_scanning(self):
        """Detect port scanning activity"""
        if not self.packets:
            return []
        
        from collections import defaultdict
        
        port_hits = defaultdict(set)
        
        for pkt in self.packets:
            if pkt.haslayer('TCP') and pkt.haslayer('IP'):
                src = pkt['IP'].src
                dst = pkt['IP'].dst
                dport = pkt['TCP'].dport
                port_hits[src].add((dst, dport))
        
        # Detect scans (many ports to same host)
        scans = []
        for src, connections in port_hits.items():
            dst_ports = defaultdict(set)
            for dst, port in connections:
                dst_ports[dst].add(port)
            
            for dst, ports in dst_ports.items():
                if len(ports) > 10:
                    scans.append({
                        'scanner': src,
                        'target': dst,
                        'ports': len(ports),
                        'sample': list(ports)[:5]
                    })
        
        return scans
    
    def analyze(self):
        """Run full analysis"""
        print(f"[*] Analyzing PCAP: {self.pcap_file}\n")
        
        if not self.load_pcap():
            return
        
        # Protocol analysis
        protocols = self.analyze_protocols()
        print("[+] Protocol distribution:")
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            print(f"    {proto}: {count}")
        
        # Find cleartext passwords
        passwords = self.find_cleartext_passwords()
        if passwords:
            print(f"\n[!] Found {len(passwords)} potential credential leaks")
            for pwd in passwords[:5]:
                print(f"    Pattern: {pwd['pattern']}")
                print(f"    Context: {pwd['context'][:50]}...")
        
        # Detect scanning
        scans = self.detect_scanning()
        if scans:
            print(f"\n[!] Detected {len(scans)} potential port scan(s)")
            for scan in scans:
                print(f"    {scan['scanner']} -> {scan['target']}")
                print(f"    Ports scanned: {scan['ports']}")


def main():
    parser = argparse.ArgumentParser(description="PCAP Analyzer")
    parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    analyzer = PCAPAnalyzer(args.file)
    analyzer.analyze()


if __name__ == "__main__":
    main()
