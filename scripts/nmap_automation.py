#!/usr/bin/env python3
"""
Nmap Automation
Automated nmap scanning for CTF and penetration testing
"""

import subprocess
import argparse
import json
import xml.etree.ElementTree as ET
import os
import sys


class NmapScanner:
    """Nmap automation class"""
    
    # Predefined scan profiles
    PROFILES = {
        "quick": {
            "description": "Quick scan - top 100 ports",
            "args": "-sV -T4 -F"
        },
        "full": {
            "description": "Full TCP port scan",
            "args": "-sV -sS -p- -T4"
        },
        "udp": {
            "description": "UDP scan - top 100 ports",
            "args": "-sU -T4 --top-ports 100"
        },
        "comprehensive": {
            "description": "Comprehensive scan with scripts",
            "args": "-sS -sV -sC -O -p- -T4"
        },
        "vuln": {
            "description": "Vulnerability scan",
            "args": "-sV --script vuln -T4"
        },
        "stealth": {
            "description": "Stealthy scan",
            "args": "-sS -T2 --max-retries 1"
        },
        "ctf": {
            "description": "CTF optimized scan",
            "args": "-sC -sV -O -p- --max-retries 2 -T4"
        },
        "http": {
            "description": "HTTP focused scan",
            "args": "-sV -p 80,443,8080,8443,3000,5000,8000,8008,8081,9000 --script http-title,http-headers,http-methods"
        },
    }
    
    def __init__(self, target, profile="quick", output_dir=".", verbose=False):
        self.target = target
        self.profile = profile
        self.output_dir = output_dir
        self.verbose = verbose
        
        # Check if nmap is installed
        if not self._check_nmap():
            print("[!] Nmap is not installed or not in PATH")
            sys.exit(1)
    
    def _check_nmap(self):
        """Check if nmap is installed"""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    def _get_output_files(self):
        """Generate output file paths"""
        base_name = f"{self.output_dir}/nmap_{self.target.replace('/', '_')}"
        return {
            "normal": f"{base_name}.txt",
            "xml": f"{base_name}.xml",
            "grepable": f"{base_name}.gnmap",
            "json": f"{base_name}.json"
        }
    
    def run(self):
        """Run nmap scan"""
        profile = self.PROFILES.get(self.profile, self.PROFILES["quick"])
        output_files = self._get_output_files()
        
        # Build command
        cmd = [
            "nmap",
            *profile["args"].split(),
            "-oN", output_files["normal"],
            "-oX", output_files["xml"],
            "-oG", output_files["grepable"],
            self.target
        ]
        
        print(f"[*] Starting {self.profile} scan...")
        print(f"[*] Target: {self.target}")
        print(f"[*] Profile: {profile['description']}")
        print(f"[*] Command: {' '.join(cmd)}\n")
        
        try:
            if self.verbose:
                result = subprocess.run(cmd, check=True)
            else:
                result = subprocess.run(cmd, capture_output=True, check=True)
            
            print(f"[+] Scan completed!")
            print(f"[*] Results saved to:")
            for format_type, filepath in output_files.items():
                if format_type != "json":
                    print(f"    - {filepath}")
            
            # Convert XML to JSON
            self._convert_to_json(output_files["xml"], output_files["json"])
            
            # Parse and display summary
            self._parse_results(output_files["xml"])
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Scan failed: {e}")
            return False
    
    def _convert_to_json(self, xml_file, json_file):
        """Convert nmap XML output to JSON"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            data = {
                "scan_info": {
                    "args": root.get("args"),
                    "start": root.get("start"),
                    "version": root.get("version")
                },
                "hosts": []
            }
            
            for host in root.findall("host"):
                host_data = {
                    "status": host.find("status").get("state") if host.find("status") else "unknown",
                    "addresses": [],
                    "hostnames": [],
                    "ports": []
                }
                
                # Addresses
                for addr in host.findall("address"):
                    host_data["addresses"].append({
                        "addr": addr.get("addr"),
                        "type": addr.get("addrtype")
                    })
                
                # Hostnames
                hostnames = host.find("hostnames")
                if hostnames:
                    for hostname in hostnames.findall("hostname"):
                        host_data["hostnames"].append({
                            "name": hostname.get("name"),
                            "type": hostname.get("type")
                        })
                
                # Ports
                ports = host.find("ports")
                if ports:
                    for port in ports.findall("port"):
                        port_data = {
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": port.find("state").get("state") if port.find("state") else "unknown"
                        }
                        
                        service = port.find("service")
                        if service:
                            port_data["service"] = {
                                "name": service.get("name"),
                                "product": service.get("product"),
                                "version": service.get("version"),
                                "extrainfo": service.get("extrainfo")
                            }
                        
                        host_data["ports"].append(port_data)
                
                data["hosts"].append(host_data)
            
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"    - {json_file}")
            
        except Exception as e:
            print(f"[!] Error converting to JSON: {e}")
    
    def _parse_results(self, xml_file):
        """Parse and display scan results"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            print("\n" + "="*60)
            print("SCAN RESULTS")
            print("="*60)
            
            for host in root.findall("host"):
                # Get IP
                ip = host.find("address").get("addr") if host.find("address") else "unknown"
                print(f"\nHost: {ip}")
                
                # Get hostname
                hostnames = host.find("hostnames")
                if hostnames:
                    for hostname in hostnames.findall("hostname"):
                        print(f"Hostname: {hostname.get('name')}")
                
                # Get OS
                os_elem = host.find("os")
                if os_elem:
                    for osmatch in os_elem.findall("osmatch"):
                        print(f"OS: {osmatch.get('name')} ({osmatch.get('accuracy')}%)")
                
                # Get ports
                ports = host.find("ports")
                if ports:
                    print("\nOpen Ports:")
                    print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'VERSION'}")
                    print("-"*60)
                    
                    for port in ports.findall("port"):
                        port_id = f"{port.get('portid')}/{port.get('protocol')}"
                        state = port.find("state").get("state") if port.find("state") else "unknown"
                        
                        service_elem = port.find("service")
                        if service_elem:
                            service = service_elem.get("name", "unknown")
                            product = service_elem.get("product", "")
                            version = service_elem.get("version", "")
                            version_str = f"{product} {version}".strip()
                        else:
                            service = "unknown"
                            version_str = ""
                        
                        if state == "open":
                            print(f"{port_id:<10} {state:<10} {service:<20} {version_str}")
            
        except Exception as e:
            print(f"[!] Error parsing results: {e}")
    
    @classmethod
    def list_profiles(cls):
        """List available scan profiles"""
        print("Available scan profiles:")
        print("-"*60)
        for name, profile in cls.PROFILES.items():
            print(f"  {name:<15} - {profile['description']}")
            print(f"                   Args: {profile['args']}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description="Nmap Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t 192.168.1.1 -p comprehensive
  %(prog)s -t target.com -p ctf -o ./scans
  %(prog)s --list-profiles
        """
    )
    
    parser.add_argument("-t", "--target", help="Target host/IP")
    parser.add_argument("-p", "--profile", default="quick",
                        choices=list(NmapScanner.PROFILES.keys()),
                        help="Scan profile")
    parser.add_argument("-o", "--output", default=".",
                        help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List available profiles")
    
    args = parser.parse_args()
    
    if args.list_profiles:
        NmapScanner.list_profiles()
        return
    
    if not args.target:
        parser.print_help()
        return
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Run scan
    scanner = NmapScanner(
        target=args.target,
        profile=args.profile,
        output_dir=args.output,
        verbose=args.verbose
    )
    
    scanner.run()


if __name__ == "__main__":
    main()
