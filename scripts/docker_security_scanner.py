#!/usr/bin/env python3
"""
Docker Security Scanner
Scan Docker containers and images for security issues
"""

import argparse
import json
import subprocess
import re


class DockerSecurityScanner:
    """Docker security scanner"""
    
    def __init__(self):
        self.findings = []
    
    def check_docker_version(self):
        """Check Docker version"""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return None
    
    def check_docker_daemon(self):
        """Check Docker daemon security"""
        print("[*] Checking Docker daemon configuration...")
        findings = []
        
        # Check if Docker is running with TLS
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True
            )
            
            docker_process = [line for line in result.stdout.split('\n') if 'dockerd' in line]
            
            for process in docker_process:
                if '--tlsverify' not in process:
                    findings.append({
                        'category': 'Daemon',
                        'severity': 'MEDIUM',
                        'issue': 'TLS Not Enforced',
                        'description': 'Docker daemon is not using TLS verification'
                    })
                
                if '--userns-remap' not in process:
                    findings.append({
                        'category': 'Daemon',
                        'severity': 'LOW',
                        'issue': 'User Namespaces Disabled',
                        'description': 'User namespace remapping is not enabled'
                    })
        
        except Exception as e:
            print(f"[!] Error checking daemon: {e}")
        
        return findings
    
    def scan_images(self):
        """Scan Docker images"""
        print("[*] Scanning Docker images...")
        findings = []
        
        try:
            # Get list of images
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                capture_output=True,
                text=True
            )
            
            images = [line for line in result.stdout.strip().split('\n') if line]
            
            for image in images:
                if image == '<none>:<none>':
                    continue
                
                print(f"  Scanning: {image}")
                
                # Run Trivy if available
                try:
                    trivy_result = subprocess.run(
                        ['trivy', 'image', '--exit-code', '0', '--format', 'json', image],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if trivy_result.returncode == 0:
                        vulnerabilities = json.loads(trivy_result.stdout)
                        
                        for result in vulnerabilities.get('Results', []):
                            for vuln in result.get('Vulnerabilities', []):
                                findings.append({
                                    'category': 'Image',
                                    'resource': image,
                                    'severity': vuln.get('Severity', 'UNKNOWN'),
                                    'issue': vuln.get('VulnerabilityID', 'Unknown'),
                                    'description': vuln.get('Description', 'No description')
                                })
                
                except FileNotFoundError:
                    # Trivy not installed
                    pass
                except Exception as e:
                    print(f"    [!] Error scanning {image}: {e}")
        
        except Exception as e:
            print(f"[!] Error listing images: {e}")
        
        return findings
    
    def scan_containers(self):
        """Scan running containers"""
        print("[*] Scanning Docker containers...")
        findings = []
        
        try:
            # Get running containers
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{.Names}}'],
                capture_output=True,
                text=True
            )
            
            containers = result.stdout.strip().split('\n')
            
            for container in containers:
                if not container:
                    continue
                
                print(f"  Checking: {container}")
                
                # Inspect container
                inspect_result = subprocess.run(
                    ['docker', 'inspect', container],
                    capture_output=True,
                    text=True
                )
                
                if inspect_result.returncode == 0:
                    container_info = json.loads(inspect_result.stdout)[0]
                    
                    # Check privileged mode
                    if container_info.get('HostConfig', {}).get('Privileged', False):
                        findings.append({
                            'category': 'Container',
                            'resource': container,
                            'severity': 'HIGH',
                            'issue': 'Privileged Mode',
                            'description': 'Container is running in privileged mode'
                        })
                    
                    # Check for host network
                    if container_info.get('HostConfig', {}).get('NetworkMode') == 'host':
                        findings.append({
                            'category': 'Container',
                            'resource': container,
                            'severity': 'MEDIUM',
                            'issue': 'Host Network',
                            'description': 'Container is using host network namespace'
                        })
                    
                    # Check for host PID
                    if container_info.get('HostConfig', {}).get('PidMode') == 'host':
                        findings.append({
                            'category': 'Container',
                            'resource': container,
                            'severity': 'MEDIUM',
                            'issue': 'Host PID',
                            'description': 'Container is using host PID namespace'
                        })
                    
                    # Check for mounted Docker socket
                    mounts = container_info.get('Mounts', [])
                    for mount in mounts:
                        if '/var/run/docker.sock' in mount.get('Source', ''):
                            findings.append({
                                'category': 'Container',
                                'resource': container,
                                'severity': 'HIGH',
                                'issue': 'Docker Socket Mounted',
                                'description': 'Container has Docker socket mounted'
                            })
                    
                    # Check for root user
                    config = container_info.get('Config', {})
                    user = config.get('User', '')
                    if not user or user == 'root':
                        findings.append({
                            'category': 'Container',
                            'resource': container,
                            'severity': 'MEDIUM',
                            'issue': 'Running as Root',
                            'description': 'Container is running as root user'
                        })
        
        except Exception as e:
            print(f"[!] Error scanning containers: {e}")
        
        return findings
    
    def check_dockerfile(self, dockerfile_path):
        """Check Dockerfile for security issues"""
        print(f"[*] Checking Dockerfile: {dockerfile_path}")
        findings = []
        
        try:
            with open(dockerfile_path, 'r') as f:
                content = f.read()
                lines = content.split('\n')
            
            for i, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Check for latest tag
                if re.match(r'^FROM\s+\S+:latest', line_stripped, re.IGNORECASE):
                    findings.append({
                        'category': 'Dockerfile',
                        'line': i,
                        'severity': 'MEDIUM',
                        'issue': 'Latest Tag',
                        'description': 'Using :latest tag is not recommended for reproducibility'
                    })
                
                # Check for ADD instead of COPY
                if re.match(r'^ADD\s+\S+\s+\S+', line_stripped, re.IGNORECASE):
                    findings.append({
                        'category': 'Dockerfile',
                        'line': i,
                        'severity': 'LOW',
                        'issue': 'Using ADD',
                        'description': 'ADD has more features than COPY, use COPY when possible'
                    })
                
                # Check for secrets in ENV
                if re.match(r'^ENV\s+(PASSWORD|SECRET|KEY|TOKEN)', line_stripped, re.IGNORECASE):
                    findings.append({
                        'category': 'Dockerfile',
                        'line': i,
                        'severity': 'HIGH',
                        'issue': 'Hardcoded Secret',
                        'description': 'Potential hardcoded secret in ENV'
                    })
                
                # Check for sudo
                if 'sudo' in line_stripped.lower():
                    findings.append({
                        'category': 'Dockerfile',
                        'line': i,
                        'severity': 'MEDIUM',
                        'issue': 'Using sudo',
                        'description': 'Avoid using sudo in containers'
                    })
                
                # Check for curl | bash
                if re.search(r'curl.*\|.*(bash|sh)', line_stripped, re.IGNORECASE):
                    findings.append({
                        'category': 'Dockerfile',
                        'line': i,
                        'severity': 'HIGH',
                        'issue': 'Remote Code Execution',
                        'description': 'Piping curl to shell is dangerous'
                    })
        
        except Exception as e:
            print(f"[!] Error reading Dockerfile: {e}")
        
        return findings
    
    def scan(self, dockerfile=None):
        """Run full Docker security scan"""
        print("[*] Docker Security Scanner\n")
        
        version = self.check_docker_version()
        if version:
            print(f"[+] Docker version: {version}\n")
        else:
            print("[!] Docker not found or not running\n")
            return []
        
        all_findings = []
        
        all_findings.extend(self.check_docker_daemon())
        all_findings.extend(self.scan_images())
        all_findings.extend(self.scan_containers())
        
        if dockerfile:
            all_findings.extend(self.check_dockerfile(dockerfile))
        
        return all_findings
    
    def generate_report(self, findings):
        """Generate scan report"""
        print("\n" + "="*60)
        print("DOCKER SECURITY SCAN REPORT")
        print("="*60)
        
        if not findings:
            print("\n[+] No security issues found")
            return
        
        # Group by severity
        by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            if severity in by_severity:
                by_severity[severity].append(finding)
        
        print(f"\n[!] Found {len(findings)} security issue(s):\n")
        
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                print(f"\n[{severity}] Issues:")
                for finding in by_severity[severity]:
                    print(f"  Category: {finding['category']}")
                    if 'resource' in finding:
                        print(f"  Resource: {finding['resource']}")
                    if 'line' in finding:
                        print(f"  Line: {finding['line']}")
                    print(f"  Issue: {finding['issue']}")
                    print(f"  Description: {finding['description']}")
                    print()


def main():
    parser = argparse.ArgumentParser(description="Docker Security Scanner")
    parser.add_argument("-f", "--dockerfile", help="Path to Dockerfile")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    scanner = DockerSecurityScanner()
    findings = scanner.scan(dockerfile=args.dockerfile)
    scanner.generate_report(findings)
    
    if args.output and findings:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
