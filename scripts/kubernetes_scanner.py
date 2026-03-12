#!/usr/bin/env python3
"""
Kubernetes Security Scanner
Scan Kubernetes clusters for security misconfigurations
"""

import argparse
import json
import subprocess
import yaml


class KubernetesScanner:
    """Kubernetes security scanner"""
    
    def __init__(self):
        self.findings = []
    
    def check_kubectl(self):
        """Check if kubectl is available"""
        try:
            result = subprocess.run(
                ['kubectl', 'version', '--client'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return None
    
    def check_cluster_access(self):
        """Check cluster access"""
        try:
            result = subprocess.run(
                ['kubectl', 'cluster-info'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    def scan_pods(self):
        """Scan pods for security issues"""
        print("[*] Scanning pods...")
        findings = []
        
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"[!] Error getting pods: {result.stderr}")
                return findings
            
            pods = json.loads(result.stdout)
            
            for pod in pods.get('items', []):
                pod_name = pod['metadata']['name']
                namespace = pod['metadata']['namespace']
                spec = pod.get('spec', {})
                
                # Check privileged
                for container in spec.get('containers', []):
                    security_context = container.get('securityContext', {})
                    
                    if security_context.get('privileged', False):
                        findings.append({
                            'resource': f"{namespace}/{pod_name}",
                            'type': 'Pod',
                            'severity': 'HIGH',
                            'issue': 'Privileged Container',
                            'description': f'Container {container["name"]} is running in privileged mode'
                        })
                    
                    if security_context.get('runAsRoot', False):
                        findings.append({
                            'resource': f"{namespace}/{pod_name}",
                            'type': 'Pod',
                            'severity': 'MEDIUM',
                            'issue': 'Running as Root',
                            'description': f'Container {container["name"]} is configured to run as root'
                        })
                    
                    if security_context.get('allowPrivilegeEscalation', True):
                        findings.append({
                            'resource': f"{namespace}/{pod_name}",
                            'type': 'Pod',
                            'severity': 'MEDIUM',
                            'issue': 'Privilege Escalation Allowed',
                            'description': f'Container {container["name"]} allows privilege escalation'
                        })
                
                # Check for host network
                if spec.get('hostNetwork', False):
                    findings.append({
                        'resource': f"{namespace}/{pod_name}",
                        'type': 'Pod',
                        'severity': 'MEDIUM',
                        'issue': 'Host Network',
                        'description': 'Pod is using host network'
                    })
                
                # Check for host PID
                if spec.get('hostPID', False):
                    findings.append({
                        'resource': f"{namespace}/{pod_name}",
                        'type': 'Pod',
                        'severity': 'MEDIUM',
                        'issue': 'Host PID',
                        'description': 'Pod is using host PID namespace'
                    })
                
                # Check for sensitive volume mounts
                for volume in spec.get('volumes', []):
                    if 'hostPath' in volume:
                        host_path = volume['hostPath'].get('path', '')
                        sensitive_paths = ['/etc', '/var/run/docker.sock', '/', '/root']
                        
                        for sensitive in sensitive_paths:
                            if host_path.startswith(sensitive):
                                findings.append({
                                    'resource': f"{namespace}/{pod_name}",
                                    'type': 'Pod',
                                    'severity': 'HIGH',
                                    'issue': 'Sensitive Host Path',
                                    'description': f'Pod mounts sensitive host path: {host_path}'
                                })
        
        except Exception as e:
            print(f"[!] Error scanning pods: {e}")
        
        return findings
    
    def scan_roles(self):
        """Scan RBAC roles"""
        print("[*] Scanning RBAC roles...")
        findings = []
        
        try:
            # Check cluster roles
            result = subprocess.run(
                ['kubectl', 'get', 'clusterroles', '-o', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                roles = json.loads(result.stdout)
                
                for role in roles.get('items', []):
                    role_name = role['metadata']['name']
                    rules = role.get('rules', [])
                    
                    for rule in rules:
                        # Check for wildcard permissions
                        if '*' in rule.get('apiGroups', []) or '*' in rule.get('resources', []) or '*' in rule.get('verbs', []):
                            findings.append({
                                'resource': role_name,
                                'type': 'ClusterRole',
                                'severity': 'HIGH',
                                'issue': 'Wildcard Permissions',
                                'description': 'Role has wildcard (*) permissions'
                            })
                        
                        # Check for dangerous permissions
                        dangerous_verbs = ['create', 'delete', 'update', 'patch', '*']
                        dangerous_resources = ['pods', 'secrets', 'serviceaccounts', 'clusterroles', 'clusterrolebindings']
                        
                        verbs = rule.get('verbs', [])
                        resources = rule.get('resources', [])
                        
                        if any(v in dangerous_verbs for v in verbs) and any(r in dangerous_resources for r in resources):
                            findings.append({
                                'resource': role_name,
                                'type': 'ClusterRole',
                                'severity': 'MEDIUM',
                                'issue': 'Dangerous Permissions',
                                'description': f'Role has dangerous permissions on {resources}'
                            })
        
        except Exception as e:
            print(f"[!] Error scanning roles: {e}")
        
        return findings
    
    def scan_secrets(self):
        """Scan secrets"""
        print("[*] Scanning secrets...")
        findings = []
        
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'secrets', '--all-namespaces', '-o', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                secrets = json.loads(result.stdout)
                
                for secret in secrets.get('items', []):
                    secret_name = secret['metadata']['name']
                    namespace = secret['metadata']['namespace']
                    secret_type = secret.get('type', 'Opaque')
                    
                    # Check for default secrets
                    if secret_name == 'default-token':
                        continue
                    
                    # Check for hardcoded credentials in annotations
                    annotations = secret.get('metadata', {}).get('annotations', {})
                    for key, value in annotations.items():
                        if any(sensitive in key.lower() for sensitive in ['password', 'secret', 'token', 'key']):
                            findings.append({
                                'resource': f"{namespace}/{secret_name}",
                                'type': 'Secret',
                                'severity': 'MEDIUM',
                                'issue': 'Sensitive Annotation',
                                'description': f'Secret has potentially sensitive annotation: {key}'
                            })
        
        except Exception as e:
            print(f"[!] Error scanning secrets: {e}")
        
        return findings
    
    def scan_network_policies(self):
        """Check network policies"""
        print("[*] Checking network policies...")
        findings = []
        
        try:
            result = subprocess.run(
                ['kubectl', 'get', 'networkpolicies', '--all-namespaces', '-o', 'json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                policies = json.loads(result.stdout)
                
                # Check if default deny policy exists
                namespaces = set()
                for policy in policies.get('items', []):
                    namespace = policy['metadata']['namespace']
                    namespaces.add(namespace)
                
                # Get all namespaces
                ns_result = subprocess.run(
                    ['kubectl', 'get', 'namespaces', '-o', 'json'],
                    capture_output=True,
                    text=True
                )
                
                if ns_result.returncode == 0:
                    all_namespaces = json.loads(ns_result.stdout)
                    
                    for ns in all_namespaces.get('items', []):
                        ns_name = ns['metadata']['name']
                        
                        if ns_name not in namespaces and ns_name not in ['kube-system', 'kube-public', 'kube-node-lease']:
                            findings.append({
                                'resource': ns_name,
                                'type': 'Namespace',
                                'severity': 'MEDIUM',
                                'issue': 'No Network Policy',
                                'description': f'Namespace {ns_name} has no network policies'
                            })
        
        except Exception as e:
            print(f"[!] Error checking network policies: {e}")
        
        return findings
    
    def scan(self):
        """Run full Kubernetes scan"""
        print("[*] Kubernetes Security Scanner\n")
        
        version = self.check_kubectl()
        if version:
            print(f"[+] kubectl version: {version.split(chr(10))[0]}\n")
        else:
            print("[!] kubectl not found\n")
            return []
        
        if not self.check_cluster_access():
            print("[!] Cannot access Kubernetes cluster")
            print("[*] Make sure you have configured kubectl with proper credentials")
            return []
        
        print("[+] Connected to cluster\n")
        
        all_findings = []
        
        all_findings.extend(self.scan_pods())
        all_findings.extend(self.scan_roles())
        all_findings.extend(self.scan_secrets())
        all_findings.extend(self.scan_network_policies())
        
        return all_findings
    
    def generate_report(self, findings):
        """Generate scan report"""
        print("\n" + "="*60)
        print("KUBERNETES SECURITY SCAN REPORT")
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
                    print(f"  Resource: {finding['resource']}")
                    print(f"  Type: {finding['type']}")
                    print(f"  Issue: {finding['issue']}")
                    print(f"  Description: {finding['description']}")
                    print()


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Security Scanner")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    scanner = KubernetesScanner()
    findings = scanner.scan()
    scanner.generate_report(findings)
    
    if args.output and findings:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
