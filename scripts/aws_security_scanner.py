#!/usr/bin/env python3
"""
AWS Security Scanner
Scan AWS resources for security misconfigurations
"""

import argparse
import json
import sys


class AWSSecurityScanner:
    """AWS security configuration scanner"""
    
    def __init__(self, profile=None):
        self.profile = profile
        self.findings = []
        
        # Try to import boto3
        try:
            import boto3
            self.boto3_available = True
            self.session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        except ImportError:
            print("[!] boto3 not installed")
            print("[*] Install with: pip install boto3")
            self.boto3_available = False
    
    def check_s3_buckets(self):
        """Check S3 bucket security"""
        if not self.boto3_available:
            return []
        
        print("[*] Checking S3 buckets...")
        findings = []
        
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check public access
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            findings.append({
                                'service': 'S3',
                                'resource': bucket_name,
                                'severity': 'HIGH',
                                'issue': 'Publicly Accessible',
                                'description': 'S3 bucket is publicly accessible'
                            })
                except:
                    pass
                
                # Check encryption
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except:
                    findings.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'severity': 'MEDIUM',
                        'issue': 'No Encryption',
                        'description': 'S3 bucket does not have default encryption'
                    })
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'severity': 'LOW',
                            'issue': 'Versioning Disabled',
                            'description': 'S3 bucket versioning is not enabled'
                        })
                except:
                    pass
        
        except Exception as e:
            print(f"[!] Error checking S3: {e}")
        
        return findings
    
    def check_security_groups(self):
        """Check EC2 security groups"""
        if not self.boto3_available:
            return []
        
        print("[*] Checking Security Groups...")
        findings = []
        
        try:
            ec2 = self.session.client('ec2')
            groups = ec2.describe_security_groups()['SecurityGroups']
            
            for group in groups:
                group_id = group['GroupId']
                group_name = group['GroupName']
                
                for rule in group.get('IpPermissions', []):
                    # Check for 0.0.0.0/0
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                            
                            severity = 'HIGH' if rule.get('FromPort') in [22, 3389, 3306, 5432] else 'MEDIUM'
                            
                            findings.append({
                                'service': 'EC2',
                                'resource': f"{group_name} ({group_id})",
                                'severity': severity,
                                'issue': 'Open to Internet',
                                'description': f'Security group allows 0.0.0.0/0 on port(s) {port_range}'
                            })
        
        except Exception as e:
            print(f"[!] Error checking Security Groups: {e}")
        
        return findings
    
    def check_iam_users(self):
        """Check IAM users and policies"""
        if not self.boto3_available:
            return []
        
        print("[*] Checking IAM users...")
        findings = []
        
        try:
            iam = self.session.client('iam')
            users = iam.list_users()['Users']
            
            for user in users:
                user_name = user['UserName']
                
                # Check for console access without MFA
                try:
                    login_profile = iam.get_login_profile(UserName=user_name)
                    mfa_devices = iam.list_mfa_devices(UserName=user_name)['MFADevices']
                    
                    if not mfa_devices:
                        findings.append({
                            'service': 'IAM',
                            'resource': user_name,
                            'severity': 'HIGH',
                            'issue': 'No MFA',
                            'description': 'IAM user has console access without MFA'
                        })
                except:
                    pass
                
                # Check access keys
                access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                for key in access_keys:
                    if key['Status'] == 'Active':
                        # Check key age
                        key_age = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                        if key_age > 90:
                            findings.append({
                                'service': 'IAM',
                                'resource': user_name,
                                'severity': 'MEDIUM',
                                'issue': 'Old Access Key',
                                'description': f'Access key is {key_age} days old'
                            })
        
        except Exception as e:
            print(f"[!] Error checking IAM: {e}")
        
        return findings
    
    def check_rds_instances(self):
        """Check RDS security"""
        if not self.boto3_available:
            return []
        
        print("[*] Checking RDS instances...")
        findings = []
        
        try:
            rds = self.session.client('rds')
            instances = rds.describe_db_instances()['DBInstances']
            
            for instance in instances:
                db_id = instance['DBInstanceIdentifier']
                
                # Check public accessibility
                if instance.get('PubliclyAccessible', False):
                    findings.append({
                        'service': 'RDS',
                        'resource': db_id,
                        'severity': 'HIGH',
                        'issue': 'Publicly Accessible',
                        'description': 'RDS instance is publicly accessible'
                    })
                
                # Check encryption
                if not instance.get('StorageEncrypted', False):
                    findings.append({
                        'service': 'RDS',
                        'resource': db_id,
                        'severity': 'MEDIUM',
                        'issue': 'Not Encrypted',
                        'description': 'RDS instance does not have storage encryption'
                    })
        
        except Exception as e:
            print(f"[!] Error checking RDS: {e}")
        
        return findings
    
    def scan(self):
        """Run full AWS security scan"""
        print("[*] AWS Security Scanner\n")
        
        if not self.boto3_available:
            print("[!] AWS SDK not available")
            return []
        
        all_findings = []
        
        all_findings.extend(self.check_s3_buckets())
        all_findings.extend(self.check_security_groups())
        all_findings.extend(self.check_iam_users())
        all_findings.extend(self.check_rds_instances())
        
        return all_findings
    
    def generate_report(self, findings):
        """Generate scan report"""
        print("\n" + "="*60)
        print("AWS SECURITY SCAN REPORT")
        print("="*60)
        
        if not findings:
            print("\n[+] No security issues found")
            return
        
        # Group by severity
        by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for finding in findings:
            severity = finding['severity']
            if severity in by_severity:
                by_severity[severity].append(finding)
        
        print(f"\n[!] Found {len(findings)} security issue(s):\n")
        
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                print(f"\n[{severity}] Issues:")
                for finding in by_severity[severity]:
                    print(f"  Service: {finding['service']}")
                    print(f"  Resource: {finding['resource']}")
                    print(f"  Issue: {finding['issue']}")
                    print(f"  Description: {finding['description']}")
                    print()


def main():
    parser = argparse.ArgumentParser(description="AWS Security Scanner")
    parser.add_argument("-p", "--profile", help="AWS profile name")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    scanner = AWSSecurityScanner(profile=args.profile)
    findings = scanner.scan()
    scanner.generate_report(findings)
    
    if args.output and findings:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
