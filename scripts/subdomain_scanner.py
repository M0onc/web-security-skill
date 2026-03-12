#!/usr/bin/env python3
"""
Subdomain Scanner
Enumerate subdomains using various techniques
"""

import requests
import argparse
import threading
from queue import Queue
import dns.resolver
import dns.zone
import dns.query
import socket

# Common subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "ns5", "ns6", "ns7", "ns8", "www1", "www2", "www3", "www4",
    "www5", "mail1", "mail2", "mail3", "mail4", "mail5", "blog", "shop", "forum",
    "admin", "api", "app", "dev", "test", "staging", "demo", "beta", "alpha",
    "portal", "secure", "vpn", "remote", "support", "help", "docs", "doc",
    "wiki", "kb", "status", "monitor", "stats", "analytics", "metrics", "grafana",
    "prometheus", "kibana", "elasticsearch", "log", "logs", "logstash", "splunk",
    "jenkins", "ci", "cd", "build", "deploy", "git", "gitlab", "github", "svn",
    "cvs", "repo", "repository", "source", "code", "npm", "maven", "pypi", "docker",
    "registry", "harbor", "nexus", "artifactory", "sonarqube", "nagios", "zabbix",
    "cacti", "munin", "ganglia", "newrelic", "datadog", "pingdom", "uptime",
    "backup", "backups", "archive", "archives", "old", "legacy", "v1", "v2",
    "v3", "api-v1", "api-v2", "api-v3", "rest", "graphql", "soap", "xmlrpc",
    "rpc", "json", "ajax", "cdn", "static", "assets", "img", "images", "css",
    "js", "javascript", "fonts", "media", "video", "videos", "download", "downloads",
    "file", "files", "storage", "s3", "bucket", "data", "db", "database", "mysql",
    "postgres", "postgresql", "mongo", "mongodb", "redis", "memcached", "elastic",
    "search", "solr", "sphinx", "whois", "dns", "ns", "mx", "spf", "dkim", "dmarc",
    "webdisk", "webdav", "caldav", "carddav", "autodiscover", "autoconfig",
    "cpanel", "whm", "plesk", "directadmin", "webmin", "virtualmin", "usermin",
    "phpmyadmin", "pma", "myadmin", "mysqladmin", "dbadmin", "adminer", "sqlpad",
    "ftp", "sftp", "ssh", "telnet", "vnc", "rdp", "remote", "desktop", "xdmcp",
    "imap", "pop3", "smtp", "mail", "email", "webmail", "exchange", "owa", "o365",
    "office", "sharepoint", "teams", "skype", "lync", "sip", "xmpp", "jabber",
    "chat", "irc", "mumble", "teamspeak", "discord", "slack", "mattermost",
    "confluence", "jira", "wiki", "redmine", "trac", "bugzilla", "mantis",
    "phabricator", "gerrit", "crucible", "fisheye", "bamboo", "bitbucket",
    "stash", "crowd", "crowd2", "auth", "sso", "oauth", "openid", "saml",
    "ldap", "ad", "active", "directory", "kerberos", "radius", "tacacs",
    "puppet", "chef", "ansible", "salt", "terraform", "vagrant", "packer",
    "vault", "consul", "nomad", "kubernetes", "k8s", "kube", "openshift",
    "rancher", "docker", "container", "swarm", "compose", "helm", "istio",
    "linkerd", "traefik", "nginx", "apache", "httpd", "tomcat", "jboss",
    "wildfly", "weblogic", "websphere", "iis", "jetty", "resin", "glassfish",
]


class SubdomainScanner:
    def __init__(self, domain, threads=20, wordlist=None, timeout=3):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.total = 0
        self.checked = 0
        
        # Load wordlist
        if wordlist:
            self.wordlist = self.load_wordlist(wordlist)
        else:
            self.wordlist = SUBDOMAIN_WORDLIST
    
    def load_wordlist(self, filepath):
        """Load wordlist from file"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return SUBDOMAIN_WORDLIST
    
    def resolve_dns(self, subdomain):
        """Resolve DNS for subdomain"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_domain, 'A', lifetime=self.timeout)
            ips = [str(rdata) for rdata in answers]
            return True, ips
        except:
            return False, []
    
    def check_http(self, subdomain):
        """Check if HTTP/HTTPS is accessible"""
        full_domain = f"{subdomain}.{self.domain}"
        results = []
        
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{full_domain}"
                response = requests.get(url, timeout=self.timeout, allow_redirects=False)
                results.append({
                    'protocol': protocol,
                    'status': response.status_code,
                    'server': response.headers.get('Server', 'Unknown')
                })
            except:
                pass
        
        return results
    
    def worker(self):
        """Worker thread"""
        while True:
            try:
                subdomain = self.queue.get(timeout=1)
            except:
                break
            
            exists, ips = self.resolve_dns(subdomain)
            
            with self.lock:
                self.checked += 1
                if self.checked % 100 == 0:
                    print(f"[*] Progress: {self.checked}/{self.total}", end="\r")
            
            if exists:
                http_results = self.check_http(subdomain)
                
                with self.lock:
                    self.found.append({
                        'subdomain': subdomain,
                        'ips': ips,
                        'http': http_results
                    })
                    self.print_result(subdomain, ips, http_results)
            
            self.queue.task_done()
    
    def print_result(self, subdomain, ips, http_results):
        """Print found subdomain"""
        full_domain = f"{subdomain}.{self.domain}"
        print(f"[+] {full_domain}")
        print(f"    IPs: {', '.join(ips)}")
        
        if http_results:
            for result in http_results:
                print(f"    {result['protocol'].upper()}: {result['status']} ({result['server']})")
        print()
    
    def scan(self):
        """Start scanning"""
        print(f"[*] Target: {self.domain}")
        print(f"[*] Wordlist: {len(self.wordlist)} entries")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Starting scan...\n")
        
        # Build queue
        for subdomain in self.wordlist:
            self.queue.put(subdomain)
        
        self.total = self.queue.qsize()
        
        # Start threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for completion
        self.queue.join()
        
        # Stop threads
        for t in threads:
            t.join(timeout=1)
        
        return self.found
    
    def save_results(self, output_file):
        """Save results to file"""
        with open(output_file, 'w') as f:
            for result in self.found:
                full_domain = f"{result['subdomain']}.{self.domain}"
                f.write(f"{full_domain}\n")
                f.write(f"  IPs: {', '.join(result['ips'])}\n")
                for http in result['http']:
                    f.write(f"  {http['protocol']}: {http['status']}\n")
                f.write("\n")
        print(f"[*] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Subdomain Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout in seconds")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    scanner = SubdomainScanner(
        domain=args.domain,
        threads=args.threads,
        wordlist=args.wordlist,
        timeout=args.timeout
    )
    
    found = scanner.scan()
    
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Total checked: {scanner.checked}")
    print(f"Found: {len(found)} subdomains")
    
    if args.output:
        scanner.save_results(args.output)


if __name__ == "__main__":
    main()
