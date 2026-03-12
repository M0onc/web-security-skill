#!/usr/bin/env python3
"""
Directory/File Scanner
Brute force directories and files on web servers
"""

import requests
import sys
import argparse
import threading
from queue import Queue
from urllib.parse import urljoin, urlparse
import time

# Common HTTP status codes and their meanings
STATUS_CODES = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found (Redirect)",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}

# Default extensions to check
DEFAULT_EXTENSIONS = [
    "",  # No extension
    ".php",
    ".html",
    ".htm",
    ".js",
    ".css",
    ".txt",
    ".bak",
    ".old",
    ".orig",
    ".zip",
    ".tar",
    ".gz",
    ".sql",
    ".db",
    ".config",
    ".xml",
    ".json",
    ".yml",
    ".yaml",
    ".log",
    ".env",
    ".git",
    ".svn",
    ".htaccess",
    ".htpasswd",
]

# Interesting files to check
INTERESTING_FILES = [
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    ".well-known/security.txt",
    "phpinfo.php",
    "info.php",
    "test.php",
    "admin",
    "admin.php",
    "admin.html",
    "login",
    "login.php",
    "wp-login.php",
    "wp-admin",
    "wp-content",
    "wp-includes",
    "config.php",
    "configuration.php",
    "wp-config.php",
    "config.xml",
    "database.yml",
    ".env",
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".svn/entries",
    ".htaccess",
    "web.config",
    "Dockerfile",
    "docker-compose.yml",
    "package.json",
    "composer.json",
    "Gemfile",
    "requirements.txt",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "backup",
    "backup.zip",
    "backup.tar.gz",
    "dump.sql",
    "database.sql",
    "db.sql",
]


class DirectoryScanner:
    def __init__(self, base_url, wordlist=None, extensions=None, threads=10,
                 timeout=5, proxy=None, user_agent=None, follow_redirects=False):
        self.base_url = base_url.rstrip("/")
        self.extensions = extensions or [""]
        self.threads = threads
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.found = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.total = 0
        self.checked = 0
        
        # Setup session
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if user_agent:
            self.session.headers["User-Agent"] = user_agent
        else:
            self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # Load wordlist
        if wordlist:
            self.paths = self.load_wordlist(wordlist)
        else:
            self.paths = self.get_default_wordlist()
    
    def load_wordlist(self, filepath):
        """Load wordlist from file"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return self.get_default_wordlist()
    
    def get_default_wordlist(self):
        """Get default directory wordlist"""
        return [
            "admin", "administrator", "api", "backup", "bak", "bin", "cgi-bin",
            "config", "css", "data", "db", "debug", "demo", "dev", "develop",
            "development", "doc", "docs", "download", "downloads", "email",
            "files", "forum", "ftp", "images", "img", "includes", "install",
            "js", "json", "lib", "library", "log", "logs", "mail", "media",
            "old", "panel", "phpmyadmin", "private", "public", "resources",
            "scripts", "search", "secure", "src", "static", "stats", "temp",
            "test", "testing", "tmp", "upload", "uploads", "user", "users",
            "vendor", "web", "webadmin", "wp-admin", "wp-content", "wp-includes",
            "api/v1", "api/v2", "api/v3", "graphql", "rest", "swagger",
            "actuator", "health", "metrics", "prometheus", "env", "config",
            "console", "shell", "status", "server-status", "server-info",
        ]
    
    def check_path(self, path):
        """Check if a path exists"""
        url = urljoin(self.base_url + "/", path)
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                stream=True
            )
            
            # Read only first few bytes to check status
            _ = response.content[:1]
            
            return {
                "url": url,
                "path": path,
                "status": response.status_code,
                "size": len(response.content),
                "redirect": response.headers.get("Location", "") if response.is_redirect else ""
            }
        except requests.exceptions.RequestException:
            return None
    
    def worker(self):
        """Worker thread"""
        while True:
            try:
                path = self.queue.get(timeout=1)
            except:
                break
            
            result = self.check_path(path)
            
            with self.lock:
                self.checked += 1
                if result and result["status"] not in [404]:
                    self.found.append(result)
                    self.print_result(result)
                
                if self.checked % 100 == 0:
                    print(f"[*] Progress: {self.checked}/{self.total}", end="\r")
            
            self.queue.task_done()
    
    def print_result(self, result):
        """Print scan result"""
        status = result["status"]
        url = result["url"]
        size = result["size"]
        
        if status in [200, 201]:
            print(f"[+] {status:3d} | {size:8d} | {url}")
        elif status in [301, 302, 307, 308]:
            redirect = result.get("redirect", "")
            print(f"[*] {status:3d} | -> {redirect[:40]} | {url}")
        elif status in [401, 403]:
            print(f"[!] {status:3d} | {size:8d} | {url}")
        elif status in [500, 502, 503]:
            print(f"[-] {status:3d} | {size:8d} | {url}")
    
    def scan(self):
        """Start scanning"""
        # Build queue
        for path in self.paths:
            for ext in self.extensions:
                self.queue.put(f"{path}{ext}")
        
        # Add interesting files
        for file in INTERESTING_FILES:
            self.queue.put(file)
        
        self.total = self.queue.qsize()
        print(f"[*] Starting scan of {self.total} paths...")
        print(f"[*] Target: {self.base_url}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Extensions: {', '.join(self.extensions) or 'none'}")
        print()
        print("Status | Size     | URL")
        print("-" * 80)
        
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
                f.write(f"{result['status']} | {result['size']} | {result['url']}\n")
        print(f"\n[*] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Directory/File Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://target.com
  %(prog)s -u http://target.com -w /usr/share/wordlists/dirb/common.txt
  %(prog)s -u http://target.com -e php,html,txt -t 20
  %(prog)s -u http://target.com --interesting-only
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-e", "--extensions", help="Extensions to check (comma-separated)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout (default: 5)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--interesting-only", action="store_true", help="Only check interesting files")
    
    args = parser.parse_args()
    
    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [f".{ext}" if not ext.startswith(".") else ext for ext in args.extensions.split(",")]
    elif not args.interesting_only:
        extensions = DEFAULT_EXTENSIONS
    
    # If interesting-only, use empty paths list
    wordlist = None if args.interesting_only else args.wordlist
    
    # Create scanner
    scanner = DirectoryScanner(
        base_url=args.url,
        wordlist=wordlist,
        extensions=extensions,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects
    )
    
    # Run scan
    found = scanner.scan()
    
    # Print summary
    print("\n" + "="*80)
    print("SCAN SUMMARY")
    print("="*80)
    print(f"Total checked: {scanner.checked}")
    print(f"Found: {len(found)}")
    
    # Group by status code
    status_groups = {}
    for result in found:
        status = result["status"]
        if status not in status_groups:
            status_groups[status] = []
        status_groups[status].append(result)
    
    print("\nResults by status code:")
    for status in sorted(status_groups.keys()):
        count = len(status_groups[status])
        meaning = STATUS_CODES.get(status, "Unknown")
        print(f"  {status} {meaning}: {count}")
    
    # Save results
    if args.output:
        scanner.save_results(args.output)


if __name__ == "__main__":
    main()
