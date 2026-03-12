#!/usr/bin/env python3
"""
Crypto Analyzer
Analyze cryptographic implementations and detect weak crypto
"""

import argparse
import base64
import binascii
import re
import hashlib
from collections import Counter


class CryptoAnalyzer:
    """Cryptographic analyzer"""
    
    # Common weak keys/passwords
    WEAK_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', 'letmein', 'dragon', '111111', 'baseball',
        'iloveyou', 'trustno1', 'sunshine', 'princess', 'admin',
        'welcome', 'shadow', 'ashley', 'football', 'jesus',
        'michael', 'ninja', 'mustang', 'password1', '123456789',
    ]
    
    # Common key patterns
    WEAK_KEY_PATTERNS = [
        r'^[0-9]+$',  # Only digits
        r'^[a-z]+$',  # Only lowercase
        r'^[A-Z]+$',  # Only uppercase
        r'^(.+?)\1+$',  # Repeated patterns
        r'^(012|123|234|345|456|567|678|789|890)+$',  # Sequential digits
        r'^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$',  # Sequential letters
    ]
    
    def __init__(self, data):
        self.data = data
        self.results = {}
    
    def detect_encoding(self):
        """Detect data encoding"""
        encodings = []
        
        # Check for Base64
        try:
            if len(self.data) % 4 == 0:
                decoded = base64.b64decode(self.data)
                encodings.append(('Base64', decoded))
        except:
            pass
        
        # Check for Hex
        try:
            if all(c in '0123456789abcdefABCDEF' for c in self.data):
                decoded = binascii.unhexlify(self.data)
                encodings.append(('Hex', decoded))
        except:
            pass
        
        # Check for URL encoding
        if '%' in self.data:
            try:
                from urllib.parse import unquote
                decoded = unquote(self.data)
                if decoded != self.data:
                    encodings.append(('URL', decoded.encode()))
            except:
                pass
        
        return encodings
    
    def analyze_hash(self):
        """Analyze hash type"""
        hash_info = {
            'length': len(self.data),
            'possible_types': []
        }
        
        # Hash length mapping
        hash_types = {
            32: ['MD5', 'MD4', 'MD2', 'NTLM'],
            40: ['SHA1', 'RIPEMD-160'],
            56: ['SHA224', 'SHA3-224'],
            64: ['SHA256', 'SHA3-256', 'BLAKE2s'],
            96: ['SHA384', 'SHA3-384'],
            128: ['SHA512', 'SHA3-512', 'BLAKE2b', 'Whirlpool'],
        }
        
        if hash_info['length'] in hash_types:
            hash_info['possible_types'] = hash_types[hash_info['length']]
        
        # Check for common hash patterns
        if re.match(r'^[a-f0-9]+$', self.data, re.IGNORECASE):
            hash_info['format'] = 'Hexadecimal'
        elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', self.data):
            hash_info['format'] = 'Base64-like'
        
        return hash_info
    
    def check_weak_crypto(self):
        """Check for weak cryptographic practices"""
        issues = []
        
        # Check for weak passwords
        if self.data.lower() in self.WEAK_PASSWORDS:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Weak Password',
                'description': f'Password is in common weak password list'
            })
        
        # Check for weak patterns
        for pattern in self.WEAK_KEY_PATTERNS:
            if re.match(pattern, self.data):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'Weak Pattern',
                    'description': f'Password matches weak pattern: {pattern}'
                })
                break
        
        # Check length
        if len(self.data) < 8:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Short Password',
                'description': f'Password is only {len(self.data)} characters (minimum 8 recommended)'
            })
        elif len(self.data) < 12:
            issues.append({
                'severity': 'LOW',
                'issue': 'Short Password',
                'description': f'Password is only {len(self.data)} characters (12+ recommended)'
            })
        
        # Check character variety
        has_lower = bool(re.search(r'[a-z]', self.data))
        has_upper = bool(re.search(r'[A-Z]', self.data))
        has_digit = bool(re.search(r'\d', self.data))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', self.data))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        
        if char_types < 3:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Low Complexity',
                'description': f'Password uses only {char_types} character types'
            })
        
        # Check for repeated characters
        char_counts = Counter(self.data)
        most_common = char_counts.most_common(1)[0]
        if most_common[1] > len(self.data) * 0.4:
            issues.append({
                'severity': 'LOW',
                'issue': 'Repeated Characters',
                'description': f'Character "{most_common[0]}" appears {most_common[1]} times'
            })
        
        return issues
    
    def calculate_entropy(self):
        """Calculate password entropy"""
        import math
        
        # Determine character set size
        charset_size = 0
        if re.search(r'[a-z]', self.data):
            charset_size += 26
        if re.search(r'[A-Z]', self.data):
            charset_size += 26
        if re.search(r'\d', self.data):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', self.data):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(self.data) * math.log2(charset_size)
        return entropy
    
    def analyze(self):
        """Run full analysis"""
        print(f"[*] Analyzing: {self.data[:50]}...\n")
        
        # Detect encoding
        encodings = self.detect_encoding()
        if encodings:
            print("[+] Detected encodings:")
            for encoding, decoded in encodings:
                print(f"    {encoding}: {decoded[:50]}...")
        
        # Analyze hash
        hash_info = self.analyze_hash()
        print(f"\n[+] Hash analysis:")
        print(f"    Length: {hash_info['length']}")
        print(f"    Format: {hash_info.get('format', 'Unknown')}")
        if hash_info['possible_types']:
            print(f"    Possible types: {', '.join(hash_info['possible_types'])}")
        
        # Check for weak crypto
        issues = self.check_weak_crypto()
        if issues:
            print(f"\n[!] Security issues found:")
            for issue in issues:
                print(f"    [{issue['severity']}] {issue['issue']}")
                print(f"    {issue['description']}")
        else:
            print(f"\n[+] No obvious weaknesses detected")
        
        # Calculate entropy
        entropy = self.calculate_entropy()
        print(f"\n[+] Entropy: {entropy:.2f} bits")
        
        if entropy < 28:
            print("    Rating: Very Weak")
        elif entropy < 36:
            print("    Rating: Weak")
        elif entropy < 60:
            print("    Rating: Reasonable")
        elif entropy < 80:
            print("    Rating: Strong")
        else:
            print("    Rating: Very Strong")


def main():
    parser = argparse.ArgumentParser(description="Crypto Analyzer")
    parser.add_argument("-d", "--data", required=True, help="Data to analyze")
    parser.add_argument("-f", "--file", help="File containing data to analyze")
    
    args = parser.parse_args()
    
    if args.file:
        with open(args.file, 'r') as f:
            data = f.read().strip()
    else:
        data = args.data
    
    analyzer = CryptoAnalyzer(data)
    analyzer.analyze()


if __name__ == "__main__":
    main()
