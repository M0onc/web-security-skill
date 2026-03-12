#!/usr/bin/env python3
"""
Hash Cracker
Simple hash cracking utility for common hash types
"""

import hashlib
import argparse
import itertools
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


class HashCracker:
    """Hash cracking utility"""
    
    # Supported hash types
    HASH_TYPES = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s,
    }
    
    def __init__(self, hash_value, hash_type='md5', wordlist=None):
        self.hash_value = hash_value.lower()
        self.hash_type = hash_type
        self.wordlist = wordlist
        self.hasher = self.HASH_TYPES.get(hash_type)
        
        if not self.hasher:
            print(f"[!] Unsupported hash type: {hash_type}")
            sys.exit(1)
    
    def crack_with_wordlist(self, wordlist_file):
        """Crack hash using wordlist"""
        print(f"[*] Cracking {self.hash_type} hash: {self.hash_value}")
        print(f"[*] Using wordlist: {wordlist_file}")
        
        try:
            with open(wordlist_file, 'r', errors='ignore') as f:
                for line_num, word in enumerate(f, 1):
                    word = word.strip()
                    if not word:
                        continue
                    
                    hashed = self.hasher(word.encode()).hexdigest()
                    
                    if hashed == self.hash_value:
                        print(f"\n[+] Hash cracked!")
                        print(f"    Password: {word}")
                        print(f"    Attempts: {line_num}")
                        return word
                    
                    if line_num % 100000 == 0:
                        print(f"[*] Checked {line_num} passwords...", end='\r')
        
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {wordlist_file}")
            return None
        except KeyboardInterrupt:
            print("\n[!] Cracking interrupted by user")
            return None
        
        print("\n[-] Password not found in wordlist")
        return None
    
    def crack_brute_force(self, min_len=1, max_len=4, charset=None):
        """Crack hash using brute force"""
        print(f"[*] Cracking {self.hash_type} hash: {self.hash_value}")
        print(f"[*] Brute force: length {min_len}-{max_len}")
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"[*] Charset: {charset}")
        
        total_attempts = sum(len(charset) ** length for length in range(min_len, max_len + 1))
        print(f"[*] Total combinations: {total_attempts}")
        
        attempts = 0
        
        try:
            for length in range(min_len, max_len + 1):
                print(f"\n[*] Trying length {length}...")
                
                for guess in itertools.product(charset, repeat=length):
                    password = ''.join(guess)
                    hashed = self.hasher(password.encode()).hexdigest()
                    attempts += 1
                    
                    if hashed == self.hash_value:
                        print(f"\n[+] Hash cracked!")
                        print(f"    Password: {password}")
                        print(f"    Attempts: {attempts}")
                        return password
                    
                    if attempts % 100000 == 0:
                        progress = (attempts / total_attempts) * 100
                        print(f"[*] Progress: {attempts}/{total_attempts} ({progress:.2f}%)", end='\r')
        
        except KeyboardInterrupt:
            print("\n[!] Cracking interrupted by user")
            return None
        
        print("\n[-] Password not found")
        return None
    
    def crack_common_passwords(self):
        """Crack using common passwords"""
        common_passwords = [
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "letmein", "dragon", "111111", "baseball",
            "iloveyou", "trustno1", "sunshine", "princess", "admin",
            "welcome", "shadow", "ashley", "football", "jesus",
            "michael", "ninja", "mustang", "password1", "123456789",
            "adobe123", "admin123", "letmein1", "photoshop", "qwertyuiop",
            "zaq12wsx", "1qaz2wsx", "password123", "1234567890", "master",
            "hello", "freedom", "whatever", "qazwsx", "trustno1",
            "jordan", "jennifer", "harley", "ranger", "iwantu",
            "batman", "thomas", "robert", "michael", "love",
            "pussy", "hello", "charlie", "888888", "superman",
            "maggie", "michael", "buster", "daniel", "andrew",
            "cookie", "jessica", "pepper", "princess", "azerty",
            "richard", "morgan", "welcome", "ginger", "joshua",
            "cheese", "amanda", "summer", "love", "ashley",
            "6969", "nicole", "chelsea", "biteme", "matthew",
            "access", "yankees", "dallas", "austin", "thunder",
            "taylor", "matrix", "william", "corvette", "hello",
            "martin", "heather", "secret", "fucker", "merlin",
            "diamond", "hammer", "silver", "anthony", "orange",
        ]
        
        print(f"[*] Cracking {self.hash_type} hash: {self.hash_value}")
        print(f"[*] Testing {len(common_passwords)} common passwords...")
        
        for password in common_passwords:
            hashed = self.hasher(password.encode()).hexdigest()
            
            if hashed == self.hash_value:
                print(f"\n[+] Hash cracked!")
                print(f"    Password: {password}")
                return password
        
        print("\n[-] Password not found in common list")
        return None
    
    def identify_hash(self):
        """Try to identify hash type based on length"""
        length = len(self.hash_value)
        
        hash_lengths = {
            32: ['md5'],
            40: ['sha1'],
            56: ['sha224'],
            64: ['sha256', 'sha3_256', 'blake2s'],
            96: ['sha384'],
            128: ['sha512', 'sha3_512'],
        }
        
        possible = hash_lengths.get(length, ['unknown'])
        return possible


def main():
    parser = argparse.ArgumentParser(
        description="Hash Cracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w /usr/share/wordlists/rockyou.txt
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 --brute-force --min 1 --max 6
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 --common
        """
    )
    
    parser.add_argument("-H", "--hash", required=True, help="Hash to crack")
    parser.add_argument("-t", "--type", default="md5",
                        choices=list(HashCracker.HASH_TYPES.keys()),
                        help="Hash type")
    parser.add_argument("-w", "--wordlist", help="Wordlist file")
    parser.add_argument("--brute-force", action="store_true", help="Use brute force")
    parser.add_argument("--min", type=int, default=1, help="Minimum length for brute force")
    parser.add_argument("--max", type=int, default=6, help="Maximum length for brute force")
    parser.add_argument("--charset", help="Custom charset for brute force")
    parser.add_argument("--common", action="store_true", help="Try common passwords")
    parser.add_argument("--identify", action="store_true", help="Identify hash type")
    
    args = parser.parse_args()
    
    cracker = HashCracker(args.hash, args.type)
    
    if args.identify:
        possible = cracker.identify_hash()
        print(f"[*] Hash length: {len(args.hash)}")
        print(f"[*] Possible types: {', '.join(possible)}")
        return
    
    if args.common:
        result = cracker.crack_common_passwords()
    elif args.brute_force:
        charset = args.charset if args.charset else None
        result = cracker.crack_brute_force(args.min, args.max, charset)
    elif args.wordlist:
        result = cracker.crack_with_wordlist(args.wordlist)
    else:
        # Default: try common passwords first
        result = cracker.crack_common_passwords()
        if not result:
            print("\n[*] Trying brute force (length 1-4)...")
            result = cracker.crack_brute_force(1, 4)


if __name__ == "__main__":
    main()
