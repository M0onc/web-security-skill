#!/usr/bin/env python3
"""
Custom Wordlist Generator
Generate custom wordlists for brute force attacks
"""

import argparse
import itertools
import os


class WordlistGenerator:
    """Generate custom wordlists"""
    
    # Common patterns
    COMMON_PATTERNS = [
        "{word}{year}",
        "{word}{num}",
        "{word}{special}",
        "{word}{year}{special}",
        "{num}{word}",
        "{special}{word}",
        "{word}{word}",
        "{word}.{year}",
        "{word}_{year}",
        "{word}-{year}",
    ]
    
    # Common years
    YEARS = [str(y) for y in range(2020, 2027)] + ["2026", "2025", "2024", "2023", "2022", "2021", "2020", "2019", "2018", "2017", "2016", "2015"]
    
    # Common numbers
    NUMBERS = [str(i) for i in range(0, 1000)] + ["123", "1234", "12345", "123456", "111", "222", "333", "444", "555", "666", "777", "888", "999", "000", "007", "001", "01", "02", "03", "04", "05", "06", "07", "08", "09"]
    
    # Common special characters
    SPECIAL_CHARS = ["!", "@", "#", "$", "%", "&", "*", "?", "!!", "@!", "#1", "123!", "!@#"]
    
    def __init__(self, base_words, output_file, min_length=1, max_length=20):
        self.base_words = base_words
        self.output_file = output_file
        self.min_length = min_length
        self.max_length = max_length
    
    def generate_basic_mutations(self, word):
        """Generate basic mutations of a word"""
        mutations = set()
        
        # Original
        mutations.add(word)
        
        # Case variations
        mutations.add(word.lower())
        mutations.add(word.upper())
        mutations.add(word.capitalize())
        mutations.add(word.swapcase())
        
        # Leet speak
        leet = self._to_leet(word)
        mutations.add(leet)
        mutations.add(leet.lower())
        mutations.add(leet.upper())
        
        # Reverse
        mutations.add(word[::-1])
        mutations.add(word.lower()[::-1])
        
        # Double
        mutations.add(word + word)
        mutations.add(word.lower() + word.lower())
        
        # Common substitutions
        mutations.add(word + "1")
        mutations.add(word + "12")
        mutations.add(word + "123")
        mutations.add(word + "!")
        mutations.add(word + "@")
        mutations.add(word + "#")
        mutations.add(word + "123!")
        
        return mutations
    
    def _to_leet(self, word):
        """Convert to leet speak"""
        leet_map = {
            'a': '4', 'A': '4',
            'e': '3', 'E': '3',
            'i': '1', 'I': '1',
            'o': '0', 'O': '0',
            's': '5', 'S': '5',
            't': '7', 'T': '7',
            'g': '9', 'G': '9',
            'b': '8', 'B': '8',
        }
        return ''.join(leet_map.get(c, c) for c in word)
    
    def generate_pattern_based(self):
        """Generate pattern-based passwords"""
        passwords = set()
        
        for word in self.base_words:
            word_lower = word.lower()
            word_cap = word.capitalize()
            
            for pattern in self.COMMON_PATTERNS:
                for year in self.YEARS:
                    for num in self.NUMBERS[:50]:  # Limit numbers
                        for special in self.SPECIAL_CHARS:
                            try:
                                pwd = pattern.format(
                                    word=word_cap,
                                    word_lower=word_lower,
                                    year=year,
                                    num=num,
                                    special=special
                                )
                                if self.min_length <= len(pwd) <= self.max_length:
                                    passwords.add(pwd)
                            except:
                                pass
        
        return passwords
    
    def generate_combinations(self, words, max_combo=2):
        """Generate combinations of words"""
        combinations = set()
        
        for r in range(1, min(max_combo + 1, len(words) + 1)):
            for combo in itertools.permutations(words, r):
                # Join with different separators
                combinations.add(''.join(combo))
                combinations.add('.'.join(combo))
                combinations.add('_'.join(combo))
                combinations.add('-'.join(combo))
        
        return combinations
    
    def generate_years_combo(self):
        """Generate word + year combinations"""
        passwords = set()
        
        for word in self.base_words:
            for year in self.YEARS:
                passwords.add(f"{word}{year}")
                passwords.add(f"{word.lower()}{year}")
                passwords.add(f"{word.capitalize()}{year}")
                passwords.add(f"{word}{year}!")
                passwords.add(f"{word}{year}@")
                passwords.add(f"{word}{year}#")
                passwords.add(f"{word}{year}123")
        
        return passwords
    
    def generate_seasons_combo(self):
        """Generate word + season combinations"""
        passwords = set()
        seasons = ["Spring", "Summer", "Fall", "Autumn", "Winter"]
        seasons_short = ["Spr", "Sum", "Fall", "Aut", "Win"]
        
        for word in self.base_words:
            for season in seasons + seasons_short:
                passwords.add(f"{word}{season}")
                passwords.add(f"{word}{season}2024")
                passwords.add(f"{word}{season}2025")
                passwords.add(f"{season}{word}")
        
        return passwords
    
    def generate_all(self):
        """Generate all wordlist variations"""
        all_passwords = set()
        
        print("[*] Generating basic mutations...")
        for word in self.base_words:
            all_passwords.update(self.generate_basic_mutations(word))
        
        print("[*] Generating year combinations...")
        all_passwords.update(self.generate_years_combo())
        
        print("[*] Generating season combinations...")
        all_passwords.update(self.generate_seasons_combo())
        
        print("[*] Generating pattern-based passwords...")
        all_passwords.update(self.generate_pattern_based())
        
        print("[*] Generating word combinations...")
        all_passwords.update(self.generate_combinations(self.base_words))
        
        # Filter by length
        filtered = {pwd for pwd in all_passwords 
                   if self.min_length <= len(pwd) <= self.max_length}
        
        return filtered
    
    def save(self, passwords):
        """Save wordlist to file"""
        with open(self.output_file, 'w') as f:
            for pwd in sorted(passwords):
                f.write(f"{pwd}\n")
        
        print(f"\n[+] Generated {len(passwords)} passwords")
        print(f"[+] Saved to: {self.output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Custom Wordlist Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -w company -o wordlist.txt
  %(prog)s -w company -w admin -w user -o wordlist.txt
  %(prog)s -w company -o wordlist.txt --min 8 --max 16
  %(prog)s -f base_words.txt -o wordlist.txt
        """
    )
    
    parser.add_argument("-w", "--word", action="append", help="Base word (can be used multiple times)")
    parser.add_argument("-f", "--file", help="File containing base words (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output file")
    parser.add_argument("--min", type=int, default=1, help="Minimum password length")
    parser.add_argument("--max", type=int, default=50, help="Maximum password length")
    
    args = parser.parse_args()
    
    # Collect base words
    base_words = []
    
    if args.word:
        base_words.extend(args.word)
    
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, 'r') as f:
                base_words.extend([line.strip() for line in f if line.strip()])
        else:
            print(f"[!] File not found: {args.file}")
            return
    
    if not base_words:
        print("[!] No base words provided. Use -w or -f")
        return
    
    print(f"[*] Base words: {', '.join(base_words)}")
    print(f"[*] Output file: {args.output}")
    print(f"[*] Length range: {args.min}-{args.max}")
    print()
    
    # Generate wordlist
    generator = WordlistGenerator(
        base_words=base_words,
        output_file=args.output,
        min_length=args.min,
        max_length=args.max
    )
    
    passwords = generator.generate_all()
    generator.save(passwords)


if __name__ == "__main__":
    main()
