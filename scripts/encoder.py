#!/usr/bin/env python3
"""
Payload Encoder/Decoder
Various encoding schemes for web security testing
"""

import argparse
import base64
import urllib.parse
import binascii
import html


def url_encode(text, double=False):
    """URL encode"""
    result = urllib.parse.quote(text, safe='')
    if double:
        result = urllib.parse.quote(result, safe='')
    return result


def url_decode(text):
    """URL decode"""
    try:
        return urllib.parse.unquote(text)
    except:
        return text


def base64_encode(text):
    """Base64 encode"""
    if isinstance(text, str):
        text = text.encode()
    return base64.b64encode(text).decode()


def base64_decode(text):
    """Base64 decode"""
    try:
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        return base64.b64decode(text).decode()
    except:
        return "[Error: Invalid Base64]"


def hex_encode(text):
    """Hex encode"""
    if isinstance(text, str):
        text = text.encode()
    return binascii.hexlify(text).decode()


def hex_decode(text):
    """Hex decode"""
    try:
        return binascii.unhexlify(text).decode()
    except:
        return "[Error: Invalid Hex]"


def html_encode(text):
    """HTML encode"""
    return html.escape(text)


def html_decode(text):
    """HTML decode"""
    return html.unescape(text)


def unicode_encode(text):
    """Unicode escape encode"""
    result = ""
    for char in text:
        if ord(char) > 127:
            result += f"\\u{ord(char):04x}"
        else:
            result += char
    return result


def unicode_decode(text):
    """Unicode escape decode"""
    try:
        return text.encode().decode('unicode_escape')
    except:
        return "[Error: Invalid Unicode escape]"


def js_string_encode(text):
    """JavaScript string encode"""
    result = ""
    for char in text:
        code = ord(char)
        if code < 128:
            result += f"\\x{code:02x}"
        else:
            result += f"\\u{code:04x}"
    return result


def rot13(text):
    """ROT13 encode/decode"""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + 13) % 26 + base)
        else:
            result += char
    return result


def xor_encode(text, key):
    """XOR encode with key"""
    result = ""
    for i, char in enumerate(text):
        result += chr(ord(char) ^ ord(key[i % len(key)]))
    return result


def all_encodings(text):
    """Show all encodings"""
    print("="*60)
    print("ALL ENCODINGS")
    print("="*60)
    
    encodings = [
        ("Original", text),
        ("URL Encode", url_encode(text)),
        ("Double URL Encode", url_encode(text, double=True)),
        ("Base64", base64_encode(text)),
        ("Hex", hex_encode(text)),
        ("HTML Entities", html_encode(text)),
        ("Unicode Escape", unicode_encode(text)),
        ("JS String Escape", js_string_encode(text)),
        ("ROT13", rot13(text)),
    ]
    
    for name, value in encodings:
        print(f"\n{name}:")
        print(f"  {value}")


def main():
    parser = argparse.ArgumentParser(
        description="Payload Encoder/Decoder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t "<script>alert(1)</script>" --all
  %(prog)s -t "<script>alert(1)</script>" -e url
  %(prog)s -t "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" -d base64
  %(prog)s -t "hello" -e rot13
  %(prog)s -t "secret" -e xor -k "key"
        """
    )
    
    parser.add_argument("-t", "--text", required=True, help="Text to encode/decode")
    parser.add_argument("-e", "--encode", choices=[
        "url", "double_url", "base64", "hex", "html", "unicode", "js", "rot13", "xor"
    ], help="Encoding type")
    parser.add_argument("-d", "--decode", choices=[
        "url", "base64", "hex", "html", "unicode"
    ], help="Decoding type")
    parser.add_argument("-k", "--key", help="Key for XOR encoding")
    parser.add_argument("--all", action="store_true", help="Show all encodings")
    
    args = parser.parse_args()
    
    if args.all:
        all_encodings(args.text)
    elif args.encode:
        if args.encode == "url":
            print(url_encode(args.text))
        elif args.encode == "double_url":
            print(url_encode(args.text, double=True))
        elif args.encode == "base64":
            print(base64_encode(args.text))
        elif args.encode == "hex":
            print(hex_encode(args.text))
        elif args.encode == "html":
            print(html_encode(args.text))
        elif args.encode == "unicode":
            print(unicode_encode(args.text))
        elif args.encode == "js":
            print(js_string_encode(args.text))
        elif args.encode == "rot13":
            print(rot13(args.text))
        elif args.encode == "xor":
            if not args.key:
                print("[!] XOR encoding requires a key (-k)")
                return
            print(xor_encode(args.text, args.key))
    elif args.decode:
        if args.decode == "url":
            print(url_decode(args.text))
        elif args.decode == "base64":
            print(base64_decode(args.text))
        elif args.decode == "hex":
            print(hex_decode(args.text))
        elif args.decode == "html":
            print(html_decode(args.text))
        elif args.decode == "unicode":
            print(unicode_decode(args.text))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
