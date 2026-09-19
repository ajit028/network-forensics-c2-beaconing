#!/usr/bin/env python3
import argparse
import math
import sys

def calculate_entropy(text):
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy

def analyze_query(domain, min_entropy=4.0, max_label_length=50):
    parts = domain.split('.')
    subdomain = parts[0] if len(parts) > 2 else ""
    entropy = calculate_entropy(subdomain)
    
    flags = []
    if len(subdomain) > max_label_length:
        flags.append("LONG_SUBDOMAIN_LABEL")
    if entropy > min_entropy:
        flags.append("HIGH_ENTROPY_SUBDOMAIN")
        
    return {
        "domain": domain,
        "subdomain": subdomain,
        "subdomain_length": len(subdomain),
        "entropy": round(entropy, 3),
        "flags": flags,
        "is_suspicious": len(flags) > 0
    }

def main():
    parser = argparse.ArgumentParser(description="Detect DNS data exfiltration and tunneling.")
    parser.add_argument("--domain", help="Single domain to analyze")
    parser.add_argument("--list", help="File containing list of domains, one per line")
    parser.add_argument("--min-entropy", type=float, default=4.0, help="Entropy threshold for suspicion")
    args = parser.parse_args()
    
    domains_to_check = []
    if args.domain:
        domains_to_check.append(args.domain)
    elif args.list:
        try:
            with open(args.list, 'r', encoding='utf-8') as f:
                domains_to_check = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Error reading list: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        domains_to_check = [
            "www.google.com",
            "update.microsoft.com",
            "a3FkOWpjYW5kc29pZGpjYXNvaWRjYXNvaWRjYXNvaWRjYXNvaWRjYQ.evil-c2.com",
            "7465737464617461657866696c74726174696f6e.exfil-tunnel.net"
        ]
        
    print(f"[*] Analyzing {len(domains_to_check)} DNS queries for exfiltration indicators...\n")
    print(f"{'DOMAIN':<65} | {'ENTROPY':<8} | {'SUB_LEN':<7} | {'STATUS'}")
    print("-" * 105)
    
    for d in domains_to_check:
        res = analyze_query(d, args.min_entropy)
        status = f"[!] SUSPICIOUS ({', '.join(res['flags'])})" if res["is_suspicious"] else "[ ] BENIGN"
        print(f"{res['domain']:<65} | {res['entropy']:<8} | {res['subdomain_length']:<7} | {status}")
        
    print("-" * 105)

if __name__ == "__main__":
    main()
