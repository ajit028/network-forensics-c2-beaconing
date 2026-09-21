#!/usr/bin/env python3
"""
Suricata Rule Generator Script
Author: Ajit Nayak
Description: Takes IOCs (IP addresses, domains, ports, custom signatures) and generates 
custom high-fidelity Suricata IDS/IPS rules for C2 beaconing and threat hunting.
"""

import argparse
import sys
import os
from datetime import datetime

def generate_suricata_rules(iocs, output_file=None, proto="tcp", sid_start=9000001):
    rules = []
    current_sid = sid_start
    timestamp = datetime.utcnow().strftime("%Y-%m-%d")

    print(f"[*] Generating Suricata rules for {len(iocs)} IOCs...")

    for ioc in iocs:
        ioc = ioc.strip()
        if not ioc or ioc.startswith("#"):
            continue

        # Determine IOC type
        if ":" in ioc:
            # IP:Port or IP only with port specified
            parts = ioc.split(":")
            ip_addr = parts[0]
            port = parts[1]
        else:
            ip_addr = ioc
            port = "any"

        # Check if IOC is a domain or IP address
        is_domain = not all(c.isdigit() or c == '.' for c in ip_addr)

        if is_domain:
            # DNS / HTTP Suricata rule for domain
            rule = (
                f'alert dns $HOME_NET any -> any 53 (msg:"[SOC-RULE] Potential C2 Domain Resolution - {ip_addr}"; '
                f'dns.query; content:"{ip_addr}"; nocase; '
                f'classtype:trojan-activity; sid:{current_sid}; rev:1; metadata:created {timestamp}, author Ajit Nayak;)'
            )
        else:
            # IP based Suricata rule
            if port == "any":
                rule = (
                    f'alert {proto} $HOME_NET any -> {ip_addr} any '
                    f'(msg:"[SOC-RULE] Suspicious Outbound Connection to C2 IP - {ip_addr}"; '
                    f'flow:to_server,established; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1; metadata:created {timestamp}, author Ajit Nayak;)'
                )
            else:
                rule = (
                    f'alert {proto} $HOME_NET any -> {ip_addr} {port} '
                    f'(msg:"[SOC-RULE] Suspicious Outbound Traffic to C2 IP:Port - {ip_addr}:{port}"; '
                    f'flow:to_server,established; '
                    f'classtype:trojan-activity; sid:{current_sid}; rev:1; metadata:created {timestamp}, author Ajit Nayak;)'
                )

        rules.append(rule)
        current_sid += 1

    rule_output = "\n".join(rules) + "\n"

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, 'w') as f:
            f.write(rule_output)
        print(f"[+] Successfully wrote {len(rules)} Suricata rules to {output_file}")
    else:
        print("\n--- Generated Suricata Rules ---\n")
        print(rule_output)

def main():
    parser = argparse.ArgumentParser(description="Advanced Suricata Rule Generator for C2 & IOCs")
    parser.add_argument("--iocs", help="Path to a text file containing IOCs (one per line, IPs or domains)")
    parser.add_argument("--ioc", help="Single IOC (IP, IP:Port, or Domain) passed via CLI")
    parser.add_argument("--output", default="ids-rules/generated-suricata-c2.rules", help="Path to output rules file")
    parser.add_argument("--proto", default="tcp", choices=["tcp", "udp", "ip"], help="Protocol for IP rules")
    parser.add_argument("--sid", type=int, default=9000001, help="Starting SID number")

    args = parser.parse_args()

    ioc_list = []
    if args.iocs:
        if not os.path.exists(args.iocs):
            print(f"[-] IOC file not found: {args.iocs}")
            sys.exit(1)
        with open(args.iocs, 'r') as f:
            ioc_list = f.readlines()
    elif args.ioc:
        ioc_list = [args.ioc]
    else:
        # Default sample IOCs if none provided
        ioc_list = [
            "185.220.101.5:443",
            "198.51.100.45:8080",
            "c2.malicious-domain-example.com",
            "exfil.dns-tunnel-test.net"
        ]
        print("[*] No IOCs provided via --iocs or --ioc. Using default sample IOCs.")

    generate_suricata_rules(ioc_list, output_file=args.output, proto=args.proto, sid_start=args.sid)

if __name__ == "__main__":
    main()
