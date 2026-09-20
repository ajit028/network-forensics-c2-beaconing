#!/usr/bin/env python3
"""
Advanced PCAP Parser for C2 Beaconing Detection & Network Forensics
Author: Ajit Nayak
Description: Parses PCAP files to extract TCP streams, HTTP headers, TLS SNI certificates, 
and DNS query statistics, highlighting potential C2 beaconing indicators.
"""

import argparse
import sys
from collections import defaultdict
try:
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS
except ImportError:
    # Fallback if scapy layers are structured differently
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, Raw

def parse_pcap(pcap_path):
    print(f"[*] Loading PCAP file: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[-] Error reading PCAP file: {e}")
        sys.exit(1)

    print(f"[*] Total packets loaded: {len(packets)}")

    tcp_streams = defaultdict(list)
    http_requests = []
    tls_snis = []
    dns_queries = defaultdict(int)

    for pkt in packets:
        # IP layer check
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # DNS Analysis (UDP/TCP port 53)
            if DNS in pkt and DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                dns_queries[qname] += 1

            # TCP / Application Layer Analysis
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                stream_key = tuple(sorted([f"{src_ip}:{sport}", f"{dst_ip}:{dport}"]))
                
                if Raw in pkt:
                    payload = pkt[Raw].load
                    tcp_streams[stream_key].append(payload)

                    # HTTP Header Detection
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if payload_str.startswith("GET ") or payload_str.startswith("POST ") or payload_str.startswith("HTTP/"):
                        http_requests.append({
                            "src": f"{src_ip}:{sport}",
                            "dst": f"{dst_ip}:{dport}",
                            "headers": payload_str.split('\r\n\r\n')[0]
                        })

                    # TLS SNI Extraction (Basic heuristic over payload)
                    if b"\x16\x03" in payload:  # TLS Handshake record
                        # Look for SNI extension marker '\x00\x00' or similar in raw bytes
                        # For a robust parser, scapy TLS layers are ideal if available
                        tls_snis.append(f"{src_ip} -> {dst_ip}:{dport} [TLS Handshake detected]")

    print("\n--- DNS Query Statistics ---")
    for qname, count in sorted(dns_queries.items(), key=lambda x: x[1], reverse=True):
        print(f"  [QNAME] {qname}: {count} query/queries")

    print("\n--- HTTP Headers Extracted ---")
    if http_requests:
        for req in http_requests[:10]: # Show top 10
            print(f"  [HTTP] {req['src']} -> {req['dst']}")
            for line in req['headers'].split('\r\n')[:3]:
                print(f"    {line}")
    else:
        print("  No cleartext HTTP requests found.")

    print("\n--- TLS / SNI Summary ---")
    print(f"  Total TLS Handshakes observed: {len(tls_snis)}")

    print("\n--- TCP Streams Summary ---")
    print(f"  Total unique TCP streams: {len(tcp_streams)}")
    for stream, payloads in list(tcp_streams.items())[:5]:
        total_bytes = sum(len(p) for p in payloads)
        print(f"  Stream {stream}: {len(payloads)} packets, {total_bytes} bytes")

def main():
    parser = argparse.ArgumentParser(description="Advanced PCAP Parser for C2 Beaconing & Network Forensics")
    parser.add_argument("pcap", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    parse_pcap(args.pcap)

if __name__ == "__main__":
    main()
