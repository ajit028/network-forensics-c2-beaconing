#!/usr/bin/env python3
import argparse
import csv
import statistics
import sys
from collections import defaultdict

def parse_arguments():
    parser = argparse.ArgumentParser(description="Detect C2 beaconing in network traffic telemetry.")
    parser.add_argument("--input", required=True, help="Path to CSV telemetry input (timestamp,src_ip,dst_ip,dst_port,interval_ms,packet_size)")
    parser.add_argument("--threshold", type=float, default=0.85, help="Confidence threshold to flag beaconing (0.0 - 1.0)")
    parser.add_argument("--min-packets", type=int, default=10, help="Minimum packet count per flow to analyze")
    return parser.parse_args()

def analyze_flows(filepath, min_packets):
    flows = defaultdict(list)
    try:
        with open(filepath, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                flow_key = (row["src_ip"], row["dst_ip"], row["dst_port"])
                interval = float(row["interval_ms"])
                size = int(row["packet_size"])
                flows[flow_key].append((interval, size))
    except Exception as e:
        print(f"[-] Error reading input file: {e}", file=sys.stderr)
        sys.exit(1)
    
    suspects = []
    for flow, packets in flows.items():
        if len(packets) < min_packets:
            continue
        
        intervals = [p[0] for p in packets]
        mean_val = statistics.mean(intervals)
        if mean_val == 0:
            continue
        
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = std_dev / mean_val  # Coefficient of variation
        
        diffs = [abs(intervals[i] - intervals[i-1]) for i in range(1, len(intervals))]
        jitter = statistics.mean(diffs) if diffs else 0.0
        
        confidence = max(0.0, 1.0 - (cv * 2.0))
        if confidence > 1.0:
            confidence = 1.0
            
        suspects.append({
            "src_ip": flow[0],
            "dst_ip": flow[1],
            "dst_port": flow[2],
            "packet_count": len(packets),
            "mean_interval_ms": round(mean_val, 2),
            "std_dev_ms": round(std_dev, 2),
            "cv": round(cv, 4),
            "jitter_ms": round(jitter, 2),
            "confidence": round(confidence, 4)
        })
        
    return suspects

def main():
    args = parse_arguments()
    print(f"[*] Analyzing telemetry from {args.input}...")
    suspects = analyze_flows(args.input, args.min_packets)
    
    suspects.sort(key=lambda x: x["confidence"], reverse=True)
    
    print("\n" + "="*80)
    print(f"{'SRC IP':<15} | {'DST IP':<15} | {'PORT':<6} | {'COUNT':<6} | {'MEAN (ms)':<10} | {'CV':<6} | {'CONF':<6}")
    print("="*80)
    
    flagged_count = 0
    for s in suspects:
        status = "[!] FLAG" if s["confidence"] >= args.threshold else "[ ] BENIGN"
        if s["confidence"] >= args.threshold:
            flagged_count += 1
        print(f"{s['src_ip']:<15} | {s['dst_ip']:<15} | {s['dst_port']:<6} | {s['packet_count']:<6} | {s['mean_interval_ms']:<10} | {s['cv']:<6} | {s['confidence']:<6} {status}")
        
    print("="*80)
    print(f"[*] Analysis complete. Flagged {flagged_count} suspect C2 beaconing flows (Threshold >= {args.threshold}).\n")

if __name__ == "__main__":
    main()
