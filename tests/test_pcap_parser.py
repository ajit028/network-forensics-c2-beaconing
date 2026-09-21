#!/usr/bin/env python3
"""
Automated Unit Tests for PCAP Parsers & Detection Modules
Author: Ajit Nayak
"""

import unittest
import os
import sys

# Add scripts directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))

from beacon_detector import analyze_flows
from dns_exfil_detector import calculate_entropy, analyze_query
from suricata_rule_generator import generate_suricata_rules

class TestForensicsToolkit(unittest.TestCase):

    def test_shannon_entropy_calculation(self):
        # Low entropy string
        low_entropy = calculate_entropy("aaaaaaaaaa")
        self.assertEqual(low_entropy, 0.0)

        # High entropy base64-like string
        high_entropy = calculate_entropy("a3FkOWpjYW5kc29pZGpjYXNvaWRjYXNvaWRjYXNvaWRjYQ")
        self.assertGreater(high_entropy, 3.5)

    def test_dns_exfil_detection_logic(self):
        normal_domain = "www.google.com"
        suspicious_domain = "a3FkOWpjYW5kc29pZGpjYXNvaWRjYXNvaWRjYXNvaWRjYQ.evil-c2.com"

        normal_res = analyze_query(normal_domain)
        suspicious_res = analyze_query(suspicious_domain)

        self.assertFalse(normal_res["is_suspicious"])
        self.assertTrue(suspicious_res["is_suspicious"])
        self.assertIn("HIGH_ENTROPY_SUBDOMAIN", suspicious_res["flags"])

    def test_beacon_analysis_with_sample_data(self):
        sample_csv = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'sample-data', 'sample-beacon-traffic.csv'))
        if os.path.exists(sample_csv):
            suspects = analyze_flows(sample_csv, min_packets=5)
            self.assertGreater(len(suspects), 0)
            # Find the flow with high confidence
            top_suspect = max(suspects, key=lambda x: x["confidence"])
            self.assertGreaterEqual(top_suspect["confidence"], 0.85)

    def test_suricata_rule_generation(self):
        iocs = ["198.51.100.45:8080", "c2.malicious-domain-example.com"]
        out_path = os.path.join(os.path.dirname(__file__), "test_rules.rules")
        
        generate_suricata_rules(iocs, output_file=out_path, sid_start=9000100)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, 'r') as f:
            content = f.read()

        self.assertIn("198.51.100.45", content)
        self.assertIn("8080", content)
        self.assertIn("c2.malicious-domain-example.com", content)
        self.assertIn("sid:9000100", content)
        self.assertIn("sid:9000101", content)

        # Cleanup
        if os.path.exists(out_path):
            os.remove(out_path)

if __name__ == '__main__':
    unittest.main()
