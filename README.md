# Network Forensics & C2 Beaconing Detection Suite

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Wireshark](https://img.shields.io/badge/Wireshark-PCAPAnalysis-green.svg)](https://www.wireshark.org/)
[![Snort IDS](https://img.shields.io/badge/Snort-IDS%2FIPS-orange.svg)](https://www.snort.org/)
[![Suricata](https://img.shields.io/badge/Suricata-Engine-red.svg)](https://suricata.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive, production-grade framework for detecting Command and Control (C2) beaconing, DNS data exfiltration, and anomalous network patterns from PCAP captures and telemetry logs. Designed for Security Operations Center (SOC) analysts, threat hunters, and incident responders.

---

## 🚀 Project Overview

Modern adversaries utilize encrypted channels, custom application-layer protocols, and low-and-slow beaconing intervals to blend with normal corporate web traffic and evade traditional signature-based detection. This repository provides a complete analytical toolkit—spanning automated statistical anomaly detection in Python, automated Suricata rule generation, signature rules for Snort and Suricata, automated test suites, Wireshark threat-hunting cheat sheets, and a rigorous forensic investigation reporting framework.

### Architecture & Methodology

```
 [ Raw Network PCAP / Telemetry / IOCs ]
               │
               ├────────────────────────────────────────┐
               ▼                                        ▼
   ┌───────────────────────┐                ┌───────────────────────┐
   │ Python Detection Core │                │   IDS / IPS Engines   │
   │                       │                │                       │
   │ • Beacon Analyzer     │                │ • Snort C2 Rules      │
   │ • Jitter & StdDev     │                │ • Suricata Signatures │
   │ • DNS Entropy/Exfil   │                │ • Suricata Generator  │
   │ • PCAP Stream Parser  │                │ • Cobalt Strike ID    │
   └──────────┬────────────┘                └──────────┬────────────┘
              │                                        │
              └───────────────────┬────────────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │ Wireshark & Playbooks   │
                     │                         │
                     │ • Display Filters       │
                     │ • Coloring Rules        │
                     │ • Step-by-Step Triage   │
                     │ • Incident Report Skele │
                     └──────────┬──────────────┘
                                ▼
                     [ Triage & SOC Alerting ]
```

---

## 🛠️ Tool Suite & Repository Structure

| Component | Path | Description |
| :--- | :--- | :--- |
| **Beacon Detector** | `scripts/beacon_detector.py` | Statistical analysis of packet inter-arrival times (IAT), jitter, and periodicity to flag C2 callbacks. |
| **Advanced PCAP Parser** | `scripts/pcap_parser_advanced.py` | Automated extraction of TCP streams, HTTP headers, TLS SNI certificates, and DNS query stats. |
| **DNS Exfil Detector** | `scripts/dns_exfil_detector.py` | Detects DNS tunneling and exfiltration via Shannon entropy, subdomain length, and high TXT query volume. |
| **Suricata Rule Generator** | `scripts/suricata_rule_generator.py` | Automated generator transforming extracted threat IOCs or IP lists into high-fidelity Suricata rules. |
| **Snort Rules** | `ids-rules/snort-c2.rules` | 10+ hardened Snort IDS rules for HTTP beaconing, DNS exfil, and Cobalt Strike profiles. |
| **Suricata Rules** | `ids-rules/suricata-c2.rules` | Equivalent Suricata rule set optimized for multi-threaded packet inspection. |
| **Sigma Rules** | `sigma-rules/network-c2-sigma.yml` | Correlation rules linking firewall/DNS telemetry with C2 beaconing and tunneling patterns. |
| **Wireshark Filters** | `wireshark/display-filters.md` | Curated display filter cheat sheet for rapid protocol and anomaly isolation. |
| **Coloring Rules** | `wireshark/coloring-rules.txt` | Custom Wireshark packet coloring rules for instant visual threat triage. |
| **Investigation Playbook**| `analysis/investigation-playbook.md`| Standard Operating Procedure (SOP) for step-by-step PCAP forensic analysis. |
| **Incident Report Template**| `reports/incident-report-template.md`| Standardized forensic incident reporting template for SOC tier-2/3 escalations. |
| **Automated Tests** | `tests/test_pcap_parser.py` | Unit test suite validating entropy calculations, beacon detection, and rule generators. |
| **Sample Data** | `sample-data/sample-beacon-traffic.csv`| Simulated telemetry dataset for testing beacon detection algorithms. |

---

## 🎯 MITRE ATT&CK Mapping

| Technique ID | Tactic | Description | Detection Mechanism |
| :--- | :--- | :--- | :--- |
| **T1071** | Command and Control | Application Layer Protocol (HTTP/HTTPS/DNS) | Snort/Suricata HTTP & DNS rules, `beacon_detector.py` |
| **T1573** | Command and Control | Encrypted Channel (TLS/SSL anomalies) | Wireshark TLS filter cheat sheet, cert inspection |
| **T1095** | Command and Control | Non-Application Layer Protocol (Raw ICMP/TCP/UDP) | Protocol hierarchy analysis, unusual port sweeps |
| **T1048** | Exfiltration | Exfiltration Over Alternative Protocol (DNS Tunneling) | `dns_exfil_detector.py`, DNS TXT volume checks |

---

## 📦 Usage Examples

### 1. Running Advanced PCAP Parsing
Extract TCP streams, HTTP headers, TLS handshakes, and DNS query statistics automatically from packet captures:
```bash
python3 scripts/pcap_parser_advanced.py capture.pcap
```

### 2. Running Beacon Detection
Analyze network connection timing telemetry for periodic C2 beaconing signatures:
```bash
python3 scripts/beacon_detector.py --input sample-data/sample-beacon-traffic.csv --threshold 0.85
```

### 3. Running DNS Exfiltration Analysis
Scan DNS query logs or PCAP exports for high-entropy subdomains and encoding anomalies:
```bash
python3 scripts/dns_exfil_detector.py --domain a3FkOWpjYW5kc29pZGpjYXNvaWRjYXNvaWRjYXNvaWRjYXNvaWRjYQ.evil-c2.com
```

### 4. Generating Custom Suricata Rules from IOCs
Generate detection rules dynamically from threat intel feeds or extracted IP/domain IOCs:
```bash
# Using CLI parameters
python3 scripts/suricata_rule_generator.py --ioc 185.220.101.5:443 --output ids-rules/custom-c2.rules

# From an IOC list file
python3 scripts/suricata_rule_generator.py --iocs ioc_list.txt --output ids-rules/generated-suricata-c2.rules
```

### 5. Running Automated Validation Tests
Verify that parsing engines, entropy metrics, and rule generators pass all quality checks:
```bash
python3 -m unittest discover tests
```

### 6. Deploying Snort & Suricata Rules
```bash
# Snort execution
snort -A console -c /etc/snort/snort.conf -R ids-rules/snort-c2.rules -r sample-traffic.pcap

# Suricata execution
suricata -c /etc/suricata/suricata.yaml -s ids-rules/suricata-c2.rules -r sample-traffic.pcap
```

---

## 👤 Author & Portfolio

**Ajit Nayak**
- Portfolio: [ajit028.github.io](https://ajit028.github.io)
- LinkedIn: [linkedin.com/in/ajit028](https://www.linkedin.com/in/ajit028)
- Focus: Security Operations, Incident Response, Network Forensics, Threat Hunting

---

## 📄 License

Licensed under the [MIT License](LICENSE).
