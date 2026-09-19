# PCAP Incident Investigation Playbook

Author: [Ajit Nayak](https://ajit028.github.io) | [LinkedIn](https://linkedin.com/in/ajit028)  
Target Audience: SOC Analysts, Incident Responders, Threat Hunters

---

## Phase 1: Initial Triage & Metadata Collection
1. **Hash the PCAP:** Calculate SHA-256 hash immediately for chain of custody and forensic integrity:
   ```bash
   sha256sum incident-capture.pcap
   ```
2. **Determine Capture Scope:** Note capture timeframe, total packets, and interface details:
   ```bash
   capinfos incident-capture.pcap
   ```
3. **High-Level Statistics:** Check average bit rate, packet sizes, and drop counts to rule out packet loss bias.

---

## Phase 2: Protocol Hierarchy & Endpoint Profiling
1. **Protocol Hierarchy Analysis:**
   - In Wireshark, navigate to `Statistics -> Protocol Hierarchy`.
   - Inspect protocol ratios. Flag disproportionate non-web protocols, excessive DNS traffic, or unusual transport protocols.
2. **Conversations & Endpoint Analysis:**
   - In Wireshark, check `Statistics -> Conversations -> IPv4 / TCP`.
   - Identify top talkers by byte volume and packet count.
   - Filter out known internal-to-internal broadcast/multicast (e.g., SSDP, mDNS, LLMNR).
   - Flag internal hosts establishing persistent sessions with suspicious external IPs or untrusted ASNs.

---

## Phase 3: DNS & C2 Beaconing Deep Dive
1. **DNS Exfiltration & Tunneling:**
   - Apply filter: `dns.qry.name.len > 50` or `dns.qry.type == 16`.
   - Calculate Shannon entropy on subdomains using `scripts/dns_exfil_detector.py`.
   - Check query rates: Is a host making rapid, continuous DNS queries to unique subdomains under a single apex domain?
2. **C2 Beaconing Analysis:**
   - Extract connection timestamps and intervals for top external connections.
   - Run `scripts/beacon_detector.py --input sample-data/sample-beacon-traffic.csv`.
   - A coefficient of variation (CV) < 0.15 indicates strict periodicity characteristic of automated C2 implants.

---

## Phase 4: HTTP & Payload Object Extraction
1. **Inspect HTTP Traffic:**
   - Filter: `http.request`.
   - Scrutinize HTTP headers for anomalous User-Agents (`python-requests`, `curl`, headless browsers, or empty headers).
2. **Export HTTP Objects:**
   - Navigate to `File -> Export Objects -> HTTP`.
   - Export suspicious files (.exe, .dll, .ps1, .sh, .vbs, or encrypted blobs).
   - Compute hashes and query VirusTotal / internal threat intel.

---

## Phase 5: TLS & Certificate Inspection
1. **JA3 / JA3S Fingerprinting:**
   - Extract JA3 client hello hashes and correlate with known adversary C2 tooling (e.g., Cobalt Strike malleable profiles, Sliver, Mythic).
2. **Certificate Validation:**
   - Filter: `tls.handshake.type == 11` (Certificate).
   - Check Issuer vs Subject. Flag self-signed certificates, missing SANs, or default tool subjects (e.g., `MetasploitRootCA`).

---

## Phase 6: Timeline Construction & SOC Reporting
1. **Correlate with Host Telemetry:**
   - Map PCAP timestamps against endpoint logs (Sysmon Event ID 3 for network connects, Event ID 1 for process execution).
2. **Compile Indicators of Compromise (IOCs):**
   - Source IP / Hostname (Patient Zero)
   - C2 Server IP & Port
   - Malicious Domains / Subdomains
   - HTTP URI endpoints & JA3 fingerprints
3. **Draft Incident Report & Remediation Recommendations:**
   - Block malicious IPs/domains at perimeter firewall/proxy.
   - Terminate compromised endpoint network access (containment).
   - Ingest custom Snort/Suricata rules into production sensors.
