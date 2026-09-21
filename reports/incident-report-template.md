# Network Forensics & PCAP Analysis Incident Report

**Incident ID:** INC-YYYYMMDD-001  
**Severity Level:** High / Critical  
**Author / Investigator:** Ajit Nayak (SOC Analyst / Incident Responder)  
**Date of Analysis:** YYYY-MM-DD  
**Target / Host Name:** `[Host Name / Asset ID]`  
**PCAP File Analyzed:** `[Filename.pcap]`  
**MD5 Hash of PCAP:** `[Hash]`  

---

## 1. Executive Summary

During proactive threat hunting / alert triage, anomalous network communication was detected originating from host `[IP Address]` (`[Host Name]`). Deep packet inspection and statistical beaconing analysis confirmed active **Command and Control (C2) beaconing** and **DNS Data Exfiltration**. The adversary established persistent callbacks over `[Protocol / Port]` with a regular jitter interval of `[X]` seconds. Immediate containment actions were executed to prevent further exfiltration or lateral movement.

---

## 2. Incident Timeline (UTC)

| Timestamp (UTC) | Source IP & Port | Destination IP & Port | Event Description / Activity |
| :--- | :--- | :--- | :--- |
| **YYYY-MM-DD HH:MM:SS** | `192.168.1.105:49152` | `185.220.101.5:443` | First observed HTTP/S connection to suspicious external IP. |
| **YYYY-MM-DD HH:MM:SS** | `192.168.1.105:53` | `8.8.8.8:53` | High-volume DNS queries for high-entropy subdomains under `*.evil-c2.com`. |
| **YYYY-MM-DD HH:MM:SS** | `192.168.1.105:49153` | `185.220.101.5:443` | Regular C2 callbacks observed (Jitter: ~5s, Interval: 60s). |

---

## 3. Key Findings & Network Artifacts

### 3.1 C2 Beaconing Characteristics
* **C2 Server IP / Domain:** `[185.220.101.5 / c2.malicious-domain.com]`
* **Protocol / Port:** `TCP/443 (HTTP/TLS)`
* **Beacon Interval:** `60 seconds` (Jitter: `~5.2%`)
* **Payload / User-Agent observed:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...`
* **Statistical Score:** Variance low (`0.12`), periodicity index (`0.94` out of `1.0`).

### 3.2 DNS Tunneling & Exfiltration
* **DNS Resolver:** `8.8.8.8`
* **Query Type:** `TXT / A`
* **Average Shannon Entropy:** `4.35` (High randomness indicative of encoded payloads)
* **Sample Subdomain Query:** `a3FkOWpjYW5kc29pZGpjYXNvaWRjYXNvaWRjYXNvaWRjYXNvaWRjYQ.evil-c2.com`

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Observation Details |
| :--- | :--- | :--- | :--- |
| **Command & Control** | T1071.001 | Web Protocols (HTTP/S) | Beaconing traffic over TCP port 443 with custom headers. |
| **Command & Control** | T1071.004 | DNS Protocol | Encoded C2 commands transferred via DNS record queries. |
| **Exfiltration** | T1048.003 | Exfiltration Over Alternative Protocol | Tunneling sensitive internal host data inside DNS TXT records. |

---

## 5. Containment & Remediation Actions Taken

1. **Host Isolation:** Isolated host `192.168.1.105` from the corporate network at `[Timestamp]`.
2. **Network Block:** Added C2 IP `185.220.101.5` and domain `c2.malicious-domain.com` to edge firewall and DNS sinkhole rules.
3. **Detection Signature Deployment:** Deployed custom Suricata rule `SID: 9000001` across perimeter sensors.
4. **Credential Reset:** Enforced forced credential reset for local user accounts logged into host during the incident window.

---

## 6. Recommendations & SOC Next Steps

- Perform full forensic memory dump and disk image analysis on host `192.168.1.105`.
- Audit proxy logs and EDR telemetry for process injection artifacts (e.g., `cmd.exe` or `powershell.exe` spawned by `rundll32.exe`).
- Review SIEM for additional hosts attempting resolution of `*.evil-c2.com`.
