# Wireshark Display Filter Cheat Sheet for Threat Hunting

Author: [Ajit Nayak](https://ajit028.github.io) | [LinkedIn](https://linkedin.com/in/ajit028)

---

## 🚀 1. C2 & Beaconing Traffic Filters

* **Frequent HTTP GET Requests (Potential Periodic Beacon):**
  ```wireshark
  http.request.method == "GET"
  ```
* **Suspicious User-Agents (Python, Curl, Go-http-client):**
  ```wireshark
  http.user_agent contains "python" || http.user_agent contains "curl" || http.user_agent contains "Go-http-client" || http.user_agent == ""
  ```
* **Cobalt Strike Default Stager / Profiles:**
  ```wireshark
  http.request.uri contains "/s?=" || http.request.uri contains "/submit.php" || http.request.uri contains "/news.php"
  ```

---

## 🔍 2. DNS Exfiltration & Tunneling Filters

* **Unusually Long Subdomain Labels (Base64/Hex Encoded):**
  ```wireshark
  dns.qry.name.len > 50
  ```
* **DNS TXT Record Queries (Often used for tunneling payload delivery):**
  ```wireshark
  dns.qry.type == 16
  ```
* **DNS Query Responses with Large Answers:**
  ```wireshark
  dns.flags.response == 1 && frame.len > 512
  ```

---

## 🌐 3. TLS / SSL Anomaly & C2 Filters

* **Self-Signed Certificates / Issuer Anomalies:**
  ```wireshark
  tls.handshake.cert && (tls.handshake.extension.ja3 || x509sat.uvalue contains "Metasploit")
  ```
* **Uncommon Destination Ports for SSL/TLS:**
  ```wireshark
  tls.record.content_type == 22 && !(tcp.dstport == 443 || tcp.dstport == 8443)
  ```
* **Unusual SNI (Server Name Indication) matching raw IP addresses or dynamic DNS:**
  ```wireshark
  tls.handshake.extensions_server_name contains "duckdns" || tls.handshake.extensions_server_name contains "ngrok"
  ```

---

## 📦 4. Data Exfiltration & Protocol Indicators

* **Large Outbound TCP Packets (Potential bulk data staging):**
  ```wireshark
  tcp.len > 1460 && ip.src == 192.168.1.0/24
  ```
* **ICMP Payload Exfiltration (Ping Tunneling):**
  ```wireshark
  icmp.type == 8 && frame.len > 150
  ```
* **Unusual Outbound Non-Standard Ports (Egress Hunting):**
  ```wireshark
  ip.src == 192.168.1.0/24 && !(tcp.dstport in {80 443 53 8080 8443 8888})
  ```
