# PCAP Security Toolkit

A Python-based PCAP analysis toolkit for CSIRT and incident response investigations.

## Author

Created by **John R. Allen**

---

## Overview

PCAP Security Toolkit analyzes `.pcap` and `.pcapng` files and produces structured, analyst-ready output mapped to the MITRE ATT&CK framework. Every alert includes a severity tier, technique ID, and tactic — designed to feed directly into incident reports, SIEM workflows, and threat intelligence platforms.

This project uses:

- **Python** for orchestration, analysis, and reporting
- **Scapy** for memory-efficient streaming packet analysis
- **TShark** for protocol-aware extraction across HTTP, DNS, TLS, SMB, FTP, SMTP, and Kerberos

---

## Features

### Traffic Analysis
- Memory-efficient streaming packet loading via `PcapReader` — handles large PCAPs without loading fully into RAM
- IPv4 and IPv6 flow analysis
- Top talkers, protocols, and conversations
- DNS query and answer extraction with passive DNS correlation map

### Protocol Extraction (TShark)
- HTTP requests and responses (including response codes and server headers)
- DNS queries with A/AAAA/CNAME answers and TTL
- TLS metadata: SNI, cipher suite, JA3/JA3S and JA4/JA4S fingerprints, certificate details
- SMB file and path indicators
- FTP RETR/STOR command extraction
- SMTP/IMAP/POP3 commands and authentication
- Kerberos authentication events: principal names, realms, error codes, encryption types

### Detection Engine (MITRE ATT&CK Mapped)
| Detection | Alert Type | MITRE |
|---|---|---|
| Large private→external transfer | `LARGE_PRIVATE_TO_EXTERNAL_TRANSFER` | T1041 |
| Beaconing / low-jitter C2 | `BEACONING_CANDIDATE` | T1071.001 |
| DNS tunneling (entropy, length, volume, TXT/NULL) | `DNS_TUNNELING_CANDIDATE` | T1071.004 |
| Entropy-based exfiltration | `ENTROPY_BASED_EXFIL_CANDIDATE` | T1048.003 |
| Credential indicators in HTTP / payloads | `CREDENTIAL_INDICATOR` | T1552 |
| Credential POST reconstruction | `CREDENTIAL_POST_RECONSTRUCTED` | T1056.003 |
| Suspicious downloads (ext, content-type, signature) | `SUSPICIOUS_DOWNLOAD` | T1105 |
| TLS SNI anomalies (long, hex-like, suspicious TLDs) | `TLS_SNI_ANOMALY` | T1071.001 |
| Malicious JA3 fingerprints (9 known families) | `MALICIOUS_JA3` | T1071.001 |
| Malicious JA4 fingerprints (5 known C2 families) | `MALICIOUS_JA4` | T1071.001 |
| Active JARM server fingerprinting (5 known C2 families) | `MALICIOUS_JARM` | T1071.001 |
| ICMP tunnel / covert channel detection | `ICMP_TUNNELING_CANDIDATE` | T1095 |
| ARP spoofing and gratuitous ARP flooding | `ARP_SPOOFING_CANDIDATE` | T1557.002 |
| YARA rule scanning on carved files and payloads | `YARA_MATCH` | T1105 |
| Suspicious user agents (tools, empty, malware-assoc.) | `SUSPICIOUS_USER_AGENT` | T1071.001 |
| Protocol on non-standard port | `PROTOCOL_ANOMALY` | T1571 |
| Internal SMB lateral spread | `LATERAL_MOVEMENT_CANDIDATE` | T1021.002 |
| Internal TCP port scan | `INTERNAL_SCAN_CANDIDATE` | T1046 |
| HTTP response anomalies (confirmed delivery, scanning) | `HTTP_RESPONSE_ANOMALY` | T1105 |
| Kerberos errors (AS-REP roasting, Kerberoasting) | `KERBEROS_ANOMALY` | T1558 |
| File name indicators (HTTP URI, SMB, FTP) | `FILE_NAME_INDICATOR_OBSERVED` | T1105 |

### Output
- Every alert includes `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO), `mitre_technique_id`, `mitre_tactic`, and `mitre_technique_name`
- Alerts sorted by severity descending
- `--severity-filter` flag to control terminal display threshold
- `--output-format html` generates a self-contained `report.html` with severity-colored alert table, stat cards, and collapsible sections — no external CSS or JS dependencies
- `analysis_workbook.xlsx` — all non-empty CSVs consolidated into a single Excel workbook, one sheet per output file, ordered by investigative priority; compatible with Excel, Google Sheets, and Apple Numbers
- `iocs.csv` — deduplicated IOC list (IPs, domains, URLs, SHA-256, user-agents, JA3/JA4/JA4H/JARM hashes) with optional GeoIP enrichment
- `iocs.stix2.json` — STIX 2.1 IOC bundle for direct import into MISP, OpenCTI, or TheHive (no external dependency)
- `timeline.csv` — chronologically sorted event timeline with MITRE technique IDs
- Optional GeoIP/ASN enrichment via `maxminddb` and GeoLite2 database

### Payload Analysis
- Passive OS fingerprinting from TCP SYN characteristics (TTL, window size, MSS)
- SMTP attachment extraction and hashing from exported streams
- YARA rule scanning on carved files and extracted payloads (optional `yara-python`)
- Active JARM TLS server fingerprinting with known C2 hash lookup (`--jarm-probe`)
- TCP stream export in ASCII and RAW modes
- HTTP payload extraction from reconstructable plaintext streams
- Base64 payload decoding
- SHA-256 hashing and Shannon entropy scoring for all extracted content
- File signature detection for 17 types
- File carving from raw TCP streams: PDF, ZIP, PE/EXE, ELF, PNG, JPEG, GIF, RAR, 7-Zip, GZIP, BZIP2, OLE2, SQLite

---

## Project Structure

```text
pcap-security-toolkit/
├── .gitignore
├── README.md
├── requirements.txt
├── bootstrap.py
├── analyzer.py
├── run.sh
├── run.bat
├── config.py
├── modules/
│   ├── __init__.py
│   ├── cases.py
│   ├── dependencies.py
│   ├── detections.py
│   ├── dns_http_tls.py
│   ├── excel_export.py
│   ├── exporters.py
│   ├── files.py
│   ├── flows.py
│   ├── geoip.py
│   ├── html_report.py
│   ├── https_metadata.py
│   ├── iocs.py
│   ├── payloads.py
│   ├── protocol_anomalies.py
│   ├── streams.py
│   ├── tshark_extract.py
│   └── utils.py
├── output/
└── samples/
```

---

## Requirements

- Python 3.10+
- TShark (Wireshark)
- Scapy
- `openpyxl` for Excel workbook export (`pip install openpyxl`)

**Optional:**
- `maxminddb` + GeoLite2 database for GeoIP/ASN enrichment
- `yara-python` for YARA rule scanning (`pip install yara-python`)

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/jallen-6386/pcap-security-toolkit.git
cd pcap-security-toolkit
```

### 2. Run bootstrap

**macOS / Linux**
```bash
python3 bootstrap.py
```

**Windows**
```bash
python bootstrap.py
```

### 3. Verify TShark

```bash
tshark -v
```

### 4. Optional: GeoIP enrichment

```bash
pip install maxminddb
```

Then download `GeoLite2-ASN.mmdb` (free, requires free MaxMind account) from:
`https://dev.maxmind.com/geoip/geolite2-free-geolocation-data`

Place the `.mmdb` file in the project root, or pass it via `--geoip-db`.

---

## Quick Run

**macOS / Linux**
```bash
./run.sh "/path/to/file.pcapng"
```

**Windows**
```bash
run.bat "C:\path\to\file.pcapng"
```

---

## CLI Reference

```bash
analyzer.py [-h] [--top N] [--case NAME]
            [--export-streams] [--max-streams N]
            [--severity-filter {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
            [--output-format {csv,html,both}]
            [--geoip-db PATH]
            pcap
```

| Flag | Default | Description |
|---|---|---|
| `pcap` | — | Path to .pcap or .pcapng file |
| `--case` | auto | Case folder name under output/ |
| `--top` | 10 | Top-N rows in summary tables |
| `--export-streams` | off | Export TCP streams to files and extract payloads |
| `--max-streams` | 25 | Maximum TCP streams to export |
| `--severity-filter` | HIGH | Minimum severity for terminal alert display |
| `--output-format` | csv | Output format: csv, html, or both |
| `--geoip-db` | auto | Path to GeoLite2 .mmdb database file |
| `--yara-rules` | off | Path to a YARA rules file or directory to scan carved files and payloads |
| `--jarm-probe` | off | Actively fingerprint observed TLS servers with JARM (requires outbound connectivity) |

---

## Usage Examples

```bash
# Basic triage
./run.sh "/path/to/capture.pcapng"

# Named case with stream export and HTML report
./run.sh "/path/to/capture.pcapng" --case incident_42 --export-streams --output-format both

# Show only CRITICAL alerts in terminal
./run.sh "/path/to/capture.pcapng" --severity-filter CRITICAL

# With GeoIP enrichment
./run.sh "/path/to/capture.pcapng" --geoip-db ./GeoLite2-ASN.mmdb --output-format both
```

---

## Output Structure

```text
output/
└── case1/
    ├── analysis_workbook.xlsx          ← All CSVs in one workbook (Excel/Sheets/Numbers)
    ├── alerts.csv                      ← Start here: severity + MITRE tagged
    ├── report.json                     ← Machine-readable summary
    ├── report.html                     ← Self-contained HTML report (--output-format html)
    ├── timeline.csv                    ← Chronological event timeline
    ├── iocs.csv                        ← Deduplicated IOC list
    ├── dns_resolutions.csv             ← Passive DNS domain→IP map
    ├── dns_tunneling_candidates.csv
    ├── http_requests.csv
    ├── http_responses.csv
    ├── http_tshark.csv
    ├── http_body_previews.csv
    ├── http_response_anomalies.csv
    ├── tls_metadata.csv
    ├── tls_sni_anomalies.csv
    ├── malicious_ja3.csv
    ├── malicious_ja4.csv
    ├── ja4h.csv
    ├── jarm_fingerprints.csv
    ├── icmp_tunneling_candidates.csv
    ├── arp_anomalies.csv
    ├── os_fingerprints.csv
    ├── smtp_attachments.csv
    ├── yara_hits.csv
    ├── iocs.stix2.json
    ├── smb_tshark.csv
    ├── ftp_tshark.csv
    ├── smtp_activity.csv
    ├── kerberos_activity.csv
    ├── tcp_stream_index.csv
    ├── file_indicators.csv
    ├── beaconing_candidates.csv
    ├── credential_findings.csv
    ├── credential_posts.csv
    ├── suspicious_downloads.csv
    ├── suspicious_user_agents.csv
    ├── entropy_exfil_candidates.csv
    ├── lateral_movement_candidates.csv
    ├── protocol_anomalies.csv
    ├── carved_files.csv
    ├── extracted_payloads_index.csv
    ├── extracted_payloads/
    ├── carved_files/
    └── streams/
        ├── tcp_stream_0.ascii.txt
        └── tcp_stream_0.raw.txt
```

---

## Recommended Review Workflow

### 1. Headline findings (< 5 min)
- Terminal output: top CRITICAL/HIGH alerts with MITRE IDs
- `report.html` (if generated): severity breakdown, stat cards, alert table
- `analysis_workbook.xlsx` — open in Excel, Google Sheets, or Apple Numbers for a single-file view of all findings

### 2. Triage (5–20 min)
- `alerts.csv` (or the **alerts** sheet in the workbook) — sorted by severity; MITRE columns link to ATT&CK framework
- `timeline.csv` — reconstruct the sequence of events
- `iocs.csv` — extract IOCs for firewall/SIEM block rules or threat intel upload

### 3. Protocol deep dive
- `dns_resolutions.csv` + `dns_tunneling_candidates.csv`
- `tls_metadata.csv` + `malicious_ja3.csv` + `tls_sni_anomalies.csv`
- `http_tshark.csv` + `http_responses.csv` + `http_body_previews.csv`
- `kerberos_activity.csv` + `smtp_activity.csv`

### 4. File and payload analysis
- `extracted_payloads_index.csv` + `extracted_payloads/`
- `carved_files.csv` + `carved_files/`
- `credential_findings.csv` + `credential_posts.csv`
- `beaconing_candidates.csv` + `entropy_exfil_candidates.csv`
- `lateral_movement_candidates.csv` + `protocol_anomalies.csv`

---

## Output File Reference

### alerts.csv
Aggregated findings with these columns:
- `severity` — CRITICAL / HIGH / MEDIUM / LOW / INFO
- `alert_type` — machine-readable finding type
- `src_ip`, `dst_ip`, `protocol`, `tcp_stream`
- `mitre_technique_id`, `mitre_tactic`, `mitre_technique_name`
- `reason` — human-readable description

### iocs.csv
Deduplicated indicators:
- `ioc_type` — ipv4, domain, url, sha256, user_agent, ja3_fingerprint, ja4_fingerprint, ja4s_fingerprint, ja4h_fingerprint
- `value`, `source`, `confidence`, `first_seen`
- `country_iso`, `asn`, `asn_org` (if GeoIP enabled)

### malicious_ja3.csv
TLS sessions matching known-malicious JA3 fingerprints:
- Cobalt Strike, Metasploit Meterpreter, Dridex, Trickbot, Emotet, AgentTesla, AsyncRAT, njRAT, Mirai

### malicious_ja4.csv
TLS sessions matching known-malicious JA4 fingerprints:
- Cobalt Strike Beacon, Metasploit Meterpreter, Sliver C2, Brute Ratel C4, Havoc C2

### ja4h.csv
HTTP client fingerprints computed from exported TCP streams (requires `--export-streams`):
- `ja4h` — JA4H fingerprint per HTTP request
- `tcp_stream`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `http_method`, `http_host`, `http_uri`

### dns_tunneling_candidates.csv
Flagged on any of:
- High-entropy subdomain labels (Shannon entropy ≥ 3.5, label length ≥ 20 chars)
- Long FQDNs (> 52 characters)
- TXT or NULL record queries
- > 50 queries to a single registered domain

### lateral_movement_candidates.csv
- `LATERAL_MOVEMENT_CANDIDATE` — single host connected to 3+ internal targets via SMB (port 445)
- `INTERNAL_SCAN_CANDIDATE` — small TCP connections to 10+ internal IPs or across 10+ ports

---

## GeoIP Enrichment

When a GeoLite2 database is configured, the following columns are added to `iocs.csv` and used in `report.html`:

- `country_iso` — ISO 3166-1 alpha-2 country code
- `asn` — Autonomous System Number
- `asn_org` — Organization name for the ASN

The database is detected automatically in the project root, or specified with `--geoip-db`.

---

## Current Limitations

- Full HTTP/2 body reconstruction is not supported
- Deep HTTPS payload inspection requires TLS decryption material (key log file)
- TCP reassembly covers reconstructable plaintext streams only
- JA3 field availability depends on TShark version (gracefully skipped if unavailable)
- GeoIP enrichment requires a separate database download

---

## Example Terminal Output

```text
======================================================================
PCAP SECURITY TOOLKIT v2.0.0
======================================================================
Total Packets:              4128
Total Bytes:                5873210 (5.60 MB)
Unique IPs:                 14
TCP Streams:                18
Alerts:                     23
Credential Hits:            2
Exfil Candidates:           1
Beaconing:                  1
DNS Tunneling:              1
JA3 Malicious:              1
IOCs Extracted:             47

======================================================================
TOP ALERTS (filter: HIGH and above — 8 shown)
======================================================================
[CRITICAL]  CREDENTIAL_POST_RECONSTRUCTED
            192.168.1.10 -> 203.0.113.25
            MITRE: T1056.003 — Collection
            POST body contains likely credential or token material

[CRITICAL]  MALICIOUS_JA3
            192.168.1.15 -> 185.220.101.42
            MITRE: T1071.001 — Command and Control
            JA3 72a589da586844d7f0818ce684948eea matches Cobalt Strike default (abuse.ch)

[HIGH]      DNS_TUNNELING_CANDIDATE
            192.168.1.12 -> 8.8.8.8
            MITRE: T1071.004 — Command and Control
            High-entropy subdomain 'a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5' (entropy=3.97)
...
```

---

## Troubleshooting

### Missing Scapy
```bash
python3 bootstrap.py
```

### TShark Not Found
Install Wireshark/TShark and ensure it is in your PATH. The toolkit also auto-detects common install locations on macOS and Windows.

### No Payloads Extracted
- Streams must be exported with `--export-streams`
- Traffic may be encrypted (TLS without key material)
- Payload may not be reconstructable from the capture

### GeoIP Not Working
1. Confirm `pip install maxminddb` succeeded
2. Confirm the `.mmdb` file exists at the specified path or project root
3. The toolkit will print a warning if the database cannot be loaded

---

## Future Improvements

- TLS key log file support for HTTPS decryption
- Additional Kerberos attack pattern signatures (AS-REP roasting scoring)
- Deeper multipart body parsing
- STIX 2.1 IOC export format
- Expanded JA3/JA4/JARM threat intel database
- TLS key log file support for HTTPS decryption
- STIX 2.1 relationship objects (Indicator → Malware / Infrastructure)
