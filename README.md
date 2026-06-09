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

### Interfaces
- Command-line interface (`analyzer.py`) — scriptable, suited for batch processing and SIEM/SOAR pipelines
- Desktop GUI (`gui.py`) — minimalist customtkinter frontend with drag-and-drop, live streaming log, and a completion summary card

### Traffic Analysis
- Memory-efficient streaming packet loading via `PcapReader` — handles large PCAPs without loading fully into RAM
- IPv4 and IPv6 flow analysis
- Top talkers, protocols, and conversations
- DNS query and answer extraction with passive DNS correlation map

### First-Pass Triage (TShark statistics taps)
- Protocol hierarchy (`-z io,phs`) — packet/byte breakdown by protocol
- Expert Info (`-z expert`) — dissector-recognized anomalies (malformed packets, protocol violations, security and decryption issues) with network-noise suppression
- Cleartext credential recovery (`-z credentials`) — protocol-aware extraction across FTP, HTTP basic, IMAP, POP, and SMTP
- Version-aware field extraction — unsupported display-filter fields are detected via `tshark -G fields` and dropped before extraction, so one unavailable field (e.g. a JA4 field on older TShark) can't fail an entire pass
- Name resolution disabled (`-n`) on all TShark calls for deterministic, faster offline analysis
- `--decode-as` forces a dissector for traffic on non-standard ports (e.g. HTTP/TLS C2 on tcp.port 8888), applied across every extraction, statistics, and JA4 pass
- `--tls-keylog` decrypts TLS sessions when the secrets are available (SSLKEYLOGFILE), so HTTPS requests, credentials, objects, and JA4H are extracted as if plaintext

### Protocol Extraction (TShark)
- HTTP requests and responses (including response codes and server headers)
- DNS queries with A/AAAA/CNAME answers and TTL
- TLS metadata: SNI, ALPN, cipher suite, JA3/JA3S and JA4/JA4S fingerprints, certificate serial/validity/SAN details
- SMB file and path indicators
- FTP RETR/STOR command extraction
- SMTP/IMAP/POP3 commands and authentication
- Kerberos authentication events: principal names, SPNs, realms, error codes, encryption types, pre-auth data — with Kerberoasting and AS-REP roasting detection
- NTLMSSP authentication: account/domain/host identity, server challenge (forensic capture + external-auth detection)
- LDAP bind/search activity: cleartext simple-bind detection and directory-enumeration volume
- DCERPC interface binds: maps well-known interface UUIDs to lateral-movement techniques (DCSync, PetitPotam, remote task scheduling, service control)

### Detection Engine (MITRE ATT&CK Mapped)
| Detection | Alert Type | MITRE |
|---|---|---|
| Large private→external transfer | `LARGE_PRIVATE_TO_EXTERNAL_TRANSFER` | T1041 |
| Beaconing / low-jitter C2 | `BEACONING_CANDIDATE` | T1071.001 |
| DNS tunneling (entropy, length, volume, TXT/NULL) | `DNS_TUNNELING_CANDIDATE` | T1071.004 |
| Entropy-based exfiltration | `ENTROPY_BASED_EXFIL_CANDIDATE` | T1048.003 |
| Credential indicators in HTTP / payloads | `CREDENTIAL_INDICATOR` | T1552 |
| Cleartext credentials (FTP, HTTP basic, IMAP, POP, SMTP) | `CLEARTEXT_CREDENTIAL` | T1552 |
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
| Kerberos errors (failed auth, ticket anomalies) | `KERBEROS_ANOMALY` | T1558 |
| Kerberoasting (TGS-REQ with RC4 service ticket) | `KERBEROASTING_CANDIDATE` | T1558.003 |
| AS-REP roasting (AS-REP without pre-authentication) | `ASREP_ROASTING_CANDIDATE` | T1558.004 |
| NTLM authentication to an external host (relay/leak) | `NTLM_EXTERNAL_AUTH` | T1187 |
| Cleartext LDAP simple bind (password on the wire) | `LDAP_CLEARTEXT_BIND` | T1552 |
| LDAP search enumeration (BloodHound/SharpHound) | `LDAP_ENUMERATION` | T1087 |
| DCERPC bind to DRSUAPI (DCSync) | `DCERPC_DCSYNC` | T1003.006 |
| DCERPC bind to MS-EFSR (PetitPotam coercion) | `DCERPC_FORCED_AUTH` | T1187 |
| DCERPC bind to task scheduler (atsvc/tsch) | `DCERPC_SCHEDULED_TASK` | T1053.005 |
| File name indicators (HTTP URI, SMB, FTP) | `FILE_NAME_INDICATOR_OBSERVED` | T1105 |
| TShark Expert Info anomalies (malformed, protocol, security) | `EXPERT_INFO_ANOMALY` | — |

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
- HTTP object export (`--export-objects http`): reconstructs files transferred over HTTP, correctly handling chunked encoding and gzip/deflate compression that raw-stream carving cannot, then hashes and fingerprints each (requires `--export-streams`)
- TCP stream triage: streams ranked by a composite suspicion score (content signals, direction, volume, TCP health) so the most interesting sessions surface first
- Passive OS fingerprinting from TCP SYN characteristics (TTL, window size, MSS)
- SMTP attachment extraction and hashing from exported streams
- YARA rule scanning on carved files and extracted payloads
- Active JARM TLS server fingerprinting with known C2 hash lookup (`--jarm-probe`)
- TCP stream export in ASCII and RAW modes
- HTTP payload extraction from reconstructable plaintext streams
- Multipart form-data parsing: decodes base64/quoted-printable parts and captures form-field names (e.g. `password`)
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
├── gui.py
├── run.sh
├── run.bat
├── gui.sh
├── gui.bat
├── config.py
├── modules/
│   ├── __init__.py
│   ├── allowlists.py
│   ├── arp_detection.py
│   ├── auth_protocols.py
│   ├── cases.py
│   ├── dependencies.py
│   ├── detections.py
│   ├── dcerpc.py
│   ├── dns_http_tls.py
│   ├── excel_export.py
│   ├── exporters.py
│   ├── files.py
│   ├── flows.py
│   ├── geoip.py
│   ├── html_report.py
│   ├── http_objects.py
│   ├── https_metadata.py
│   ├── icmp_tunnel.py
│   ├── iocs.py
│   ├── ja4.py
│   ├── kerberos_attacks.py
│   ├── jarm.py
│   ├── os_fingerprint.py
│   ├── payloads.py
│   ├── protocol_anomalies.py
│   ├── smtp_attachments.py
│   ├── stix_export.py
│   ├── stream_triage.py
│   ├── streams.py
│   ├── tshark_capabilities.py
│   ├── tshark_config.py
│   ├── tshark_extract.py
│   ├── tshark_stats.py
│   ├── utils.py
│   └── yara_scanner.py
├── rules/
│   └── suspicious_strings.yar
├── intel/
├── tests/
├── output/
└── samples/
```

---

## Requirements

- Python 3.10+
- TShark (Wireshark)
- Scapy
- `openpyxl` for Excel workbook export
- `customtkinter` for the desktop GUI
- `tkinterdnd2` for drag-and-drop PCAP support in the GUI
- `yara-python` for YARA rule scanning

All Python requirements are installed automatically by `bootstrap.py`.

**Optional:**
- `maxminddb` + GeoLite2 database for GeoIP/ASN enrichment

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

## Desktop GUI

For analysts who prefer a point-and-click workflow, the toolkit ships with a minimalist desktop frontend (`gui.py`) that wraps the CLI.  It exposes every flag as a toggle, streams analyzer output in real time with color-coded log lines, and presents a summary card at completion with quick buttons to open the output folder, Excel workbook, or HTML report.

**macOS / Linux**
```bash
./gui.sh
```

**Windows**
```bash
gui.bat
```

**Features:**
- Drag-and-drop PCAP files or click Browse
- Toggle switches for `--export-streams`, `--jarm-probe`, `--yara-rules`, `--geoip-db`
- Output format selector (CSV + Excel / HTML / Both)
- Severity-filter and minimum-IOC-confidence dropdowns, plus decode-as, threat-intel directory, and TLS key-log fields
- Live streaming log with color-coded `[*]`/`[!]`/`[+]` lines
- Summary card with severity breakdown, top alerts (with MITRE IDs), and detection counts
- One-click "Open Folder" / "Open Excel Workbook" / "Open HTML Report" buttons
- System / dark / light theme toggle
- Cancel button to terminate a running analysis

The CLI workflow is unchanged — the GUI is purely additive and subprocesses `analyzer.py`.

---

## CLI Reference

```bash
analyzer.py [-h] [--top N] [--case NAME]
            [--export-streams] [--max-streams N]
            [--severity-filter {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
            [--output-format {csv,html,both}]
            [--geoip-db PATH]
            [--yara-rules PATH]
            [--jarm-probe]
            [--min-ioc-confidence {LOW,MEDIUM,HIGH}]
            [--decode-as RULE]
            [--intel-dir PATH] [--tls-keylog PATH]
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
| `--min-ioc-confidence` | LOW | Drop IOCs below this confidence from iocs.csv and the STIX bundle (MEDIUM removes flow-only IPs, user-agents, JA4S; HIGH keeps only corroborated indicators) |
| `--decode-as` | — | Force a dissector for a non-standard port, e.g. `tcp.port==8888,http` (repeatable). Applies to all TShark extraction, statistics, and JA4 passes |
| `--intel-dir` | intel/ | Directory of JA3/JA4/JARM threat-intel feed CSVs to merge into the detection tables |
| `--tls-keylog` | — | Path to a TLS key-log file (SSLKEYLOGFILE format) to decrypt TLS so HTTPS content is extracted like plaintext |

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

# Full malware-hunting profile: stream export, YARA, and JARM probing
./run.sh "/path/to/capture.pcapng" --case incident_42 --export-streams \
    --yara-rules ./rules --jarm-probe --output-format both

# C2 on a non-standard port: dissect tcp/8888 as HTTP and tcp/4443 as TLS
./run.sh "/path/to/capture.pcapng" --decode-as tcp.port==8888,http --decode-as tcp.port==4443,tls
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
    ├── protocol_hierarchy.csv          ← Protocol breakdown by packets/bytes (-z io,phs)
    ├── protocol_hierarchy_raw.txt
    ├── expert_info.csv                 ← Dissector-recognized anomalies (-z expert)
    ├── expert_info_raw.txt
    ├── credentials_tshark.csv          ← Cleartext credentials (-z credentials)
    ├── credentials_raw.txt
    ├── iocs.stix2.json
    ├── smb_tshark.csv
    ├── ftp_tshark.csv
    ├── smtp_activity.csv
    ├── kerberos_activity.csv
    ├── kerberos_attacks.csv            ← Kerberoasting / AS-REP roasting candidates
    ├── ntlm_activity.csv               ← NTLM auth events (account/domain/host)
    ├── ldap_activity.csv               ← LDAP bind/search activity
    ├── dcerpc_activity.csv             ← DCERPC interface binds (lateral movement)
    ├── tcp_stream_index.csv
    ├── stream_triage.csv               ← TCP streams ranked by suspicion score
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
    ├── http_objects.csv                ← HTTP files (chunked/gzip-decoded)
    ├── extracted_payloads/
    ├── carved_files/
    ├── http_objects/
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
- `stream_triage.csv` — start with the highest-scoring streams, then pull their content from `streams/`
- `extracted_payloads_index.csv` + `extracted_payloads/`
- `carved_files.csv` + `carved_files/`
- `http_objects.csv` + `http_objects/` (HTTP files, chunked/gzip-decoded)
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
- `benign_infra` — True only for well-known benign *endpoints* (public DNS resolver IPs), so a SIEM import can filter them instead of block-listing them. CDN/cloud domains are deliberately **not** marked benign — a specific host or distribution on a trusted CDN can itself be malicious (phishing kits, C2 redirectors)
- `country_iso`, `asn`, `asn_org` (if GeoIP enabled)

IPv4 noise reduction: special-use ranges are never emitted as IOCs or treated as external targets — private (RFC 1918), loopback, link-local, CGNAT (RFC 6598), documentation/TEST-NET (RFC 5737/3849), benchmarking (RFC 2544), multicast, broadcast, and unspecified addresses.

### False-positive tuning
To keep findings actionable, several detectors are tuned against benign noise (nothing is hidden — findings are downgraded/annotated, not dropped):
- **Beaconing** to public DNS resolvers or the NTP port is kept but downgraded to INFO and annotated as benign infrastructure
- **Suspicious downloads** are tiered: executables/scripts (`.exe`, `.dll`, `.ps1`, `.hta`, …) are HIGH; documents/archives (`.pdf`, `.zip`, `.docm`, …) are MEDIUM — content-based detection (carving + YARA + hashing) still inspects the bytes
- **TLS SNI morphology** (long/hex-like/digit-heavy) and **high-volume DNS** aggregate checks skip known CDN/cloud parent domains — those heuristics can't distinguish a malicious CDN host from a benign one, so they only add noise. CDN traffic is still fully subject to JA3/JA4, beaconing (by IP), suspicious-download, payload (carving/YARA/hash), and per-query DNS-entropy detection
- **Multi-User-Agent** flagging requires 15+ distinct UAs from one host (a normal workstation easily shows 10+)
- **`--min-ioc-confidence`** optionally drops low-value IOCs (flow-only external IPs, user-agents, JA4S) from `iocs.csv` and the STIX bundle; default `LOW` keeps everything

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
- NULL record queries; TXT queries only when paired with an entropy/length indicator (TXT alone is too common — SPF/DKIM/DMARC — to flag)
- > 50 queries to a single registered domain

Reverse-DNS lookups (`*.in-addr.arpa`, `*.ip6.arpa`) are excluded as normal operational traffic.

### lateral_movement_candidates.csv
- `LATERAL_MOVEMENT_CANDIDATE` — single host connected to 3+ internal targets via SMB (port 445)
- `INTERNAL_SCAN_CANDIDATE` — small TCP connections to 10+ internal IPs or across 10+ ports

### kerberos_attacks.csv
Kerberos credential-attack candidates (MEDIUM — leads for review):
- `KERBEROASTING_CANDIDATE` (T1558.003) — a TGS-REQ requesting a service ticket with RC4 (etype 23), which is crackable offline; the SPN is included
- `ASREP_ROASTING_CANDIDATE` (T1558.004) — an account that received an AS-REP without ever sending Kerberos pre-authentication (PA-ENC-TIMESTAMP), so its AS-REP is crackable. Normal accounts that retry with pre-auth are not flagged

### ntlm_activity.csv / ldap_activity.csv / dcerpc_activity.csv
Forensic records of Windows authentication and RPC traffic:
- `ntlm_activity.csv` — NTLM AUTHENTICATE events: `username`, `domain`, `hostname`, `has_server_challenge`, src/dst/stream. NTLM auth directed at an external host raises a `NTLM_EXTERNAL_AUTH` alert (possible relay/leak).
- `ldap_activity.csv` — LDAP bind/search operations: `operation`, `bind_dn`, `auth_type`, `base_object`, `result_code`. A cleartext simple bind raises `LDAP_CLEARTEXT_BIND` (HIGH); 100+ search requests from one host raises `LDAP_ENUMERATION` (MEDIUM).
- `dcerpc_activity.csv` — binds to recognized DCERPC interfaces: `interface`, `uuid`, `mitre_technique_id`, `alert_worthy`, src/dst/stream. Rare high-signal interfaces (DRSUAPI/DCSync, MS-EFSR/PetitPotam, task scheduler) raise alerts; common-but-abusable interfaces (svcctl, samr, lsarpc, winreg, srvsvc, spoolss) are recorded with their technique label but not alerted, to keep false positives low.

### http_objects.csv
Files reconstructed by TShark's `--export-objects http` (requires `--export-streams`), saved under `http_objects/`:
- `filename`, `saved_path`, `size_bytes`, `sha256`, `entropy`, `detected_file_type`, `detected_extension`
- Handles chunked transfer-encoding and gzip/deflate compression that raw-stream carving cannot, so it recovers files carving would miss. Hashes feed the IOC list and the objects are scanned by YARA.

### stream_triage.csv
TCP streams ranked by a composite **suspicion score** (highest first) so you can review the most interesting sessions before reading raw stream content:
- `tcp_stream`, `src_ip`, `dst_ip`, `dst_port`, `packet_count`, `total_bytes`, `client_bytes`, `server_bytes`, `duration_sec`
- `resets`, `retransmissions`, `zero_windows`, `lost_segments`, `completeness` (TCP health — light weight, usually network conditions)
- `has_carved_file`, `has_payload`, `has_credential`, `suspicion_score`, `reasons`
- Score is driven mainly by content signals (carved files, extracted payloads, credentials, high entropy), external destination, and upload-heavy direction; TCP health flags only sharpen ranking. This is a navigational ranking, not new alerts — the underlying signals raise their own alerts.

### protocol_hierarchy.csv
Protocol breakdown of the capture from TShark's `-z io,phs` tap:
- `protocol`, `depth` (nesting level), `frames`, `bytes`
- Fast "what's in this PCAP?" overview; raw tap output preserved in `protocol_hierarchy_raw.txt`

### expert_info.csv
Dissector-recognized anomalies from TShark's `-z expert` tap:
- `severity` (Error / Warning / Note / Chat), `frequency`, `group`, `protocol`, `summary`
- Pure network-condition groups (retransmissions, checksum offload) are kept here but suppressed from alerts
- Error-severity and high-interest Warning items (Malformed, Security, Decryption, Protocol, Reassemble) become `EXPERT_INFO_ANOMALY` alerts
- Raw tap output preserved in `expert_info_raw.txt`

### credentials_tshark.csv
Cleartext credentials recovered by TShark's `-z credentials` tap:
- `packet`, `protocol` (e.g. "HTTP basic auth", "FTP"), `username`, `info`
- Each row becomes a HIGH `CLEARTEXT_CREDENTIAL` alert; raw tap output preserved in `credentials_raw.txt`

### jarm_fingerprints.csv
Active TLS server fingerprints generated when `--jarm-probe` is set:
- 62-character JARM hash per `(dst_ip, dst_port)` observed in TLS metadata
- Hits against a small built-in C2 hash table (Cobalt Strike, Merlin, Covenant, AsyncRAT)
- Skips private IPs; requires outbound network connectivity from the host running the toolkit

### icmp_tunneling_candidates.csv
ICMP covert-channel indicators:
- Echo/Echo-Reply pairs with payloads > 64 bytes
- High-volume ICMP between a single source/destination pair (> 100 packets)
- Non-standard ICMP types

### arp_anomalies.csv
- IP↔MAC conflicts (HIGH — possible ARP cache poisoning, T1557.002)
- Gratuitous ARP flooding from a single source (MEDIUM)

### os_fingerprints.csv
Passive OS guesses for each unique source IP based on the first observed TCP SYN:
- TTL, TCP window size, MSS, and window-scale signature match against a small p0f-style table
- Covers Windows 7/8/10/11/Server, Linux 2.4/2.6/4.x/5.x, macOS/iOS, FreeBSD, OpenBSD, Android, Cisco IOS, Solaris

### smtp_attachments.csv
MIME attachments extracted from SMTP DATA sections in exported streams:
- `filename`, `content_type`, `size_bytes`, `sha256`, `tcp_stream`, saved file path
- Attachments are saved under `smtp_attachments/` inside the case directory

### yara_hits.csv
Matches from `--yara-rules` scanning over carved files, extracted payloads, and SMTP attachments:
- `rule`, `tags`, `severity` (from rule meta or tags), `matched_strings`, target file path, sha256

### iocs.stix2.json
STIX 2.1 bundle containing one Indicator object per IOC, ready for import into MISP, OpenCTI, or TheHive. Indicator IDs are deterministic across runs (UUIDv5) so the same IOC always gets the same STIX ID. IOCs flagged `benign_infra` (public DNS resolvers) are excluded from the bundle — a STIX Indicator asserts malicious activity — but remain visible, annotated, in `iocs.csv`. When an IOC matches a known malware family (via JA3/JA4/JARM fingerprints), the bundle also includes a **Malware SDO** and an `indicates` **Relationship** from the indicator to it, so threat-intel platforms can correlate indicators to the family.

### analysis_workbook.xlsx
All non-empty CSVs consolidated into a single Excel workbook, one sheet per file, ordered by investigative priority (alerts → iocs → timeline → detections → raw protocol data). Opens natively in Microsoft Excel, Google Sheets, and Apple Numbers. Any sheet that would exceed Excel's 1,048,576-row limit (e.g. a per-packet index on a very large capture) is truncated with a final row pointing to the full CSV.

### extracted_payloads_index.csv
Index of every payload reconstructed from exported TCP streams:
- `filename` — constructed safe name (used on disk)
- `original_filename` — exact filename advertised in the HTTP `Content-Disposition` header, when present
- `form_field_name` — the multipart form-field name (e.g. `password`, `upload`), when present
- `content_type`, `sha256`, `entropy`, `detected_file_type`, `detected_extension`, `size_bytes`, `preview`

Multipart parts carrying a `Content-Transfer-Encoding` (base64 or quoted-printable) are decoded so the real file/field content — and its true type and hash — are recovered rather than the encoded text.

---

## GeoIP Enrichment

When a GeoLite2 database is configured, the following columns are added to `iocs.csv` and used in `report.html`:

- `country_iso` — ISO 3166-1 alpha-2 country code
- `asn` — Autonomous System Number
- `asn_org` — Organization name for the ASN

The database is detected automatically in the project root, or specified with `--geoip-db`.

---

## Performance

The toolkit is built to handle large captures (300,000+ packets) without loading the whole file into RAM:

- **Streaming packet analysis** — Scapy's `PcapReader` yields packets one at a time; the file is never fully materialized in memory.
- **Single-pass packet analysis** — flow statistics and DNS/HTTP summaries are computed in one combined iteration rather than two separate passes over the capture.
- **Parallel TShark extraction** — the independent per-protocol extraction passes (HTTP, DNS, TLS, SMB, FTP, SMTP, Kerberos, ICMP, ARP, TCP SYN, stream index) run concurrently instead of serially. The worker count defaults to the number of CPU cores (capped at 8) and is configurable via `TSHARK_MAX_WORKERS` in `config.py`.
- **Parallel stream export** — when `--export-streams` is set, the per-stream follow passes are also run concurrently.
- **Adaptive scaling for large captures** — running many TShark passes in parallel on a multi-gigabyte capture can exhaust RAM, so the worker count is reduced automatically by file size (≥250 MB → 4 workers, ≥1 GB → 2 workers), and huge captures also reset TShark's dissector state periodically (`-M`) to bound per-process memory. Thresholds live in `config.py`.
- **Name resolution disabled** — all TShark calls use `-n`, avoiding DNS/host lookups that would otherwise add latency and non-determinism on large captures.

**Tuning tips for very large captures:**
- `--export-streams` adds two TShark follow passes per stream. Keep `--max-streams` modest (default 25) on large files; raise it only when you need deeper payload coverage.
- `--jarm-probe` makes live outbound network connections and is the slowest optional step — enable it only when you intend to fingerprint observed servers.
- Lower `TSHARK_MAX_WORKERS` if running on a memory-constrained host, or raise it on a many-core workstation.

---

## Testing

The detection and parsing logic is covered by a `unittest` suite (no extra
dependencies required):

```bash
.venv/bin/python -m unittest discover -s tests
```

It validates IP classification, the false-positive tuning (DNS, beaconing,
downloads, SNI, multi-UA), the NTLM/LDAP/DCERPC detections, the threat-intel
feed loader, the Excel row-limit handling, the YARA ruleset (compiles + matches
known-malicious samples while leaving benign content clean), the TCP
stream-triage scoring, and the TShark statistics parsers. Tests that need an
optional package (openpyxl, yara) skip cleanly when it is absent.

---

## Current Limitations

- Full HTTP/2 body reconstruction is not supported
- Deep HTTPS payload inspection requires TLS decryption material — supply it with `--tls-keylog` (SSLKEYLOGFILE); without it, TLS stays encrypted (metadata only)
- TCP reassembly covers reconstructable plaintext streams only
- Some fields (JA3/JA4 family, newer protocol fields) depend on TShark version; unavailable fields are detected via `tshark -G fields` and dropped automatically rather than failing the pass
- GeoIP enrichment requires a separate database download

---

## Example Terminal Output

```text
======================================================================
PCAP SECURITY TOOLKIT v2.3.0
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

- Full HTTP/2 body reconstruction
- Bundled GUI distribution (PyInstaller `.app` / `.exe`) for analysts without Python installed
