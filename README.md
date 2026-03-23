# PCAP Security Toolkit

A versatile Python-based PCAP analysis toolkit for security investigations.

## Author

Created by **John R. Allen**

## Overview

PCAP Security Toolkit is designed to help analyze `.pcap` and `.pcapng` files across multiple investigation scenarios, including:

- General traffic triage
- Suspicious web activity analysis
- Potential data exfiltration review
- File transfer and filename indicators
- DNS and HTTP analysis
- TCP stream review
- Payload extraction from reconstructable plaintext traffic
- CSV export for Excel, Splunk, or SIEM workflows

This project uses:

- **Python** for orchestration, analysis, and reporting
- **Scapy** for packet loading and custom flow logic
- **TShark** for protocol-aware extraction, TCP stream following, and richer parsing

## Features

- Flow analysis
- DNS and HTTP parsing
- TShark-assisted extraction
- HTTP, SMB, and FTP filename/file-transfer indicators
- Per-case output folders
- JSON and CSV output
- TCP stream indexing
- Optional TCP stream export
- HTTP body previews
- TLS metadata extraction
- Automatic readable payload extraction from reconstructable plaintext streams
- Dual stream export support:
  - ASCII streams for parsing headers and filenames
  - RAW streams for byte-accurate payload recovery where possible
- Correlated extracted payload filenames including:
  - TCP stream
  - source IP/port
  - destination IP/port
- SHA-256 hashing for extracted and decoded payloads
- File signature enrichment beyond basic file extension matching
- Credential indicator detection with severity scoring
- Base64 payload decoding
- Suspicious download detection
- Entropy-based exfiltration detection
- Beaconing and jitter analysis
- Credential POST reconstruction
- Raw TCP file carving
- TLS SNI anomaly detection

## Current Capabilities

The toolkit can currently help with:

- Summarizing traffic volume and top talkers
- Reviewing DNS and HTTP activity
- Identifying top conversations
- Detecting large private-to-external transfers
- Surfacing file references from:
  - HTTP URIs / filenames
  - SMB paths / filenames
  - FTP RETR / STOR commands
- Exporting followed TCP streams for deeper inspection
- Extracting readable payloads from reconstructable plaintext captures
- Saving payload bytes to disk with contextual filenames
- Detecting likely credentials or tokens in HTTP content
- Identifying suspicious downloads and transferred file types
- Detecting high-entropy outbound payloads that may indicate exfiltration
- Highlighting low-jitter beaconing candidates
- Reconstructing credential-related POST activity
- Flagging unusual TLS SNI values
- Carving select file types from raw TCP streams

## Current Limitations

This version is intended for triage and investigative support.

It does **not** yet provide:

- Full protocol-perfect TCP reassembly for every edge case
- Full HTTP/2 body reconstruction
- Deep HTTPS payload inspection without TLS decryption material
- Perfect binary extraction for every multipart / stream edge case
- Full file carving across all protocols

For encrypted HTTPS content, plaintext inspection still requires TLS decryption material such as a key log file or another supported secret source.

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
│   ├── exporters.py
│   ├── files.py
│   ├── flows.py
│   ├── https_metadata.py
│   ├── payloads.py
│   ├── streams.py
│   ├── tshark_extract.py
│   └── utils.py
├── output/
└── samples/

```
## Requirements

	•	Python 3
	•	TShark
	•	Scapy

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/jallen-6386/pcap-security-toolkit.git
cd pcap-security-toolkit

```
### 2. Run bootstrap

macOS/Linux

```bash
python3 bootstrap.py

```
Windows

```bash
python bootstrap.py

```
### 3 Verify TShark

```bash
tshark -v

```
## Quick Run

### macOS / Linux

```bash
./run.sh "/path/to/file.pcapng"

```
### Windows

```bash
run.bat "C:\path\to\file.pcapng"

```
## Running the Toolkit

### Basic Run
```bash
./run.sh "/path/to/file.pcapng"

```
### Custom Case Name
```bash
./run.sh "/path/to/file.pcapng" --case investigation1

```

### Export Streams + Payload Extraction
```bash
./run.sh "/path/to/file.pcapng" --case http_case --export-streams --max-streams 10

```

## Output Structure

Each run creates a dedicated case folder:

```text
output/
└── case1/
    ├── alerts.csv
    ├── beaconing_candidates.csv
    ├── carved_files.csv
    ├── credential_findings.csv
    ├── credential_posts.csv
    ├── entropy_exfil_candidates.csv
    ├── extracted_payloads/
    ├── extracted_payloads_index.csv
    ├── file_indicators.csv
    ├── ftp_tshark.csv
    ├── http_body_previews.csv
    ├── http_requests.csv
    ├── http_tshark.csv
    ├── report.json
    ├── smb_tshark.csv
    ├── streams/
    │   ├── tcp_stream_0.ascii.txt
    │   ├── tcp_stream_0.raw.txt
    ├── suspicious_downloads.csv
    ├── tcp_stream_index.csv
    ├── tls_metadata.csv
    └── tls_sni_anomalies.csv

```

## How to Read the Output

### Start Here
	1.	report.json
	2.	alerts.csv
	3.	file_indicators.csv

### Then Investigate
	•	http_tshark.csv
	•	http_body_previews.csv
	•	tcp_stream_index.csv
	•	tls_metadata.csv

### Deep Analysis
	•	streams/
	•	extracted_payloads/
	•	extracted_payloads_index.csv
	•	credential_findings.csv
	•	credential_posts.csv
	•	suspicious_downloads.csv
	•	entropy_exfil_candidates.csv
	•	beaconing_candidates.csv
	•	tls_sni_anomalies.csv
	•	carved_files.csv

## Extracted Payloads

**Recovered payloads will look like:**

```text
tcpstream_5__src_192_168_10_15_51522__to__dst_203_0_113_25_80__document_upload.txt

```
```text
This includes:
	•	TCP stream ID
	•	Source IP/port
	•	Destination IP/port
	•	Original filename when available
```

### What the Main Output Files Mean

#### report.json
```text
High-level case summary including:
	•	total packets
	•	total bytes
	•	human-readable total size
	•	unique IPs
	•	top protocols
	•	top IPs
	•	top conversations
	•	top DNS queries
	•	top HTTP hosts
	•	top HTTP user agents
	•	TCP stream count
	•	HTTP body preview count
	•	TLS metadata count
	•	extracted payload count
	•	credential finding count
	•	suspicious download count
	•	entropy exfil candidate count
	•	beaconing candidate count
	•	TLS SNI anomaly count
	•	carved file count
	•	alert count
```

#### alerts.csv
```text
High-level notable findings such as:
	•	large outbound transfer candidates
	•	credential indicators
	•	suspicious downloads
	•	entropy-based exfil candidates
	•	beaconing candidates
	•	TLS SNI anomalies
  ```

#### http_body_previews.csv

	•	form submissions
	•	POST body review
	•	quick triage of visible content

#### extracted_payloads_index.csv
```text
Index of extracted payloads including:
	•	filename
	•	source and destination
	•	content type
	•	detected file type
	•	SHA-256
	•	entropy
	•	whether raw bytes were used
	•	a short preview if text
  ```

#### credential_findings.csv

Credential or token-like patterns found in extracted content or HTTP previews, with severity scoring.

#### credential_posts.csv

POST bodies where likely credential material was reconstructed.

#### suspicious_downloads.csv

Potentially suspicious downloads or transferred file types based on extension, content type, or detected signature.

#### entropy_exfil_candidates.csv

Large high-entropy payloads sent from private to external destinations that may indicate encoded, encrypted, or compressed exfiltration.

#### beaconing_candidates.csv

Flows with repeated timing patterns and low jitter that may indicate command-and-control style beaconing.

#### tls_sni_anomalies.csv
```text
Suspicious or unusual TLS SNI values such as:
	•	overly long names
	•	digit-heavy names
	•	hex-like names
	•	suspicious suffixes
  ```

#### carved_files.csv

Files carved from raw TCP streams based on basic file signatures such as PDF, ZIP, and PE executable.

## Example Workflow
```text
A practical review flow is:
	1.	Open report.json
	2.	Review alerts.csv
	3.	Check file_indicators.csv
	4.	Review http_tshark.csv and http_body_previews.csv
	5.	If stream export was enabled, review:
	  •	extracted_payloads_index.csv
	  •	extracted_payloads/
	  •	streams/
	6.	Review:
	  •	credential_findings.csv
	  •	credential_posts.csv
	  •	suspicious_downloads.csv
	  •	entropy_exfil_candidates.csv
	  •	beaconing_candidates.csv
	  •	tls_sni_anomalies.csv
	  •	carved_files.csv
```

## Troubleshooting

### Missing Scapy

```bash
python3 bootstrap.py

```

### TShark Not Found

Install Wireshark/TShark and ensure it is available. This toolkit can also auto-detect common TShark locations on Windows and macOS.

### No Payloads Extracted
```text
Possible reasons:
	•	traffic is encrypted
	•	payload is not reconstructable from the capture
	•	streams were not exported
	•	the payload is binary or structured in a way not yet fully supported
```

### CSV Field Too Large

If you encounter a large field parsing error, update to the latest version of the toolkit. The current version raises the Python CSV field limit to support larger http.file_data values.

## Example Terminal Output

```text
PCAP SECURITY TOOLKIT v1.5.0

Total Packets: 4128
Total Bytes: 5873210 (5.60 MB)
TCP Streams: 18
HTTP Body Previews: 4
TLS Metadata Rows: 9
File Indicators: 3
Extracted Payloads: 5
Credential Findings: 2
Credential POSTs: 1
Suspicious Downloads: 2
Entropy Exfil Candidates: 1
Beaconing Candidates: 1
TLS SNI Anomalies: 1
Carved Files: 2
Alerts: 11

```

## Future Improvements

	•	Deeper file carving across additional signatures
	•	Better multipart parsing for edge cases
	•	Optional TLS key log support
	•	Additional protocol-aware extraction
	•	Stronger exfil scoring and clustering
	•	Expanded anomaly detection for C2 patterns