# PCAP Security Toolkit

A versatile Python-based PCAP analysis toolkit for security investigations.

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

  ## Current Capabilities

The toolkit can currently help with:

- Summarizing traffic volume and top talkers
- Reviewing DNS and HTTP activity
- Identifying top conversations
- Detecting large private-to-external transfers
- Surfacing file references from:
  - HTTP URIs / content-disposition
  - SMB paths / filenames
  - FTP RETR / STOR commands
- Exporting followed TCP streams for deeper inspection
- Extracting readable payloads from reconstructable plaintext captures
- Saving payload bytes to disk with contextual filenames

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

- Python 3
- TShark
- Scapy

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/pcap-security-toolkit.git
cd pcap-security-toolkit

```
## Requirements

- Python 3
- TShark
- Scapy

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
    ├── extracted_payloads/
    ├── extracted_payloads_index.csv
    ├── file_indicators.csv
    ├── http_requests.csv
    ├── http_tshark.csv
    ├── http_body_previews.csv
    ├── report.json
    ├── streams/
    │   ├── tcp_stream_0.ascii.txt
    │   ├── tcp_stream_0.raw.txt
    ├── tcp_stream_index.csv
    └── tls_metadata.csv

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

### Deep Analysis
	•	streams/
	•	extracted_payloads/
	•	extracted_payloads_index.csv

## Extracted Payloads

Recovered payloads will look like:

```text
tcpstream_1__192_168_1_3_65140__to__128_119_245_12_80__alice.txt

This includes:
	•	TCP stream ID
	•	Source IP/port
	•	Destination IP/port
	•	Original filename (if available)

```
## Troubleshooting

### Missing Scapy

```bash
python3 bootstrap.py

```
### TShark Not Found

Install Wireshark/TShark and ensure it is in PATH.

### No Payloads Extracted

Possible reasons:
	•	traffic is encrypted
	•	payload not reconstructable
	•	streams not exported
	•	binary format not fully supported

## Example Terminal Output

```text
PCAP SECURITY TOOLKIT v1.3.0

Total Packets: 175
Total Bytes: 174143 (170.06 KB)
TCP Streams: 2
Extracted Payloads: 1
Alerts: 2

```
## Future Improvements

- Better binary file reconstruction
- File hashing (SHA256)
- File signature detection
- TLS key log support
- Advanced exfil detection

## Author

Created by **John R. Allen**