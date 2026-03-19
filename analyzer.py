#!/usr/bin/env python3

"""
PCAP Security Toolkit
Version: 1.3.0
"""

import argparse
import sys
from pathlib import Path

try:
    from scapy.all import rdpcap
except ImportError:
    print("[!] Missing dependency: scapy")
    print("[!] Please run bootstrap or install requirements:")
    print("    python3 bootstrap.py")
    print("    OR")
    print("    pip install -r requirements.txt")
    sys.exit(1)

from config import OUTPUT_DIR
from modules.cases import get_case_output_dir
from modules.dependencies import has_tshark
from modules.detections import build_alerts
from modules.dns_http_tls import analyze_dns_http_tls
from modules.exporters import write_csv, write_json
from modules.files import build_http_body_previews, extract_file_indicators
from modules.flows import analyze_flows
from modules.https_metadata import extract_tls_metadata, summarize_tls_rows
from modules.payloads import save_extracted_payloads, write_extracted_payload_index
from modules.streams import (
    export_follow_stream,
    extract_tcp_stream_index,
    get_unique_tcp_stream_ids,
)
from modules.tshark_extract import (
    extract_ftp_fields,
    extract_http_fields,
    extract_smb_fields,
)


def print_report_summary(report: dict) -> None:
    summary = report.get("summary", {})

    print("\n" + "=" * 70)
    print("PCAP SECURITY TOOLKIT REPORT")
    print("=" * 70)
    print(f"Total Packets: {summary.get('total_packets', 0)}")
    print(
        f"Total Bytes: {summary.get('total_bytes', 0)} "
        f"({summary.get('total_size_human', 'N/A')})"
    )
    print(f"Unique IPs: {summary.get('unique_ips', 0)}")
    print(f"TCP Streams: {report.get('tcp_stream_count', 0)}")
    print(f"HTTP Body Previews: {report.get('http_body_preview_count', 0)}")
    print(f"TLS Metadata Rows: {report.get('tls_metadata_count', 0)}")
    print(f"File Indicators: {report.get('file_indicators_count', 0)}")
    print(f"Extracted Payloads: {report.get('extracted_payload_count', 0)}")
    print(f"Alerts: {report.get('alerts_count', 0)}")

    print("\nTop Protocols:")
    for proto, count in report.get("top_protocols", []):
        print(f"  {proto}: {count}")

    print("\nTop IPs:")
    for ip, count in report.get("top_ips", []):
        print(f"  {ip}: {count}")

    print("\nTop Conversations:")
    for conversation, count in report.get("top_conversations", []):
        print(f"  {conversation}: {count}")

    if report.get("top_dns_queries"):
        print("\nTop DNS Queries:")
        for query, count in report.get("top_dns_queries", []):
            print(f"  {query}: {count}")

    if report.get("top_http_hosts"):
        print("\nTop HTTP Hosts:")
        for host, count in report.get("top_http_hosts", []):
            print(f"  {host}: {count}")

    if report.get("top_http_user_agents"):
        print("\nTop HTTP User-Agents:")
        for ua, count in report.get("top_http_user_agents", []):
            print(f"  {ua}: {count}")

    print(f"\nCase Output Directory: {report.get('case_output_dir', 'N/A')}")


def main():
    parser = argparse.ArgumentParser(description="PCAP Security Toolkit")
    parser.add_argument("pcap", help="Path to a .pcap or .pcapng file")
    parser.add_argument("--top", type=int, default=10, help="Top N rows to summarize")
    parser.add_argument("--case", help="Optional case folder name")
    parser.add_argument(
        "--export-streams",
        action="store_true",
        help="Export followed TCP streams to files",
    )
    parser.add_argument(
        "--max-streams",
        type=int,
        default=25,
        help="Maximum number of TCP streams to export",
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    case_output_dir = get_case_output_dir(OUTPUT_DIR, args.case)

    print("=" * 70)
    print("PCAP SECURITY TOOLKIT v1.3.0")
    print("=" * 70)

    print(f"[*] Loading packets from {pcap_path}")
    packets = rdpcap(str(pcap_path))

    print("[*] Analyzing flows")
    flow_data = analyze_flows(packets)

    print("[*] Analyzing DNS/HTTP")
    protocol_data = analyze_dns_http_tls(packets)

    http_rows = []
    smb_rows = []
    ftp_rows = []
    tcp_stream_rows = []
    tls_rows = []
    tls_summary = []
    http_body_previews = []
    extracted_payloads = []

    if has_tshark():
        print("[*] Running TShark extraction")
        http_rows, http_err = extract_http_fields(pcap_path)
        smb_rows, smb_err = extract_smb_fields(pcap_path)
        ftp_rows, ftp_err = extract_ftp_fields(pcap_path)

        if http_err:
            print(f"[!] HTTP TShark extraction warning: {http_err}")
        if smb_err:
            print(f"[!] SMB TShark extraction warning: {smb_err}")
        if ftp_err:
            print(f"[!] FTP TShark extraction warning: {ftp_err}")

        print("[*] Extracting TCP stream index")
        tcp_stream_rows, stream_err = extract_tcp_stream_index(pcap_path)
        if stream_err:
            print(f"[!] TCP stream extraction warning: {stream_err}")

        print("[*] Extracting TLS metadata")
        tls_rows, tls_err = extract_tls_metadata(pcap_path)
        if tls_err:
            print(f"[!] TLS metadata extraction warning: {tls_err}")
        tls_summary = summarize_tls_rows(tls_rows)

        print("[*] Building HTTP body previews")
        http_body_previews = build_http_body_previews(http_rows)

        if args.export_streams:
            streams_dir = case_output_dir / "streams"
            streams_dir.mkdir(parents=True, exist_ok=True)

            stream_ids = get_unique_tcp_stream_ids(tcp_stream_rows)[: args.max_streams]
            print(f"[*] Exporting up to {len(stream_ids)} TCP streams in ascii and raw modes")

            for stream_id in stream_ids:
                ascii_content, ascii_err = export_follow_stream(
                    pcap_path,
                    stream_id,
                    mode="ascii",
                )
                if ascii_content is not None:
                    ascii_output = streams_dir / f"tcp_stream_{stream_id}.ascii.txt"
                    ascii_output.write_text(ascii_content, encoding="utf-8", errors="replace")
                else:
                    print(f"[!] Failed to export tcp.stream {stream_id} ascii: {ascii_err}")

                raw_content, raw_err = export_follow_stream(
                    pcap_path,
                    stream_id,
                    mode="raw",
                )
                if raw_content is not None:
                    raw_output = streams_dir / f"tcp_stream_{stream_id}.raw.txt"
                    raw_output.write_text(raw_content, encoding="utf-8", errors="replace")
                else:
                    print(f"[!] Failed to export tcp.stream {stream_id} raw: {raw_err}")

            print("[*] Detecting and extracting payloads using ascii + raw streams")
            extracted_payloads = save_extracted_payloads(
                case_output_dir,
                streams_dir,
                tcp_stream_rows,
            )
    else:
        print("[!] TShark not found. Skipping TShark-assisted extraction.")

    print("[*] Extracting file indicators")
    file_indicators = extract_file_indicators(http_rows, smb_rows, ftp_rows)

    print("[*] Building alerts")
    alerts = build_alerts(
        flow_data["flow_bytes"],
        file_indicators,
        http_body_previews=http_body_previews,
        tls_summary=tls_summary,
    )

    report = {
        "summary": flow_data["summary"],
        "top_protocols": flow_data["protocol_counter"].most_common(args.top),
        "top_ips": flow_data["ip_counter"].most_common(args.top),
        "top_conversations": flow_data["conversation_counter"].most_common(args.top),
        "top_dns_queries": protocol_data["dns_queries"].most_common(args.top),
        "top_http_hosts": protocol_data["http_hosts"].most_common(args.top),
        "top_http_user_agents": protocol_data["http_user_agents"].most_common(args.top),
        "tcp_stream_count": len(get_unique_tcp_stream_ids(tcp_stream_rows)) if tcp_stream_rows else 0,
        "http_body_preview_count": len(http_body_previews),
        "tls_metadata_count": len(tls_summary),
        "file_indicators_count": len(file_indicators),
        "extracted_payload_count": len(extracted_payloads),
        "alerts_count": len(alerts),
        "case_output_dir": str(case_output_dir),
    }

    print("[*] Writing output files")
    write_json(case_output_dir / "report.json", report)
    write_csv(case_output_dir / "http_requests.csv", protocol_data["notable_http"])
    write_csv(case_output_dir / "http_tshark.csv", http_rows)
    write_csv(case_output_dir / "http_body_previews.csv", http_body_previews)
    write_csv(case_output_dir / "tcp_stream_index.csv", tcp_stream_rows)
    write_csv(case_output_dir / "tls_metadata.csv", tls_summary)
    write_csv(case_output_dir / "smb_tshark.csv", smb_rows)
    write_csv(case_output_dir / "ftp_tshark.csv", ftp_rows)
    write_csv(case_output_dir / "file_indicators.csv", file_indicators)
    write_csv(case_output_dir / "alerts.csv", alerts)
    write_extracted_payload_index(
        case_output_dir / "extracted_payloads_index.csv",
        extracted_payloads,
    )

    print_report_summary(report)
    print(f"\n[+] Results written to: {case_output_dir}")


if __name__ == "__main__":
    main()