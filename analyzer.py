#!/usr/bin/env python3

"""
PCAP Security Toolkit
Version: 2.3.0
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from scapy.utils import PcapReader
except ImportError:
    print("[!] Missing dependency: scapy")
    print("[!] Please run bootstrap or install requirements:")
    print("    python bootstrap.py")
    print("    OR")
    print("    python -m pip install -r requirements.txt --no-user")
    sys.exit(1)

from config import OUTPUT_DIR, TSHARK_MAX_WORKERS
from modules.cases import get_case_output_dir
from modules.dependencies import has_tshark
from modules.detections import (
    _SEVERITY_ORDER,
    build_alerts,
    build_suspicious_downloads,
    detect_beaconing,
    detect_dns_tunneling,
    detect_entropy_exfil_candidates,
    detect_http_response_anomalies,
    detect_lateral_movement,
    detect_suspicious_user_agents,
    detect_tls_sni_anomalies,
    find_credential_indicators,
    reconstruct_credential_posts,
)
from modules.exporters import write_csv, write_json
from modules.files import build_http_body_previews, extract_file_indicators
from modules.flows import analyze_packets
from modules.geoip import GeoIPEnricher, enrich_ips
from modules.html_report import generate_html_report
from modules.https_metadata import (
    detect_malicious_ja3,
    detect_malicious_ja4,
    extract_tls_metadata,
    summarize_tls_rows,
)
from modules.ja4 import compute_ja4h_rows, enrich_tls_summary_with_ja4
from modules.iocs import extract_iocs
from modules.arp_detection import detect_arp_spoofing
from modules.icmp_tunnel import detect_icmp_tunneling
from modules.jarm import probe_observed_servers
from modules.os_fingerprint import fingerprint_hosts
from modules.smtp_attachments import extract_smtp_attachments
from modules.excel_export import build_excel_workbook
from modules.stix_export import export_stix_bundle
from modules.yara_scanner import load_rules, scan_files, yara_available
from modules.payloads import (
    carve_files_from_raw_streams,
    save_extracted_payloads,
    write_extracted_payload_index,
)
from modules.protocol_anomalies import detect_protocol_anomalies
from modules.streams import (
    export_follow_stream,
    extract_tcp_stream_index,
    get_unique_tcp_stream_ids,
)
from modules.tshark_capabilities import get_available_fields
from modules.tshark_stats import (
    run_credentials,
    run_expert_info,
    run_protocol_hierarchy,
)
from modules.tshark_extract import (
    extract_arp_fields,
    extract_dns_fields,
    extract_ftp_fields,
    extract_http_fields,
    extract_http_response_fields,
    extract_icmp_fields,
    extract_kerberos_fields,
    extract_smtp_fields,
    extract_smb_fields,
    extract_tcp_stream_stats,
    extract_tcp_syn_fields,
)
from modules.stream_triage import score_streams
from modules.utils import is_noise_ip


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

def _severity_label(severity: str) -> str:
    labels = {
        "CRITICAL": "[CRITICAL]",
        "HIGH":     "[HIGH]    ",
        "MEDIUM":   "[MEDIUM]  ",
        "LOW":      "[LOW]     ",
        "INFO":     "[INFO]    ",
    }
    return labels.get(severity, "[INFO]    ")


def print_report_summary(report: dict, alerts: list[dict], severity_filter: str) -> None:
    summary = report.get("summary", {})
    filter_order = _SEVERITY_ORDER.get(severity_filter, 4)

    print("\n" + "=" * 70)
    print("PCAP SECURITY TOOLKIT REPORT")
    print("=" * 70)
    print(f"Total Packets:              {summary.get('total_packets', 0)}")
    print(
        f"Total Bytes:                {summary.get('total_bytes', 0)} "
        f"({summary.get('total_size_human', 'N/A')})"
    )
    print(f"Unique IPs:                 {summary.get('unique_ips', 0)}")
    print(f"TCP Streams:                {report.get('tcp_stream_count', 0)}")
    print(f"HTTP Body Previews:         {report.get('http_body_preview_count', 0)}")
    print(f"TLS Metadata Rows:          {report.get('tls_metadata_count', 0)}")
    print(f"File Indicators:            {report.get('file_indicators_count', 0)}")
    print(f"Extracted Payloads:         {report.get('extracted_payload_count', 0)}")
    print(f"Credential Findings:        {report.get('credential_finding_count', 0)}")
    print(f"Credential POSTs:           {report.get('credential_post_count', 0)}")
    print(f"Cleartext Credentials:      {report.get('cleartext_credential_count', 0)}")
    print(f"Suspicious Downloads:       {report.get('suspicious_download_count', 0)}")
    print(f"Entropy Exfil Candidates:   {report.get('entropy_exfil_candidate_count', 0)}")
    print(f"Beaconing Candidates:       {report.get('beaconing_candidate_count', 0)}")
    print(f"TLS SNI Anomalies:          {report.get('tls_sni_anomaly_count', 0)}")
    print(f"DNS Tunneling Candidates:   {report.get('dns_tunneling_count', 0)}")
    print(f"Suspicious User Agents:     {report.get('suspicious_ua_count', 0)}")
    print(f"Lateral Movement Hits:      {report.get('lateral_movement_count', 0)}")
    print(f"Protocol Anomalies:         {report.get('protocol_anomaly_count', 0)}")
    print(f"Malicious JA3 Hits:         {report.get('malicious_ja3_count', 0)}")
    print(f"Malicious JA4 Hits:         {report.get('malicious_ja4_count', 0)}")
    print(f"JA4H Fingerprints:          {report.get('ja4h_count', 0)}")
    print(f"JARM Fingerprints:          {report.get('jarm_count', 0)}")
    print(f"ICMP Tunneling Candidates:  {report.get('icmp_tunneling_count', 0)}")
    print(f"ARP Anomalies:              {report.get('arp_anomaly_count', 0)}")
    print(f"OS Fingerprints:            {report.get('os_fingerprint_count', 0)}")
    print(f"SMTP Attachments:           {report.get('smtp_attachment_count', 0)}")
    print(f"YARA Hits:                  {report.get('yara_hit_count', 0)}")
    print(
        f"Expert Info Items:          {report.get('expert_info_count', 0)} "
        f"({report.get('expert_error_count', 0)} errors)"
    )
    print(f"HTTP Response Anomalies:    {report.get('http_response_anomaly_count', 0)}")
    print(f"Carved Files:               {report.get('carved_file_count', 0)}")
    print(
        f"Top Stream Suspicion:       {report.get('top_stream_suspicion_score', 0)} "
        f"(of {report.get('stream_triage_count', 0)} streams)"
    )
    print(f"IOCs Extracted:             {report.get('ioc_count', 0)}")
    print(f"Alerts:                     {report.get('alerts_count', 0)}")

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

    # Top critical/high alerts
    visible = [
        a for a in alerts
        if _SEVERITY_ORDER.get(a.get("severity", "INFO"), 4) <= filter_order
    ]
    if visible:
        print(f"\n{'=' * 70}")
        print(f"TOP ALERTS (filter: {severity_filter} and above — {len(visible)} shown)")
        print("=" * 70)
        for alert in visible[:15]:
            sev = alert.get("severity", "INFO")
            label = _severity_label(sev)
            atype = alert.get("alert_type", "")
            src = alert.get("src_ip", "")
            dst = alert.get("dst_ip", "")
            reason = alert.get("reason", "")
            technique = alert.get("mitre_technique_id", "")
            print(f"{label} {atype}")
            if src or dst:
                print(f"           {src} -> {dst}")
            if technique:
                print(f"           MITRE: {technique} — {alert.get('mitre_tactic', '')}")
            print(f"           {reason}")
            print()
        if len(visible) > 15:
            print(f"  ... and {len(visible) - 15} more. See alerts.csv for full list.")

    print(f"\nCase Output Directory: {report.get('case_output_dir', 'N/A')}")


# ---------------------------------------------------------------------------
# Timeline builder
# ---------------------------------------------------------------------------

def build_timeline(
    dns_tunneling_candidates: list[dict],
    credential_findings: list[dict],
    suspicious_downloads: list[dict],
    beaconing_candidates: list[dict],
    http_body_previews: list[dict],
    tls_sni_anomalies: list[dict],
    suspicious_user_agents: list[dict],
    lateral_movement_candidates: list[dict],
    malicious_ja3_findings: list[dict],
    credential_posts: list[dict],
    file_indicators: list[dict],
    http_response_anomalies: list[dict],
    flow_times: dict,
) -> list[dict]:
    """Assemble a chronologically sorted event timeline from all detection results."""
    events = []

    def _add(timestamp, event_type, src_ip, dst_ip, detail, technique=""):
        events.append({
            "timestamp": str(timestamp or ""),
            "event_type": event_type,
            "src_ip": str(src_ip or ""),
            "dst_ip": str(dst_ip or ""),
            "detail": str(detail or "")[:300],
            "mitre_technique_id": technique,
        })

    for item in dns_tunneling_candidates:
        _add(item.get("timestamp"), "DNS_TUNNELING", item.get("src_ip"), item.get("dst_ip"),
             item.get("reason"), "T1071.004")

    for item in credential_findings:
        _add("", "CREDENTIAL_INDICATOR", item.get("src_ip"), item.get("dst_ip"),
             f"{item.get('severity')} — {item.get('indicator_type')} in {item.get('source_type')}",
             "T1552")

    for item in credential_posts:
        _add("", "CREDENTIAL_POST", item.get("src_ip"), item.get("dst_ip"),
             f"POST to {item.get('host')}{item.get('uri')}", "T1056.003")

    for item in suspicious_downloads:
        _add("", "SUSPICIOUS_DOWNLOAD", item.get("src_ip"), item.get("dst_ip"),
             item.get("reason"), "T1105")

    for item in http_body_previews:
        method = (item.get("http_method") or "").upper()
        if method in {"POST", "PUT", "PATCH"}:
            _add(item.get("timestamp"), "HTTP_BODY_OBSERVED", item.get("src_ip"), item.get("dst_ip"),
                 f"{method} {item.get('host')}{item.get('uri')}", "T1071.001")

    for item in tls_sni_anomalies:
        _add("", "TLS_SNI_ANOMALY", item.get("src_ip"), item.get("dst_ip"),
             item.get("reason"), "T1071.001")

    for item in suspicious_user_agents:
        _add(item.get("timestamp"), "SUSPICIOUS_UA", item.get("src_ip"), item.get("dst_ip"),
             item.get("reason"), "T1071.001")

    for item in lateral_movement_candidates:
        _add("", "LATERAL_MOVEMENT", item.get("src_ip"), "",
             item.get("reason"), item.get("mitre_technique_id", "T1021.002"))

    for item in malicious_ja3_findings:
        _add(item.get("timestamp"), "MALICIOUS_JA3", item.get("src_ip"), item.get("dst_ip"),
             item.get("reason"), "T1071.001")

    for item in file_indicators:
        _add(item.get("timestamp"), "FILE_INDICATOR", item.get("src_ip"), item.get("dst_ip"),
             f"{item.get('protocol')} — {item.get('filename')}", "T1105")

    for item in beaconing_candidates:
        # Use first seen timestamp from flow_times if available
        flow_key = (
            item.get("src_ip"), item.get("dst_ip"),
            item.get("sport"), item.get("dport"), item.get("protocol"),
        )
        times = flow_times.get(flow_key, [])
        ts = str(min(times)) if times else ""
        _add(ts, "BEACONING", item.get("src_ip"), item.get("dst_ip"),
             f"jitter={item.get('jitter_pct')}% avg_interval={item.get('avg_interval_sec')}s",
             "T1071.001")

    for item in http_response_anomalies:
        _add("", "HTTP_RESPONSE_ANOMALY", item.get("src_ip"), item.get("dst_ip"),
             item.get("reason"), "T1105")

    # Sort: entries with timestamps first, sorted ascending; timestampless at end
    events_with_ts = sorted(
        [e for e in events if e["timestamp"]],
        key=lambda x: x["timestamp"],
    )
    events_without_ts = [e for e in events if not e["timestamp"]]
    return events_with_ts + events_without_ts


# ---------------------------------------------------------------------------
# Passive DNS map
# ---------------------------------------------------------------------------

def build_dns_resolution_map(dns_rows: list[dict]) -> list[dict]:
    """Return deduplicated domain→IP resolution rows for dns_resolutions.csv."""
    seen: set[tuple] = set()
    results = []
    for row in dns_rows:
        qname = (row.get("dns.qry.name", "") or "").strip().lower().rstrip(".")
        resolved = (row.get("dns.a", "") or "").strip()
        cname = (row.get("dns.cname", "") or "").strip()
        ttl = (row.get("dns.resp.ttl", "") or "").strip()
        ts = row.get("frame.time", "")
        src = row.get("ip.src", "")
        dst = row.get("ip.dst", "")

        if resolved:
            key = (qname, resolved)
            if key not in seen:
                seen.add(key)
                results.append({
                    "timestamp": ts,
                    "src_ip": src,
                    "dns_server": dst,
                    "qname": qname,
                    "resolved_ip": resolved,
                    "cname": cname,
                    "ttl": ttl,
                })
        elif cname:
            key = (qname, cname)
            if key not in seen:
                seen.add(key)
                results.append({
                    "timestamp": ts,
                    "src_ip": src,
                    "dns_server": dst,
                    "qname": qname,
                    "resolved_ip": "",
                    "cname": cname,
                    "ttl": ttl,
                })
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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
    parser.add_argument(
        "--severity-filter",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="HIGH",
        help="Minimum severity level to display in terminal output (default: HIGH)",
    )
    parser.add_argument(
        "--output-format",
        choices=["csv", "html", "both"],
        default="csv",
        help="Output format: csv (default), html, or both",
    )
    parser.add_argument(
        "--geoip-db",
        help="Path to a GeoLite2-ASN.mmdb or GeoLite2-City.mmdb file for IP enrichment",
    )
    parser.add_argument(
        "--yara-rules",
        help="Path to a YARA rules file (.yar) or directory of rules to scan carved files and payloads",
    )
    parser.add_argument(
        "--jarm-probe",
        action="store_true",
        help="Actively probe observed TLS servers with JARM fingerprinting (requires outbound connectivity)",
    )
    parser.add_argument(
        "--min-ioc-confidence",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="LOW",
        help="Drop IOCs below this confidence from iocs.csv and the STIX bundle "
             "(default: LOW = keep all). MEDIUM removes low-value flow-only IPs, "
             "user-agents, and JA4S; HIGH keeps only corroborated indicators.",
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    case_output_dir = get_case_output_dir(OUTPUT_DIR, args.case)

    print("=" * 70)
    print("PCAP SECURITY TOOLKIT v2.3.0")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Packet-level analysis — two streaming passes to avoid loading into RAM
    # ------------------------------------------------------------------
    print(f"[*] Loading and analyzing flows + DNS/HTTP from {pcap_path}")
    with PcapReader(str(pcap_path)) as reader:
        combined = analyze_packets(reader)
    flow_data = combined["flow"]
    protocol_data = combined["protocol"]

    # ------------------------------------------------------------------
    # Initialize result containers
    # ------------------------------------------------------------------
    http_rows = []
    http_response_rows = []
    dns_rows = []
    smb_rows = []
    ftp_rows = []
    smtp_rows = []
    kerberos_rows = []
    tcp_stream_rows = []
    stream_ids = []
    tls_rows = []
    tls_summary = []
    http_body_previews = []
    extracted_payloads = []
    carved_files = []

    beaconing_candidates = detect_beaconing(flow_data["flow_times"], flow_data["flow_bytes"])
    credential_findings = []
    credential_posts = []
    suspicious_downloads = []
    entropy_exfil_candidates = []
    tls_sni_anomalies = []
    dns_tunneling_candidates = []
    suspicious_user_agents = []
    lateral_movement_candidates = []
    protocol_anomaly_findings = []
    malicious_ja3_findings = []
    malicious_ja4_findings = []
    ja4h_rows = []
    http_response_anomalies = []
    icmp_rows = []
    arp_rows = []
    syn_rows = []
    icmp_candidates = []
    arp_anomalies = []
    os_fingerprints = []
    smtp_attachments_list = []
    yara_hits = []
    jarm_results = []
    protocol_hierarchy_rows = []
    expert_info_rows = []
    credential_tap_rows = []
    stream_stats_rows = []
    stream_triage_rows = []

    # ------------------------------------------------------------------
    # TShark-assisted extraction
    # ------------------------------------------------------------------
    if has_tshark():
        # Each extractor is an independent full-file TShark pass. They share no
        # state, so we run them concurrently — on large captures this turns a
        # dozen serial reads into a handful of parallel ones.
        # Warm the field-capability cache once (in the main thread) so the
        # parallel workers below all hit the cache instead of each running
        # `tshark -G fields`.
        get_available_fields()

        print(f"[*] Running TShark extraction ({TSHARK_MAX_WORKERS} parallel workers)")
        extractors = {
            "http":         extract_http_fields,
            "http_resp":    extract_http_response_fields,
            "dns":          extract_dns_fields,
            "smb":          extract_smb_fields,
            "ftp":          extract_ftp_fields,
            "smtp":         extract_smtp_fields,
            "kerberos":     extract_kerberos_fields,
            "icmp":         extract_icmp_fields,
            "arp":          extract_arp_fields,
            "syn":          extract_tcp_syn_fields,
            "stream_index": extract_tcp_stream_index,
            "stream_stats": extract_tcp_stream_stats,
            "tls":          extract_tls_metadata,
        }
        extraction_results: dict = {}
        with ThreadPoolExecutor(max_workers=TSHARK_MAX_WORKERS) as executor:
            future_to_name = {
                executor.submit(fn, pcap_path): name for name, fn in extractors.items()
            }
            # Statistics taps run in the same pool but return (rows, raw, err).
            phs_future = executor.submit(run_protocol_hierarchy, pcap_path)
            expert_future = executor.submit(run_expert_info, pcap_path)
            cred_future = executor.submit(run_credentials, pcap_path)
            for future in as_completed(future_to_name):
                extraction_results[future_to_name[future]] = future.result()
            protocol_hierarchy_rows, phs_raw, phs_err = phs_future.result()
            expert_info_rows, expert_raw, expert_err = expert_future.result()
            credential_tap_rows, cred_raw, cred_err = cred_future.result()

        http_rows, http_err = extraction_results["http"]
        http_response_rows, http_resp_err = extraction_results["http_resp"]
        dns_rows, dns_err = extraction_results["dns"]
        smb_rows, smb_err = extraction_results["smb"]
        ftp_rows, ftp_err = extraction_results["ftp"]
        smtp_rows, smtp_err = extraction_results["smtp"]
        kerberos_rows, kerb_err = extraction_results["kerberos"]
        icmp_rows, icmp_err = extraction_results["icmp"]
        arp_rows, arp_err = extraction_results["arp"]
        syn_rows, syn_err = extraction_results["syn"]
        tcp_stream_rows, stream_err = extraction_results["stream_index"]
        stream_stats_rows, stream_stats_err = extraction_results["stream_stats"]
        tls_rows, tls_err = extraction_results["tls"]

        for label, err in [
            ("HTTP request", http_err),
            ("HTTP response", http_resp_err),
            ("DNS", dns_err),
            ("SMB", smb_err),
            ("FTP", ftp_err),
            ("SMTP/IMAP", smtp_err),
            ("Kerberos", kerb_err),
            ("ICMP", icmp_err),
            ("ARP", arp_err),
            ("TCP SYN", syn_err),
            ("TCP stream index", stream_err),
            ("TCP stream stats", stream_stats_err),
            ("TLS metadata", tls_err),
            ("Protocol hierarchy", phs_err),
            ("Expert Info", expert_err),
            ("Credentials", cred_err),
        ]:
            if err:
                print(f"[!] {label} TShark extraction warning: {err}")

        # Preserve the raw statistics output as case artifacts.
        if phs_raw:
            (case_output_dir / "protocol_hierarchy_raw.txt").write_text(
                phs_raw, encoding="utf-8", errors="replace"
            )
        if expert_raw:
            (case_output_dir / "expert_info_raw.txt").write_text(
                expert_raw, encoding="utf-8", errors="replace"
            )
        if cred_raw:
            (case_output_dir / "credentials_raw.txt").write_text(
                cred_raw, encoding="utf-8", errors="replace"
            )

        if tcp_stream_rows:
            stream_ids = get_unique_tcp_stream_ids(tcp_stream_rows)

        if tls_rows:
            tls_summary = summarize_tls_rows(tls_rows)

        if http_rows:
            print("[*] Building HTTP body previews")
            http_body_previews = build_http_body_previews(http_rows)

        # Stream export and payload extraction
        if args.export_streams and stream_ids:
            streams_dir = case_output_dir / "streams"
            streams_dir.mkdir(parents=True, exist_ok=True)

            export_stream_ids = stream_ids[: args.max_streams]
            print(
                f"[*] Exporting up to {len(export_stream_ids)} TCP streams "
                f"(ascii + raw, {TSHARK_MAX_WORKERS} parallel workers)"
            )

            # Each follow is its own full-file pass; run them concurrently and
            # write the results out afterward in deterministic order.
            follow_tasks = [
                (sid, mode) for sid in export_stream_ids for mode in ("ascii", "raw")
            ]
            follow_results: dict = {}
            with ThreadPoolExecutor(max_workers=TSHARK_MAX_WORKERS) as executor:
                future_to_task = {
                    executor.submit(export_follow_stream, pcap_path, sid, mode): (sid, mode)
                    for sid, mode in follow_tasks
                }
                for future in as_completed(future_to_task):
                    follow_results[future_to_task[future]] = future.result()

            for stream_id in export_stream_ids:
                ascii_content, ascii_err = follow_results.get(
                    (stream_id, "ascii"), (None, "no result")
                )
                if ascii_content is not None:
                    (streams_dir / f"tcp_stream_{stream_id}.ascii.txt").write_text(
                        ascii_content, encoding="utf-8", errors="replace"
                    )
                else:
                    print(f"[!] Failed to export tcp.stream {stream_id} ascii: {ascii_err}")

                raw_content, raw_err = follow_results.get(
                    (stream_id, "raw"), (None, "no result")
                )
                if raw_content is not None:
                    (streams_dir / f"tcp_stream_{stream_id}.raw.txt").write_text(
                        raw_content, encoding="utf-8", errors="replace"
                    )
                else:
                    print(f"[!] Failed to export tcp.stream {stream_id} raw: {raw_err}")

            print("[*] Detecting and extracting payloads using ascii + raw streams")
            extracted_payloads = save_extracted_payloads(
                case_output_dir, streams_dir, tcp_stream_rows
            )

            print("[*] Carving files from raw TCP streams")
            carved_files = carve_files_from_raw_streams(
                case_output_dir, streams_dir, tcp_stream_rows
            )

            print("[*] Computing JA4H HTTP fingerprints from streams")
            ja4h_rows = compute_ja4h_rows(streams_dir, tcp_stream_rows)

            print("[*] Extracting SMTP attachments from streams")
            smtp_attachments_list = extract_smtp_attachments(
                streams_dir, tcp_stream_rows, case_output_dir
            )

    else:
        print("[!] TShark not found — skipping TShark-assisted extraction.")

    # ------------------------------------------------------------------
    # Detections
    # ------------------------------------------------------------------
    print("[*] Extracting file indicators")
    file_indicators = extract_file_indicators(http_rows, smb_rows, ftp_rows)

    if http_body_previews or extracted_payloads:
        print("[*] Detecting credential indicators")
        credential_findings = find_credential_indicators(http_body_previews, extracted_payloads)

    if http_body_previews:
        print("[*] Reconstructing credential POSTs")
        credential_posts = reconstruct_credential_posts(http_body_previews)

    if http_rows or extracted_payloads:
        print("[*] Detecting suspicious downloads")
        suspicious_downloads = build_suspicious_downloads(http_rows, extracted_payloads)

    if extracted_payloads:
        print("[*] Detecting entropy-based exfil candidates")
        entropy_exfil_candidates = detect_entropy_exfil_candidates(extracted_payloads)

    if tls_summary:
        print("[*] Enriching TLS metadata with JA4 fingerprints")
        enrich_tls_summary_with_ja4(tls_summary, pcap_path)
        print("[*] Detecting TLS SNI anomalies")
        tls_sni_anomalies = detect_tls_sni_anomalies(tls_summary)
        print("[*] Detecting malicious JA3/JA4 fingerprints")
        malicious_ja3_findings = detect_malicious_ja3(tls_summary)
        malicious_ja4_findings = detect_malicious_ja4(tls_summary)

    if dns_rows:
        print("[*] Detecting DNS tunneling candidates")
        dns_tunneling_candidates = detect_dns_tunneling(dns_rows)

    if http_rows:
        print("[*] Detecting suspicious user agents")
        suspicious_user_agents = detect_suspicious_user_agents(http_rows)

    print("[*] Detecting lateral movement candidates")
    lateral_movement_candidates = detect_lateral_movement(
        flow_data["flow_bytes"], flow_data["flow_times"]
    )

    print("[*] Detecting protocol anomalies")
    protocol_anomaly_findings = detect_protocol_anomalies(
        http_rows, tls_summary, ftp_rows, smtp_rows, kerberos_rows
    )

    if http_response_rows:
        print("[*] Detecting HTTP response anomalies")
        http_response_anomalies = detect_http_response_anomalies(http_response_rows)

    if icmp_rows:
        print("[*] Detecting ICMP tunneling candidates")
        icmp_candidates = detect_icmp_tunneling(icmp_rows)

    if arp_rows:
        print("[*] Detecting ARP spoofing")
        arp_anomalies = detect_arp_spoofing(arp_rows)

    if syn_rows:
        print("[*] Passive OS fingerprinting")
        os_fingerprints = fingerprint_hosts(syn_rows)

    if args.yara_rules:
        yara_rules_compiled = load_rules(args.yara_rules)
        if yara_rules_compiled:
            print("[*] Running YARA scanning")
            yara_targets = carved_files + extracted_payloads + smtp_attachments_list
            yara_hits = scan_files(yara_rules_compiled, yara_targets)
        elif not yara_available():
            print("[!] YARA scanning requires: pip install yara-python")
        else:
            print(f"[!] Could not load YARA rules from: {args.yara_rules}")

    if args.jarm_probe and tls_summary:
        print("[*] Running JARM fingerprinting (active probing)")
        jarm_results = probe_observed_servers(tls_summary)

    if stream_stats_rows:
        print("[*] Scoring TCP streams for triage")
        stream_triage_rows = score_streams(
            stream_stats_rows,
            extracted_payloads=extracted_payloads,
            carved_files=carved_files,
            credential_findings=credential_findings,
        )

    # ------------------------------------------------------------------
    # GeoIP enrichment (optional)
    # ------------------------------------------------------------------
    geoip_map: dict = {}
    enricher = GeoIPEnricher(db_path=args.geoip_db)
    if enricher.available:
        print("[*] Running GeoIP enrichment")
        external_ips = [
            ip for flow_key in flow_data["flow_bytes"]
            for ip in (flow_key[0], flow_key[1])
            if ip and not is_noise_ip(ip)
        ]
        geoip_map = enrich_ips(list(set(external_ips)), enricher)
        enricher.close()
    else:
        if args.geoip_db:
            print("[!] GeoIP db specified but could not be loaded — skipping enrichment.")

    # ------------------------------------------------------------------
    # Build alerts
    # ------------------------------------------------------------------
    print("[*] Building alerts")
    alerts = build_alerts(
        flow_data["flow_bytes"],
        file_indicators,
        http_body_previews=http_body_previews,
        tls_summary=tls_summary,
        beaconing_candidates=beaconing_candidates,
        credential_findings=credential_findings,
        suspicious_downloads=suspicious_downloads,
        entropy_exfil_candidates=entropy_exfil_candidates,
        credential_posts=credential_posts,
        tls_sni_anomalies=tls_sni_anomalies,
        dns_tunneling_candidates=dns_tunneling_candidates,
        suspicious_user_agents=suspicious_user_agents,
        lateral_movement_candidates=lateral_movement_candidates,
        protocol_anomalies=protocol_anomaly_findings,
        malicious_ja3_findings=malicious_ja3_findings,
        malicious_ja4_findings=malicious_ja4_findings,
        icmp_candidates=icmp_candidates,
        arp_anomalies=arp_anomalies,
        jarm_results=jarm_results,
        yara_hits=yara_hits,
        kerberos_rows=kerberos_rows,
        http_response_anomalies=http_response_anomalies,
        expert_info_items=expert_info_rows,
        credential_tap_items=credential_tap_rows,
    )

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------
    print("[*] Extracting IOCs")
    iocs = extract_iocs(
        flow_bytes=flow_data["flow_bytes"],
        dns_rows=dns_rows,
        tls_summary=tls_summary,
        http_rows=http_rows,
        extracted_payloads=extracted_payloads,
        carved_files=carved_files,
        alerts=alerts,
        geoip_map=geoip_map,
        ja4h_rows=ja4h_rows,
        smtp_attachments=smtp_attachments_list,
    )

    if args.min_ioc_confidence != "LOW":
        _conf_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        threshold = _conf_order[args.min_ioc_confidence]
        before = len(iocs)
        iocs = [
            i for i in iocs
            if _conf_order.get(i.get("confidence", "LOW"), 0) >= threshold
        ]
        print(
            f"[*] IOC confidence filter ({args.min_ioc_confidence}+): "
            f"kept {len(iocs)} of {before}"
        )

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------
    print("[*] Building timeline")
    timeline = build_timeline(
        dns_tunneling_candidates=dns_tunneling_candidates,
        credential_findings=credential_findings,
        suspicious_downloads=suspicious_downloads,
        beaconing_candidates=beaconing_candidates,
        http_body_previews=http_body_previews,
        tls_sni_anomalies=tls_sni_anomalies,
        suspicious_user_agents=suspicious_user_agents,
        lateral_movement_candidates=lateral_movement_candidates,
        malicious_ja3_findings=malicious_ja3_findings,
        credential_posts=credential_posts,
        file_indicators=file_indicators,
        http_response_anomalies=http_response_anomalies,
        flow_times=flow_data["flow_times"],
    )

    # ------------------------------------------------------------------
    # DNS resolution map
    # ------------------------------------------------------------------
    dns_resolutions = build_dns_resolution_map(dns_rows)

    # ------------------------------------------------------------------
    # Build report dict
    # ------------------------------------------------------------------
    report = {
        "summary": flow_data["summary"],
        "top_protocols": flow_data["protocol_counter"].most_common(args.top),
        "top_ips": flow_data["ip_counter"].most_common(args.top),
        "top_conversations": flow_data["conversation_counter"].most_common(args.top),
        "top_dns_queries": protocol_data["dns_queries"].most_common(args.top),
        "top_http_hosts": protocol_data["http_hosts"].most_common(args.top),
        "top_http_user_agents": protocol_data["http_user_agents"].most_common(args.top),
        "tcp_stream_count": len(stream_ids),
        "http_body_preview_count": len(http_body_previews),
        "tls_metadata_count": len(tls_summary),
        "file_indicators_count": len(file_indicators),
        "extracted_payload_count": len(extracted_payloads),
        "credential_finding_count": len(credential_findings),
        "credential_post_count": len(credential_posts),
        "suspicious_download_count": len(suspicious_downloads),
        "entropy_exfil_candidate_count": len(entropy_exfil_candidates),
        "beaconing_candidate_count": len(beaconing_candidates),
        "tls_sni_anomaly_count": len(tls_sni_anomalies),
        "dns_tunneling_count": len(dns_tunneling_candidates),
        "suspicious_ua_count": len(suspicious_user_agents),
        "lateral_movement_count": len(lateral_movement_candidates),
        "protocol_anomaly_count": len(protocol_anomaly_findings),
        "malicious_ja3_count": len(malicious_ja3_findings),
        "malicious_ja4_count": len(malicious_ja4_findings),
        "ja4h_count": len(ja4h_rows),
        "icmp_tunneling_count": len(icmp_candidates),
        "arp_anomaly_count": len(arp_anomalies),
        "os_fingerprint_count": len(os_fingerprints),
        "smtp_attachment_count": len(smtp_attachments_list),
        "yara_hit_count": len(yara_hits),
        "jarm_count": len(jarm_results),
        "protocol_hierarchy_count": len(protocol_hierarchy_rows),
        "expert_info_count": len(expert_info_rows),
        "expert_error_count": sum(
            1 for r in expert_info_rows if r.get("severity") == "Error"
        ),
        "cleartext_credential_count": len(credential_tap_rows),
        "stream_triage_count": len(stream_triage_rows),
        "top_stream_suspicion_score": (
            stream_triage_rows[0]["suspicion_score"] if stream_triage_rows else 0
        ),
        "http_response_anomaly_count": len(http_response_anomalies),
        "carved_file_count": len(carved_files),
        "ioc_count": len(iocs),
        "alerts_count": len(alerts),
        "case_output_dir": str(case_output_dir),
        "geoip_enabled": enricher.available,
    }

    # ------------------------------------------------------------------
    # Write output files
    # ------------------------------------------------------------------
    print("[*] Writing output files")
    write_json(case_output_dir / "report.json", report)
    write_csv(case_output_dir / "http_requests.csv", protocol_data["notable_http"])
    write_csv(case_output_dir / "http_tshark.csv", http_rows)
    write_csv(case_output_dir / "http_responses.csv", http_response_rows)
    write_csv(case_output_dir / "http_body_previews.csv", http_body_previews)
    write_csv(case_output_dir / "tcp_stream_index.csv", tcp_stream_rows)
    write_csv(case_output_dir / "tls_metadata.csv", tls_summary)
    write_csv(case_output_dir / "tls_sni_anomalies.csv", tls_sni_anomalies)
    write_csv(case_output_dir / "malicious_ja3.csv", malicious_ja3_findings)
    write_csv(case_output_dir / "malicious_ja4.csv", malicious_ja4_findings)
    write_csv(case_output_dir / "ja4h.csv", ja4h_rows)
    write_csv(case_output_dir / "smb_tshark.csv", smb_rows)
    write_csv(case_output_dir / "ftp_tshark.csv", ftp_rows)
    write_csv(case_output_dir / "smtp_activity.csv", smtp_rows)
    write_csv(case_output_dir / "kerberos_activity.csv", kerberos_rows)
    write_csv(case_output_dir / "dns_resolutions.csv", dns_resolutions)
    write_csv(case_output_dir / "dns_tunneling_candidates.csv", dns_tunneling_candidates)
    write_csv(case_output_dir / "file_indicators.csv", file_indicators)
    write_csv(case_output_dir / "beaconing_candidates.csv", beaconing_candidates)
    write_csv(case_output_dir / "credential_findings.csv", credential_findings)
    write_csv(case_output_dir / "credential_posts.csv", credential_posts)
    write_csv(case_output_dir / "suspicious_downloads.csv", suspicious_downloads)
    write_csv(case_output_dir / "suspicious_user_agents.csv", suspicious_user_agents)
    write_csv(case_output_dir / "entropy_exfil_candidates.csv", entropy_exfil_candidates)
    write_csv(case_output_dir / "lateral_movement_candidates.csv", lateral_movement_candidates)
    write_csv(case_output_dir / "protocol_anomalies.csv", protocol_anomaly_findings)
    write_csv(case_output_dir / "http_response_anomalies.csv", http_response_anomalies)
    write_csv(case_output_dir / "icmp_tunneling_candidates.csv", icmp_candidates)
    write_csv(case_output_dir / "arp_anomalies.csv", arp_anomalies)
    write_csv(case_output_dir / "os_fingerprints.csv", os_fingerprints)
    write_csv(case_output_dir / "smtp_attachments.csv", smtp_attachments_list)
    write_csv(case_output_dir / "yara_hits.csv", yara_hits)
    write_csv(case_output_dir / "jarm_fingerprints.csv", jarm_results)
    write_csv(case_output_dir / "protocol_hierarchy.csv", protocol_hierarchy_rows)
    write_csv(case_output_dir / "expert_info.csv", expert_info_rows)
    write_csv(case_output_dir / "credentials_tshark.csv", credential_tap_rows)
    write_csv(case_output_dir / "stream_triage.csv", stream_triage_rows)
    write_csv(case_output_dir / "carved_files.csv", carved_files)
    write_csv(case_output_dir / "iocs.csv", iocs)

    print("[*] Exporting STIX 2.1 IOC bundle")
    stix_bundle = export_stix_bundle(iocs, case_name=args.case or "")
    (case_output_dir / "iocs.stix2.json").write_text(stix_bundle, encoding="utf-8")
    write_csv(case_output_dir / "timeline.csv", timeline)
    write_csv(case_output_dir / "alerts.csv", alerts)
    write_extracted_payload_index(
        case_output_dir / "extracted_payloads_index.csv",
        extracted_payloads,
    )

    # Excel workbook — consolidates all non-empty CSVs into one file
    print("[*] Building Excel workbook")
    wb_path = build_excel_workbook(case_output_dir)
    if wb_path:
        print(f"[+] Excel workbook: {wb_path}")
    else:
        print("[!] Excel workbook skipped — install openpyxl: pip install openpyxl")

    # Optional HTML report
    if args.output_format in {"html", "both"}:
        print("[*] Generating HTML report")
        html_content = generate_html_report(
            report=report,
            alerts=alerts,
            pcap_name=pcap_path.name,
            case_output_dir=str(case_output_dir),
            top_protocols=report["top_protocols"],
            top_ips=report["top_ips"],
            top_conversations=report["top_conversations"],
            top_dns=report["top_dns_queries"],
            top_hosts=report["top_http_hosts"],
            iocs=iocs,
            timeline=timeline,
        )
        html_path = case_output_dir / "report.html"
        html_path.write_text(html_content, encoding="utf-8")
        print(f"[+] HTML report: {html_path}")

    print_report_summary(report, alerts, args.severity_filter)
    print(f"\n[+] Results written to: {case_output_dir}")


if __name__ == "__main__":
    main()
