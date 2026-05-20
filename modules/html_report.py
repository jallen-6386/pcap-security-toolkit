"""
Self-contained HTML report generator. No external dependencies — pure Python
string rendering. The output is a single .html file suitable for emailing
to leadership or attaching to a case ticket.
"""

import html
from datetime import datetime


_SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "INFO":     "#7f8c8d",
}

_SEVERITY_BG = {
    "CRITICAL": "#fde8e8",
    "HIGH":     "#fef0e6",
    "MEDIUM":   "#fefde6",
    "LOW":      "#eafaf1",
    "INFO":     "#f2f3f4",
}


def _esc(value) -> str:
    return html.escape(str(value or ""))


def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#7f8c8d")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.82em;font-weight:bold;">'
        f"{_esc(severity)}</span>"
    )


def _table(rows: list[dict], max_rows: int = 200) -> str:
    if not rows:
        return "<p style='color:#888;font-style:italic;'>No data.</p>"
    cols = list(rows[0].keys())
    header = "".join(f"<th>{_esc(c)}</th>" for c in cols)
    body_rows = []
    for row in rows[:max_rows]:
        cells = "".join(f"<td>{_esc(row.get(c,''))}</td>" for c in cols)
        body_rows.append(f"<tr>{cells}</tr>")
    overflow = ""
    if len(rows) > max_rows:
        overflow = (
            f"<p style='color:#888;font-size:0.9em;'>"
            f"Showing first {max_rows} of {len(rows)} rows. See CSV for full data.</p>"
        )
    return (
        "<div style='overflow-x:auto;'>"
        "<table>"
        f"<thead><tr>{header}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        "</table>"
        "</div>"
        + overflow
    )


def _alerts_table(alerts: list[dict], max_rows: int = 100) -> str:
    if not alerts:
        return "<p style='color:#888;font-style:italic;'>No alerts.</p>"
    rows_html = []
    for alert in alerts[:max_rows]:
        sev = alert.get("severity", "INFO")
        bg = _SEVERITY_BG.get(sev, "#fff")
        badge = _severity_badge(sev)
        technique = _esc(alert.get("mitre_technique_id", ""))
        tactic = _esc(alert.get("mitre_tactic", ""))
        mitre_cell = f"{technique} — {tactic}" if technique else ""
        rows_html.append(
            f'<tr style="background:{bg};">'
            f"<td>{badge}</td>"
            f"<td>{_esc(alert.get('alert_type',''))}</td>"
            f"<td>{_esc(alert.get('src_ip',''))}</td>"
            f"<td>{_esc(alert.get('dst_ip',''))}</td>"
            f"<td>{mitre_cell}</td>"
            f"<td>{_esc(alert.get('reason',''))}</td>"
            f"</tr>"
        )
    overflow = ""
    if len(alerts) > max_rows:
        overflow = (
            f"<p style='color:#888;font-size:0.9em;'>"
            f"Showing top {max_rows} of {len(alerts)} alerts. See alerts.csv for full list.</p>"
        )
    return (
        "<div style='overflow-x:auto;'>"
        "<table>"
        "<thead><tr>"
        "<th>Severity</th><th>Type</th><th>Src IP</th>"
        "<th>Dst IP</th><th>MITRE</th><th>Reason</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows_html)}</tbody>"
        "</table>"
        "</div>"
        + overflow
    )


def _stat_card(label: str, value) -> str:
    return (
        f'<div style="display:inline-block;background:#f8f9fa;border:1px solid #dee2e6;'
        f'border-radius:6px;padding:12px 20px;margin:6px;min-width:130px;text-align:center;">'
        f'<div style="font-size:1.8em;font-weight:bold;color:#2c3e50;">{_esc(value)}</div>'
        f'<div style="font-size:0.85em;color:#666;margin-top:2px;">{_esc(label)}</div>'
        f"</div>"
    )


def _section(title: str, content: str, collapsed: bool = False) -> str:
    style = "display:none;" if collapsed else ""
    uid = title.replace(" ", "_").lower()
    return (
        f'<div style="margin-bottom:24px;">'
        f'<h2 style="background:#2c3e50;color:#fff;padding:8px 14px;border-radius:4px;'
        f'cursor:pointer;user-select:none;" '
        f'onclick="var e=document.getElementById(\'{uid}\');'
        f'e.style.display=e.style.display===\'none\'?\'block\':\'none\';">'
        f"{_esc(title)}</h2>"
        f'<div id="{uid}" style="{style}padding:4px 0;">{content}</div>'
        f"</div>"
    )


def generate_html_report(
    report: dict,
    alerts: list[dict],
    pcap_name: str,
    case_output_dir: str,
    top_protocols: list = None,
    top_ips: list = None,
    top_conversations: list = None,
    top_dns: list = None,
    top_hosts: list = None,
    iocs: list = None,
    timeline: list = None,
) -> str:
    top_protocols = top_protocols or []
    top_ips = top_ips or []
    top_conversations = top_conversations or []
    top_dns = top_dns or []
    top_hosts = top_hosts or []
    iocs = iocs or []
    timeline = timeline or []

    summary = report.get("summary", {})
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Severity breakdown
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for a in alerts:
        sev = a.get("severity", "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_html = "".join(
        f'<span style="margin-right:12px;">{_severity_badge(k)}'
        f' <strong>{v}</strong></span>'
        for k, v in sev_counts.items()
        if v > 0
    )

    # Stat cards
    stats_html = "".join([
        _stat_card("Total Packets", summary.get("total_packets", 0)),
        _stat_card("Total Size", summary.get("total_size_human", "N/A")),
        _stat_card("Unique IPs", summary.get("unique_ips", 0)),
        _stat_card("TCP Streams", report.get("tcp_stream_count", 0)),
        _stat_card("Alerts", report.get("alerts_count", 0)),
        _stat_card("Credential Hits", report.get("credential_finding_count", 0)),
        _stat_card("Exfil Candidates", report.get("entropy_exfil_candidate_count", 0)),
        _stat_card("Beaconing", report.get("beaconing_candidate_count", 0)),
        _stat_card("DNS Tunneling", report.get("dns_tunneling_count", 0)),
        _stat_card("JA3 Malicious", report.get("malicious_ja3_count", 0)),
        _stat_card("IOCs", len(iocs)),
    ])

    # Top lists
    def _kv_table(rows):
        if not rows:
            return "<p style='color:#888;font-style:italic;'>None.</p>"
        items = "".join(
            f"<tr><td>{_esc(k)}</td><td style='text-align:right;'><strong>{_esc(v)}</strong></td></tr>"
            for k, v in rows
        )
        return f"<table>{items}</table>"

    top_content = (
        "<div style='display:flex;flex-wrap:wrap;gap:20px;'>"
        f"<div><h3>Top Protocols</h3>{_kv_table(top_protocols)}</div>"
        f"<div><h3>Top IPs</h3>{_kv_table(top_ips[:10])}</div>"
        f"<div><h3>Top DNS Queries</h3>{_kv_table(top_dns[:10])}</div>"
        f"<div><h3>Top HTTP Hosts</h3>{_kv_table(top_hosts[:10])}</div>"
        "</div>"
    )

    # IOC summary
    ioc_type_counts: dict[str, int] = {}
    for ioc in iocs:
        t = ioc.get("ioc_type", "other")
        ioc_type_counts[t] = ioc_type_counts.get(t, 0) + 1
    ioc_summary = " | ".join(f"{t}: {c}" for t, c in sorted(ioc_type_counts.items()))

    body = f"""
    <div style="margin-bottom:16px;">
      <p><strong>PCAP File:</strong> {_esc(pcap_name)} &nbsp;|&nbsp;
         <strong>Case Output:</strong> {_esc(case_output_dir)} &nbsp;|&nbsp;
         <strong>Generated:</strong> {generated}</p>
      <div style="margin:10px 0;">{sev_html}</div>
      <div>{stats_html}</div>
    </div>

    {_section("Alerts", _alerts_table(alerts, max_rows=150))}

    {_section("Traffic Overview", top_content)}

    {_section("Timeline", _table(timeline, max_rows=200), collapsed=True)}

    {_section("IOCs", f"<p style='color:#555;font-size:0.9em;'>{_esc(ioc_summary)}</p>" + _table(iocs[:300], max_rows=300), collapsed=True)}
    """

    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           margin: 0; padding: 20px; background: #f5f6fa; color: #2c3e50; }
    h1   { color: #2c3e50; border-bottom: 3px solid #2c3e50; padding-bottom: 8px; }
    table { border-collapse: collapse; width: 100%; font-size: 0.87em; }
    th   { background: #2c3e50; color: #fff; padding: 6px 10px; text-align: left; white-space: nowrap; }
    td   { padding: 5px 10px; border-bottom: 1px solid #e0e0e0; word-break: break-all; }
    tr:hover td { background: #f0f4ff; }
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PCAP Security Toolkit Report — {_esc(pcap_name)}</title>
  <style>{css}</style>
</head>
<body>
  <h1>PCAP Security Toolkit Report</h1>
  {body}
</body>
</html>
"""
