def truncate_text(value, limit=500):
    if value is None:
        return ""
    value = str(value)
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def extract_file_indicators(http_rows, smb_rows, ftp_rows):
    results = []

    for row in http_rows:
        uri = row.get("http.request.uri", "") or ""
        disposition = row.get("http.content_disposition", "") or ""
        filename = None

        if "/" in uri:
            candidate = uri.rstrip("/").split("/")[-1]
            if "." in candidate and len(candidate) < 260:
                filename = candidate

        if disposition and "filename=" in disposition.lower():
            filename = disposition

        if filename:
            results.append({
                "timestamp": row.get("frame.time", ""),
                "src_ip": row.get("ip.src", ""),
                "dst_ip": row.get("ip.dst", ""),
                "tcp_stream": row.get("tcp.stream", ""),
                "protocol": "HTTP",
                "filename": filename,
                "source_field": "http.request.uri/http.content_disposition",
                "context": uri,
            })

    for row in smb_rows:
        smb_file = row.get("smb.file", "") or row.get("smb.path", "")
        if smb_file:
            results.append({
                "timestamp": row.get("frame.time", ""),
                "src_ip": row.get("ip.src", ""),
                "dst_ip": row.get("ip.dst", ""),
                "tcp_stream": row.get("tcp.stream", ""),
                "protocol": "SMB",
                "filename": smb_file,
                "source_field": "smb.file/smb.path",
                "context": smb_file,
            })

    for row in ftp_rows:
        command = row.get("ftp.request.command", "")
        arg = row.get("ftp.request.arg", "")
        if command in {"RETR", "STOR"} and arg:
            results.append({
                "timestamp": row.get("frame.time", ""),
                "src_ip": row.get("ip.src", ""),
                "dst_ip": row.get("ip.dst", ""),
                "tcp_stream": row.get("tcp.stream", ""),
                "protocol": "FTP",
                "filename": arg,
                "source_field": "ftp.request.arg",
                "context": f"{command} {arg}",
            })

    return results


def build_http_body_previews(http_rows, preview_limit=500):
    previews = []

    for row in http_rows:
        file_data = row.get("http.file_data", "") or ""
        if not file_data:
            continue

        previews.append({
            "frame_number": row.get("frame.number", ""),
            "timestamp": row.get("frame.time", ""),
            "src_ip": row.get("ip.src", ""),
            "src_port": row.get("tcp.srcport", ""),
            "dst_ip": row.get("ip.dst", ""),
            "dst_port": row.get("tcp.dstport", ""),
            "tcp_stream": row.get("tcp.stream", ""),
            "http_method": row.get("http.request.method", ""),
            "host": row.get("http.host", ""),
            "uri": row.get("http.request.uri", ""),
            "content_type": row.get("http.content_type", ""),
            "content_length": row.get("http.content_length", ""),
            "body_preview": truncate_text(file_data, preview_limit),
        })

    return previews