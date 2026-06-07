"""
YARA rule scanning for carved files and extracted payloads.

Optional dependency: yara-python
    pip install yara-python

Pass --yara-rules <path> to a .yar file or a directory of .yar/.yara files.
"""
from pathlib import Path

try:
    import yara as _yara
    _HAS_YARA = True
except ImportError:
    _yara = None
    _HAS_YARA = False


def yara_available() -> bool:
    return _HAS_YARA


def load_rules(rules_path: str):
    """
    Compile YARA rules from a file or directory.
    Returns a compiled rules object, or None if unavailable or path is invalid.
    """
    if not _HAS_YARA:
        return None

    path = Path(rules_path)
    if not path.exists():
        return None

    try:
        if path.is_dir():
            filepaths = {}
            for rule_file in sorted(path.rglob("*.yar")) + sorted(path.rglob("*.yara")):
                filepaths[rule_file.stem] = str(rule_file)
            if not filepaths:
                return None
            return _yara.compile(filepaths=filepaths)
        else:
            return _yara.compile(filepath=str(path))
    except Exception as exc:
        # Surface compile errors (e.g. a malformed rule) instead of silently
        # disabling scanning, which previously hid a broken ruleset.
        print(f"[!] YARA rule compilation failed for {path}: {exc}")
        return None


def scan_files(rules, file_records: list[dict]) -> list[dict]:
    """
    Scan a list of file records against compiled YARA rules.

    file_records must contain either a 'file_path' or 'saved_path' key
    pointing to a file on disk. Silently skips missing files.

    Returns a list of hit dicts: file_path, sha256, rule_name, tags,
    matched_strings, severity.
    """
    if not _HAS_YARA or rules is None:
        return []

    hits: list[dict] = []
    seen: set[tuple] = set()

    for record in file_records:
        file_path = (record.get("file_path") or record.get("saved_path") or "").strip()
        if not file_path:
            continue

        path = Path(file_path)
        if not path.exists():
            continue

        try:
            matches = rules.match(str(path))
        except Exception:
            continue

        for match in matches:
            key = (file_path, match.rule)
            if key in seen:
                continue
            seen.add(key)

            hits.append({
                "file_path": file_path,
                "sha256": record.get("sha256", ""),
                "rule_name": match.rule,
                "rule_namespace": match.namespace,
                "rule_tags": ", ".join(match.tags) if match.tags else "",
                "matched_strings": ", ".join(
                    str(s.identifier) for s in (match.strings or [])[:10]
                ),
                "severity": _infer_severity(match),
            })

    return hits


def _infer_severity(match) -> str:
    meta = getattr(match, "meta", {}) or {}
    sev = str(meta.get("severity", "")).upper()
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return sev
    tags = {t.lower() for t in (match.tags or [])}
    if "critical" in tags:
        return "CRITICAL"
    if tags & {"high", "rat", "backdoor", "ransomware", "rootkit"}:
        return "HIGH"
    if tags & {"medium", "suspicious", "dropper", "loader"}:
        return "MEDIUM"
    return "LOW"
