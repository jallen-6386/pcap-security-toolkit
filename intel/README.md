# Threat-intelligence feeds

Drop fingerprint feed files in this directory to extend the built-in
known-malicious JA3/JA4/JARM tables. Files are loaded automatically at the
start of every run (or point at another directory with `--intel-dir`).

JA3/JA4/JARM fingerprints go stale quickly, so keeping these feeds current
from an authoritative source is more reliable than a hardcoded list.

## File naming (case-insensitive prefix)

| Prefix | Loaded as |
|--------|-----------|
| `ja3*.csv` | JA3 fingerprints |
| `ja4*.csv` | JA4 fingerprints |
| `jarm*.csv` | JARM fingerprints |

## Row formats

Lines starting with `#` are ignored. Each data row may be:

- **abuse.ch format** — `<hash>,<first_seen>,<last_seen>,<reason>`
  (the reason column becomes the label)
- **simple** — `<fingerprint>,<label>[,<source>]`
- **bare** — `<fingerprint>` (label defaults to "threat-intel feed")

Existing built-in entries are never overwritten by a feed.

## Recommended sources

- abuse.ch SSLBL JA3 fingerprints: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
- FoxIO JA4 database: https://github.com/FoxIO-LLC/ja4/blob/main/database/ja4db.csv

Download the CSV, name it with the matching prefix (e.g. `ja3_sslbl.csv`),
and place it here.

See `sample_feed.csv.example` for the format.
