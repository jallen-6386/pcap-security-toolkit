import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

DEFAULT_TOP_N = 10
DEFAULT_LARGE_FLOW_BYTES = 1_000_000
DEFAULT_CASE_PREFIX = "case"

# Number of concurrent TShark subprocesses for independent extraction passes
# and TCP stream follow exports. Each pass reads the whole capture, so this is
# bounded by CPU cores; large captures benefit most from parallelism here.
TSHARK_MAX_WORKERS = min(8, (os.cpu_count() or 2))

# Capture-size thresholds (bytes) for scaling back TShark concurrency and
# bounding per-process memory. Running many TShark passes in parallel on a
# multi-gigabyte capture can exhaust RAM, so parallelism is reduced and, for
# huge files, dissector session state is reset periodically (-M).
LARGE_PCAP_BYTES = 250_000_000          # 250 MB  -> cap workers at 4
HUGE_PCAP_BYTES = 1_000_000_000         # 1 GB    -> cap workers at 2, enable -M
HUGE_PCAP_SESSION_RESET = 100_000       # -M packet count for huge captures