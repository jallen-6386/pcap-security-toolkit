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