from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

DEFAULT_TOP_N = 10
DEFAULT_LARGE_FLOW_BYTES = 1_000_000
DEFAULT_CASE_PREFIX = "case"