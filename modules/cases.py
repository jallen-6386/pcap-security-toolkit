from pathlib import Path
import re

def get_next_case_folder(base_output_dir: Path, prefix: str = "case") -> Path:
    base_output_dir.mkdir(parents=True, exist_ok=True)

    existing_numbers = []
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")

    for item in base_output_dir.iterdir():
        if item.is_dir():
            match = pattern.match(item.name)
            if match:
                existing_numbers.append(int(match.group(1)))

    next_number = max(existing_numbers, default=0) + 1
    return base_output_dir / f"{prefix}{next_number}"

def get_case_output_dir(base_output_dir: Path, case_name: str | None = None, prefix: str = "case") -> Path:
    if case_name:
        safe_name = case_name.strip().replace(" ", "_")
        case_dir = base_output_dir / safe_name
    else:
        case_dir = get_next_case_folder(base_output_dir, prefix)

    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir