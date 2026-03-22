import os
import shutil


def find_tshark() -> str | None:
    tshark = shutil.which("tshark")
    if tshark:
        return tshark

    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    return None


def has_tshark() -> bool:
    return find_tshark() is not None