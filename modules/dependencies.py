import os
import shutil
from functools import lru_cache


@lru_cache(maxsize=1)
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


@lru_cache(maxsize=1)
def find_editcap() -> str | None:
    editcap = shutil.which("editcap")
    if editcap:
        return editcap

    possible_paths = [
        r"C:\Program Files\Wireshark\editcap.exe",
        r"C:\Program Files (x86)\Wireshark\editcap.exe",
        "/opt/homebrew/bin/editcap",
        "/usr/local/bin/editcap",
        "/usr/bin/editcap",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    return None