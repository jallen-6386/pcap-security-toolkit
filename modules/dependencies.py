import shutil

def has_tshark() -> bool:
    return shutil.which("tshark") is not None