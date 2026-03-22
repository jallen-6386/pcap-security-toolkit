#!/usr/bin/env python3

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
VENV_DIR = PROJECT_ROOT / ".venv"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"


def ask_yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} [y/n]: ").strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please enter y or n.")


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def create_venv():
    if VENV_DIR.exists():
        print(f"[+] Virtual environment already exists: {VENV_DIR}")
        return
    print("[*] Creating virtual environment...")
    subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    print("[+] Virtual environment created.")


def get_venv_python() -> Path:
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def get_venv_activate_command() -> str:
    if platform.system() == "Windows":
        return r".venv\Scripts\activate"
    return "source .venv/bin/activate"


def build_clean_env() -> dict:
    env = dict(os.environ)
    env.pop("PIP_USER", None)
    env.pop("PYTHONHOME", None)
    return env


def install_python_requirements():
    venv_python = get_venv_python()
    if not venv_python.exists():
        print("[!] Virtual environment Python not found.")
        return

    if not REQUIREMENTS_FILE.exists():
        print(f"[!] requirements.txt not found: {REQUIREMENTS_FILE}")
        return

    env = build_clean_env()

    print("[*] Installing Python requirements...")
    upgrade = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "--no-user"],
        check=False,
        env=env,
        text=True,
        capture_output=True,
    )
    if upgrade.stdout:
        print(upgrade.stdout, end="")
    if upgrade.stderr:
        print(upgrade.stderr, end="")

    install = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE), "--no-user"],
        check=False,
        env=env,
        text=True,
        capture_output=True,
    )
    if install.stdout:
        print(install.stdout, end="")
    if install.stderr:
        print(install.stderr, end="")

    if upgrade.returncode != 0 or install.returncode != 0:
        print("[!] Python requirements installation reported an issue.")
        print("[!] If you saw '--user' related errors, bootstrap already tried to bypass them.")
        print("[!] You can also run this manually:")
        print(f"    {get_venv_python()} -m pip install -r requirements.txt --no-user")
        return

    print("[+] Python requirements installation finished.")


def install_tshark_mac():
    if not command_exists("brew"):
        print("[!] Homebrew is not installed.")
        print("    Install it from https://brew.sh")
        return

    print("[*] Installing Wireshark/TShark via Homebrew...")
    subprocess.run(["brew", "install", "wireshark"], check=False)
    print("[+] Installation attempt finished.")


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


def main():
    print("=" * 70)
    print("PCAP Security Toolkit Bootstrap")
    print("=" * 70)
    print(f"[*] Python: {sys.executable}")
    print(f"[*] Platform: {platform.system()} {platform.release()}")

    if os.environ.get("PIP_USER"):
        print(f"[!] Detected PIP_USER={os.environ.get('PIP_USER')}")
        print("[!] Bootstrap will ignore this for installs inside the virtual environment.")

    if not VENV_DIR.exists():
        if ask_yes_no("Virtual environment not found. Create it now?"):
            create_venv()
    else:
        print(f"[+] Virtual environment found: {VENV_DIR}")

    if ask_yes_no("Install or refresh Python requirements?"):
        install_python_requirements()

    tshark_path = find_tshark()
    if tshark_path:
        print(f"[+] TShark is installed: {tshark_path}")
    else:
        print("[!] TShark is not installed or not detected.")
        if platform.system() == "Darwin":
            if ask_yes_no("Would you like to install TShark using Homebrew now?"):
                install_tshark_mac()
        elif platform.system() == "Windows":
            print(r"[*] Windows tip: if tshark.exe is already installed, this toolkit can auto-detect it")
            print(r"    in C:\Program Files\Wireshark\tshark.exe")
            print(r"    or C:\Program Files (x86)\Wireshark\tshark.exe")

    print("\n[+] Bootstrap complete.")
    print("[*] To run the toolkit with the virtual environment:")
    print(f"    {get_venv_activate_command()}")
    print("    python analyzer.py /path/to/file.pcapng")
    print("\n[*] Or run it directly with the venv Python:")
    print(f"    {get_venv_python()} analyzer.py /path/to/file.pcapng")


if __name__ == "__main__":
    main()