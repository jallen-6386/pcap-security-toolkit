#!/usr/bin/env python3

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


def install_python_requirements():
    venv_python = get_venv_python()
    if not venv_python.exists():
        print("[!] Virtual environment Python not found.")
        return

    if not REQUIREMENTS_FILE.exists():
        print(f"[!] requirements.txt not found: {REQUIREMENTS_FILE}")
        return

    print("[*] Installing Python requirements...")
    subprocess.run([str(venv_python), "-m", "pip", "install", "--upgrade", "pip"], check=False)
    subprocess.run([str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)], check=False)
    print("[+] Python requirements installation finished.")


def install_tshark_mac():
    if not command_exists("brew"):
        print("[!] Homebrew is not installed.")
        print("    Install it from https://brew.sh")
        return

    print("[*] Installing Wireshark/TShark via Homebrew...")
    subprocess.run(["brew", "install", "wireshark"], check=False)
    print("[+] Installation attempt finished.")


def main():
    print("=" * 70)
    print("PCAP Security Toolkit Bootstrap")
    print("=" * 70)
    print(f"[*] Python: {sys.executable}")
    print(f"[*] Platform: {platform.system()} {platform.release()}")

    if not VENV_DIR.exists():
        if ask_yes_no("Virtual environment not found. Create it now?"):
            create_venv()
    else:
        print(f"[+] Virtual environment found: {VENV_DIR}")

    if ask_yes_no("Install or refresh Python requirements?"):
        install_python_requirements()

    if command_exists("tshark"):
        print("[+] TShark is installed.")
    else:
        print("[!] TShark is not installed.")
        if platform.system() == "Darwin":
            if ask_yes_no("Would you like to install TShark using Homebrew now?"):
                install_tshark_mac()
        else:
            print("[!] Auto-install is only included for macOS in this version.")

    print("\n[+] Bootstrap complete.")
    print("[*] To run the toolkit with the virtual environment:")
    print(f"    {get_venv_activate_command()}")
    print("    python analyzer.py /path/to/file.pcapng")
    print("\n[*] Or run it directly with the venv Python:")
    print(f"    {get_venv_python()} analyzer.py /path/to/file.pcapng")


if __name__ == "__main__":
    main()