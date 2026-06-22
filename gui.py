#!/usr/bin/env python3

"""
PCAP Security Toolkit — Desktop GUI
Version: 2.3.0

A minimalist desktop frontend that subprocesses analyzer.py.  The CLI
workflow is unchanged; this file is purely additive.
"""

import csv
import json
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
except ImportError:
    print("[!] Missing dependency: customtkinter")
    print("    pip install customtkinter")
    sys.exit(1)

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _HAS_DND = True
except ImportError:
    _HAS_DND = False


REPO_ROOT = Path(__file__).resolve().parent
ANALYZER_PATH = REPO_ROOT / "analyzer.py"


def resolve_analyzer_python() -> str:
    """
    Return the interpreter to run analyzer.py with.

    Prefer the project's virtualenv so the analyzer subprocess always has
    the toolkit's dependencies (scapy, etc.), regardless of which Python
    launched the GUI. Falls back to the current interpreter if no venv
    is present.
    """
    if platform.system() == "Windows":
        venv_python = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable

SEVERITY_COLORS = {
    "CRITICAL": "#E74C3C",
    "HIGH":     "#E67E22",
    "MEDIUM":   "#F1C40F",
    "LOW":      "#3498DB",
    "INFO":     "#95A5A6",
}

LOG_INFO_COLOR    = "#D0D0D0"
LOG_WARNING_COLOR = "#F1C40F"
LOG_ERROR_COLOR   = "#E74C3C"
LOG_SUCCESS_COLOR = "#2ECC71"
LOG_SECTION_COLOR = "#5DADE2"
LOG_BG_DARK       = "#1E1E1E"

MONO_FONT = "Menlo" if platform.system() == "Darwin" else "Consolas"


# ---------------------------------------------------------------------------
# Root window — adds drag-and-drop if tkinterdnd2 is available
# ---------------------------------------------------------------------------

if _HAS_DND:
    class _Root(TkinterDnD.DnDWrapper, ctk.CTk):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # tkinterdnd2 can import successfully but still fail to load its
            # native tkdnd library at runtime (e.g. a Tcl/Tk stubs mismatch on
            # some Python builds). Degrade to Browse-only instead of crashing.
            self.dnd_available = False
            try:
                self.TkdndVersion = TkinterDnD._require(self)
                self.dnd_available = True
            except Exception:
                self.dnd_available = False
else:
    class _Root(ctk.CTk):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.dnd_available = False


# ---------------------------------------------------------------------------
# OS file-manager helpers
# ---------------------------------------------------------------------------

def reveal_in_file_manager(path: Path):
    path = Path(path)
    if not path.exists():
        messagebox.showwarning("Not found", f"Path no longer exists:\n{path}")
        return
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["open", str(path)], check=False)
        elif system == "Windows":
            os.startfile(str(path))  # noqa: S606
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception as exc:
        messagebox.showerror("Open failed", str(exc))


def open_with_default(path: Path):
    path = Path(path)
    if not path.exists():
        messagebox.showwarning("Not found", f"File no longer exists:\n{path}")
        return
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["open", str(path)], check=False)
        elif system == "Windows":
            os.startfile(str(path))  # noqa: S606
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception as exc:
        messagebox.showerror("Open failed", str(exc))


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    m, s = divmod(seconds, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

class App(_Root):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self.title("PCAP Security Toolkit")
        self.geometry("860x980")
        self.minsize(760, 720)

        # State
        self.process = None
        self.run_thread = None
        self.start_time = None
        self.output_queue: queue.Queue = queue.Queue()
        self.case_output_dir: Path | None = None
        self.log_lines: list[tuple[str, str]] = []
        self.summary_built = False
        self.is_running = False
        self.theme_mode = "system"

        self._build_header()
        self._build_input_panel()
        self._build_output_panel()
        self._build_status_bar()

        if self.dnd_available:
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)

        self._set_idle_state()

        self.after(80, self._process_queue)
        self.after(500, self._update_timer)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(18, 6))

        title = ctk.CTkLabel(
            header,
            text="PCAP Security Toolkit",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        title.pack(side="left")

        subtitle_text = "v2.3.0"
        if not self.dnd_available:
            subtitle_text += "   (drag-and-drop unavailable — use Browse)"
        subtitle = ctk.CTkLabel(
            header,
            text=subtitle_text,
            font=ctk.CTkFont(size=11),
            text_color="#888888",
        )
        subtitle.pack(side="left", padx=(10, 0), pady=(8, 0))

        self.theme_button = ctk.CTkButton(
            header,
            text="Theme",
            width=70,
            command=self._toggle_theme,
        )
        self.theme_button.pack(side="right")

    def _build_input_panel(self):
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(fill="x", padx=20, pady=(8, 8))

        # PCAP file(s) — multiple captures are merged into one case
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=(15, 5))
        ctk.CTkLabel(row, text="PCAP file(s):", width=110, anchor="w").pack(side="left")
        self.pcap_var = tk.StringVar()
        self.selected_pcaps: list[str] = []
        self._pcap_summary = ""
        placeholder = (
            "Drop file(s) here or click Browse"
            if self.dnd_available else "Click Browse to select one or more .pcap/.pcapng"
        )
        self.pcap_entry = ctk.CTkEntry(row, textvariable=self.pcap_var, placeholder_text=placeholder)
        self.pcap_entry.pack(side="left", fill="x", expand=True, padx=(5, 5))
        ctk.CTkButton(row, text="Browse", width=90, command=self._browse_pcap).pack(side="left")

        # Case name
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text="Case name:", width=110, anchor="w").pack(side="left")
        self.case_var = tk.StringVar()
        ctk.CTkEntry(row, textvariable=self.case_var, placeholder_text="optional — used as the output folder name").pack(
            side="left", fill="x", expand=True, padx=(5, 5)
        )

        # Output format
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=(5, 10))
        ctk.CTkLabel(row, text="Output format:", width=110, anchor="w").pack(side="left")
        self.format_var = tk.StringVar(value="csv")
        ctk.CTkRadioButton(row, text="CSV + Excel",  variable=self.format_var, value="csv").pack(side="left", padx=(5, 15))
        ctk.CTkRadioButton(row, text="HTML",         variable=self.format_var, value="html").pack(side="left", padx=15)
        ctk.CTkRadioButton(row, text="Both",         variable=self.format_var, value="both").pack(side="left", padx=15)

        # Severity filter
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text="Severity filter:", width=110, anchor="w").pack(side="left")
        self.severity_var = tk.StringVar(value="HIGH")
        ctk.CTkOptionMenu(
            row,
            variable=self.severity_var,
            values=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            width=130,
        ).pack(side="left", padx=(5, 0))
        ctk.CTkLabel(
            row,
            text="(controls terminal display only — all alerts still saved to CSV)",
            font=ctk.CTkFont(size=11),
            text_color="#888888",
        ).pack(side="left", padx=10)

        # Minimum IOC confidence
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text="Min IOC conf:", width=110, anchor="w").pack(side="left")
        self.min_ioc_conf_var = tk.StringVar(value="LOW")
        ctk.CTkOptionMenu(
            row,
            variable=self.min_ioc_conf_var,
            values=["LOW", "MEDIUM", "HIGH"],
            width=130,
        ).pack(side="left", padx=(5, 0))
        ctk.CTkLabel(
            row,
            text="(LOW keeps all; MEDIUM drops flow-only IPs/UAs; HIGH only corroborated)",
            font=ctk.CTkFont(size=11),
            text_color="#888888",
        ).pack(side="left", padx=10)

        # Decode-as (force dissector on non-standard ports)
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text="Decode as:", width=110, anchor="w").pack(side="left")
        self.decode_as_var = tk.StringVar()
        ctk.CTkEntry(
            row,
            textvariable=self.decode_as_var,
            placeholder_text="e.g. tcp.port==8888,http  (space-separate multiple rules)",
        ).pack(side="left", fill="x", expand=True, padx=(5, 0))

        # Threat-intel feed directory (optional override; default is intel/)
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text="Intel dir:", width=110, anchor="w").pack(side="left")
        self.intel_dir_var = tk.StringVar()
        ctk.CTkEntry(
            row,
            textvariable=self.intel_dir_var,
            placeholder_text="JA3/JA4/JARM feed CSVs (blank = project intel/ folder)",
        ).pack(side="left", fill="x", expand=True, padx=(5, 5))
        ctk.CTkButton(row, text="Browse", width=90, command=self._browse_intel_dir).pack(side="left")

        # TLS key-log file (optional; decrypts HTTPS when secrets are available)
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(row, text="TLS keylog:", width=110, anchor="w").pack(side="left")
        self.tls_keylog_var = tk.StringVar()
        ctk.CTkEntry(
            row,
            textvariable=self.tls_keylog_var,
            placeholder_text="SSLKEYLOGFILE to decrypt TLS (optional)",
        ).pack(side="left", fill="x", expand=True, padx=(5, 5))
        ctk.CTkButton(row, text="Browse", width=90, command=self._browse_tls_keylog).pack(side="left")

        # Modules section header
        ctk.CTkLabel(
            self.input_frame,
            text="Analysis Modules",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        ).pack(fill="x", padx=15, pady=(15, 4))

        # Export streams
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=3)
        self.streams_var = tk.BooleanVar(value=True)
        ctk.CTkSwitch(
            row,
            text="Export TCP streams  (required for payload extraction, JA4H, SMTP attachments)",
            variable=self.streams_var,
        ).pack(side="left")
        ctk.CTkLabel(row, text="Max:").pack(side="left", padx=(20, 5))
        self.max_streams_var = tk.StringVar(value="25")
        ctk.CTkEntry(row, textvariable=self.max_streams_var, width=60).pack(side="left")

        # JARM probe
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=3)
        self.jarm_var = tk.BooleanVar(value=False)
        ctk.CTkSwitch(
            row,
            text="JARM active probing  (requires outbound connectivity to observed TLS servers)",
            variable=self.jarm_var,
        ).pack(side="left")

        # YARA
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=3)
        self.yara_var = tk.BooleanVar(value=False)
        ctk.CTkSwitch(row, text="YARA scan", variable=self.yara_var, width=120).pack(side="left")
        self.yara_path_var = tk.StringVar(value=str(REPO_ROOT / "rules"))
        ctk.CTkEntry(
            row, textvariable=self.yara_path_var, placeholder_text="Rules file or directory"
        ).pack(side="left", fill="x", expand=True, padx=(15, 5))
        ctk.CTkButton(row, text="Browse", width=90, command=self._browse_yara).pack(side="left")

        # GeoIP
        row = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=3)
        self.geoip_var = tk.BooleanVar(value=False)
        ctk.CTkSwitch(row, text="GeoIP enrich", variable=self.geoip_var, width=120).pack(side="left")
        self.geoip_path_var = tk.StringVar()
        ctk.CTkEntry(
            row, textvariable=self.geoip_path_var, placeholder_text="GeoLite2 .mmdb file"
        ).pack(side="left", fill="x", expand=True, padx=(15, 5))
        ctk.CTkButton(row, text="Browse", width=90, command=self._browse_geoip).pack(side="left")

        # Run button
        self.run_button = ctk.CTkButton(
            self.input_frame,
            text="▶   RUN ANALYSIS",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=52,
            command=self._on_run,
        )
        self.run_button.pack(fill="x", padx=15, pady=(15, 15))

    def _build_output_panel(self):
        self.output_frame = ctk.CTkFrame(self)
        self.output_frame.pack(fill="both", expand=True, padx=20, pady=(8, 8))

        self.view_toggle = ctk.CTkSegmentedButton(
            self.output_frame,
            values=["Log"],
            command=self._on_view_change,
        )
        self.view_toggle.set("Log")
        self.view_toggle.pack(anchor="ne", padx=10, pady=(10, 0))

        # Log view
        self.log_view = ctk.CTkFrame(self.output_frame, fg_color="transparent")
        self.log_view.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = ctk.CTkTextbox(
            self.log_view,
            font=(MONO_FONT, 12),
            wrap="word",
            fg_color=LOG_BG_DARK,
            text_color=LOG_INFO_COLOR,
        )
        self.log_text.pack(fill="both", expand=True)

        self.log_text._textbox.tag_configure("info",    foreground=LOG_INFO_COLOR)
        self.log_text._textbox.tag_configure("warning", foreground=LOG_WARNING_COLOR)
        self.log_text._textbox.tag_configure("error",   foreground=LOG_ERROR_COLOR)
        self.log_text._textbox.tag_configure("success", foreground=LOG_SUCCESS_COLOR)
        self.log_text._textbox.tag_configure(
            "section",
            foreground=LOG_SECTION_COLOR,
            font=(MONO_FONT, 12, "bold"),
        )
        self.log_text.configure(state="disabled")

        self.summary_view = None  # built after completion

    def _build_status_bar(self):
        self.status_bar = ctk.CTkFrame(self, height=44)
        self.status_bar.pack(fill="x", padx=20, pady=(0, 14))

        self.status_indicator = ctk.CTkLabel(
            self.status_bar,
            text="● Idle",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#888888",
        )
        self.status_indicator.pack(side="left", padx=14, pady=8)

        self.timer_label = ctk.CTkLabel(
            self.status_bar,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#888888",
        )
        self.timer_label.pack(side="left", padx=4, pady=8)

        self.clear_button = ctk.CTkButton(
            self.status_bar, text="Clear", width=90, command=self._on_clear
        )
        self.clear_button.pack(side="right", padx=6, pady=6)

        self.open_folder_button = ctk.CTkButton(
            self.status_bar, text="Open Output Folder", width=160, command=self._on_open_folder
        )
        self.open_folder_button.pack(side="right", padx=6, pady=6)

        self.cancel_button = ctk.CTkButton(
            self.status_bar, text="Cancel", width=90, command=self._on_cancel,
            fg_color="#A03030", hover_color="#C04040",
        )

    # ------------------------------------------------------------------
    # File browsing
    # ------------------------------------------------------------------

    def _browse_pcap(self):
        paths = filedialog.askopenfilenames(
            title="Select one or more PCAP files",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng *.cap"),
                ("All files", "*.*"),
            ],
        )
        if paths:
            self._set_pcaps(list(paths))

    def _set_pcaps(self, paths: list[str]):
        """Record the selected PCAP(s) and show them (or a count) in the field."""
        self.selected_pcaps = [p for p in paths if p.strip()]
        if len(self.selected_pcaps) == 1:
            self._pcap_summary = self.selected_pcaps[0]
        elif self.selected_pcaps:
            names = ", ".join(Path(p).name for p in self.selected_pcaps)
            self._pcap_summary = f"{len(self.selected_pcaps)} files: {names}"
        else:
            self._pcap_summary = ""
        self.pcap_var.set(self._pcap_summary)

    def _get_pcaps(self) -> list[str]:
        """Return the PCAP paths to analyze (multi-select list, or the typed path)."""
        # Use the multi-select list only if the field still shows our summary;
        # if the user edited the field, treat its text as a single path.
        if len(self.selected_pcaps) > 1 and self.pcap_var.get() == self._pcap_summary:
            return self.selected_pcaps
        text = self.pcap_var.get().strip()
        return [text] if text else []

    def _browse_yara(self):
        path = filedialog.askopenfilename(
            title="Select a YARA rules file",
            filetypes=[("YARA files", "*.yar *.yara"), ("All files", "*.*")],
        )
        if not path:
            # Allow choosing a directory if no file was picked
            path = filedialog.askdirectory(title="Or pick a YARA rules directory")
        if path:
            self.yara_path_var.set(path)
            self.yara_var.set(True)

    def _browse_geoip(self):
        path = filedialog.askopenfilename(
            title="Select GeoLite2 .mmdb file",
            filetypes=[("MaxMind DB", "*.mmdb"), ("All files", "*.*")],
        )
        if path:
            self.geoip_path_var.set(path)
            self.geoip_var.set(True)

    def _browse_intel_dir(self):
        path = filedialog.askdirectory(title="Select threat-intel feed directory")
        if path:
            self.intel_dir_var.set(path)

    def _browse_tls_keylog(self):
        path = filedialog.askopenfilename(
            title="Select TLS key-log file",
            filetypes=[("Key log", "*.log *.keylog *.txt"), ("All files", "*.*")],
        )
        if path:
            self.tls_keylog_var.set(path)

    # ------------------------------------------------------------------
    # Drag-and-drop
    # ------------------------------------------------------------------

    def _on_drop(self, event):
        data = event.data.strip()
        # tkinterdnd2 wraps paths with spaces in braces, multiple files separated by spaces
        paths = []
        buf = ""
        in_brace = False
        for ch in data:
            if ch == "{":
                in_brace = True
                continue
            if ch == "}":
                in_brace = False
                if buf:
                    paths.append(buf)
                    buf = ""
                continue
            if ch == " " and not in_brace:
                if buf:
                    paths.append(buf)
                    buf = ""
                continue
            buf += ch
        if buf:
            paths.append(buf)

        if not paths:
            return
        # Prefer capture files when multiple items are dropped; fall back to all.
        pcaps = [p for p in paths if p.lower().endswith((".pcap", ".pcapng", ".cap"))]
        self._set_pcaps(pcaps or paths)

    # ------------------------------------------------------------------
    # Theme toggle
    # ------------------------------------------------------------------

    def _toggle_theme(self):
        order = ["system", "light", "dark"]
        idx = order.index(self.theme_mode) if self.theme_mode in order else 0
        self.theme_mode = order[(idx + 1) % len(order)]
        ctk.set_appearance_mode(self.theme_mode)
        self.theme_button.configure(text=f"Theme: {self.theme_mode}")

    # ------------------------------------------------------------------
    # Run lifecycle
    # ------------------------------------------------------------------

    def _on_run(self):
        if self.is_running:
            return

        pcaps = self._get_pcaps()
        if not pcaps:
            messagebox.showerror("Missing PCAP", "Please select one or more PCAP files to analyze.")
            return
        missing = [p for p in pcaps if not Path(p).exists()]
        if missing:
            messagebox.showerror("Not found", "PCAP(s) not found:\n" + "\n".join(missing))
            return

        if self.yara_var.get():
            yp = self.yara_path_var.get().strip()
            if yp and not Path(yp).exists():
                messagebox.showerror("YARA path not found", f"Path not found:\n{yp}")
                return

        if self.geoip_var.get():
            gp = self.geoip_path_var.get().strip()
            if gp and not Path(gp).exists():
                messagebox.showerror("GeoIP DB not found", f"Path not found:\n{gp}")
                return

        # Reset state
        self.case_output_dir = None
        self.log_lines = []
        self.summary_built = False
        self._clear_log()
        self._destroy_summary()
        self.view_toggle.configure(values=["Log"])
        self.view_toggle.set("Log")

        self._set_running_state()
        self.start_time = time.time()

        cmd = self._build_command(pcaps)
        self._append_log(f"$ {' '.join(self._quote_cmd(cmd))}\n", tag="section")

        self.run_thread = threading.Thread(target=self._run_subprocess, args=(cmd,), daemon=True)
        self.run_thread.start()

    def _build_command(self, pcaps) -> list[str]:
        if isinstance(pcaps, (str, Path)):
            pcaps = [pcaps]
        cmd = [resolve_analyzer_python(), "-u", str(ANALYZER_PATH)]
        cmd += [str(p) for p in pcaps]

        if self.case_var.get().strip():
            cmd += ["--case", self.case_var.get().strip()]

        if self.streams_var.get():
            cmd += ["--export-streams"]
            try:
                mx = int(self.max_streams_var.get())
                if mx > 0:
                    cmd += ["--max-streams", str(mx)]
            except ValueError:
                pass

        if self.jarm_var.get():
            cmd += ["--jarm-probe"]

        if self.yara_var.get() and self.yara_path_var.get().strip():
            cmd += ["--yara-rules", self.yara_path_var.get().strip()]

        if self.geoip_var.get() and self.geoip_path_var.get().strip():
            cmd += ["--geoip-db", self.geoip_path_var.get().strip()]

        cmd += ["--severity-filter", self.severity_var.get()]
        cmd += ["--output-format", self.format_var.get()]
        if self.min_ioc_conf_var.get() != "LOW":
            cmd += ["--min-ioc-confidence", self.min_ioc_conf_var.get()]
        for rule in self.decode_as_var.get().split():
            if rule.strip():
                cmd += ["--decode-as", rule.strip()]
        if self.intel_dir_var.get().strip():
            cmd += ["--intel-dir", self.intel_dir_var.get().strip()]
        if self.tls_keylog_var.get().strip():
            cmd += ["--tls-keylog", self.tls_keylog_var.get().strip()]
        return cmd

    @staticmethod
    def _quote_cmd(cmd: list[str]) -> list[str]:
        quoted = []
        for piece in cmd:
            if " " in piece:
                quoted.append(f'"{piece}"')
            else:
                quoted.append(piece)
        return quoted

    def _run_subprocess(self, cmd: list[str]):
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                cwd=str(REPO_ROOT),
            )
            assert self.process.stdout is not None
            for line in iter(self.process.stdout.readline, ""):
                self.output_queue.put(("line", line))
            self.process.stdout.close()
            rc = self.process.wait()
            self.output_queue.put(("done", rc))
        except Exception as exc:
            self.output_queue.put(("error", str(exc)))

    def _on_cancel(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.after(2000, self._force_kill_if_alive)
            except Exception:
                pass
            self._append_log("[!] Analysis cancelled by user.\n", tag="warning")

    def _force_kill_if_alive(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.kill()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Output queue processing
    # ------------------------------------------------------------------

    def _process_queue(self):
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "line":
                    self._append_log(payload)
                elif kind == "done":
                    self._on_complete(payload)
                elif kind == "error":
                    self._append_log(f"[!] GUI subprocess error: {payload}\n", tag="error")
                    self._on_complete(-1)
        except queue.Empty:
            pass
        self.after(80, self._process_queue)

    def _classify_line(self, line: str) -> str:
        s = line.strip()
        if not s:
            return "info"
        if s.startswith("[+]"):
            return "success"
        if s.startswith("[!]"):
            lowered = s.lower()
            if "error" in lowered or "fail" in lowered or "could not" in lowered or "not found" in lowered:
                return "error"
            return "warning"
        if s.startswith("==="):
            return "section"
        if s.startswith("PCAP SECURITY TOOLKIT") or s.startswith("TOP ALERTS"):
            return "section"
        if re.match(r"^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]", s):
            return "info"
        return "info"

    def _append_log(self, line: str, tag: str | None = None):
        line = line.rstrip("\n")
        if not line:
            line = ""
        tag = tag or self._classify_line(line)
        self.log_lines.append((line, tag))

        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

        m = re.search(r"Results written to:\s*(.+)$", line)
        if m:
            self.case_output_dir = Path(m.group(1).strip())
        m2 = re.search(r"Case Output Directory:\s*(.+)$", line)
        if m2 and not self.case_output_dir:
            self.case_output_dir = Path(m2.group(1).strip())

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.log_lines = []

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------

    def _on_complete(self, exit_code: int):
        self.is_running = False
        elapsed = time.time() - self.start_time if self.start_time else 0

        if exit_code == 0 and self.case_output_dir and self.case_output_dir.exists():
            self._build_summary_view(elapsed)
            self.view_toggle.configure(values=["Summary", "Log"])
            self.view_toggle.set("Summary")
            self._switch_view("Summary")
            self._set_status("✓ Done", LOG_SUCCESS_COLOR)
        else:
            self._build_error_view(exit_code, elapsed)
            self.view_toggle.configure(values=["Summary", "Log"])
            self.view_toggle.set("Summary")
            self._switch_view("Summary")
            self._set_status("✗ Error", LOG_ERROR_COLOR)

        self.timer_label.configure(text=f"Elapsed: {format_duration(elapsed)}")
        self._set_done_state()

    def _build_summary_view(self, elapsed: float):
        self._destroy_summary()
        self.summary_view = ctk.CTkScrollableFrame(self.output_frame, fg_color="transparent")

        # Read structured results
        report_data: dict = {}
        report_path = self.case_output_dir / "report.json"
        if report_path.exists():
            try:
                report_data = json.loads(report_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        alerts: list[dict] = []
        alerts_path = self.case_output_dir / "alerts.csv"
        if alerts_path.exists():
            try:
                with open(alerts_path, newline="", encoding="utf-8") as f:
                    alerts = list(csv.DictReader(f))
            except Exception:
                pass

        # Header
        ctk.CTkLabel(
            self.summary_view,
            text=f"✓  ANALYSIS COMPLETE   ({format_duration(elapsed)})",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=LOG_SUCCESS_COLOR,
            anchor="w",
        ).pack(fill="x", pady=(10, 14), padx=10)

        # Severity counts
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for a in alerts:
            s = a.get("severity", "INFO")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        sev_row = ctk.CTkFrame(self.summary_view, fg_color="transparent")
        sev_row.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(
            sev_row, text="Alerts:", font=ctk.CTkFont(size=14, weight="bold"), width=110, anchor="w"
        ).pack(side="left")
        any_alerts = False
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            if count <= 0:
                continue
            any_alerts = True
            ctk.CTkLabel(
                sev_row,
                text=f"●  {count} {sev}",
                text_color=SEVERITY_COLORS[sev],
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(side="left", padx=12)
        if not any_alerts:
            ctk.CTkLabel(sev_row, text="No alerts triggered", text_color="#888888").pack(side="left", padx=10)

        # Stats grid
        stats_frame = ctk.CTkFrame(self.summary_view)
        stats_frame.pack(fill="x", padx=10, pady=(0, 10))
        stats = [
            ("IOCs extracted",       report_data.get("ioc_count", 0)),
            ("Extracted payloads",   report_data.get("extracted_payload_count", 0)),
            ("Carved files",         report_data.get("carved_file_count", 0)),
            ("YARA hits",            report_data.get("yara_hit_count", 0)),
            ("SMTP attachments",     report_data.get("smtp_attachment_count", 0)),
            ("HTTP objects",         report_data.get("http_object_count", 0)),
            ("Credential findings",  report_data.get("credential_finding_count", 0)),
            ("Beaconing candidates", report_data.get("beaconing_candidate_count", 0)),
            ("DNS tunneling",        report_data.get("dns_tunneling_count", 0)),
            ("JA4H fingerprints",    report_data.get("ja4h_count", 0)),
            ("JARM fingerprints",    report_data.get("jarm_count", 0)),
            ("Malicious JA3",        report_data.get("malicious_ja3_count", 0)),
            ("Malicious JA4",        report_data.get("malicious_ja4_count", 0)),
            ("Cleartext creds",      report_data.get("cleartext_credential_count", 0)),
            ("Expert Info errors",   report_data.get("expert_error_count", 0)),
            ("Top stream score",     report_data.get("top_stream_suspicion_score", 0)),
            ("NTLM auth events",     report_data.get("ntlm_event_count", 0)),
            ("DCERPC binds",         report_data.get("dcerpc_bind_count", 0)),
            ("Kerberos attacks",     report_data.get("kerberos_attack_count", 0)),
        ]
        for i, (label, value) in enumerate(stats):
            row = i // 3
            col = i % 3
            cell = ctk.CTkFrame(stats_frame, fg_color="transparent")
            cell.grid(row=row, column=col, sticky="w", padx=14, pady=6)
            ctk.CTkLabel(cell, text=f"{label}:", font=ctk.CTkFont(size=12), anchor="w").pack(side="left")
            ctk.CTkLabel(
                cell,
                text=f"  {value}",
                font=ctk.CTkFont(size=12, weight="bold"),
            ).pack(side="left")
        for c in range(3):
            stats_frame.grid_columnconfigure(c, weight=1)

        # Top alerts
        ctk.CTkLabel(
            self.summary_view,
            text="Top Alerts",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        ).pack(fill="x", padx=10, pady=(10, 4))

        top = alerts[:12]
        if not top:
            ctk.CTkLabel(self.summary_view, text="No alerts triggered.", text_color="#888888").pack(
                anchor="w", padx=20, pady=4
            )
        else:
            for a in top:
                sev = a.get("severity", "INFO")
                color = SEVERITY_COLORS.get(sev, LOG_INFO_COLOR)
                atype = a.get("alert_type", "")
                src = a.get("src_ip", "")
                dst = a.get("dst_ip", "")
                mitre = a.get("mitre_technique_id", "")
                reason = (a.get("reason") or "")[:160]

                row_frame = ctk.CTkFrame(self.summary_view, fg_color="transparent")
                row_frame.pack(fill="x", padx=14, pady=3)

                ctk.CTkLabel(
                    row_frame,
                    text=f"[{sev}]".ljust(10),
                    text_color=color,
                    font=(MONO_FONT, 11, "bold"),
                    width=90,
                    anchor="w",
                ).pack(side="left")
                arrow = f"{src} → {dst}" if (src or dst) else ""
                ctk.CTkLabel(
                    row_frame,
                    text=f"{atype}   {arrow}   {mitre}".strip(),
                    font=(MONO_FONT, 11),
                    anchor="w",
                ).pack(side="left", padx=(4, 0))

                if reason:
                    ctk.CTkLabel(
                        self.summary_view,
                        text=f"        {reason}",
                        font=(MONO_FONT, 10),
                        text_color="#A0A0A0",
                        anchor="w",
                        wraplength=720,
                        justify="left",
                    ).pack(fill="x", padx=14, pady=(0, 4))

        # Output path
        ctk.CTkLabel(
            self.summary_view,
            text="Output Directory",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        ).pack(fill="x", padx=10, pady=(12, 4))
        ctk.CTkLabel(
            self.summary_view,
            text=str(self.case_output_dir),
            font=(MONO_FONT, 11),
            anchor="w",
            wraplength=780,
            justify="left",
        ).pack(fill="x", padx=14)

        # Action buttons
        actions = ctk.CTkFrame(self.summary_view, fg_color="transparent")
        actions.pack(fill="x", padx=10, pady=(14, 14))

        ctk.CTkButton(
            actions, text="Open Output Folder", height=36,
            command=self._on_open_folder,
        ).pack(side="left", padx=4)

        wb_path = self.case_output_dir / "analysis_workbook.xlsx"
        if wb_path.exists():
            ctk.CTkButton(
                actions, text="Open Excel Workbook", height=36,
                command=lambda p=wb_path: open_with_default(p),
            ).pack(side="left", padx=4)

        html_path = self.case_output_dir / "report.html"
        if html_path.exists():
            ctk.CTkButton(
                actions, text="Open HTML Report", height=36,
                command=lambda p=html_path: open_with_default(p),
            ).pack(side="left", padx=4)

        alerts_path = self.case_output_dir / "alerts.csv"
        if alerts_path.exists():
            ctk.CTkButton(
                actions, text="Open alerts.csv", height=36,
                command=lambda p=alerts_path: open_with_default(p),
            ).pack(side="left", padx=4)

        self.summary_built = True

    def _build_error_view(self, exit_code: int, elapsed: float):
        self._destroy_summary()
        self.summary_view = ctk.CTkScrollableFrame(self.output_frame, fg_color="transparent")

        ctk.CTkLabel(
            self.summary_view,
            text="✗  ANALYSIS FAILED",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=LOG_ERROR_COLOR,
            anchor="w",
        ).pack(fill="x", padx=10, pady=(10, 14))

        msg = f"Process exited with code {exit_code} after {format_duration(elapsed)}."
        ctk.CTkLabel(
            self.summary_view,
            text=msg,
            anchor="w",
        ).pack(fill="x", padx=14, pady=(0, 10))

        # Find the most informative error line in the log
        error_lines = [line for line, tag in self.log_lines if tag in {"error", "warning"}]
        if error_lines:
            ctk.CTkLabel(
                self.summary_view,
                text="Errors:",
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
            ).pack(fill="x", padx=10, pady=(8, 4))
            for el in error_lines[-10:]:
                ctk.CTkLabel(
                    self.summary_view,
                    text=el,
                    font=(MONO_FONT, 11),
                    text_color=LOG_ERROR_COLOR,
                    anchor="w",
                    wraplength=780,
                    justify="left",
                ).pack(fill="x", padx=20, pady=2)

        ctk.CTkButton(
            self.summary_view, text="View Full Log", command=lambda: self.view_toggle.set("Log") or self._switch_view("Log"),
        ).pack(anchor="w", padx=14, pady=14)

        self.summary_built = True

    def _destroy_summary(self):
        if self.summary_view is not None:
            self.summary_view.destroy()
            self.summary_view = None
        self.summary_built = False

    # ------------------------------------------------------------------
    # View switching
    # ------------------------------------------------------------------

    def _on_view_change(self, value: str):
        self._switch_view(value)

    def _switch_view(self, view: str):
        if view == "Summary" and self.summary_view is not None:
            self.log_view.pack_forget()
            self.summary_view.pack(fill="both", expand=True, padx=10, pady=10)
        else:
            if self.summary_view is not None:
                self.summary_view.pack_forget()
            self.log_view.pack(fill="both", expand=True, padx=10, pady=10)

    # ------------------------------------------------------------------
    # Status-bar state machine
    # ------------------------------------------------------------------

    def _set_idle_state(self):
        self.is_running = False
        self._set_status("● Idle", "#888888")
        self.run_button.configure(state="normal")
        self.cancel_button.pack_forget()
        self.timer_label.configure(text="")

    def _set_running_state(self):
        self.is_running = True
        self._set_status("◐ Running…", LOG_SECTION_COLOR)
        self.run_button.configure(state="disabled")
        self.cancel_button.pack(side="right", padx=6, pady=6)

    def _set_done_state(self):
        self.is_running = False
        self.run_button.configure(state="normal")
        self.cancel_button.pack_forget()

    def _set_status(self, text: str, color: str):
        self.status_indicator.configure(text=text, text_color=color)

    def _update_timer(self):
        if self.is_running and self.start_time:
            elapsed = time.time() - self.start_time
            self.timer_label.configure(text=f"⏱ {format_duration(elapsed)}")
        self.after(500, self._update_timer)

    # ------------------------------------------------------------------
    # Status-bar button handlers
    # ------------------------------------------------------------------

    def _on_clear(self):
        if self.is_running:
            return
        self._clear_log()
        self._destroy_summary()
        self.view_toggle.configure(values=["Log"])
        self.view_toggle.set("Log")
        self._switch_view("Log")
        self.case_output_dir = None
        self.timer_label.configure(text="")
        self._set_status("● Idle", "#888888")

    def _on_open_folder(self):
        if self.case_output_dir and self.case_output_dir.exists():
            reveal_in_file_manager(self.case_output_dir)
        else:
            default_dir = REPO_ROOT / "output"
            if default_dir.exists():
                reveal_in_file_manager(default_dir)
            else:
                messagebox.showinfo(
                    "No output yet",
                    "No analysis has been run yet — no output folder exists.",
                )

    def _on_close(self):
        if self.is_running and self.process:
            if messagebox.askyesno(
                "Analysis running",
                "An analysis is still running.  Cancel it and exit?",
            ):
                try:
                    self.process.terminate()
                except Exception:
                    pass
                self.destroy()
        else:
            self.destroy()


def main():
    if not ANALYZER_PATH.exists():
        print(f"[!] analyzer.py not found at: {ANALYZER_PATH}")
        sys.exit(1)
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
