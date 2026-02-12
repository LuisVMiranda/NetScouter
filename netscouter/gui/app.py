"""Main NetScouter dashboard UI."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import importlib.util
import os
import queue
import shutil
import subprocess
import sys
import threading
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from apscheduler.schedulers.background import BackgroundScheduler

from netscouter.export import (
    analyze_logs_with_ollama,
    append_scan_result,
    build_analyst_prompt,
    build_network_engine_prompt,
    ensure_ai_readiness,
    export_ai_audit_report,
    export_session_to_xlsx,
    resolve_local_network_context,
)
from netscouter.firewall.controller import banish_ip, get_firewall_status
from netscouter.intel.geo import get_ip_intel
from netscouter.scanner.engine import ScanJob, ScanResult, scan_established_connections, scan_targets

DARK_THEME = {
    "window": "#0B0E14",
    "card": "#1F2937",
    "text": "#E2E8F0",
    "scan": "#00F5FF",
    "row_alt": "#253245",
}

LIGHT_THEME = {
    "window": "#F8FAFC",
    "card": "#FFFFFF",
    "text": "#1E293B",
    "scan": "#0EA5E9",
    "row_alt": "#EEF2FF",
}

RISK_COLORS = {
    "dark": {"low": "#39FF14", "average": "#FFB100", "high": "#FF3131"},
    "light": {"low": "#16A34A", "average": "#D97706", "high": "#DC2626"},
}

QUEUE_BATCH_LIMIT = 120
MAX_LOG_LINES = 2000


class NetScouterApp(ctk.CTk):
    """Top-level dashboard window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("NetScouter")
        self.geometry("1200x760")

        self.current_mode = "dark"
        ctk.set_appearance_mode("dark")

        self.scheduler = BackgroundScheduler()
        self.scheduled_job_id = "recurring_scan"

        self.scan_job: ScanJob | None = None
        self.scan_results: list[dict[str, str | int]] = []
        self.ui_queue: queue.Queue[dict[str, str | int]] = queue.Queue()
        self.intel_executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="intel")
        self.scan_guard = threading.Lock()
        self.is_scan_running = False
        self.active_scan_id = 0
        self.log_line_count = 0

        self.target_var = ctk.StringVar(value="127.0.0.1")
        self.port_range_var = ctk.StringVar(value="20-1024")
        self.schedule_hours_var = ctk.StringVar(value="6")
        self.firewall_status_var = ctk.StringVar(value="Not queried")

        self.status_filter_var = ctk.StringVar(value="All Status")
        self.risk_filter_var = ctk.StringVar(value="All Risk")

        self._configure_grid()
        self._build_controls()
        self._build_results_table()
        self._build_console()
        self._apply_theme()

        self.after(120, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_scan_running(self, running: bool) -> None:
        self.is_scan_running = running
        state = "disabled" if running else "normal"
        self.scan_button.configure(state=state)
        self.scan_established_button.configure(state=state)

    def _configure_grid(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

    def _build_controls(self) -> None:
        self.control_card = ctk.CTkFrame(self, corner_radius=10)
        self.control_card.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        self.control_card.grid_columnconfigure(0, weight=1)

        self.scan_row = ctk.CTkFrame(self.control_card, corner_radius=10)
        self.scan_row.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        self.scan_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.scan_row, text="Target").grid(row=0, column=0, padx=6, pady=8, sticky="w")
        ctk.CTkEntry(self.scan_row, textvariable=self.target_var).grid(row=0, column=1, padx=6, pady=8, sticky="ew")

        ctk.CTkLabel(self.scan_row, text="Port Range").grid(row=0, column=2, padx=6, pady=8, sticky="w")
        ctk.CTkEntry(self.scan_row, width=120, textvariable=self.port_range_var).grid(row=0, column=3, padx=6, pady=8)

        self.scan_button = ctk.CTkButton(
            self.scan_row,
            text="Scan",
            corner_radius=10,
            command=self.start_scan,
            width=110,
        )
        self.scan_button.grid(row=0, column=4, padx=6, pady=8)

        self.scan_established_button = ctk.CTkButton(
            self.scan_row,
            text="Scan ESTABLISHED",
            corner_radius=10,
            command=self.start_established_scan,
            width=150,
        )
        self.scan_established_button.grid(row=0, column=5, padx=6, pady=8)

        ctk.CTkButton(
            self.scan_row,
            text="Show Charts",
            corner_radius=10,
            command=self.show_charts,
            width=110,
        ).grid(row=0, column=6, padx=6, pady=8)

        self.ops_row = ctk.CTkFrame(self.control_card, corner_radius=10)
        self.ops_row.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))

        ctk.CTkLabel(self.ops_row, text="Every (hours)").grid(row=0, column=0, padx=6, pady=8)
        ctk.CTkEntry(self.ops_row, width=70, textvariable=self.schedule_hours_var).grid(row=0, column=1, padx=6, pady=8)

        ctk.CTkButton(
            self.ops_row,
            text="Start Recurring",
            corner_radius=10,
            command=self.start_recurring_scan,
            width=130,
        ).grid(row=0, column=2, padx=6, pady=8)

        ctk.CTkButton(
            self.ops_row,
            text="Stop Recurring",
            corner_radius=10,
            command=self.stop_recurring_scan,
            width=120,
        ).grid(row=0, column=3, padx=6, pady=8)

        ctk.CTkButton(
            self.ops_row,
            text="Refresh Firewall",
            corner_radius=10,
            command=self.refresh_firewall_insight,
            width=140,
        ).grid(row=0, column=4, padx=6, pady=8)

        ctk.CTkButton(
            self.ops_row,
            text="Banish Selected IP",
            corner_radius=10,
            command=self.banish_selected_ip,
            width=155,
        ).grid(row=0, column=5, padx=6, pady=8)

        self.theme_switch = ctk.CTkSegmentedButton(
            self.ops_row,
            values=["🌙", "☀️"],
            command=self._switch_theme,
            corner_radius=10,
            width=170,
        )
        self.theme_switch.set("🌙")
        self.theme_switch.grid(row=0, column=6, padx=(10, 6), pady=8)

        ctk.CTkLabel(self.ops_row, text="Firewall:").grid(row=0, column=7, padx=(10, 4), pady=8)
        ctk.CTkLabel(self.ops_row, textvariable=self.firewall_status_var, width=340, anchor="w").grid(
            row=0, column=8, padx=4, pady=8, sticky="w"
        )

    def _build_results_table(self) -> None:
        self.table_card = ctk.CTkFrame(self, corner_radius=10)
        self.table_card.grid(row=1, column=0, sticky="nsew", padx=16, pady=8)
        self.table_card.grid_rowconfigure(1, weight=1)
        self.table_card.grid_columnconfigure(0, weight=1)

        self.filter_row = ctk.CTkFrame(self.table_card, corner_radius=10)
        self.filter_row.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.filter_row.grid_columnconfigure(8, weight=1)

        ctk.CTkLabel(self.filter_row, text="Display Filters:").grid(row=0, column=0, padx=6, pady=8)

        self.status_filter = ctk.CTkOptionMenu(
            self.filter_row,
            values=["All Status", "Open", "Closed"],
            variable=self.status_filter_var,
            command=lambda _: self._rerender_table(),
            corner_radius=10,
            width=130,
        )
        self.status_filter.grid(row=0, column=1, padx=6, pady=8)

        self.risk_filter = ctk.CTkOptionMenu(
            self.filter_row,
            values=["All Risk", "Low", "Average", "High"],
            variable=self.risk_filter_var,
            command=lambda _: self._rerender_table(),
            corner_radius=10,
            width=130,
        )
        self.risk_filter.grid(row=0, column=2, padx=6, pady=8)

        ctk.CTkButton(
            self.filter_row,
            text="Clear Filters",
            corner_radius=10,
            width=120,
            command=self.clear_filters,
        ).grid(row=0, column=3, padx=6, pady=8)

        self.filter_summary_var = ctk.StringVar(value="Showing 0 / 0 rows")
        ctk.CTkLabel(self.filter_row, textvariable=self.filter_summary_var).grid(row=0, column=8, padx=8, pady=8, sticky="e")

        columns = ("port", "status", "remote_ip", "location", "provider", "risk")
        self.results_table = ttk.Treeview(self.table_card, columns=columns, show="headings", selectmode="browse")

        headings = {
            "port": "Port",
            "status": "Status",
            "remote_ip": "Remote IP",
            "location": "Location",
            "provider": "Provider",
            "risk": "Risk",
        }
        widths = {"port": 80, "status": 90, "remote_ip": 175, "location": 200, "provider": 250, "risk": 80}

        for name in columns:
            self.results_table.heading(name, text=headings[name])
            self.results_table.column(name, width=widths[name], anchor="center")

        y_scroll = ttk.Scrollbar(self.table_card, orient="vertical", command=self.results_table.yview)
        self.results_table.configure(yscrollcommand=y_scroll.set)

        self.results_table.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(4, 10))
        y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(4, 10))

    def _build_console(self) -> None:
        self.console_card = ctk.CTkFrame(self, corner_radius=10)
        self.console_card.grid(row=2, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self.console_card.grid_rowconfigure(0, weight=1)
        self.console_card.grid_columnconfigure(0, weight=1)

        self.bottom_tabs = ctk.CTkTabview(self.console_card, corner_radius=10)
        self.bottom_tabs.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.bottom_tabs.add("Scanner")
        self.bottom_tabs.add("AI")

        scanner_tab = self.bottom_tabs.tab("Scanner")
        scanner_tab.grid_columnconfigure(0, weight=1)
        scanner_tab.grid_rowconfigure(1, weight=1)

        scanner_header = ctk.CTkFrame(scanner_tab, corner_radius=10)
        scanner_header.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 6))
        ctk.CTkLabel(scanner_header, text="Console Logs").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(
            scanner_header,
            text="Export AI Audit",
            corner_radius=10,
            command=self.export_ai_audit,
            width=120,
        ).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(
            scanner_header,
            text="Export XLSX",
            corner_radius=10,
            command=self.export_xlsx,
            width=110,
        ).grid(row=0, column=2, padx=6, pady=6)

        self.console = ctk.CTkTextbox(scanner_tab, corner_radius=10)
        self.console.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 0))

        ai_tab = self.bottom_tabs.tab("AI")
        ai_tab.grid_columnconfigure(0, weight=1)
        ai_tab.grid_rowconfigure(2, weight=1)

        ai_header = ctk.CTkFrame(ai_tab, corner_radius=10)
        ai_header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ctk.CTkLabel(ai_header, text="AI Feedback from Logs").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(
            ai_header,
            text="Analyze Logs",
            corner_radius=10,
            command=self.analyze_logs,
            width=120,
        ).grid(row=0, column=1, padx=6, pady=6)

        self.ai_status_var = ctk.StringVar(
            value="Run scans, then click Analyze Logs to query llama3.2:3b via Ollama."
        )
        ctk.CTkLabel(ai_tab, textvariable=self.ai_status_var, anchor="w", justify="left").grid(
            row=1, column=0, sticky="ew", pady=(0, 6)
        )

        self.ai_feedback_box = ctk.CTkTextbox(ai_tab, corner_radius=10)
        self.ai_feedback_box.grid(row=2, column=0, sticky="nsew")

    def _active_theme(self) -> dict[str, str]:
        return DARK_THEME if self.current_mode == "dark" else LIGHT_THEME

    def _apply_theme(self) -> None:
        theme = self._active_theme()
        self.configure(fg_color=theme["window"])

        for card in (
            self.control_card,
            self.scan_row,
            self.ops_row,
            self.table_card,
            self.filter_row,
            self.console_card,
        ):
            card.configure(fg_color=theme["card"])

        self.scan_button.configure(fg_color=theme["scan"], text_color="#0B0E14" if self.current_mode == "dark" else "#FFFFFF")

        style = ttk.Style(self)
        style.theme_use("default")
        style.configure(
            "Treeview",
            background=theme["card"],
            fieldbackground=theme["card"],
            foreground=theme["text"],
            rowheight=30,
            borderwidth=0,
        )
        style.configure("Treeview.Heading", background=theme["card"], foreground=theme["text"], relief="flat")
        style.map("Treeview", background=[("selected", theme["scan"])], foreground=[("selected", "#0B0E14")])

        self.results_table.tag_configure("even", background=theme["card"])
        self.results_table.tag_configure("odd", background=theme["row_alt"])
        self._refresh_risk_tag_colors()

    def _refresh_risk_tag_colors(self) -> None:
        palette = RISK_COLORS[self.current_mode]
        self.results_table.tag_configure("risk_low", foreground=palette["low"])
        self.results_table.tag_configure("risk_average", foreground=palette["average"])
        self.results_table.tag_configure("risk_high", foreground=palette["high"])

    def _switch_theme(self, selected: str) -> None:
        selected_lower = selected.lower()
        self.current_mode = "light" if "☀" in selected_lower or "sun" in selected_lower else "dark"
        ctk.set_appearance_mode(self.current_mode)
        self._apply_theme()
        self._rerender_table()
        self._log(f"Switched to {self.current_mode} theme")

    def _parse_ports(self) -> list[int]:
        raw = self.port_range_var.get().strip()
        if "-" in raw:
            start_text, end_text = raw.split("-", maxsplit=1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            return list(range(start, end + 1))
        return [int(chunk.strip()) for chunk in raw.split(",") if chunk.strip()]

    def start_scan(self) -> None:
        threading.Thread(target=self._start_scan_worker, daemon=True, name="scan-launcher").start()

    def start_established_scan(self) -> None:
        threading.Thread(target=self._start_established_scan_worker, daemon=True, name="established-scan-launcher").start()

    def _start_scan_worker(self) -> None:
        if self.is_scan_running:
            self.after(0, lambda: self._log("A scan is already running. Please wait for completion."))
            return

        target = self.target_var.get().strip()
        if not target:
            self.after(0, lambda: self._log("No target provided"))
            return

        try:
            ports = self._parse_ports()
        except ValueError:
            self.after(0, lambda: self._log("Invalid port range"))
            return

        with self.scan_guard:
            self.active_scan_id += 1
            scan_id = self.active_scan_id

        self.after(0, lambda: self._set_scan_running(True))
        self.after(0, lambda: self._log(f"Starting scan for {target} on {len(ports)} ports"))

        def enqueue_result(scan_result: ScanResult) -> None:
            self.intel_executor.submit(self._enrich_and_queue, scan_result, scan_id)

        def on_complete() -> None:
            self.after(0, lambda: self._finish_scan(scan_id, "Target scan finished"))

        self.scan_job = scan_targets(targets=[target], ports=ports, on_result=enqueue_result, on_complete=on_complete)

    def _start_established_scan_worker(self) -> None:
        if self.is_scan_running:
            self.after(0, lambda: self._log("A scan is already running. Please wait for completion."))
            return

        try:
            ports = self._parse_ports()
        except ValueError:
            self.after(0, lambda: self._log("Invalid port range"))
            return

        with self.scan_guard:
            self.active_scan_id += 1
            scan_id = self.active_scan_id

        self.after(0, lambda: self._set_scan_running(True))
        self.after(0, lambda: self._log("Scanning remote IPs from ESTABLISHED connections"))

        def enqueue_result(scan_result: ScanResult) -> None:
            self.intel_executor.submit(self._enrich_and_queue, scan_result, scan_id)

        def on_complete() -> None:
            self.after(0, lambda: self._finish_scan(scan_id, "ESTABLISHED scan finished"))

        self.scan_job = scan_established_connections(ports=ports, on_result=enqueue_result, on_complete=on_complete)

    def _finish_scan(self, scan_id: int, message: str) -> None:
        if scan_id != self.active_scan_id:
            return
        self._set_scan_running(False)
        self._log(message)

    def _enrich_and_queue(self, scan_result: ScanResult, scan_id: int) -> None:
        location = "Unknown"
        provider = "Unknown"
        risk_level = "average"
        country = ""
        city = ""

        try:
            intel = get_ip_intel(scan_result.host)
            country = str(intel.get("country", ""))
            city = str(intel.get("city", ""))
            location = ", ".join(filter(None, [city, country])) or "Unknown"
            provider = str(intel.get("provider", "Unknown"))
            risk_level = str(intel.get("risk_level", "average")).lower()
        except Exception as exc:  # noqa: BLE001
            provider = f"Lookup error: {exc}"

        payload = {
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "port": scan_result.port,
            "status": "Open" if scan_result.is_open else "Closed",
            "remote_ip": scan_result.host,
            "country": country,
            "city": city,
            "location": location,
            "provider": provider,
            "risk_level": risk_level,
            "risk": risk_level.capitalize(),
        }
        self.ui_queue.put(payload)

    def _passes_filters(self, row: dict[str, str | int]) -> bool:
        selected_status = self.status_filter_var.get()
        selected_risk = self.risk_filter_var.get()

        if selected_status != "All Status" and str(row.get("status", "")).lower() != selected_status.lower():
            return False
        if selected_risk != "All Risk" and str(row.get("risk", "")).lower() != selected_risk.lower():
            return False
        return True

    def _rerender_table(self) -> None:
        for item in self.results_table.get_children():
            self.results_table.delete(item)

        visible = [row for row in self.scan_results if self._passes_filters(row)]
        for index, payload in enumerate(visible):
            stripe_tag = "even" if index % 2 == 0 else "odd"
            risk_tag = f"risk_{str(payload['risk']).lower()}"
            self.results_table.insert(
                "",
                "end",
                values=(
                    payload["port"],
                    payload["status"],
                    payload["remote_ip"],
                    payload["location"],
                    payload["provider"],
                    payload["risk"],
                ),
                tags=(stripe_tag, risk_tag),
            )

        self.filter_summary_var.set(f"Showing {len(visible)} / {len(self.scan_results)} rows")

    def clear_filters(self) -> None:
        self.status_filter_var.set("All Status")
        self.risk_filter_var.set("All Risk")
        self._rerender_table()

    def _drain_ui_queue(self) -> None:
        processed = 0

        while processed < QUEUE_BATCH_LIMIT:
            try:
                payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            if int(payload.get("scan_id", -1)) != self.active_scan_id:
                processed += 1
                continue

            self.scan_results.append(payload)
            append_scan_result(payload)
            if self._passes_filters(payload):
                inserted_index = len(self.results_table.get_children())
                stripe_tag = "even" if inserted_index % 2 == 0 else "odd"
                risk_tag = f"risk_{str(payload['risk']).lower()}"
                self.results_table.insert(
                    "",
                    "end",
                    values=(
                        payload["port"],
                        payload["status"],
                        payload["remote_ip"],
                        payload["location"],
                        payload["provider"],
                        payload["risk"],
                    ),
                    tags=(stripe_tag, risk_tag),
                )

            if processed % 4 == 0:
                self._log(f"Port {payload['port']} on {payload['remote_ip']}: {payload['status']} | Risk {payload['risk']}")
            processed += 1

        if processed > 0:
            visible_count = sum(1 for row in self.scan_results if self._passes_filters(row))
            self.filter_summary_var.set(f"Showing {visible_count} / {len(self.scan_results)} rows")

        self.after(20 if processed >= QUEUE_BATCH_LIMIT else 120, self._drain_ui_queue)

    def start_recurring_scan(self) -> None:
        try:
            interval_hours = float(self.schedule_hours_var.get().strip())
            if interval_hours <= 0:
                raise ValueError
        except ValueError:
            self._log("Invalid recurring interval; use a positive number of hours")
            return

        if not self.scheduler.running:
            self.scheduler.start()

        self.scheduler.add_job(
            self.start_scan,
            "interval",
            hours=interval_hours,
            id=self.scheduled_job_id,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        self._log(f"Recurring scan scheduled every {interval_hours:g} hour(s)")

    def stop_recurring_scan(self) -> None:
        if self.scheduler.get_job(self.scheduled_job_id):
            self.scheduler.remove_job(self.scheduled_job_id)
            self._log("Recurring scan stopped")
        else:
            self._log("No recurring scan job to stop")

    def refresh_firewall_insight(self) -> None:
        threading.Thread(target=self._refresh_firewall_worker, daemon=True, name="firewall-insight").start()

    def _refresh_firewall_worker(self) -> None:
        try:
            result = get_firewall_status()
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self._log(f"Firewall insight failed: {exc}"))
            return

        status_text = result.get("message") or result.get("stdout") or str(result)
        self.after(0, lambda: self.firewall_status_var.set(status_text[:90]))
        self.after(0, lambda: self._log(f"Firewall insight: {status_text}"))

    def banish_selected_ip(self) -> None:
        selection = self.results_table.selection()
        if not selection:
            self._log("Select a row first to banish an IP")
            return

        values = self.results_table.item(selection[0], "values")
        ip = str(values[2])
        if not ip:
            self._log("Selected row has no remote IP")
            return

        confirm = messagebox.askyesno("Banish IP", f"Block {ip} permanently in firewall?")
        if not confirm:
            return

        threading.Thread(target=self._banish_ip_worker, args=(ip,), daemon=True, name="banish-ip").start()

    def _banish_ip_worker(self, ip: str) -> None:
        try:
            result = banish_ip(ip)
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self._log(f"Banish command failed: {exc}"))
            return

        message = result.get("message", str(result))
        self.after(0, lambda: self._log(f"Banish {ip}: {message}"))

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.see("end")
        self.log_line_count += 1

        if self.log_line_count > MAX_LOG_LINES:
            self.console.delete("1.0", "200.0")
            self.log_line_count -= 199

    def _ensure_matplotlib(self) -> tuple[bool, str]:
        if importlib.util.find_spec("matplotlib") is not None:
            return True, "matplotlib is already available."

        self._log("Charts: matplotlib not found. Downloading dependencies in background...")

        python_executable = sys.executable
        if not python_executable:
            return False, "Python executable path is unavailable."

        if shutil.which("pip") is None:
            self._log("Charts: pip not found. Attempting ensurepip bootstrap...")
            try:
                proc = subprocess.run(
                    [python_executable, "-m", "ensurepip", "--upgrade"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            except Exception as exc:  # noqa: BLE001
                return False, f"Failed to bootstrap pip: {exc}"

            if proc.returncode != 0:
                return False, f"Failed to bootstrap pip: {(proc.stderr or proc.stdout).strip()}"

        self._log("Charts: installing matplotlib (this can take a moment)...")
        try:
            install_proc = subprocess.run(
                [python_executable, "-m", "pip", "install", "matplotlib"],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"Failed to run pip install matplotlib: {exc}"

        if install_proc.returncode != 0:
            error_text = (install_proc.stderr or install_proc.stdout or "").strip()
            return False, f"matplotlib install failed: {error_text}"

        if importlib.util.find_spec("matplotlib") is None:
            return False, "matplotlib install reported success but import still failed."

        return True, "matplotlib installed successfully."

    def _open_charts_window(self) -> None:
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from matplotlib.figure import Figure

        risk_counts = Counter(str(row.get("risk", "Average")) for row in self.scan_results)
        status_counts = Counter(str(row.get("status", "Closed")) for row in self.scan_results)

        chart_window = ctk.CTkToplevel(self)
        chart_window.title("NetScouter Charts")
        chart_window.geometry("760x420")

        figure = Figure(figsize=(7.4, 4), dpi=100)
        ax1 = figure.add_subplot(121)
        ax2 = figure.add_subplot(122)

        labels1 = list(risk_counts.keys())
        values1 = list(risk_counts.values())
        ax1.pie(values1, labels=labels1, autopct="%1.1f%%")
        ax1.set_title("Risk Distribution")

        labels2 = list(status_counts.keys())
        values2 = list(status_counts.values())
        ax2.bar(labels2, values2, color=["#0EA5E9", "#FFB100"])
        ax2.set_title("Status Count")
        ax2.set_ylabel("Connections")

        figure.tight_layout()

        canvas = FigureCanvasTkAgg(figure, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

    def _show_charts_worker(self) -> None:
        ok, details = self._ensure_matplotlib()
        if not ok:
            self.after(0, lambda: self._log(f"Charts unavailable: {details}"))
            return
        self.after(0, lambda: self._log(f"Charts: {details}"))
        self.after(0, self._open_charts_window)

    def export_ai_audit(self) -> None:
        if not self.scan_results:
            self._log("No results to export")
            return

        ready = ensure_ai_readiness(console=self._log)
        if not ready:
            self._log("AI audit export skipped: local model unavailable")
            return

        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not path:
            return

        context = resolve_local_network_context()
        analyst_prompt = build_analyst_prompt()
        engine_prompt = build_network_engine_prompt(context)
        export_ai_audit_report(
            self.scan_results,
            path,
            analyst_prompt=analyst_prompt,
            network_prompt=engine_prompt,
        )
        self._log(f"Exported AI audit report to {path}")

    def export_xlsx(self) -> None:
        if not self.scan_results:
            self._log("No results to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if not path:
            return

        export_session_to_xlsx(self.scan_results, path)
        self._log(f"Exported XLSX to {path}")

    def analyze_logs(self) -> None:
        if not self.scan_results:
            self._log("No results available for AI analysis")
            self.ai_status_var.set("No scan data available. Run a scan first.")
            return

        self.ai_status_var.set("Checking local AI readiness...")
        self.bottom_tabs.set("AI")
        threading.Thread(target=self._analyze_logs_worker, daemon=True, name="ai-analyze-worker").start()

    def _analyze_logs_worker(self) -> None:
        ready = ensure_ai_readiness(console=self._log)
        if not ready:
            self.after(0, lambda: self.ai_status_var.set("AI readiness failed. Install/enable Ollama and llama3.2:3b."))
            return

        context = resolve_local_network_context()
        self.after(0, lambda: self.ai_status_var.set("Running Ollama analysis..."))
        ok, output = analyze_logs_with_ollama(self.scan_results, context=context)

        def publish() -> None:
            self.ai_feedback_box.delete("1.0", "end")
            if ok:
                self.ai_feedback_box.insert("1.0", output)
                self.ai_status_var.set("AI analysis complete.")
                self._log("AI analysis complete (see AI tab).")
            else:
                self.ai_feedback_box.insert("1.0", output)
                self.ai_status_var.set("AI analysis failed.")
                self._log(f"AI analysis failed: {output}")

        self.after(0, publish)

    def show_charts(self) -> None:
        if not self.scan_results:
            self._log("No results available for charting")
            return
        threading.Thread(target=self._show_charts_worker, daemon=True, name="charts-worker").start()

    def _on_close(self) -> None:
        if self.scan_job:
            self.scan_job.cancel()

        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

        self.intel_executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def launch_dashboard() -> None:
    """Start the NetScouter dashboard."""
    app = NetScouterApp()
    app.mainloop()
