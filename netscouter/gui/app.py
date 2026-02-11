"""Main NetScouter dashboard UI."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import csv
import queue
import threading
from pathlib import Path
from tkinter import filedialog, ttk
import customtkinter as ctk

from apscheduler.schedulers.background import BackgroundScheduler

from netscouter.intel.geo import get_ip_intel
from netscouter.scanner.engine import ScanJob, ScanResult, scan_targets

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
    "dark": {
        "low": "#39FF14",
        "average": "#FFB100",
        "high": "#FF3131",
    },
    "light": {
        "low": "#16A34A",
        "average": "#D97706",
        "high": "#DC2626",
    },
}


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

        self.target_var = ctk.StringVar(value="scanme.nmap.org")
        self.port_range_var = ctk.StringVar(value="20-1024")
        self.schedule_hours_var = ctk.StringVar(value="6")

        self._configure_grid()
        self._build_controls()
        self._build_results_table()
        self._build_console()
        self._apply_theme()

        self.after(120, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_grid(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)

    def _build_controls(self) -> None:
        self.control_card = ctk.CTkFrame(self, corner_radius=10)
        self.control_card.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        self.control_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.control_card, text="Target").grid(row=0, column=0, padx=8, pady=10, sticky="w")
        ctk.CTkEntry(self.control_card, textvariable=self.target_var).grid(
            row=0, column=1, padx=8, pady=10, sticky="ew"
        )

        ctk.CTkLabel(self.control_card, text="Port Range").grid(row=0, column=2, padx=8, pady=10, sticky="w")
        ctk.CTkEntry(self.control_card, width=140, textvariable=self.port_range_var).grid(
            row=0, column=3, padx=8, pady=10, sticky="w"
        )

        self.scan_button = ctk.CTkButton(
            self.control_card,
            text="Scan",
            corner_radius=10,
            command=self.start_scan,
            width=120,
        )
        self.scan_button.grid(row=0, column=4, padx=8, pady=10)

        ctk.CTkLabel(self.control_card, text="Every (hours)").grid(row=0, column=5, padx=8, pady=10, sticky="w")
        ctk.CTkEntry(self.control_card, width=70, textvariable=self.schedule_hours_var).grid(
            row=0, column=6, padx=8, pady=10
        )

        ctk.CTkButton(
            self.control_card,
            text="Start Recurring",
            corner_radius=10,
            command=self.start_recurring_scan,
            width=130,
        ).grid(row=0, column=7, padx=6, pady=10)

        ctk.CTkButton(
            self.control_card,
            text="Stop Recurring",
            corner_radius=10,
            command=self.stop_recurring_scan,
            width=120,
        ).grid(row=0, column=8, padx=6, pady=10)

        ctk.CTkButton(
            self.control_card,
            text="Export CSV",
            corner_radius=10,
            command=self.export_csv,
            width=100,
        ).grid(row=0, column=9, padx=6, pady=10)

        ctk.CTkButton(
            self.control_card,
            text="Export JSON",
            corner_radius=10,
            command=self.export_json,
            width=100,
        ).grid(row=0, column=10, padx=6, pady=10)

        self.theme_switch = ctk.CTkSegmentedButton(
            self.control_card,
            values=["Dark", "Light"],
            command=self._switch_theme,
            corner_radius=10,
        )
        self.theme_switch.set("Dark")
        self.theme_switch.grid(row=0, column=11, padx=(12, 8), pady=10)

    def _build_results_table(self) -> None:
        self.table_card = ctk.CTkFrame(self, corner_radius=10)
        self.table_card.grid(row=1, column=0, sticky="nsew", padx=16, pady=8)
        self.table_card.grid_rowconfigure(0, weight=1)
        self.table_card.grid_columnconfigure(0, weight=1)

        columns = ("port", "status", "remote_ip", "location", "provider", "risk")
        self.results_table = ttk.Treeview(
            self.table_card,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "port": "Port",
            "status": "Status",
            "remote_ip": "Remote IP",
            "location": "Location",
            "provider": "Provider",
            "risk": "Risk",
        }
        widths = {
            "port": 90,
            "status": 90,
            "remote_ip": 180,
            "location": 190,
            "provider": 220,
            "risk": 90,
        }

        for name in columns:
            self.results_table.heading(name, text=headings[name])
            self.results_table.column(name, width=widths[name], anchor="center")

        y_scroll = ttk.Scrollbar(self.table_card, orient="vertical", command=self.results_table.yview)
        self.results_table.configure(yscrollcommand=y_scroll.set)

        self.results_table.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
        y_scroll.grid(row=0, column=1, sticky="ns", padx=(0, 10), pady=10)

    def _build_console(self) -> None:
        self.console_card = ctk.CTkFrame(self, corner_radius=10)
        self.console_card.grid(row=2, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self.console_card.grid_rowconfigure(1, weight=1)
        self.console_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.console_card, text="Console Logs").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
        self.console = ctk.CTkTextbox(self.console_card, corner_radius=10)
        self.console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _active_theme(self) -> dict[str, str]:
        return DARK_THEME if self.current_mode == "dark" else LIGHT_THEME

    def _apply_theme(self) -> None:
        theme = self._active_theme()
        self.configure(fg_color=theme["window"])

        for card in (self.control_card, self.table_card, self.console_card):
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
        style.configure(
            "Treeview.Heading",
            background=theme["card"],
            foreground=theme["text"],
            relief="flat",
        )
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
        self.current_mode = "dark" if selected.lower() == "dark" else "light"
        ctk.set_appearance_mode(selected.lower())
        self._apply_theme()
        self._recolor_existing_rows()
        self._log(f"Switched to {selected.lower()} theme")

    def _recolor_existing_rows(self) -> None:
        for index, item in enumerate(self.results_table.get_children()):
            values = self.results_table.item(item, "values")
            risk_tag = f"risk_{str(values[5]).lower()}"
            stripe_tag = "even" if index % 2 == 0 else "odd"
            self.results_table.item(item, tags=(stripe_tag, risk_tag))

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

    def _start_scan_worker(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            self.after(0, lambda: self._log("No target provided"))
            return

        try:
            ports = self._parse_ports()
        except ValueError:
            self.after(0, lambda: self._log("Invalid port range"))
            return

        if self.scan_job:
            self.scan_job.cancel()

        self.after(0, lambda: self._log(f"Starting scan for {target} on {len(ports)} ports"))

        def enqueue_result(scan_result: ScanResult) -> None:
            self.intel_executor.submit(self._enrich_and_queue, scan_result)

        self.scan_job = scan_targets(targets=[target], ports=ports, on_result=enqueue_result)

    def _enrich_and_queue(self, scan_result: ScanResult) -> None:
        location = "Unknown"
        provider = "Unknown"
        risk_level = "average"

        try:
            intel = get_ip_intel(scan_result.host)
            location = ", ".join(filter(None, [intel.get("city", ""), intel.get("country", "")])) or "Unknown"
            provider = str(intel.get("provider", "Unknown"))
            risk_level = str(intel.get("risk_level", "average")).lower()
        except Exception as exc:  # noqa: BLE001
            provider = f"Lookup error: {exc}"

        payload = {
            "port": scan_result.port,
            "status": "Open" if scan_result.is_open else "Closed",
            "remote_ip": scan_result.host,
            "location": location,
            "provider": provider,
            "risk": risk_level.capitalize(),
        }
        self.ui_queue.put(payload)

    def _drain_ui_queue(self) -> None:
        while True:
            try:
                payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            self.scan_results.append(payload)
            row_index = len(self.scan_results) - 1
            stripe_tag = "even" if row_index % 2 == 0 else "odd"
            risk_tag = f"risk_{str(payload['risk']).lower()}"
            values = (
                payload["port"],
                payload["status"],
                payload["remote_ip"],
                payload["location"],
                payload["provider"],
                payload["risk"],
            )
            self.results_table.insert("", "end", values=values, tags=(stripe_tag, risk_tag))
            self._log(
                f"Port {payload['port']} on {payload['remote_ip']}: {payload['status']} | Risk {payload['risk']}"
            )

        self.after(120, self._drain_ui_queue)

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

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.see("end")

    def export_csv(self) -> None:
        if not self.scan_results:
            self._log("No results to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return

        with Path(path).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["port", "status", "remote_ip", "location", "provider", "risk"],
            )
            writer.writeheader()
            writer.writerows(self.scan_results)

        self._log(f"Exported CSV to {path}")

    def export_json(self) -> None:
        if not self.scan_results:
            self._log("No results to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return

        import json

        with Path(path).open("w", encoding="utf-8") as handle:
            json.dump(self.scan_results, handle, indent=2)

        self._log(f"Exported JSON to {path}")

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
