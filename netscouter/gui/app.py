"""Main NetScouter dashboard UI."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import queue
import threading
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from apscheduler.schedulers.background import BackgroundScheduler

from netscouter.export import (
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

        ctk.CTkButton(
            self.scan_row,
            text="Scan ESTABLISHED",
            corner_radius=10,
            command=self.start_established_scan,
            width=150,
        ).grid(row=0, column=5, padx=6, pady=8)

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
            values=["🌙 Lights Off", "☀️ Lights On"],
            command=self._switch_theme,
            corner_radius=10,
            width=170,
        )
        self.theme_switch.set("🌙 Lights Off")
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
        self.console_card.grid_rowconfigure(1, weight=1)
        self.console_card.grid_columnconfigure(0, weight=1)

        header_row = ctk.CTkFrame(self.console_card, corner_radius=10)
        header_row.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))

        ctk.CTkLabel(header_row, text="Console Logs").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(
            header_row,
            text="Export AI Audit",
            corner_radius=10,
            command=self.export_ai_audit,
            width=120,
        ).grid(row=0, column=1, padx=6, pady=6)

        ctk.CTkButton(
            header_row,
            text="Export XLSX",
            corner_radius=10,
            command=self.export_xlsx,
            width=110,
        ).grid(row=0, column=2, padx=6, pady=6)

        self.console = ctk.CTkTextbox(self.console_card, corner_radius=10)
        self.console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

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
        self.current_mode = "light" if "sun" in selected_lower or "lights on" in selected_lower else "dark"
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

    def _start_established_scan_worker(self) -> None:
        try:
            ports = self._parse_ports()
        except ValueError:
            self.after(0, lambda: self._log("Invalid port range"))
            return

        if self.scan_job:
            self.scan_job.cancel()

        self.after(0, lambda: self._log("Scanning remote IPs from ESTABLISHED connections"))

        def enqueue_result(scan_result: ScanResult) -> None:
            self.intel_executor.submit(self._enrich_and_queue, scan_result)

        self.scan_job = scan_established_connections(ports=ports, on_result=enqueue_result)

    def _enrich_and_queue(self, scan_result: ScanResult) -> None:
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
        while True:
            try:
                payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break

            self.scan_results.append(payload)
            append_scan_result(payload)
            self._rerender_table()
            self._log(f"Port {payload['port']} on {payload['remote_ip']}: {payload['status']} | Risk {payload['risk']}")

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

    def show_charts(self) -> None:
        if not self.scan_results:
            self._log("No results available for charting")
            return

        try:
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
        except Exception as exc:  # noqa: BLE001
            self._log(f"Charts unavailable: install matplotlib ({exc})")
            return

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
