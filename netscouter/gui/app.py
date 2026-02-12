"""Main NetScouter dashboard UI."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import importlib.util
import os
import platform
import queue
import shutil
import subprocess
import sys
import threading
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from apscheduler.schedulers.background import BackgroundScheduler

from netscouter.analytics.timeline import (
    bucket_events_by_time,
    build_heatmap_matrix,
    filter_timeline_events,
    normalize_timeline_rows,
)
from netscouter.export import (
    analyze_logs_with_ollama,
    append_quarantine_interaction,
    append_scan_result,
    build_analyst_prompt,
    build_network_engine_prompt,
    ensure_ai_readiness,
    export_ai_audit_report,
    export_session_to_xlsx,
    export_timeline_to_csv,
    export_timeline_to_xlsx,
    resolve_local_network_context,
)
from netscouter.firewall.controller import (
    add_custom_rule,
    apply_firewall_preset,
    enforce_ip_policy,
    get_firewall_status,
    panic_button,
    remove_custom_rule,
    toggle_firewall,
)
from netscouter.gui.icons import get_process_identity_label
from netscouter.intel.geo import get_ip_intel
from netscouter.intel.reputation import evaluate_reputation_consensus
from netscouter.intel.packet_signals import evaluate_packet_signals
from netscouter.scanner.engine import ScanJob, ScanResult, scan_established_connections, scan_targets
from netscouter.scanner.honeypot import LocalHoneypot
from netscouter.scanner.packet_stream import PacketCaptureService
from netscouter.scheduler.jobs import get_schedule_events, log_schedule_event

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
PACKET_SLICE_LIMIT = 120
SUSPICIOUS_PROCESS_NAMES = {
    "svchost.exe",
    "lsass.exe",
    "explorer.exe",
    "services.exe",
    "winlogon.exe",
    "csrss.exe",
    "systemd",
    "kthreadd",
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
        self.scan_results: list[dict[str, str | int | list[str]]] = []
        self.ui_queue: queue.Queue[dict[str, str | int | list[str]]] = queue.Queue()
        self.intel_executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="intel")
        self.scan_guard = threading.Lock()
        self.is_scan_running = False
        self.active_scan_id = 0
        self.log_line_count = 0
        self.packet_service = PacketCaptureService(max_packets=1200)
        self.honeypot = LocalHoneypot()
        self.packet_alert_cache: set[str] = set()
        self.quarantine_events: list[dict[str, str | bool]] = []
        self.selected_remote_ip: str | None = None
        self.selected_port: int | None = None

        self.target_var = ctk.StringVar(value="127.0.0.1")
        self.port_range_var = ctk.StringVar(value="20-1024")
        self.schedule_hours_var = ctk.StringVar(value="6")
        self.firewall_status_var = ctk.StringVar(value="Not queried")
        self.firewall_rule_name_var = ctk.StringVar(value="NetScouter Custom Rule")
        self.firewall_rule_port_var = ctk.StringVar(value="")
        self.firewall_rule_ip_var = ctk.StringVar(value="")
        self.firewall_direction_var = ctk.StringVar(value="in")
        self.firewall_action_var = ctk.StringVar(value="block")
        self.firewall_protocol_var = ctk.StringVar(value="tcp")
        self.firewall_preset_var = ctk.StringVar(value="normal")

        self.status_filter_var = ctk.StringVar(value="All Status")
        self.risk_filter_var = ctk.StringVar(value="All Risk")
        self.timeline_status_var = ctk.StringVar(value="All Status")
        self.timeline_risk_var = ctk.StringVar(value="All Risk")
        self.timeline_source_ip_var = ctk.StringVar(value="")
        self.auto_block_consensus_var = ctk.BooleanVar(value=False)
        self.reputation_threshold_var = ctk.StringVar(value="3")
        self.reputation_timeout_var = ctk.StringVar(value="4")
        self.abuseipdb_key_var = ctk.StringVar(value=os.getenv("ABUSEIPDB_API_KEY", ""))
        self.virustotal_key_var = ctk.StringVar(
            value=os.getenv("VIRUSTOTAL_API_KEY", "") or os.getenv("VT_API_KEY", "")
        )
        self.otx_key_var = ctk.StringVar(value=os.getenv("OTX_API_KEY", ""))
        self.auto_blocked_ips: set[str] = set()
        self.auto_block_guard = threading.Lock()

        self._configure_grid()
        self._build_controls()
        self._build_results_table()
        self._build_console()
        self._apply_theme()

        self._start_honeypot()

        self.after(120, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_scan_running(self, running: bool) -> None:
        self.is_scan_running = running
        state = "disabled" if running else "normal"
        self.scan_button.configure(state=state)
        self.scan_established_button.configure(state=state)

    def _start_honeypot(self) -> None:
        started = self.honeypot.start()
        if started:
            self._log(f"Quarantine sinkhole ready on {self.honeypot.host}:{self.honeypot.port}")
        else:
            self._log(f"Quarantine sinkhole unavailable on {self.honeypot.host}:{self.honeypot.port}")

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

        ctk.CTkButton(
            self.ops_row,
            text="Quarantine Selected IP",
            corner_radius=10,
            command=self.quarantine_selected_ip,
            width=175,
        ).grid(row=0, column=6, padx=6, pady=8)

        self.theme_switch = ctk.CTkSegmentedButton(
            self.ops_row,
            values=["🌙", "☀️"],
            command=self._switch_theme,
            corner_radius=10,
            width=170,
        )
        self.theme_switch.set("🌙")
        self.theme_switch.grid(row=0, column=7, padx=(10, 6), pady=8)

        ctk.CTkLabel(self.ops_row, text="Firewall:").grid(row=0, column=8, padx=(10, 4), pady=8)
        ctk.CTkLabel(self.ops_row, textvariable=self.firewall_status_var, width=340, anchor="w").grid(
            row=0, column=9, padx=4, pady=8, sticky="w"
        )

        self.settings_row = ctk.CTkFrame(self.control_card, corner_radius=10)
        self.settings_row.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))

        ctk.CTkLabel(self.settings_row, text="Reputation API Keys").grid(row=0, column=0, padx=(8, 4), pady=8, sticky="w")
        ctk.CTkEntry(self.settings_row, width=180, textvariable=self.abuseipdb_key_var, placeholder_text="ABUSEIPDB_API_KEY").grid(
            row=0, column=1, padx=4, pady=8
        )
        ctk.CTkEntry(
            self.settings_row,
            width=180,
            textvariable=self.virustotal_key_var,
            placeholder_text="VIRUSTOTAL_API_KEY / VT_API_KEY",
        ).grid(row=0, column=2, padx=4, pady=8)
        ctk.CTkEntry(self.settings_row, width=160, textvariable=self.otx_key_var, placeholder_text="OTX_API_KEY").grid(
            row=0, column=3, padx=4, pady=8
        )

        ctk.CTkLabel(self.settings_row, text="Threshold").grid(row=0, column=4, padx=(8, 4), pady=8)
        ctk.CTkEntry(self.settings_row, width=55, textvariable=self.reputation_threshold_var).grid(row=0, column=5, padx=4, pady=8)
        ctk.CTkLabel(self.settings_row, text="Timeout (s)").grid(row=0, column=6, padx=(8, 4), pady=8)
        ctk.CTkEntry(self.settings_row, width=55, textvariable=self.reputation_timeout_var).grid(row=0, column=7, padx=4, pady=8)

        ctk.CTkCheckBox(
            self.settings_row,
            text="Auto-block by consensus",
            variable=self.auto_block_consensus_var,
        ).grid(row=0, column=8, padx=8, pady=8)
        ctk.CTkButton(
            self.settings_row,
            text="Apply Settings",
            command=self.apply_settings,
            width=120,
        ).grid(row=0, column=9, padx=(4, 8), pady=8)

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

        ctk.CTkButton(
            self.filter_row,
            text="Start Live Packet Stream",
            corner_radius=10,
            width=180,
            command=self.start_live_packet_stream,
        ).grid(row=0, column=4, padx=6, pady=8)

        ctk.CTkButton(
            self.filter_row,
            text="Stop",
            corner_radius=10,
            width=80,
            command=self.stop_live_packet_stream,
        ).grid(row=0, column=5, padx=6, pady=8)

        ctk.CTkButton(
            self.filter_row,
            text="Export packet slice",
            corner_radius=10,
            width=150,
            command=self.export_packet_slice,
        ).grid(row=0, column=6, padx=6, pady=8)

        self.packet_stream_status_var = ctk.StringVar(value="Live stream idle")
        ctk.CTkLabel(self.filter_row, textvariable=self.packet_stream_status_var).grid(
            row=0, column=7, padx=8, pady=8, sticky="w"
        )

        self.filter_summary_var = ctk.StringVar(value="Showing 0 / 0 rows")
        ctk.CTkLabel(self.filter_row, textvariable=self.filter_summary_var).grid(row=0, column=8, padx=8, pady=8, sticky="e")

        columns = (
            "port",
            "status",
            "remote_ip",
            "process",
            "exe_path",
            "location",
            "provider",
            "consensus",
            "risk",
            "containment",
            "alerts",
        )
        self.results_table = ttk.Treeview(self.table_card, columns=columns, show="headings", selectmode="browse")

        headings = {
            "port": "Port",
            "status": "Status",
            "remote_ip": "Remote IP",
            "process": "Process",
            "exe_path": "Executable Path",
            "location": "Location",
            "provider": "Provider",
            "consensus": "Consensus",
            "risk": "Risk",
            "containment": "Containment",
            "alerts": "Alerts",
        }
        widths = {
            "port": 80,
            "status": 90,
            "remote_ip": 170,
            "process": 180,
            "exe_path": 300,
            "location": 160,
            "provider": 170,
            "consensus": 110,
            "risk": 80,
            "containment": 120,
            "alerts": 200,
        }

        for name in columns:
            self.results_table.heading(name, text=headings[name])
            self.results_table.column(name, width=widths[name], anchor="center")

        y_scroll = ttk.Scrollbar(self.table_card, orient="vertical", command=self.results_table.yview)
        self.results_table.configure(yscrollcommand=y_scroll.set)

        self.results_table.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(4, 6))
        y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(4, 6))
        self.results_table.bind("<<TreeviewSelect>>", self._on_table_select)

        self.packet_detail_card = ctk.CTkFrame(self.table_card, corner_radius=10)
        self.packet_detail_card.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        self.packet_detail_card.grid_columnconfigure(0, weight=1)

        self.packet_detail_header_var = ctk.StringVar(value="Packet detail panel: select a row to inspect traffic")
        ctk.CTkLabel(self.packet_detail_card, textvariable=self.packet_detail_header_var, anchor="w").grid(
            row=0, column=0, sticky="ew", padx=8, pady=(8, 4)
        )

        self.packet_detail_box = ctk.CTkTextbox(self.packet_detail_card, corner_radius=10, height=120)
        self.packet_detail_box.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 8))

    def _build_console(self) -> None:
        self.console_card = ctk.CTkFrame(self, corner_radius=10)
        self.console_card.grid(row=2, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self.console_card.grid_rowconfigure(0, weight=1)
        self.console_card.grid_columnconfigure(0, weight=1)

        self.bottom_tabs = ctk.CTkTabview(self.console_card, corner_radius=10)
        self.bottom_tabs.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.bottom_tabs.add("Scanner")
        self.bottom_tabs.add("AI")
        self.bottom_tabs.add("Firewall")

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

        firewall_tab = self.bottom_tabs.tab("Firewall")
        firewall_tab.grid_columnconfigure(0, weight=1)

        firewall_header = ctk.CTkLabel(
            firewall_tab,
            text="Use confirmations before risky actions. Rollback hint: restore preset to Normal and remove temporary rules.",
            justify="left",
            anchor="w",
        )
        firewall_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        actions_row = ctk.CTkFrame(firewall_tab, corner_radius=10)
        actions_row.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkButton(actions_row, text="Refresh Status", command=self.refresh_firewall_insight, width=130).grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Toggle ON", command=lambda: self.toggle_firewall_from_ui(True), width=110).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Toggle OFF", command=lambda: self.toggle_firewall_from_ui(False), width=110).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkOptionMenu(actions_row, values=["soft", "normal", "paranoid"], variable=self.firewall_preset_var, width=120).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Apply Preset", command=self.apply_firewall_preset_from_ui, width=130).grid(row=0, column=4, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Panic Button", command=self.run_panic_button, fg_color="#DC2626", hover_color="#B91C1C", width=120).grid(row=0, column=5, padx=6, pady=6)

        rule_row = ctk.CTkFrame(firewall_tab, corner_radius=10)
        rule_row.grid(row=2, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkEntry(rule_row, textvariable=self.firewall_rule_name_var, width=180, placeholder_text="Rule name").grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkOptionMenu(rule_row, values=["in", "out"], variable=self.firewall_direction_var, width=90).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkOptionMenu(rule_row, values=["allow", "block"], variable=self.firewall_action_var, width=100).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkOptionMenu(rule_row, values=["tcp", "udp"], variable=self.firewall_protocol_var, width=90).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkEntry(rule_row, textvariable=self.firewall_rule_port_var, width=100, placeholder_text="Port").grid(row=0, column=4, padx=6, pady=6)
        ctk.CTkEntry(rule_row, textvariable=self.firewall_rule_ip_var, width=150, placeholder_text="Remote IP (optional)").grid(row=0, column=5, padx=6, pady=6)
        ctk.CTkButton(rule_row, text="Add Rule", command=self.add_custom_rule_from_ui, width=100).grid(row=0, column=6, padx=6, pady=6)
        ctk.CTkButton(rule_row, text="Remove Rule", command=self.remove_custom_rule_from_ui, width=120).grid(row=0, column=7, padx=6, pady=6)

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
            self.packet_detail_card,
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

    def start_scan(self, *, source: str = "manual") -> None:
        threading.Thread(
            target=self._start_scan_worker,
            kwargs={"source": source},
            daemon=True,
            name="scan-launcher",
        ).start()

    def _start_scan_from_schedule(self) -> None:
        log_schedule_event(action="triggered", job_id=self.scheduled_job_id, source="scheduler")
        self.start_scan(source="scheduler")

    def start_established_scan(self) -> None:
        threading.Thread(target=self._start_established_scan_worker, daemon=True, name="established-scan-launcher").start()

    def _start_scan_worker(self, *, source: str = "manual") -> None:
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

        log_schedule_event(
            action="scan_started",
            job_id=self.scheduled_job_id if source == "scheduler" else "manual",
            source=source,
            scan_id=scan_id,
        )

        self.after(0, lambda: self._set_scan_running(True))
        self.after(0, lambda: self._log(f"Starting scan for {target} on {len(ports)} ports"))

        def enqueue_result(scan_result: ScanResult) -> None:
            self.intel_executor.submit(self._enrich_and_queue, scan_result, scan_id)

        def on_complete() -> None:
            log_schedule_event(
                action="scan_completed",
                job_id=self.scheduled_job_id if source == "scheduler" else "manual",
                source=source,
                scan_id=scan_id,
            )
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

        log_schedule_event(
            action="scan_started",
            job_id="established_manual",
            source="manual_established",
            scan_id=scan_id,
        )

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

    def _trusted_system_roots(self) -> tuple[str, ...]:
        if platform.system().lower() == "windows":
            roots = [
                os.environ.get("SystemRoot", r"C:\\Windows"),
                os.environ.get("ProgramFiles", r"C:\\Program Files"),
                os.environ.get("ProgramFiles(x86)", r"C:\\Program Files (x86)"),
            ]
            return tuple(root.lower() for root in roots if root)
        return ("/usr/bin", "/usr/sbin", "/bin", "/sbin")

    def _detect_process_warnings(self, process_name: str, exe_path: str) -> list[str]:
        warnings: list[str] = []
        normalized_name = process_name.strip().lower()
        normalized_path = exe_path.strip().lower()

        if normalized_name in SUSPICIOUS_PROCESS_NAMES and normalized_path:
            trusted_roots = self._trusted_system_roots()
            if not any(normalized_path.startswith(root) for root in trusted_roots):
                warnings.append("⚠️ Masquerading path")
        return warnings

    def apply_settings(self) -> None:
        os.environ["ABUSEIPDB_API_KEY"] = self.abuseipdb_key_var.get().strip()
        os.environ["VIRUSTOTAL_API_KEY"] = self.virustotal_key_var.get().strip()
        os.environ["OTX_API_KEY"] = self.otx_key_var.get().strip()
        self._log("Settings applied (API keys, consensus threshold, timeout, auto-block preference)")

    def _consensus_threshold(self) -> int:
        try:
            return max(1, int(self.reputation_threshold_var.get().strip()))
        except ValueError:
            return 3

    def _reputation_timeout(self) -> float:
        try:
            return max(1.0, float(self.reputation_timeout_var.get().strip()))
        except ValueError:
            return 4.0

    def _queue_auto_block_if_needed(self, remote_ip: str, should_block: bool, consensus_score: str) -> None:
        if not self.auto_block_consensus_var.get() or not should_block:
            return
        with self.auto_block_guard:
            if remote_ip in self.auto_blocked_ips:
                return
            self.auto_blocked_ips.add(remote_ip)
        self.after(0, lambda: self._log(f"Auto-block triggered for {remote_ip} (consensus {consensus_score})"))
        threading.Thread(target=self._banish_ip_worker, args=(remote_ip,), daemon=True, name="auto-banish-ip").start()

    def _enrich_and_queue(self, scan_result: ScanResult, scan_id: int) -> None:
        location = "Unknown"
        provider = "Unknown"
        risk_level = "average"
        country = ""
        city = ""
        consensus_score = "0/0"
        consensus_summary = "n/a"
        should_block = False

        try:
            intel = get_ip_intel(scan_result.host)
            country = str(intel.get("country", ""))
            city = str(intel.get("city", ""))
            location = ", ".join(filter(None, [city, country])) or "Unknown"
            provider = str(intel.get("provider", "Unknown"))
            risk_level = str(intel.get("risk_level", "average")).lower()
        except Exception as exc:  # noqa: BLE001
            provider = f"Lookup error: {exc}"

        process_name = str(scan_result.process_name or "Unknown")
        exe_path = str(scan_result.exe_path or "")
        pid = int(scan_result.pid) if scan_result.pid is not None else ""
        cmdline = str(scan_result.cmdline or "")
        process_label = get_process_identity_label(process_name, exe_path)
        warnings = self._detect_process_warnings(process_name, exe_path)
        if warnings and risk_level != "high":
            risk_level = "high"

        try:
            reputation = evaluate_reputation_consensus(
                scan_result.host,
                threshold=self._consensus_threshold(),
                timeout_seconds=self._reputation_timeout(),
                api_keys={
                    "abuseipdb": self.abuseipdb_key_var.get().strip(),
                    "virustotal": self.virustotal_key_var.get().strip(),
                    "otx": self.otx_key_var.get().strip(),
                },
            )
            consensus_score = str(reputation.get("consensus_score", "0/0"))
            consensus_summary = str(reputation.get("disposition", "allow"))
            should_block = bool(reputation.get("should_block", False))
            provider_bits = [
                f"{name}:{details.get('reason', '')}"
                for name, details in dict(reputation.get("providers", {})).items()
            ]
            warnings.extend([f"Intel {consensus_summary.upper()} {consensus_score}"])
            if provider_bits:
                warnings.append(" | ".join(provider_bits[:2]))
            if should_block:
                risk_level = "high"
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Reputation lookup failed: {exc}")

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
            "consensus": consensus_score,
            "risk_level": risk_level,
            "risk": risk_level.capitalize(),
            "containment": "None",
            "pid": pid,
            "process_name": process_name,
            "process_label": process_label,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "warnings": warnings,
            "alerts": " ".join(warnings) if warnings else "—",
        }
        self.ui_queue.put(payload)
        self._queue_auto_block_if_needed(scan_result.host, should_block, consensus_score)

    def _passes_filters(self, row: dict[str, str | int | list[str]]) -> bool:
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
                    payload["process_label"],
                    payload["exe_path"],
                    payload["location"],
                    payload["provider"],
                    payload["consensus"],
                    payload["risk"],
                    payload.get("containment", "None"),
                    payload["alerts"],
                ),
                tags=(stripe_tag, risk_tag),
            )

        self.filter_summary_var.set(f"Showing {len(visible)} / {len(self.scan_results)} rows")

    def clear_filters(self) -> None:
        self.status_filter_var.set("All Status")
        self.risk_filter_var.set("All Risk")
        self._rerender_table()

    def _on_table_select(self, _event: object | None = None) -> None:
        selection = self.results_table.selection()
        if not selection:
            return

        values = self.results_table.item(selection[0], "values")
        if len(values) < 3:
            return

        selected_ip = str(values[2]).strip()
        selected_port = None
        try:
            selected_port = int(str(values[0]).strip())
        except ValueError:
            selected_port = None
        if not selected_ip:
            return

        self.selected_remote_ip = selected_ip
        self.selected_port = selected_port
        self.packet_detail_header_var.set(f"Packet detail panel for {selected_ip}")
        self._render_packet_slice(selected_ip)

    def start_live_packet_stream(self) -> None:
        selected_ip = self.selected_remote_ip
        target_ip = selected_ip or self.target_var.get().strip()
        capture_port = self.selected_port if selected_ip else None
        if not target_ip:
            self._log("Select a row (or set target) before starting packet stream")
            return

        try:
            self.packet_service.start(target_ip, port=capture_port)
        except Exception as exc:  # noqa: BLE001
            self._log(f"Live packet stream failed to start: {exc}")
            return

        self.packet_alert_cache.clear()
        self.packet_stream_status_var.set(f"Streaming {target_ip}")
        self.packet_detail_header_var.set(f"Packet detail panel for {target_ip}")
        self._log(f"Live packet stream started for {target_ip}")
        self.after(350, self._poll_packet_stream)

    def stop_live_packet_stream(self) -> None:
        stopped = self.packet_service.stop()
        if not stopped:
            self._log("Live packet stream stop timed out")
        self.packet_stream_status_var.set("Live stream idle")
        self._log("Live packet stream stopped")

    def export_packet_slice(self) -> None:
        ip = self.selected_remote_ip or self.packet_service.remote_ip
        if not ip:
            self._log("Select an IP before exporting packet slice")
            return

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return

        count = self.packet_service.export_packets(path, remote_ip=ip, limit=PACKET_SLICE_LIMIT)
        self._log(f"Exported {count} packets for {ip} to {path}")

    def _poll_packet_stream(self) -> None:
        if not self.packet_service.is_running:
            return

        active_ip = self.packet_service.remote_ip or self.selected_remote_ip
        if active_ip:
            self._render_packet_slice(active_ip)

        self.after(350, self._poll_packet_stream)

    def _render_packet_slice(self, remote_ip: str) -> None:
        packets = self.packet_service.get_packets(remote_ip=remote_ip, limit=PACKET_SLICE_LIMIT)
        self.packet_detail_box.delete("1.0", "end")

        if not packets:
            self.packet_detail_box.insert("1.0", "No packets captured yet for this host.")
            return

        lines = []
        for packet in packets[-24:]:
            lines.append(
                f"{packet.get('timestamp')} | {packet.get('proto')} | "
                f"{packet.get('src')}:{packet.get('raw', {}).get('src_port')} -> "
                f"{packet.get('dst')}:{packet.get('raw', {}).get('dst_port')} | "
                f"len={packet.get('packet_length')} flags={packet.get('tcp_flags')} "
                f"malformed={packet.get('malformed')} error={packet.get('parse_error')}"
            )
        self.packet_detail_box.insert("1.0", "\n".join(lines))


        alerts = evaluate_packet_signals(remote_ip, packets)
        if alerts:
            self._escalate_risk_for_ip(remote_ip)

        for alert in alerts:
            if alert not in self.packet_alert_cache:
                self.packet_alert_cache.add(alert)
                self._log(f"[Packet Alert] {alert}")

    def _escalate_risk_for_ip(self, remote_ip: str) -> None:
        changed = False
        for row in self.scan_results:
            if str(row.get("remote_ip", "")) == remote_ip and str(row.get("risk", "")).lower() != "high":
                row["risk"] = "High"
                row["risk_level"] = "high"
                changed = True
        if changed:
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
                        payload["process_label"],
                        payload["exe_path"],
                        payload["location"],
                        payload["provider"],
                        payload["consensus"],
                        payload["risk"],
                        payload.get("containment", "None"),
                        payload["alerts"],
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
            self._start_scan_from_schedule,
            "interval",
            hours=interval_hours,
            id=self.scheduled_job_id,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log_schedule_event(
            action="scheduled",
            job_id=self.scheduled_job_id,
            source="scheduler",
            metadata={"interval_hours": interval_hours},
        )
        self._log(f"Recurring scan scheduled every {interval_hours:g} hour(s)")

    def stop_recurring_scan(self) -> None:
        if self.scheduler.get_job(self.scheduled_job_id):
            self.scheduler.remove_job(self.scheduled_job_id)
            log_schedule_event(action="stopped", job_id=self.scheduled_job_id, source="scheduler")
            self._log("Recurring scan stopped")
        else:
            self._log("No recurring scan job to stop")

    def refresh_firewall_insight(self) -> None:
        threading.Thread(target=self._refresh_firewall_worker, daemon=True, name="firewall-insight").start()

    def toggle_firewall_from_ui(self, enabled: bool) -> None:
        action = "enable" if enabled else "disable"
        confirm = messagebox.askyesno("Confirm Firewall Toggle", f"Do you want to {action} the firewall?")
        if not confirm:
            self._log(f"Firewall toggle cancelled ({action}).")
            return
        threading.Thread(target=self._toggle_firewall_worker, args=(enabled,), daemon=True, name="firewall-toggle").start()

    def _toggle_firewall_worker(self, enabled: bool) -> None:
        result = toggle_firewall(enabled, confirmed=True, safe_mode=True)
        self.after(0, lambda: self._log_operation_result("toggle_firewall", result))

    def apply_firewall_preset_from_ui(self) -> None:
        preset = self.firewall_preset_var.get().strip().lower()
        confirm = messagebox.askyesno(
            "Apply Firewall Preset",
            f"Apply '{preset}' preset? Rollback hint: switch to 'normal' preset if needed.",
        )
        if not confirm:
            self._log(f"Firewall preset cancelled ({preset}).")
            return
        threading.Thread(target=self._apply_preset_worker, args=(preset,), daemon=True, name="firewall-preset").start()

    def _apply_preset_worker(self, preset: str) -> None:
        result = apply_firewall_preset(preset)
        self.after(0, lambda: self._log_operation_result("apply_firewall_preset", result))

    def add_custom_rule_from_ui(self) -> None:
        rule_name = self.firewall_rule_name_var.get().strip()
        if not rule_name:
            self._log("Firewall custom rule: name is required.")
            return

        port_text = self.firewall_rule_port_var.get().strip()
        port: int | None = None
        if port_text:
            try:
                port = int(port_text)
            except ValueError:
                self._log("Firewall custom rule: port must be an integer.")
                return

        threading.Thread(
            target=self._add_custom_rule_worker,
            args=(rule_name, port, self.firewall_rule_ip_var.get().strip() or None),
            daemon=True,
            name="firewall-add-rule",
        ).start()

    def _add_custom_rule_worker(self, rule_name: str, port: int | None, remote_ip: str | None) -> None:
        result = add_custom_rule(
            name=rule_name,
            direction=self.firewall_direction_var.get(),
            action=self.firewall_action_var.get(),
            protocol=self.firewall_protocol_var.get(),
            port=port,
            remote_ip=remote_ip,
        )
        self.after(0, lambda: self._log_operation_result("add_custom_rule", result))

    def remove_custom_rule_from_ui(self) -> None:
        rule_name = self.firewall_rule_name_var.get().strip()
        if not rule_name:
            self._log("Firewall custom rule removal: name is required.")
            return

        confirm = messagebox.askyesno(
            "Remove Firewall Rule",
            f"Remove firewall rule '{rule_name}'? Rollback hint: re-add with the same name and settings.",
        )
        if not confirm:
            self._log(f"Firewall custom rule removal cancelled ({rule_name}).")
            return
        threading.Thread(target=self._remove_custom_rule_worker, args=(rule_name,), daemon=True, name="firewall-remove-rule").start()

    def _remove_custom_rule_worker(self, rule_name: str) -> None:
        result = remove_custom_rule(rule_name)
        self.after(0, lambda: self._log_operation_result("remove_custom_rule", result))

    def run_panic_button(self) -> None:
        confirm = messagebox.askyesno(
            "Panic Button",
            "Run emergency firewall lockdown sequence now? This may disrupt current connections.",
        )
        if not confirm:
            self._log("Panic button cancelled.")
            return
        threading.Thread(target=self._panic_button_worker, daemon=True, name="firewall-panic").start()

    def _panic_button_worker(self) -> None:
        result = panic_button()
        self.after(0, lambda: self._log_operation_result("panic_button", result))

    def _log_operation_result(self, operation: str, result: dict[str, object]) -> None:
        message = str(result.get("message", result))
        status = "SUCCESS" if bool(result.get("success")) else "FAIL"
        self._log(f"Firewall {operation} [{status}]: {message}")

        steps = result.get("steps")
        if isinstance(steps, list):
            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    self._log(f"  step-{idx}: {step}")
                    continue
                step_name = str(step.get("step", f"step-{idx}"))
                step_ok = "SUCCESS" if bool(step.get("success")) else "FAIL"
                self._log(f"  {step_name} [{step_ok}]: {step}")

        self.after(0, self.refresh_firewall_insight)

    def _refresh_firewall_worker(self) -> None:
        try:
            result = get_firewall_status()
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self._log(f"Firewall insight failed: {exc}"))
            return

        if result.get("success"):
            status_text = (
                f"enabled={result.get('enabled')} | rules={result.get('active_rules_count')} | "
                f"in={result.get('default_inbound_action')} / out={result.get('default_outbound_action')}"
            )
        else:
            status_text = str(result.get("message") or result)
        self.after(0, lambda: self.firewall_status_var.set(status_text[:90]))
        self.after(0, lambda: self._log(f"Firewall insight: {result}"))

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

    def quarantine_selected_ip(self) -> None:
        selection = self.results_table.selection()
        if not selection:
            self._log("Select a row first to quarantine an IP")
            return

        values = self.results_table.item(selection[0], "values")
        ip = str(values[2])
        if not ip:
            self._log("Selected row has no remote IP")
            return

        confirm = messagebox.askyesno(
            "Quarantine IP",
            f"Redirect {ip} to local sinkhole ({self.honeypot.host}:{self.honeypot.port})?",
        )
        if not confirm:
            return

        threading.Thread(target=self._quarantine_ip_worker, args=(ip,), daemon=True, name="quarantine-ip").start()

    def _banish_ip_worker(self, ip: str) -> None:
        try:
            result = enforce_ip_policy(ip, action="block")
        except Exception as exc:  # noqa: BLE001
            with self.auto_block_guard:
                self.auto_blocked_ips.discard(ip)
            self.after(0, lambda: self._log(f"Banish command failed: {exc}"))
            return

        if result.get("success"):
            self.after(0, lambda: self._apply_containment_state(ip, "Blocked"))
        message = result.get("message", str(result))
        self.after(0, lambda: self._log(f"Banish {ip}: {message}"))

    def _quarantine_ip_worker(self, ip: str) -> None:
        try:
            result = enforce_ip_policy(
                ip,
                action="quarantine",
                sinkhole_host=self.honeypot.host,
                sinkhole_port=self.honeypot.port,
            )
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self._log(f"Quarantine command failed: {exc}"))
            return

        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": "quarantine",
            "ip": ip,
            "sinkhole": f"{self.honeypot.host}:{self.honeypot.port}",
            "success": bool(result.get("success")),
        }
        self.quarantine_events.append(event)
        append_quarantine_interaction({**event, "result": result})

        if result.get("success"):
            self.after(0, lambda: self._apply_containment_state(ip, "Quarantined"))
        message = result.get("message", str(result))
        self.after(0, lambda: self._log(f"Quarantine {ip}: {message}"))

    def _apply_containment_state(self, ip: str, state: str) -> None:
        changed = False
        for row in self.scan_results:
            if str(row.get("remote_ip", "")) == ip:
                row["containment"] = state
                changed = True
        if changed:
            self._rerender_table()

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

    def _build_timeline_rows(self) -> list[dict[str, str | int]]:
        overlays = get_schedule_events(job_id=self.scheduled_job_id)
        return normalize_timeline_rows(self.scan_results, schedule_overlays=overlays)

    def _export_timeline_csv(self) -> None:
        rows = self._build_timeline_rows()
        filtered = filter_timeline_events(
            rows,
            status=self.timeline_status_var.get(),
            risk=self.timeline_risk_var.get(),
            source_ip=self.timeline_source_ip_var.get(),
        )
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        export_timeline_to_csv(filtered, path)
        self._log(f"Exported timeline CSV to {path}")

    def _export_timeline_xlsx(self) -> None:
        rows = self._build_timeline_rows()
        filtered = filter_timeline_events(
            rows,
            status=self.timeline_status_var.get(),
            risk=self.timeline_risk_var.get(),
            source_ip=self.timeline_source_ip_var.get(),
        )
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if not path:
            return
        export_timeline_to_xlsx(filtered, path)
        self._log(f"Exported timeline XLSX to {path}")

    def _open_charts_window(self) -> None:
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        from matplotlib.figure import Figure

        chart_window = ctk.CTkToplevel(self)
        chart_window.title("NetScouter Charts")
        chart_window.geometry("1060x760")

        controls = ctk.CTkFrame(chart_window, corner_radius=10)
        controls.pack(fill="x", padx=8, pady=(8, 4))

        ctk.CTkLabel(controls, text="Timeline Status").grid(row=0, column=0, padx=6, pady=8)
        ctk.CTkOptionMenu(
            controls,
            values=["All Status", "Open", "Closed"],
            variable=self.timeline_status_var,
            width=130,
        ).grid(row=0, column=1, padx=6, pady=8)

        ctk.CTkLabel(controls, text="Timeline Risk").grid(row=0, column=2, padx=6, pady=8)
        ctk.CTkOptionMenu(
            controls,
            values=["All Risk", "Low", "Average", "High"],
            variable=self.timeline_risk_var,
            width=130,
        ).grid(row=0, column=3, padx=6, pady=8)

        ctk.CTkLabel(controls, text="Source IP").grid(row=0, column=4, padx=6, pady=8)
        ctk.CTkEntry(controls, textvariable=self.timeline_source_ip_var, width=160).grid(row=0, column=5, padx=6, pady=8)

        figure = Figure(figsize=(10.2, 6.8), dpi=100)
        ax1 = figure.add_subplot(221)
        ax2 = figure.add_subplot(222)
        ax3 = figure.add_subplot(223)
        ax4 = figure.add_subplot(224)
        canvas = FigureCanvasTkAgg(figure, master=chart_window)

        def render_charts() -> None:
            rows = self._build_timeline_rows()
            filtered = filter_timeline_events(
                rows,
                status=self.timeline_status_var.get(),
                risk=self.timeline_risk_var.get(),
                source_ip=self.timeline_source_ip_var.get(),
            )

            risk_counts = Counter(str(row.get("risk", "Average")) for row in filtered)
            status_counts = Counter(str(row.get("status", "Closed")) for row in filtered)
            timeline = bucket_events_by_time(filtered, bucket="hour")
            heatmap, weekdays, _hours = build_heatmap_matrix(filtered)

            ax1.clear()
            ax2.clear()
            ax3.clear()
            ax4.clear()

            labels1 = list(risk_counts.keys())
            values1 = list(risk_counts.values())
            if values1:
                ax1.pie(values1, labels=labels1, autopct="%1.1f%%")
            else:
                ax1.text(0.5, 0.5, "No data", ha="center", va="center")
            ax1.set_title("Risk Distribution")

            labels2 = list(status_counts.keys())
            values2 = list(status_counts.values())
            ax2.bar(labels2, values2, color=["#0EA5E9", "#FFB100", "#39FF14"][: len(values2)])
            ax2.set_title("Status Count")
            ax2.set_ylabel("Connections")

            if timeline:
                x_vals = [item["bucket"] for item in timeline]
                y_vals = [item["total"] for item in timeline]
                ax3.plot(x_vals, y_vals, color="#FF6B6B", linewidth=2, label="attacks")
                for overlay in get_schedule_events(job_id=self.scheduled_job_id):
                    if str(overlay.get("action")) not in {"triggered", "scan_started"}:
                        continue
                    when = overlay.get("timestamp")
                    if isinstance(when, str):
                        parsed = datetime.fromisoformat(when.replace("Z", "+00:00"))
                        ax3.axvline(parsed, color="#8B5CF6", alpha=0.35, linestyle="--")
                ax3.legend(loc="upper left")
            else:
                ax3.text(0.5, 0.5, "No timeline events", ha="center", va="center")
            ax3.set_title("Attack Timeline (hourly)")
            ax3.tick_params(axis="x", rotation=35)

            image = ax4.imshow(heatmap, aspect="auto", cmap="magma")
            ax4.set_title("Weekday/Hour Attack Heatmap")
            ax4.set_yticks(range(len(weekdays)))
            ax4.set_yticklabels(weekdays)
            ax4.set_xticks([0, 4, 8, 12, 16, 20, 23])
            ax4.set_xticklabels(["00", "04", "08", "12", "16", "20", "23"])
            figure.colorbar(image, ax=ax4, fraction=0.046, pad=0.04)

            figure.tight_layout()
            canvas.draw()

        ctk.CTkButton(controls, text="Apply Filters", command=render_charts, width=120).grid(row=0, column=6, padx=6, pady=8)
        ctk.CTkButton(controls, text="Export CSV", command=self._export_timeline_csv, width=110).grid(row=0, column=7, padx=6, pady=8)
        ctk.CTkButton(controls, text="Export XLSX", command=self._export_timeline_xlsx, width=110).grid(row=0, column=8, padx=6, pady=8)

        canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=(4, 8))
        render_charts()

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
            quarantine_logs=self.quarantine_events,
        )
        self._log(f"Exported AI audit report to {path}")

    def export_xlsx(self) -> None:
        if not self.scan_results:
            self._log("No results to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if not path:
            return

        export_session_to_xlsx(self.scan_results, path, quarantine_logs=self.quarantine_events)
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

        self.packet_service.stop(timeout=0.8)
        self.honeypot.stop(timeout=0.8)

        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

        self.intel_executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def launch_dashboard() -> None:
    """Start the NetScouter dashboard."""
    app = NetScouterApp()
    app.mainloop()
