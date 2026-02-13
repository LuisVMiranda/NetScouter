"""Main NetScouter dashboard UI."""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import multiprocessing as mp
import time
import ipaddress
import importlib.util
import os
import platform
import queue
import shutil
import socket
import subprocess
import sys
import threading
from tkinter import Menu, filedialog, messagebox, ttk

import customtkinter as ctk
import psutil
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
    unbanish_ip,
)
from netscouter.gui.icons import get_process_identity_label
from netscouter.intel.geo import get_ip_intel
from netscouter.intel.reputation import evaluate_reputation_consensus
from netscouter.intel.packet_signals import evaluate_packet_signals
from netscouter.scanner.engine import ScanJob, ScanResult, scan_established_connections, scan_targets
from netscouter.scanner.honeypot import LocalHoneypot
from netscouter.scanner.packet_stream import PacketCaptureService, derive_lan_cidr
from netscouter.scanner.lan_mapper import DeviceRegistry, correlate_iot_outbound_anomalies, discover_lan_devices
from netscouter.scheduler.jobs import get_schedule_events, log_schedule_event
from netscouter.storage import get_preference, list_threat_events, record_scan_history, record_threat_event, set_preference
from netscouter.storage.preferences import DB_PATH

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

STOP_RED = "#7F1D1D"
STOP_RED_HOVER = "#991B1B"
CLEAR_AMBER = "#B45309"
CLEAR_AMBER_HOVER = "#92400E"

QUEUE_BATCH_LIMIT = 120
MAX_LOG_LINES = 2000
PACKET_SLICE_LIMIT = 120
TABLE_PAGE_SIZE = 200
TABLE_RENDER_CHUNK_SIZE = 40
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


def packet_alert_worker(input_queue: mp.Queue, output_queue: mp.Queue, stop_event: mp.Event) -> None:
    """Process packet events off the GUI thread and emit behavioral alerts."""
    hits_by_ip: dict[str, list[float]] = {}
    while not stop_event.is_set():
        try:
            event = input_queue.get(timeout=0.4)
        except Exception:
            continue
        ip = str(event.get("ip") or "").strip()
        if not ip:
            continue
        now = float(event.get("when") or time.time())
        bucket = hits_by_ip.setdefault(ip, [])
        bucket.append(now)
        hits_by_ip[ip] = [stamp for stamp in bucket if now - stamp <= 1.0]
        if len(hits_by_ip[ip]) > 10:
            output_queue.put({"ip": ip, "reason": "Connection frequency > 10 hits/sec", "points": 50})


class NetScouterApp(ctk.CTk):
    """Top-level dashboard window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("NetScouter")
        self.geometry("1280x820")

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
        self.intel_log_line_count = 0
        self.packet_log_line_count = 0
        self.packet_service = PacketCaptureService(max_packets=1200)
        self.honeypot = LocalHoneypot()
        self.packet_alert_cache: set[str] = set()
        self.quarantine_events: list[dict[str, str | bool]] = []
        self.threat_events: list[dict[str, str | bool]] = []
        self.threat_event_lookup: dict[str, dict[str, str | bool]] = {}
        self.selected_threat_event: dict[str, str | bool] | None = None
        self.temp_ban_timers: dict[str, threading.Timer] = {}
        self.selected_remote_ip: str | None = None
        self.selected_port: int | None = None
        self.local_ipv4 = "n/a"
        self.local_ipv6 = "n/a"
        self.packet_watchlist: set[str] = set()

        self.target_var = ctk.StringVar(value="127.0.0.1")
        self.port_range_var = ctk.StringVar(value="20-1024")
        self.local_info_var = ctk.StringVar(value="Local network context not loaded")
        self.schedule_hours_var = ctk.StringVar(value="6")
        self.firewall_status_var = ctk.StringVar(value="Not queried")
        self.firewall_rule_name_var = ctk.StringVar(value="NetScouter Custom Rule")
        self.firewall_rule_port_var = ctk.StringVar(value="")
        self.firewall_rule_ip_var = ctk.StringVar(value="")
        self.firewall_direction_var = ctk.StringVar(value="in")
        self.firewall_action_var = ctk.StringVar(value="block")
        self.firewall_protocol_var = ctk.StringVar(value="tcp")
        self.firewall_preset_var = ctk.StringVar(value="normal")

        self.status_filter_var = ctk.StringVar(value="All Ports")
        self.risk_filter_var = ctk.StringVar(value="All Risk")
        self.established_only_var = ctk.BooleanVar(value=False)
        self.timeline_status_var = ctk.StringVar(value="All Status")
        self.timeline_risk_var = ctk.StringVar(value="All Risk")
        self.timeline_source_ip_var = ctk.StringVar(value="")
        self.auto_block_consensus_var = ctk.BooleanVar(value=False)
        self.reputation_threshold_var = ctk.StringVar(value="3")
        self.reputation_timeout_var = ctk.StringVar(value="4")
        self.ai_timeout_var = ctk.StringVar(value="120")
        self.abuseipdb_key_var = ctk.StringVar(value=os.getenv("ABUSEIPDB_API_KEY", ""))
        self.virustotal_key_var = ctk.StringVar(
            value=os.getenv("VIRUSTOTAL_API_KEY", "") or os.getenv("VT_API_KEY", "")
        )
        self.otx_key_var = ctk.StringVar(value=os.getenv("OTX_API_KEY", ""))
        self.auto_blocked_ips: set[str] = set()
        self.auto_block_guard = threading.Lock()
        self.filtered_rows: list[dict[str, str | int | list[str]]] = []
        self.table_page_start = 0
        self._render_token = 0
        self._table_item_lookup: dict[str, dict[str, str | int | list[str]]] = {}
        self.ai_cancel_event = threading.Event()
        self.ai_job_thread: threading.Thread | None = None
        self.ai_elapsed_var = ctk.StringVar(value="Elapsed: 00:00")
        self.ai_started_at: float | None = None
        self.ai_timer_token = 0
        self.ai_max_rows_var = ctk.StringVar(value="600")
        self.ai_high_risk_only_var = ctk.BooleanVar(value=True)
        self.ai_open_ports_only_var = ctk.BooleanVar(value=False)
        self.ai_alerts_only_var = ctk.BooleanVar(value=False)
        self.theme_cards: list[ctk.CTkFrame] = []
        self.firewall_refresh_in_progress = False
        self._last_firewall_status_fetch = 0.0
        self._table_tooltip: ctk.CTkToplevel | None = None
        self._table_tooltip_label: ctk.CTkLabel | None = None
        self.stop_all_requested = False
        self.device_registry = DeviceRegistry()
        self.discovered_devices: list[dict[str, str]] = []
        self.lan_anomalies: list[dict[str, str | int]] = []
        self.automation_enabled_var = ctk.BooleanVar(value=False)
        self.automation_threshold_var = ctk.StringVar(value="80")
        self.automation_action_var = ctk.StringVar(value="banish")
        self.automation_triggered_ips: set[str] = set()
        self.automation_scoreboard: dict[str, dict[str, object]] = {}
        self.automation_scope_var = ctk.StringVar(value="All Connections")
        self.automation_points_unassigned_var = ctk.StringVar(value="20")
        self.automation_points_frequency_var = ctk.StringVar(value="50")
        self.automation_points_dns_var = ctk.StringVar(value="30")
        self.automation_dns_cache: dict[str, bool] = {}
        self.automation_dns_pending: set[str] = set()
        self.popup_notifications_var = ctk.BooleanVar(value=True)
        self.packet_stream_mode_var = ctk.StringVar(value="Selected Row")
        self.packet_scope_hint_var = ctk.StringVar(value="Scope: select a row or set target host")
        self.packet_stream_status_var = ctk.StringVar(value="Live stream idle")
        self.packet_risk_filter_var = ctk.StringVar(value="All")
        self.packet_behavior_filter_var = ctk.StringVar(value="All")
        self.packet_selected_summary_var = ctk.StringVar(value="Select a packet row to inspect details.")
        self.packet_selected_packet: dict[str, object] | None = None
        self.packet_filtered_packets: list[dict[str, object]] = []
        self.blocked_packet_ips: set[str] = set()
        self.ai_log_source_var = ctk.StringVar(value="App Logs")
        self.ai_external_log_path_var = ctk.StringVar(value="")
        self.ai_data_type_var = ctk.StringVar(value="Port Scan")
        self.prompt_type_var = ctk.StringVar(value="Port Scan")
        self.log_detail_mode_var = ctk.StringVar(value="Expert")
        self.save_ports_var = ctk.BooleanVar(value=True)
        self.save_packets_var = ctk.BooleanVar(value=True)
        self.save_intel_var = ctk.BooleanVar(value=False)
        self.save_ai_var = ctk.BooleanVar(value=False)
        self.settings_save_feedback_var = ctk.StringVar(value="")
        self.threat_action_hint_var = ctk.StringVar(value="Select a threat row to inspect evidence and follow-up guidance.")
        self.local_info_visible = False

        self._configure_grid()
        self._build_layout()
        self._load_saved_prompt_templates()
        self._load_runtime_preferences()
        self._load_threat_events_from_db()
        self._refresh_threats_table()
        self._apply_theme()
        self.after(80, self._maximize_window)

        self._start_honeypot()
        self._ensure_nmap_available()
        self._init_packet_alert_process()
        self._ensure_tray_icon()

        self.after(120, self._drain_ui_queue)
        self.after(300, self._poll_packet_alert_queue)
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

    def _ensure_nmap_available(self) -> None:
        if shutil.which("nmap"):
            self._log("Dependency check: nmap detected.")
            return
        self._log("Dependency check: nmap missing. Attempting automatic install...")
        system = platform.system().lower()
        commands = []
        if system == "linux":
            commands = [["bash", "-lc", "apt-get update && apt-get install -y nmap"]]
        elif system == "darwin":
            commands = [["brew", "install", "nmap"]]
        elif system == "windows":
            commands = [["winget", "install", "Nmap.Nmap", "-e"]]
        for cmd in commands:
            try:
                proc = subprocess.run(cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
            except Exception as exc:  # noqa: BLE001
                self._log(f"nmap auto-install failed: {exc}")
                break
            if proc.returncode == 0 and shutil.which("nmap"):
                self._log("nmap installed successfully.")
                return
        self._log("Could not auto-install nmap. Please use installer/wizard for your OS.")

    def _init_packet_alert_process(self) -> None:
        self.packet_alert_input: mp.Queue = mp.Queue()
        self.packet_alert_output: mp.Queue = mp.Queue()
        self.packet_alert_stop = mp.Event()
        self.packet_alert_proc = mp.Process(
            target=packet_alert_worker,
            args=(self.packet_alert_input, self.packet_alert_output, self.packet_alert_stop),
            daemon=True,
            name="packet-alert-worker",
        )
        self.packet_alert_proc.start()

    def _poll_packet_alert_queue(self) -> None:
        for _ in range(20):
            try:
                event = self.packet_alert_output.get_nowait()
            except Exception:
                break
            ip = str(event.get("ip") or "")
            points = self._automation_points("frequency") if int(event.get("points") or 0) > 0 else 0
            reason = str(event.get("reason") or "")
            if ip:
                try:
                    obj = ipaddress.ip_address(ip)
                    if obj.is_private or obj.is_loopback or obj.is_link_local:
                        continue
                except ValueError:
                    continue
                self._update_behavioral_score(ip, points, reason)
        self.after(300, self._poll_packet_alert_queue)

    def _notify_popup(self, message: str, *, tab: str = "Dashboard") -> None:
        if not self.popup_notifications_var.get():
            return
        popup = ctk.CTkToplevel(self)
        popup.overrideredirect(True)
        width, height = 360, 110
        x = max(0, self.winfo_screenwidth() - width - 30)
        y = max(0, self.winfo_screenheight() - height - 70)
        popup.geometry(f"{width}x{height}+{x}+{y}")
        bg = "#111827" if self.current_mode == "dark" else "#DBEAFE"
        fg = "#E2E8F0" if self.current_mode == "dark" else "#1E3A8A"
        accent = "#0EA5E9" if self.current_mode == "dark" else "#2563EB"
        popup.configure(fg_color=bg)
        shell = ctk.CTkFrame(popup, fg_color=bg)
        shell.pack(fill="both", expand=True)
        ctk.CTkFrame(shell, width=5, fg_color=accent).pack(side="left", fill="y")
        content = ctk.CTkFrame(shell, fg_color=bg)
        content.pack(side="left", fill="both", expand=True, padx=(8, 6), pady=4)
        ctk.CTkLabel(content, text="NetScouter - Notification", text_color=fg, font=ctk.CTkFont(family="Roboto Medium", size=12, weight="bold"), anchor="w").pack(fill="x", padx=2, pady=(0,1))
        close_btn = ctk.CTkButton(content, text="X", width=13, height=13, fg_color=STOP_RED, hover_color=STOP_RED_HOVER, command=popup.destroy)
        close_btn.place(relx=1.0, x=-2, y=2, anchor="ne")
        body = ctk.CTkLabel(content, text=message, text_color=fg, justify="left", anchor="w", wraplength=320, font=ctk.CTkFont(family="Roboto Medium", size=12))
        body.pack(fill="both", expand=True, padx=2, pady=(4, 6))

        def open_tab(_event: object) -> None:
            popup.destroy()
            self.deiconify()
            self.lift()
            self.focus_force()
            self._show_workspace_tab(tab)

        body.bind("<Button-1>", open_tab)
        popup.after(5000, popup.destroy)

    def _configure_grid(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

    def _register_card(self, frame: ctk.CTkFrame) -> ctk.CTkFrame:
        self.theme_cards.append(frame)
        return frame

    def _build_layout(self) -> None:
        self.topbar = self._register_card(ctk.CTkFrame(self, corner_radius=10))
        self.topbar.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        self.topbar.grid_columnconfigure(0, weight=1)

        left_bar = self._register_card(ctk.CTkFrame(self.topbar, corner_radius=10))
        left_bar.grid(row=0, column=0, sticky="w", padx=8, pady=8)
        ctk.CTkLabel(left_bar, text="NetScouter", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, padx=(8, 14), pady=8)

        self.tab_buttons: dict[str, ctk.CTkButton] = {}
        self.workspace_panes: dict[str, ctk.CTkFrame] = {}
        tabs = ["Dashboard", "Packet Filtering", "Intelligence", "AI Auditor", "Operations", "Possible Threats", "Settings"]
        for index, name in enumerate(tabs, start=1):
            button = ctk.CTkButton(
                left_bar,
                text=name,
                height=34,
                width=132,
                command=lambda tab_name=name: self._show_workspace_tab(tab_name),
            )
            button.grid(row=0, column=index, padx=4, pady=8)
            self.tab_buttons[name] = button

        right_bar = self._register_card(ctk.CTkFrame(self.topbar, corner_radius=10))
        right_bar.grid(row=0, column=1, sticky="e", padx=8, pady=8)
        ctk.CTkLabel(right_bar, text="Appearance").grid(row=0, column=0, padx=(8, 4), pady=8)
        self.theme_switch = ctk.CTkSegmentedButton(
            right_bar,
            values=["Dark", "Light"],
            command=self._switch_theme,
            corner_radius=10,
            width=160,
        )
        self.theme_switch.set("Dark")
        self.theme_switch.grid(row=0, column=1, padx=(4, 8), pady=8)

        self.workspace = self._register_card(ctk.CTkFrame(self, corner_radius=10))
        self.workspace.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self.workspace.grid_columnconfigure(0, weight=1)
        self.workspace.grid_rowconfigure(0, weight=1)

        self._build_dashboard_tab(self._create_workspace_pane("Dashboard"))
        self._build_packet_filtering_tab(self._create_workspace_pane("Packet Filtering"))
        self._build_possible_threats_tab(self._create_workspace_pane("Possible Threats"))
        self._build_intelligence_tab(self._create_workspace_pane("Intelligence"))
        self._build_ai_auditor_tab(self._create_workspace_pane("AI Auditor"))
        self._build_ops_schedule_tab(self._create_workspace_pane("Operations"))
        self._build_settings_tab(self._create_workspace_pane("Settings"))
        self._show_workspace_tab("Dashboard")

    def _maximize_window(self) -> None:
        try:
            self.state("zoomed")
            return
        except Exception:  # noqa: BLE001
            pass
        width = max(1280, self.winfo_screenwidth())
        height = max(820, self.winfo_screenheight())
        self.geometry(f"{width}x{height}+0+0")

    def _create_workspace_pane(self, name: str) -> ctk.CTkFrame:
        pane = self._register_card(ctk.CTkFrame(self.workspace, corner_radius=10))
        pane.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        self.workspace_panes[name] = pane
        return pane

    def _show_workspace_tab(self, name: str) -> None:
        self.workspace_panes[name].tkraise()
        for tab_name, button in self.tab_buttons.items():
            button.configure(fg_color=("#1E3A8A" if tab_name == name else "#374151"))

    def _build_dashboard_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_rowconfigure(2, weight=1)

        self.scan_row = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        self.scan_row.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        self.scan_row.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(self.scan_row, text="Target").grid(row=0, column=0, padx=(6, 2), pady=8, sticky="w")
        ctk.CTkEntry(self.scan_row, textvariable=self.target_var, placeholder_text="127.0.0.1 or hostname").grid(row=0, column=1, columnspan=2, padx=(2, 6), pady=8, sticky="ew")
        ctk.CTkLabel(self.scan_row, text="Port Range").grid(row=0, column=4, padx=6, pady=8, sticky="w")
        ctk.CTkEntry(self.scan_row, width=140, textvariable=self.port_range_var, placeholder_text="20-1024").grid(row=0, column=5, padx=6, pady=8)
        self.scan_button = ctk.CTkButton(self.scan_row, text="Scan", corner_radius=10, command=self.start_scan, width=110)
        self.scan_button.grid(row=0, column=6, padx=6, pady=8, sticky="w")
        self.scan_established_button = ctk.CTkButton(self.scan_row, text="Scan Established", corner_radius=10, command=self.start_established_scan, width=150)
        self.scan_established_button.grid(row=0, column=7, padx=6, pady=8, sticky="w")

        ctk.CTkButton(self.scan_row, text="Stop All", corner_radius=10, width=110, command=self.stop_all_tasks, fg_color=STOP_RED, hover_color=STOP_RED_HOVER).grid(row=0, column=8, padx=6, pady=8, sticky="w")
        ctk.CTkButton(self.scan_row, text="Show Charts", corner_radius=10, command=self.show_charts, width=110).grid(row=1, column=0, padx=6, pady=8, sticky="w")
        ctk.CTkButton(self.scan_row, text="Save Log (DB)", corner_radius=10, width=120, command=lambda: self.save_logs_to_db("dashboard")).grid(row=1, column=1, padx=6, pady=8, sticky="w")
        self.local_info_button = ctk.CTkButton(self.scan_row, text="Local IP", corner_radius=10, command=self.toggle_local_network_info, width=120)
        self.local_info_button.grid(row=2, column=0, padx=6, pady=(2, 8), sticky="w")

        ctk.CTkLabel(
            self.scan_row,
            textvariable=self.local_info_var,
            anchor="w",
            justify="left",
            wraplength=980,
        ).grid(row=2, column=1, columnspan=8, padx=8, pady=(0, 8), sticky="ew")

        self._build_results_table(pane, row=2)

    def _build_intelligence_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_rowconfigure(8, weight=1)

        guide = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        guide.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkLabel(
            guide,
            text=(
                "Configure threat-intel providers. Keys are optional but improve reputation consensus accuracy. "
                "Typical key format is long alphanumeric API tokens."
            ),
            anchor="w",
            justify="left",
            wraplength=1100,
        ).grid(row=0, column=0, padx=10, pady=8, sticky="w")

        self.settings_row = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        self.settings_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkLabel(self.settings_row, text="AbuseIPDB key").grid(row=0, column=0, padx=(8, 4), pady=8, sticky="w")
        ctk.CTkEntry(self.settings_row, width=260, textvariable=self.abuseipdb_key_var, placeholder_text="e.g. 1f2a...abuseipdb-token").grid(row=0, column=1, padx=4, pady=8)
        ctk.CTkLabel(self.settings_row, text="VirusTotal key").grid(row=0, column=2, padx=(8, 4), pady=8, sticky="w")
        ctk.CTkEntry(self.settings_row, width=260, textvariable=self.virustotal_key_var, placeholder_text="e.g. 5ab3...virustotal-api-key").grid(row=0, column=3, padx=4, pady=8)
        ctk.CTkLabel(self.settings_row, text="(API v3 key from VirusTotal profile)", anchor="w").grid(row=0, column=8, padx=(4, 8), pady=8, sticky="w")
        ctk.CTkLabel(self.settings_row, text="AlienVault OTX key").grid(row=1, column=0, padx=(8, 4), pady=8, sticky="w")
        ctk.CTkEntry(self.settings_row, width=260, textvariable=self.otx_key_var, placeholder_text="e.g. 7cd9...otx-token").grid(row=1, column=1, padx=4, pady=8)
        ctk.CTkLabel(self.settings_row, text="Consensus Threshold").grid(row=1, column=2, padx=(8, 4), pady=8)
        ctk.CTkEntry(self.settings_row, width=70, textvariable=self.reputation_threshold_var, placeholder_text="3").grid(row=1, column=3, padx=4, pady=8, sticky="w")
        ctk.CTkLabel(self.settings_row, text="Intel timeout (s)").grid(row=0, column=4, padx=(8, 4), pady=8)
        ctk.CTkEntry(self.settings_row, width=80, textvariable=self.reputation_timeout_var, placeholder_text="4").grid(row=0, column=5, padx=4, pady=8)
        ctk.CTkLabel(self.settings_row, text="AI timeout (s)").grid(row=1, column=4, padx=(8, 4), pady=8)
        ctk.CTkEntry(self.settings_row, width=80, textvariable=self.ai_timeout_var, placeholder_text="120").grid(row=1, column=5, padx=4, pady=8)
        ctk.CTkCheckBox(self.settings_row, text="Auto-block by consensus", variable=self.auto_block_consensus_var).grid(row=0, column=6, rowspan=2, padx=10, pady=8)
        ctk.CTkButton(self.settings_row, text="Apply Intel Keys", command=self.apply_settings, width=130).grid(row=0, column=7, rowspan=2, padx=(4, 10), pady=8)

        firewall_frame = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        firewall_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkLabel(firewall_frame, text="Firewall Operations", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")
        self._build_firewall_controls(firewall_frame, start_row=1)

        self._build_console(pane, row=3, compact=True)

    def _build_ops_schedule_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_rowconfigure(5, weight=1)

        schedule_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        schedule_label.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkLabel(schedule_label, text="Scheduling", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        self.ops_row = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        self.ops_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkLabel(self.ops_row, text="Every (hours)").grid(row=0, column=0, padx=6, pady=8)
        ctk.CTkEntry(self.ops_row, width=70, textvariable=self.schedule_hours_var, placeholder_text="6").grid(row=0, column=1, padx=6, pady=8)
        ctk.CTkButton(self.ops_row, text="Start Recurring", corner_radius=10, command=self.start_recurring_scan, width=130).grid(row=0, column=2, padx=6, pady=8)
        ctk.CTkButton(self.ops_row, text="Stop Recurring", corner_radius=10, command=self.stop_recurring_scan, width=120).grid(row=0, column=3, padx=6, pady=8)
        self.ops_refresh_firewall_button = ctk.CTkButton(self.ops_row, text="Refresh Firewall", corner_radius=10, command=self.refresh_firewall_insight, width=140)
        self.ops_refresh_firewall_button.grid(row=0, column=4, padx=6, pady=8)
        ctk.CTkButton(self.ops_row, text="STOP ALL", corner_radius=10, command=self.stop_all_tasks, width=110, fg_color="#DC2626", hover_color="#B91C1C").grid(row=0, column=5, padx=6, pady=8)
        ctk.CTkLabel(self.ops_row, text="Firewall:").grid(row=0, column=6, padx=(10, 4), pady=8)
        ctk.CTkLabel(self.ops_row, textvariable=self.firewall_status_var, width=300, anchor="w").grid(row=0, column=7, padx=4, pady=8, sticky="w")

        automation_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        automation_label.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkLabel(automation_label, text="Conditional Automations", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        automation_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        automation_card.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkCheckBox(automation_card, text="Enable auto-response", variable=self.automation_enabled_var).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkLabel(automation_card, text="Point threshold").grid(row=0, column=2, padx=(12, 4), pady=6)
        ctk.CTkEntry(automation_card, width=70, textvariable=self.automation_threshold_var, placeholder_text="80").grid(row=0, column=3, padx=4, pady=6)
        ctk.CTkLabel(automation_card, text="Action").grid(row=0, column=4, padx=(12, 4), pady=6)
        ctk.CTkOptionMenu(automation_card, values=["quarantine", "banish"], variable=self.automation_action_var, width=120).grid(row=0, column=5, padx=4, pady=6)
        ctk.CTkOptionMenu(automation_card, values=["All Connections", "Open Ports Only", "Established Only"], variable=self.automation_scope_var, width=150).grid(row=0, column=6, padx=4, pady=6)
        ctk.CTkLabel(automation_card, text="Pts: unassigned").grid(row=1, column=0, padx=(10,4), pady=(0,6), sticky="w")
        ctk.CTkEntry(automation_card, width=55, textvariable=self.automation_points_unassigned_var, placeholder_text="20").grid(row=1, column=1, padx=4, pady=(0,6), sticky="w")
        ctk.CTkLabel(automation_card, text="freq").grid(row=1, column=2, padx=(10,4), pady=(0,6), sticky="w")
        ctk.CTkEntry(automation_card, width=55, textvariable=self.automation_points_frequency_var, placeholder_text="50").grid(row=1, column=3, padx=4, pady=(0,6), sticky="w")
        ctk.CTkLabel(automation_card, text="dns/vpn").grid(row=1, column=4, padx=(10,4), pady=(0,6), sticky="w")
        ctk.CTkEntry(automation_card, width=55, textvariable=self.automation_points_dns_var, placeholder_text="30").grid(row=1, column=5, padx=4, pady=(0,6), sticky="w")

        lan_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        lan_label.grid(row=4, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkLabel(lan_label, text="LAN Device Monitor", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        lan_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        lan_card.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))
        lan_card.grid_columnconfigure(0, weight=1)
        lan_card.grid_rowconfigure(2, weight=1)

        header = self._register_card(ctk.CTkFrame(lan_card, corner_radius=10))
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkLabel(header, text="LAN Controls").grid(row=0, column=0, padx=8, pady=6, sticky="w")
        ctk.CTkButton(header, text="Discover Devices", width=130, command=self.refresh_lan_devices).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(header, text="Show IoT Anomalies", width=140, command=self.show_lan_anomalies).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkButton(header, text="Quarantine Device IP", width=150, command=self.quarantine_selected_lan_device).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkButton(header, text="Banish Device IP", width=130, command=self.banish_selected_lan_device).grid(row=0, column=4, padx=6, pady=6)

        self.lan_status_var = ctk.StringVar(value="No discovery yet")
        ctk.CTkLabel(lan_card, textvariable=self.lan_status_var, anchor="w").grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 6))

        columns = ("ip", "hostname", "vendor", "type", "mac")
        self.lan_table = ttk.Treeview(lan_card, columns=columns, show="headings", selectmode="browse", height=8)
        headings = {"ip": "IP", "hostname": "Hostname", "vendor": "Vendor", "type": "Type", "mac": "MAC"}
        widths = {"ip": 150, "hostname": 200, "vendor": 220, "type": 90, "mac": 150}
        for col in columns:
            self.lan_table.heading(col, text=headings[col])
            self.lan_table.column(col, width=widths[col], anchor="center")
        y_scroll = ttk.Scrollbar(lan_card, orient="vertical", command=self.lan_table.yview, style="NetScouter.Vertical.TScrollbar")
        self.lan_table.configure(yscrollcommand=y_scroll.set)
        self.lan_table.grid(row=2, column=0, sticky="nsew", padx=(8, 0), pady=(0, 8))
        y_scroll.grid(row=2, column=1, sticky="ns", padx=(0, 8), pady=(0, 8))
        self.lan_table.bind("<Button-3>", self._open_lan_context_menu)

        ops_actions = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        ops_actions.grid(row=6, column=0, sticky="ew", padx=8, pady=(0, 8))
        ctk.CTkButton(ops_actions, text="Export AI Audit", corner_radius=10, command=self.export_ai_audit, width=140).grid(row=0, column=0, padx=8, pady=10)
        ctk.CTkButton(ops_actions, text="Export XLSX", corner_radius=10, command=self.export_xlsx, width=120).grid(row=0, column=1, padx=8, pady=10)

    def _build_settings_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_rowconfigure(8, weight=1)

        dashboard_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        dashboard_label.grid(row=0, column=0, sticky="ew", padx=8, pady=(10, 5))
        ctk.CTkLabel(dashboard_label, text="Dashboard Settings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        dashboard_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        dashboard_card.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 10))
        ctk.CTkEntry(dashboard_card, textvariable=self.target_var, width=180, placeholder_text="Persistent target IP/hostname").grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkEntry(dashboard_card, textvariable=self.port_range_var, width=120, placeholder_text="Persistent port range").grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkOptionMenu(dashboard_card, values=["Layman", "Expert"], variable=self.log_detail_mode_var, width=110).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkCheckBox(dashboard_card, text="Popup notifications", variable=self.popup_notifications_var).grid(row=0, column=4, padx=6, pady=6)

        packet_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        packet_label.grid(row=2, column=0, sticky="ew", padx=8, pady=(5, 5))
        ctk.CTkLabel(packet_label, text="Packet Filtering Settings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        packet_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        packet_card.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 10))
        ctk.CTkCheckBox(packet_card, text="Save Port Scan logs", variable=self.save_ports_var).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkCheckBox(packet_card, text="Save Packet logs", variable=self.save_packets_var).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkCheckBox(packet_card, text="Save Intel events", variable=self.save_intel_var).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkCheckBox(packet_card, text="Save AI output", variable=self.save_ai_var).grid(row=0, column=4, padx=6, pady=6)

        intel_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        intel_label.grid(row=4, column=0, sticky="ew", padx=8, pady=(5, 5))
        ctk.CTkLabel(intel_label, text="Intelligence/API Settings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        intel_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        intel_card.grid(row=5, column=0, sticky="ew", padx=8, pady=(0, 10))
        ctk.CTkEntry(intel_card, textvariable=self.abuseipdb_key_var, width=220, placeholder_text="AbuseIPDB API key").grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkEntry(intel_card, textvariable=self.virustotal_key_var, width=220, placeholder_text="VirusTotal API key").grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkEntry(intel_card, textvariable=self.otx_key_var, width=220, placeholder_text="AlienVault OTX key").grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkButton(intel_card, text="Apply Intel Keys", width=130, command=self.apply_settings).grid(row=0, column=4, padx=6, pady=6)

        ai_label = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        ai_label.grid(row=6, column=0, sticky="ew", padx=8, pady=(5, 5))
        ctk.CTkLabel(ai_label, text="AI Auditor/Database", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

        ai_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        ai_card.grid(row=7, column=0, sticky="ew", padx=8, pady=(0, 10))
        ctk.CTkButton(ai_card, text="Clear DB Logs", width=130, command=self.clear_db_logs, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkButton(ai_card, text="Clear Prompt Prefs", width=150, command=self.clear_prompt_prefs, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(ai_card, text="Save All Settings", width=150, command=self.save_settings_preferences, fg_color="#0F766E", hover_color="#115E59").grid(row=0, column=2, padx=(16, 6), pady=6)
        ctk.CTkLabel(ai_card, textvariable=self.settings_save_feedback_var, anchor="w").grid(row=0, column=3, padx=(4, 6), pady=6, sticky="w")
        ctk.CTkLabel(ai_card, text="Use Save All Settings to persist every option above.", anchor="w").grid(row=1, column=0, columnspan=4, padx=10, pady=(0, 6), sticky="w")

    def _build_possible_threats_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_rowconfigure(1, weight=1)
        pane.grid_rowconfigure(2, weight=1)

        header = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkLabel(header, text="Possible Threats", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")
        ctk.CTkButton(header, text="Refresh", width=92, command=self._refresh_threats_table).grid(row=0, column=1, padx=4, pady=6)
        ctk.CTkButton(header, text="Drop/Block IP", width=108, command=self._threat_block_selected).grid(row=0, column=2, padx=4, pady=6)
        ctk.CTkButton(header, text="Quarantine IP", width=118, command=self._threat_quarantine_selected).grid(row=0, column=3, padx=4, pady=6)
        ctk.CTkButton(header, text="Temp Ban", width=96, command=self._threat_temp_ban_selected).grid(row=0, column=4, padx=4, pady=6)
        ctk.CTkButton(header, text="Unban + Watch", width=116, command=self._threat_unban_watch_selected).grid(row=0, column=5, padx=4, pady=6)
        ctk.CTkButton(header, text="Unban IP", width=92, command=self._threat_unban_selected).grid(row=0, column=6, padx=4, pady=6)

        cols = ("timestamp", "ip", "action", "status", "reason", "expires")
        self.threats_table = ttk.Treeview(pane, columns=cols, show="headings", height=10, selectmode="browse")
        widths = {"timestamp": 165, "ip": 170, "action": 105, "status": 100, "reason": 360, "expires": 150}
        for col in cols:
            self.threats_table.heading(col, text=col.title())
            self.threats_table.column(col, width=widths[col], anchor="center")
        y_scroll = ttk.Scrollbar(pane, orient="vertical", command=self.threats_table.yview, style="NetScouter.Vertical.TScrollbar")
        self.threats_table.configure(yscrollcommand=y_scroll.set)
        self.threats_table.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 6))
        y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 6))
        self.threats_table.bind("<<TreeviewSelect>>", self._on_threat_selected)

        bottom = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        bottom.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=2)
        bottom.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(bottom, text="Evidence Timeline", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))
        ctk.CTkLabel(bottom, text="Threat Detail", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, sticky="w", padx=10, pady=(8, 4))

        self.threat_timeline_box = ctk.CTkTextbox(bottom, corner_radius=10)
        self.threat_timeline_box.grid(row=1, column=0, sticky="nsew", padx=(10, 6), pady=(0, 8))
        self.threat_detail_box = ctk.CTkTextbox(bottom, corner_radius=10)
        self.threat_detail_box.grid(row=1, column=1, sticky="nsew", padx=(6, 10), pady=(0, 8))
        ctk.CTkButton(bottom, text="⧉ Copy Threat Detail", width=150, command=self._copy_threat_detail).grid(row=2, column=1, sticky="e", padx=10, pady=(0, 4))
        ctk.CTkLabel(bottom, textvariable=self.threat_action_hint_var, anchor="w").grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))

    def _build_results_table(self, parent: ctk.CTkFrame, row: int) -> None:
        self.table_card = self._register_card(ctk.CTkFrame(parent, corner_radius=10))
        self.table_card.grid(row=row, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.table_card.grid_rowconfigure(1, weight=1)
        self.table_card.grid_rowconfigure(4, weight=0)
        self.table_card.grid_columnconfigure(0, weight=1)

        self.filter_row = self._register_card(ctk.CTkFrame(self.table_card, corner_radius=10))
        self.filter_row.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.filter_row.grid_columnconfigure(0, weight=1)
        self.filter_row.grid_columnconfigure(1, weight=1)

        filter_left = ctk.CTkFrame(self.filter_row, fg_color="transparent")
        filter_left.grid(row=0, column=0, sticky="w", padx=(6, 18), pady=6)
        filter_right = ctk.CTkFrame(self.filter_row, fg_color="transparent")
        filter_right.grid(row=0, column=1, sticky="e", padx=(18, 6), pady=6)

        ctk.CTkLabel(filter_left, text="Display Filters:").grid(row=0, column=0, padx=4, pady=6)
        self.status_filter = ctk.CTkOptionMenu(filter_left, values=["All Ports", "Open Ports", "Closed Ports"], variable=self.status_filter_var, command=lambda _: self._rerender_table(), corner_radius=10, width=130)
        self.status_filter.grid(row=0, column=1, padx=4, pady=6)
        self.risk_filter = ctk.CTkOptionMenu(filter_left, values=["All Risk", "Low", "Average", "High"], variable=self.risk_filter_var, command=lambda _: self._rerender_table(), corner_radius=10, width=130)
        self.risk_filter.grid(row=0, column=2, padx=4, pady=6)
        ctk.CTkCheckBox(filter_left, text="Established-only", variable=self.established_only_var, command=self._rerender_table).grid(row=0, column=3, padx=4, pady=6)
        ctk.CTkButton(filter_left, text="Clear Filters", corner_radius=10, width=120, command=self.clear_filters, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=4, padx=4, pady=6)
        ctk.CTkButton(filter_left, text="Clear Scan Logs", corner_radius=10, width=130, command=self.clear_scan_logs, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=5, padx=4, pady=6)

        ctk.CTkButton(filter_right, text="◀", width=38, command=self._prev_table_page).grid(row=0, column=0, padx=(6, 2), pady=6)
        ctk.CTkButton(filter_right, text="▶", width=38, command=self._next_table_page).grid(row=0, column=1, padx=(2, 6), pady=6)

        self.filter_summary_var = ctk.StringVar(value="Showing 0 / 0 rows")
        ctk.CTkLabel(self.filter_row, textvariable=self.filter_summary_var).grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 8), sticky="w")

        columns = ("port", "status", "remote_ip", "process", "exe_path", "location", "provider", "consensus", "risk", "containment", "alerts")
        self.results_table = ttk.Treeview(self.table_card, columns=columns, show="headings", selectmode="extended")
        headings = {"port": "Port", "status": "Status", "remote_ip": "Remote IP", "process": "Process", "exe_path": "Executable Path", "location": "Location", "provider": "Provider", "consensus": "Consensus", "risk": "Risk", "containment": "Containment", "alerts": "Alerts"}
        widths = {"port": 80, "status": 90, "remote_ip": 170, "process": 180, "exe_path": 300, "location": 160, "provider": 170, "consensus": 110, "risk": 80, "containment": 120, "alerts": 200}
        for name in columns:
            self.results_table.heading(name, text=headings[name])
            self.results_table.column(name, width=widths[name], anchor="center")

        y_scroll = ttk.Scrollbar(self.table_card, orient="vertical", command=self.results_table.yview, style="NetScouter.Vertical.TScrollbar")
        x_scroll = ttk.Scrollbar(self.table_card, orient="horizontal", command=self.results_table.xview, style="NetScouter.Horizontal.TScrollbar")
        self.results_table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.results_table.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(4, 0))
        y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 10), pady=(4, 0))
        x_scroll.grid(row=2, column=0, sticky="ew", padx=(10, 10), pady=(0, 6))
        self.results_table.bind("<<TreeviewSelect>>", self._on_table_select)
        self.results_table.bind("<Double-1>", self._open_selected_row_report)
        self.results_table.bind("<Button-3>", self._open_table_context_menu)
        self.results_table.bind("<Motion>", self._on_table_hover)
        self.results_table.bind("<Leave>", lambda _e: self._hide_table_tooltip())

        self.dashboard_console_card = self._register_card(ctk.CTkFrame(self.table_card, corner_radius=10))
        self.dashboard_console_card.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        self.dashboard_console_card.grid_columnconfigure(0, weight=1)
        self.dashboard_console = ctk.CTkTextbox(self.dashboard_console_card, corner_radius=10, height=150)
        self.dashboard_console.grid(row=0, column=0, sticky="ew", padx=8, pady=8)


    def _build_packet_filtering_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_rowconfigure(2, weight=1)

        controls = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        controls.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkOptionMenu(controls, values=["Selected Row", "Target Host", "Local Network"], variable=self.packet_stream_mode_var, width=140, command=self._on_packet_scope_changed).grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkButton(controls, text="Start Live Packet Stream", corner_radius=10, width=180, command=self.start_live_packet_stream).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(controls, text="Stop", corner_radius=10, width=90, command=self.stop_live_packet_stream, fg_color=STOP_RED, hover_color=STOP_RED_HOVER).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkButton(controls, text="Export packet slice", corner_radius=10, width=140, command=self.export_packet_slice).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkButton(controls, text="Save Log (DB)", corner_radius=10, width=120, command=lambda: self.save_logs_to_db("packet_filtering")).grid(row=0, column=6, padx=6, pady=6)
        ctk.CTkOptionMenu(controls, values=["All", "High", "Average", "Low"], variable=self.packet_risk_filter_var, width=100, command=lambda _x: self._refresh_packet_filtering_table()).grid(row=0, column=4, padx=6, pady=6)
        ctk.CTkOptionMenu(controls, values=["All", "Weird", "Normal"], variable=self.packet_behavior_filter_var, width=100, command=lambda _x: self._refresh_packet_filtering_table()).grid(row=0, column=5, padx=6, pady=6)
        ctk.CTkLabel(controls, textvariable=self.packet_stream_status_var).grid(row=1, column=0, columnspan=3, padx=8, pady=(0, 6), sticky="w")
        ctk.CTkLabel(controls, textvariable=self.packet_scope_hint_var).grid(row=1, column=3, columnspan=3, padx=8, pady=(0, 6), sticky="e")

        self.packet_filter_table = ttk.Treeview(pane, columns=("time", "connection", "proto", "risk", "behavior", "process"), show="headings", height=12)
        for col, width in {"time": 180, "connection": 380, "proto": 90, "risk": 90, "behavior": 140, "process": 220}.items():
            self.packet_filter_table.heading(col, text=col.title())
            self.packet_filter_table.column(col, width=width, anchor="center")
        pkt_y_scroll = ttk.Scrollbar(pane, orient="vertical", command=self.packet_filter_table.yview, style="NetScouter.Vertical.TScrollbar")
        self.packet_filter_table.configure(yscrollcommand=pkt_y_scroll.set)
        self.packet_filter_table.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 6))
        pkt_y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 6))
        self.packet_filter_table.bind("<<TreeviewSelect>>", self._on_packet_filter_select)
        self.packet_filter_table.bind("<Button-3>", self._open_packet_filter_context_menu)

        detail = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        detail.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        detail.grid_columnconfigure(0, weight=1)
        detail.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(detail, textvariable=self.packet_selected_summary_var, anchor="w", justify="left").grid(row=0, column=0, sticky="ew", padx=8, pady=6)
        self.packet_detail_box = ctk.CTkTextbox(detail, corner_radius=10, height=180)
        self.packet_detail_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=6)
        self.packet_stream_console = self.packet_detail_box
        action_row = ctk.CTkFrame(detail, fg_color="transparent")
        action_row.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8))
        ctk.CTkButton(action_row, text="Block Selected IP", width=140, command=self.block_selected_packet_ip).grid(row=0, column=0, padx=4, pady=4)
        ctk.CTkButton(action_row, text="Unblock Selected IP", width=160, command=self.unblock_selected_packet_ip).grid(row=0, column=1, padx=4, pady=4)

    def _build_console(self, parent: ctk.CTkFrame, row: int, *, compact: bool = False) -> None:
        self.console_card = self._register_card(ctk.CTkFrame(parent, corner_radius=10))
        self.console_card.grid(row=row, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.console_card.grid_rowconfigure(1, weight=0 if compact else 1)
        self.console_card.grid_columnconfigure(0, weight=1)

        header = self._register_card(ctk.CTkFrame(self.console_card, corner_radius=10))
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkLabel(header, text="Console Logs").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(header, text="Clear Logs", width=110, command=self.clear_intelligence_logs, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=1, padx=6, pady=6)
        self.intelligence_console = ctk.CTkTextbox(self.console_card, corner_radius=10, height=180 if compact else 320)
        self.intelligence_console.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

    def _build_ai_auditor_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        pane.grid_columnconfigure(1, weight=0)
        pane.grid_rowconfigure(6, weight=1)

        ai_header = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        ai_header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        ctk.CTkLabel(ai_header, text="AI Feedback from Logs").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(ai_header, text="Analyze Logs", corner_radius=10, command=self.analyze_logs, width=120).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(ai_header, text="Cancel", corner_radius=10, command=self.cancel_ai_analysis, width=90, fg_color=STOP_RED, hover_color=STOP_RED_HOVER).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkButton(ai_header, text="Clear Logs", corner_radius=10, command=self.clear_ai_logs, width=100, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=3, padx=6, pady=6)

        ai_filter_row = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        ai_filter_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
        ctk.CTkCheckBox(ai_filter_row, text="High risk only", variable=self.ai_high_risk_only_var).grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkCheckBox(ai_filter_row, text="Open ports only", variable=self.ai_open_ports_only_var).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkCheckBox(ai_filter_row, text="Alerts only", variable=self.ai_alerts_only_var).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkOptionMenu(ai_filter_row, values=["App Logs", "External File"], variable=self.ai_log_source_var, width=120).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkOptionMenu(ai_filter_row, values=["Port Scan", "Packet Scan"], variable=self.ai_data_type_var, width=110).grid(row=0, column=4, padx=6, pady=6)
        ctk.CTkEntry(ai_filter_row, width=220, textvariable=self.ai_external_log_path_var, placeholder_text="External log path (.json/.txt)").grid(row=0, column=5, padx=6, pady=6)
        ctk.CTkLabel(ai_filter_row, text="Max rows").grid(row=0, column=6, padx=(10, 4), pady=6)
        ctk.CTkEntry(ai_filter_row, width=80, textvariable=self.ai_max_rows_var, placeholder_text="600").grid(row=0, column=7, padx=4, pady=6)
        ctk.CTkLabel(ai_filter_row, textvariable=self.ai_elapsed_var).grid(row=0, column=8, padx=(12, 6), pady=6)

        prompt_card = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        prompt_card.grid(row=0, column=1, rowspan=2, sticky="ne", padx=(0, 8), pady=(8, 6))
        ctk.CTkLabel(prompt_card, text="PROMPT EDITOR", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=8, pady=6, sticky="w")
        ctk.CTkOptionMenu(prompt_card, values=["Port Scan", "Packet Scan"], variable=self.prompt_type_var, width=110, command=lambda _v: self._load_prompt_editor_text()).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(prompt_card, text="Save Prompt", width=110, command=self.save_prompt_editor).grid(row=0, column=2, padx=6, pady=6)
        self.prompt_editor_box = ctk.CTkTextbox(prompt_card, corner_radius=10, height=100, width=420)
        self.prompt_editor_box.grid(row=1, column=0, columnspan=3, sticky="ew", padx=8, pady=(0, 8))

        self.ai_status_var = ctk.StringVar(value="Run scans, choose AI filters, then Analyze Logs.")
        ctk.CTkLabel(pane, textvariable=self.ai_status_var, anchor="w", justify="left").grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 6))
        self.ai_progress = ctk.CTkProgressBar(pane)
        self.ai_progress.grid(row=4, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 6))
        self.ai_progress.set(0)
        self.ai_feedback_box = ctk.CTkTextbox(pane, corner_radius=10)
        self.ai_feedback_box.grid(row=6, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 8))

    def _build_firewall_controls(self, parent: ctk.CTkFrame, *, start_row: int = 0) -> None:
        actions_row = self._register_card(ctk.CTkFrame(parent, corner_radius=10))
        actions_row.grid(row=start_row, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.firewall_refresh_button = ctk.CTkButton(actions_row, text="Refresh Status", command=self.refresh_firewall_insight, width=130)
        self.firewall_refresh_button.grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Toggle ON", command=lambda: self.toggle_firewall_from_ui(True), width=110).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Toggle OFF", command=lambda: self.toggle_firewall_from_ui(False), width=110).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkOptionMenu(actions_row, values=["soft", "normal", "paranoid"], variable=self.firewall_preset_var, width=120).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Apply Preset", command=self.apply_firewall_preset_from_ui, width=130).grid(row=0, column=4, padx=6, pady=6)
        ctk.CTkButton(actions_row, text="Panic Button", command=self.run_panic_button, fg_color="#DC2626", hover_color="#B91C1C", width=120).grid(row=0, column=5, padx=6, pady=6)

        rule_row = self._register_card(ctk.CTkFrame(parent, corner_radius=10))
        rule_row.grid(row=start_row + 1, column=0, sticky="ew", padx=8, pady=(0, 8))
        ctk.CTkEntry(rule_row, textvariable=self.firewall_rule_name_var, width=180, placeholder_text="Rule name").grid(row=0, column=0, padx=6, pady=6)
        ctk.CTkOptionMenu(rule_row, values=["in", "out"], variable=self.firewall_direction_var, width=90).grid(row=0, column=1, padx=6, pady=6)
        ctk.CTkOptionMenu(rule_row, values=["allow", "block"], variable=self.firewall_action_var, width=100).grid(row=0, column=2, padx=6, pady=6)
        ctk.CTkOptionMenu(rule_row, values=["tcp", "udp"], variable=self.firewall_protocol_var, width=90).grid(row=0, column=3, padx=6, pady=6)
        ctk.CTkEntry(rule_row, textvariable=self.firewall_rule_port_var, width=100, placeholder_text="Port").grid(row=0, column=4, padx=6, pady=6)
        ctk.CTkEntry(rule_row, textvariable=self.firewall_rule_ip_var, width=150, placeholder_text="Remote IP (optional)").grid(row=0, column=5, padx=6, pady=6)
        ctk.CTkButton(rule_row, text="Add Rule", command=self.add_custom_rule_from_ui, width=100).grid(row=0, column=6, padx=6, pady=6)
        ctk.CTkButton(rule_row, text="Remove Rule", command=self.remove_custom_rule_from_ui, width=120).grid(row=0, column=7, padx=6, pady=6)

    def _build_firewall_tab(self, pane: ctk.CTkFrame) -> None:
        pane.grid_columnconfigure(0, weight=1)
        info = self._register_card(ctk.CTkFrame(pane, corner_radius=10))
        info.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 8))
        ctk.CTkLabel(
            info,
            text="Firewall controls were migrated to Intelligence for consolidated operations and logs.",
            anchor="w",
            justify="left",
        ).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkButton(info, text="Go to Intelligence", command=lambda: self._show_workspace_tab("Intelligence"), width=150).grid(row=0, column=1, padx=10, pady=10)

    def _active_theme(self) -> dict[str, str]:
        return DARK_THEME if self.current_mode == "dark" else LIGHT_THEME

    def _apply_theme(self) -> None:
        theme = self._active_theme()
        self.configure(fg_color=theme["window"])

        for card in self.theme_cards:
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
        scroll_thumb = "#374151" if self.current_mode == "dark" else "#BFDBFE"
        trough = "#111827" if self.current_mode == "dark" else "#EFF6FF"
        border = "#1F2937" if self.current_mode == "dark" else "#93C5FD"
        style.configure("NetScouter.Vertical.TScrollbar", gripcount=0, troughcolor=trough, background=scroll_thumb, bordercolor=border, arrowcolor=theme["text"], lightcolor=scroll_thumb, darkcolor=scroll_thumb, relief="flat")
        style.configure("NetScouter.Horizontal.TScrollbar", gripcount=0, troughcolor=trough, background=scroll_thumb, bordercolor=border, arrowcolor=theme["text"], lightcolor=scroll_thumb, darkcolor=scroll_thumb, relief="flat")

        self.results_table.tag_configure("even", background=theme["card"])
        self.results_table.tag_configure("odd", background=theme["row_alt"])
        self._refresh_risk_tag_colors()

    def _refresh_risk_tag_colors(self) -> None:
        palette = RISK_COLORS[self.current_mode]
        self.results_table.tag_configure("risk_low", foreground=palette["low"])
        self.results_table.tag_configure("risk_average", foreground=palette["average"])
        self.results_table.tag_configure("risk_high", foreground=palette["high"])
        if hasattr(self, "packet_filter_table"):
            self.packet_filter_table.tag_configure("pkt_risk_low", foreground=palette["low"])
            self.packet_filter_table.tag_configure("pkt_risk_average", foreground=palette["average"])
            self.packet_filter_table.tag_configure("pkt_risk_high", foreground=palette["high"])
            self.packet_filter_table.tag_configure("pkt_behavior_normal", foreground=palette["low"])
            self.packet_filter_table.tag_configure("pkt_behavior_weird", foreground=palette["average"])

    def _switch_theme(self, selected: str) -> None:
        selected_lower = selected.lower()
        self.current_mode = "light" if selected_lower.startswith("light") else "dark"
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

    def _behavioral_scheduler_tick(self) -> None:
        """Scheduler now checks stateful scoreboard before active scan actions."""
        log_schedule_event(action="behavioral_tick", job_id=self.scheduled_job_id, source="scheduler")
        stale_cutoff = time.time() - 1800
        for ip, board in list(self.automation_scoreboard.items()):
            if float(board.get("last_seen", 0.0)) < stale_cutoff:
                self.automation_scoreboard.pop(ip, None)
                continue
            self._maybe_trigger_behavioral_action(ip)

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
        self.after(0, lambda: self._notify_popup(f"Scan started for {target}", tab="Dashboard"))

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
        self.after(0, lambda: self._notify_popup("Established scan started", tab="Dashboard"))

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
        self._notify_popup(message, tab="Dashboard")

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
        self._intel_log("Settings applied (API keys, consensus threshold, reputation timeout, AI timeout, auto-block preference)")

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

    def _ai_timeout(self) -> int:
        try:
            return max(30, int(float(self.ai_timeout_var.get().strip())))
        except ValueError:
            return 120

    def _scan_rows_for_reporting(self) -> list[dict[str, str | int | list[str]]]:
        return self._filtered_scan_rows()

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
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
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

    def _current_filter_model(self) -> dict[str, str | bool]:
        return {
            "status": self.status_filter_var.get(),
            "risk": self.risk_filter_var.get(),
            "established_only": bool(self.established_only_var.get()),
        }

    def _filtered_scan_rows(self) -> list[dict[str, str | int | list[str]]]:
        return [row for row in self.scan_results if self._passes_filters(row)]

    def _passes_filters(self, row: dict[str, str | int | list[str]]) -> bool:
        selected_status = self.status_filter_var.get()
        selected_risk = self.risk_filter_var.get()
        established_only = bool(self.established_only_var.get())

        status = str(row.get("status", "")).lower()
        if selected_status == "Open Ports" and status != "open":
            return False
        if selected_status == "Closed Ports" and status != "closed":
            return False

        if selected_risk != "All Risk" and str(row.get("risk", "")).lower() != selected_risk.lower():
            return False
        if established_only and status != "open":
            return False
        return True

    def _insert_result_row(self, payload: dict[str, str | int | list[str]], index: int) -> None:
        stripe_tag = "even" if index % 2 == 0 else "odd"
        risk_tag = f"risk_{str(payload['risk']).lower()}"
        item_id = self.results_table.insert(
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
        self._table_item_lookup[item_id] = payload

    def _rerender_table(self) -> None:
        self.table_page_start = 0
        self._render_token += 1
        self.filtered_rows = self._filtered_scan_rows()
        self._render_table_page(self._render_token)

    def _render_table_page(self, token: int, offset: int = 0) -> None:
        if token != self._render_token:
            return
        if offset == 0:
            self._table_item_lookup.clear()
            for item in self.results_table.get_children():
                self.results_table.delete(item)

        page_rows = self.filtered_rows[self.table_page_start : self.table_page_start + TABLE_PAGE_SIZE]
        chunk = page_rows[offset : offset + TABLE_RENDER_CHUNK_SIZE]
        for index, payload in enumerate(chunk, start=offset):
            self._insert_result_row(payload, index)

        if offset + TABLE_RENDER_CHUNK_SIZE < len(page_rows):
            self.after(1, lambda: self._render_table_page(token, offset + TABLE_RENDER_CHUNK_SIZE))
            return

        page_start = self.table_page_start + 1 if page_rows else 0
        page_end = self.table_page_start + len(page_rows)
        self.filter_summary_var.set(
            f"Showing {len(self.filtered_rows)} / {len(self.scan_results)} rows | Page rows {page_start}-{page_end}"
        )

    def _prev_table_page(self) -> None:
        if self.table_page_start <= 0:
            return
        self.table_page_start = max(0, self.table_page_start - TABLE_PAGE_SIZE)
        self._render_token += 1
        self._render_table_page(self._render_token)

    def _next_table_page(self) -> None:
        next_start = self.table_page_start + TABLE_PAGE_SIZE
        if next_start >= len(self.filtered_rows):
            return
        self.table_page_start = next_start
        self._render_token += 1
        self._render_table_page(self._render_token)

    def clear_scan_logs(self) -> None:
        self.dashboard_console.delete("1.0", "end")
        self.packet_stream_console.delete("1.0", "end")
        self.log_line_count = 0
        self.packet_log_line_count = 0
        self.scan_results.clear()
        self.filtered_rows.clear()
        self._table_item_lookup.clear()
        self.results_table.selection_remove(*self.results_table.selection())
        self._render_token += 1
        self._render_table_page(self._render_token)
        self._log("Scan logs and table rows cleared")

    def _open_selected_row_report(self, _event: object | None = None) -> None:
        selection = self.results_table.selection()
        if not selection:
            return
        item = selection[0]
        payload = self._table_item_lookup.get(item, {})
        values = self.results_table.item(item, "values")
        if not payload and not values:
            return

        report = ctk.CTkToplevel(self)
        report.title("Port Intelligence Report")
        report.geometry("900x520")
        report.grid_columnconfigure(0, weight=1)
        report.grid_rowconfigure(0, weight=1)

        box = ctk.CTkTextbox(report, corner_radius=10)
        box.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)

        lines = ["Detailed result report", "=" * 72]
        key_order = [
            "port", "status", "remote_ip", "process", "pid", "exe_path", "location", "provider",
            "country", "city", "consensus", "consensus_summary", "risk", "containment", "alerts",
        ]
        source = payload if payload else {
            "port": values[0] if len(values) > 0 else "",
            "status": values[1] if len(values) > 1 else "",
            "remote_ip": values[2] if len(values) > 2 else "",
            "process": values[3] if len(values) > 3 else "",
            "exe_path": values[4] if len(values) > 4 else "",
            "location": values[5] if len(values) > 5 else "",
            "provider": values[6] if len(values) > 6 else "",
            "consensus": values[7] if len(values) > 7 else "",
            "risk": values[8] if len(values) > 8 else "",
            "containment": values[9] if len(values) > 9 else "",
            "alerts": values[10] if len(values) > 10 else "",
        }
        for key in key_order:
            value = source.get(key, "")
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            lines.append(f"{key:18}: {value}")

        packets = self.packet_service.get_packets(remote_ip=str(source.get("remote_ip", "")), limit=20)
        lines.append("\nRecent packet events")
        lines.append("-" * 72)
        if not packets:
            lines.append("No packets captured yet for this host.")
        else:
            for packet in packets[-20:]:
                lines.append(
                    f"{packet.get('timestamp')} | {packet.get('proto')} | "
                    f"{packet.get('src')}:{packet.get('raw', {}).get('src_port')} -> "
                    f"{packet.get('dst')}:{packet.get('raw', {}).get('dst_port')} | "
                    f"flags={packet.get('tcp_flags')} malformed={packet.get('malformed')}"
                )

        box.insert("1.0", "\n".join(lines))

    def _on_table_hover(self, event: object) -> None:
        if not hasattr(event, "x") or not hasattr(event, "y"):
            return
        row_id = self.results_table.identify_row(event.y)
        col_id = self.results_table.identify_column(event.x)
        if not row_id or not col_id:
            self._hide_table_tooltip()
            return
        try:
            col_index = int(col_id.replace("#", "")) - 1
        except ValueError:
            self._hide_table_tooltip()
            return
        values = self.results_table.item(row_id, "values")
        if col_index < 0 or col_index >= len(values):
            self._hide_table_tooltip()
            return
        text = str(values[col_index])
        if len(text) < 30:
            self._hide_table_tooltip()
            return

        x_root = self.results_table.winfo_rootx() + event.x + 18
        y_root = self.results_table.winfo_rooty() + event.y + 18
        if self._table_tooltip is None or not self._table_tooltip.winfo_exists():
            self._table_tooltip = ctk.CTkToplevel(self)
            self._table_tooltip.wm_overrideredirect(True)
            self._table_tooltip.attributes("-topmost", True)
            self._table_tooltip_label = ctk.CTkLabel(self._table_tooltip, text="", justify="left", anchor="w")
            self._table_tooltip_label.pack(padx=8, pady=6)
        if self._table_tooltip_label is not None:
            self._table_tooltip_label.configure(text=text[:700])
        self._table_tooltip.geometry(f"+{x_root}+{y_root}")
        self._table_tooltip.deiconify()

    def _hide_table_tooltip(self) -> None:
        if self._table_tooltip and self._table_tooltip.winfo_exists():
            self._table_tooltip.withdraw()

    def _detect_local_ip(self) -> tuple[str, str]:
        ipv4 = "n/a"
        ipv6 = "n/a"
        for iface in psutil.net_if_addrs().values():
            for addr in iface:
                if getattr(addr, "family", None) == socket.AF_INET:
                    if addr.address and not addr.address.startswith("127."):
                        ipv4 = addr.address
                elif getattr(addr, "family", None) == socket.AF_INET6:
                    if addr.address and not addr.address.startswith("::1"):
                        ipv6 = addr.address.split("%", maxsplit=1)[0]
            if ipv4 != "n/a" and ipv6 != "n/a":
                break
        if ipv4 == "n/a":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(("8.8.8.8", 80))
                    ipv4 = sock.getsockname()[0]
            except OSError:
                pass
        self.local_ipv4, self.local_ipv6 = ipv4, ipv6
        return ipv4, ipv6

    def show_local_network_info(self) -> None:
        context = resolve_local_network_context()
        lan_ipv4, lan_ipv6 = self._detect_local_ip()
        public_ip = context.get("public_ip", "Unknown")
        self.local_info_var.set(f"IPv4 {lan_ipv4} | IPv6 {lan_ipv6} | WAN {public_ip}")
        self._log(f"Local network info: IPv4={lan_ipv4} IPv6={lan_ipv6} WAN={public_ip}")

    def toggle_local_network_info(self) -> None:
        if self.local_info_visible:
            self.local_info_visible = False
            self.local_info_var.set("Local network info hidden")
            return
        self.local_info_visible = True
        self.show_local_network_info()

    def stop_all_tasks(self) -> None:
        stopped: list[str] = []
        if self.scan_job is not None:
            try:
                self.scan_job.cancel()
                stopped.append("scan")
            except Exception:
                pass
            self.scan_job = None
        if self.packet_service.is_running:
            self.stop_live_packet_stream()
            stopped.append("packet stream")
        if self.ai_job_thread and self.ai_job_thread.is_alive():
            self.cancel_ai_analysis()
            stopped.append("AI analysis")
        self._set_scan_running(False)
        if not stopped:
            self._log("STOP ALL: no active tasks found")
        else:
            self._log(f"STOP ALL: stopped {', '.join(stopped)}")

    def refresh_lan_devices(self) -> None:
        self.lan_status_var.set("Discovering LAN devices...")
        threading.Thread(target=self._refresh_lan_devices_worker, daemon=True, name="lan-discovery").start()

    def _refresh_lan_devices_worker(self) -> None:
        try:
            devices = discover_lan_devices(max_hosts=256)
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self.lan_status_var.set(f"LAN discovery failed: {exc}"))
            return

        local_ipv4, _ = self._detect_local_ip()
        if local_ipv4 != "n/a" and all(str(dev.get("ip", "")) != local_ipv4 for dev in devices):
            devices.append(
                {
                    "ip": local_ipv4,
                    "mac": "",
                    "hostname": socket.gethostname() or "This Device",
                    "vendor": "Local Host",
                    "device_type": "computer",
                }
            )

        now = datetime.now()
        for dev in devices:
            self.device_registry.upsert(
                ip=str(dev.get("ip", "")),
                mac=str(dev.get("mac", "")),
                hostname=str(dev.get("hostname", "Unknown")),
                vendor=str(dev.get("vendor", "Unknown")),
                device_type=str(dev.get("device_type", "unknown")),
                seen_at=now,
            )
        self.discovered_devices = self.device_registry.devices
        self.lan_anomalies = correlate_iot_outbound_anomalies(self.device_registry)
        self.after(0, self._render_lan_table)
        self.after(0, lambda: self._log(f"LAN discovery complete: {len(self.discovered_devices)} devices, {len(self.lan_anomalies)} IoT anomalies"))

    def _render_lan_table(self) -> None:
        for item in self.lan_table.get_children():
            self.lan_table.delete(item)
        local_ipv4 = self.local_ipv4
        for dev in self.discovered_devices:
            ip = str(dev.get("ip", ""))
            hostname = str(dev.get("hostname", "Unknown"))
            vendor = str(dev.get("vendor", "Unknown"))
            if local_ipv4 != "n/a" and ip == local_ipv4:
                hostname = f"{hostname} (This Device)"
                vendor = f"{vendor} / Local Host"
            self.lan_table.insert(
                "",
                "end",
                values=(
                    ip,
                    hostname,
                    vendor,
                    str(dev.get("device_type", "unknown")),
                    str(dev.get("mac", "")),
                ),
            )
        self.lan_status_var.set(f"Discovered {len(self.discovered_devices)} devices | IoT anomalies {len(self.lan_anomalies)}")

    def _open_lan_context_menu(self, event: object) -> None:
        if not hasattr(event, "x") or not hasattr(event, "y"):
            return
        item = self.lan_table.identify_row(event.y)
        if item:
            self.lan_table.selection_set(item)
        menu = Menu(self, tearoff=0)
        menu.add_command(label="Track packets for selected device", command=self.track_selected_lan_device_packets)
        menu.add_command(label="Packet breakdown (last 40)", command=self.show_selected_lan_packet_breakdown)
        menu.tk_popup(int(getattr(event, "x_root", 0)), int(getattr(event, "y_root", 0)))

    def track_selected_lan_device_packets(self) -> None:
        ip = self._selected_lan_ip()
        if not ip:
            self._log("Select a LAN device row first")
            return
        self.target_var.set(ip)
        self.selected_remote_ip = ip
        self.selected_port = None
        if ip == self.local_ipv4:
            self.packet_stream_mode_var.set("Local Network")
        else:
            self.packet_stream_mode_var.set("Target Host")
        self._on_packet_scope_changed()
        self._show_workspace_tab("Dashboard")
        stream_mode = self.packet_stream_mode_var.get()
        self._packet_log(f"Tracking packets for LAN device {ip}. Starting stream in {stream_mode} mode.")
        self.start_live_packet_stream()

    def start_network_wide_capture(self) -> None:
        self.packet_stream_mode_var.set("Local Network")
        self._on_packet_scope_changed()
        self._packet_log("One-click LAN capture enabled. Monitoring inbound/outbound traffic for the local subnet.")
        self.start_live_packet_stream()

    def show_selected_lan_packet_breakdown(self) -> None:
        ip = self._selected_lan_ip()
        if not ip:
            self._log("Select a LAN device row first")
            return
        packets = self.packet_service.get_packets(remote_ip=ip, limit=40)
        if not packets:
            messagebox.showinfo("Packet breakdown", f"No captured packets yet for {ip}.")
            return
        lines = []
        for pkt in packets[-40:]:
            lines.append(
                f"{pkt.get('timestamp')} | {pkt.get('proto')} | "
                f"{pkt.get('src')}:{pkt.get('raw', {}).get('src_port')} -> {pkt.get('dst')}:{pkt.get('raw', {}).get('dst_port')} | "
                f"pid={pkt.get('pid')} proc={pkt.get('process_name')}"
            )
        messagebox.showinfo(f"Packet breakdown: {ip}", "\n".join(lines))

    def show_lan_anomalies(self) -> None:
        if not self.lan_anomalies:
            self._log("LAN anomalies: none detected yet")
            messagebox.showinfo("LAN Anomalies", "No IoT outbound anomalies detected.")
            return
        lines = []
        for item in self.lan_anomalies[:20]:
            lines.append(
                f"{item.get('risk')} | {item.get('local_ip')} -> {item.get('remote_ip')}:{item.get('remote_port')} | {item.get('reason')}"
            )
        messagebox.showinfo("LAN Anomalies", "\n".join(lines))

    def _selected_lan_ip(self) -> str | None:
        selection = self.lan_table.selection()
        if not selection:
            return None
        values = self.lan_table.item(selection[0], "values")
        if not values:
            return None
        return str(values[0]).strip() or None

    def quarantine_selected_lan_device(self) -> None:
        ip = self._selected_lan_ip()
        if not ip:
            self._log("Select a LAN device row first")
            return
        threading.Thread(target=self._quarantine_ip_worker, args=(ip,), daemon=True, name="lan-quarantine").start()

    def banish_selected_lan_device(self) -> None:
        ip = self._selected_lan_ip()
        if not ip:
            self._log("Select a LAN device row first")
            return
        threading.Thread(target=self._banish_ip_worker, args=(ip,), daemon=True, name="lan-banish").start()

    def _automation_threshold(self) -> int:
        try:
            return max(20, int(self.automation_threshold_var.get().strip()))
        except ValueError:
            return 80

    def _automation_points(self, kind: str) -> int:
        mapping = {
            "unassigned": self.automation_points_unassigned_var,
            "frequency": self.automation_points_frequency_var,
            "dns": self.automation_points_dns_var,
        }
        var = mapping.get(kind)
        if var is None:
            return 0
        try:
            return max(0, int(var.get().strip()))
        except ValueError:
            return {"unassigned": 20, "frequency": 50, "dns": 30}.get(kind, 0)

    def _queue_dns_resolution(self, ip: str) -> None:
        if ip in self.automation_dns_cache or ip in self.automation_dns_pending:
            return
        self.automation_dns_pending.add(ip)

        def worker() -> None:
            failed = False
            try:
                socket.gethostbyaddr(ip)
            except OSError:
                failed = True
            self.automation_dns_cache[ip] = failed
            self.automation_dns_pending.discard(ip)

        threading.Thread(target=worker, daemon=True, name=f"dns-eval-{ip}").start()

    def _is_unassigned_port(self, port: int) -> bool:
        assigned = {20, 21, 22, 23, 25, 53, 80, 110, 123, 135, 137, 138, 139, 143, 443, 445, 3389}
        return int(port) not in assigned

    def _update_behavioral_score(self, remote_ip: str, points: int, reason: str) -> None:
        now = time.time()
        board = self.automation_scoreboard.setdefault(remote_ip, {"points": 0, "last_seen": now, "reasons": []})
        board["points"] = int(board.get("points", 0)) + int(points)
        board["last_seen"] = now
        reasons = list(board.get("reasons", []))
        reasons.append(reason)
        board["reasons"] = reasons[-8:]
        self._maybe_trigger_behavioral_action(remote_ip)

    def _maybe_trigger_behavioral_action(self, remote_ip: str) -> None:
        if not self.automation_enabled_var.get() or remote_ip in self.automation_triggered_ips:
            return
        board = self.automation_scoreboard.get(remote_ip, {})
        points = int(board.get("points", 0))
        if points < self._automation_threshold():
            return
        self.automation_triggered_ips.add(remote_ip)
        action = self.automation_action_var.get().strip().lower()
        reasons = "; ".join(str(x) for x in board.get("reasons", []))
        self._log(f"🤖 Behavioral automation triggered for {remote_ip}: points={points}, action={action}, reasons={reasons}")
        record_scan_history("behavioral_automation", {"ip": remote_ip, "points": points, "action": action, "reasons": reasons})
        self._notify_popup(f"Behavioral action: {action} on {remote_ip} ({points} pts)", tab="Operations")
        if action == "banish":
            threading.Thread(target=self._banish_ip_worker, args=(remote_ip,), daemon=True, name="auto-banish").start()
        else:
            threading.Thread(target=self._quarantine_ip_worker, args=(remote_ip,), daemon=True, name="auto-quarantine").start()

    def _evaluate_conditional_automation(self, payload: dict[str, str | int | list[str]]) -> None:
        if not self.automation_enabled_var.get():
            return
        remote_ip = str(payload.get("remote_ip", "")).strip()
        if not remote_ip:
            return
        try:
            ip_obj = ipaddress.ip_address(remote_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return
        except ValueError:
            return

        scope = self.automation_scope_var.get()
        status = str(payload.get("status", "")).lower()
        source = str(payload.get("source", "")).lower()
        if scope == "Open Ports Only" and status != "open":
            return
        if scope == "Established Only" and source != "established":
            return

        port = int(payload.get("port", 0) or 0)
        if port > 0 and self._is_unassigned_port(port):
            self._update_behavioral_score(remote_ip, self._automation_points("unassigned"), f"unassigned-port:{port}")

        self._queue_dns_resolution(remote_ip)
        if self.automation_dns_cache.get(remote_ip, False):
            self._update_behavioral_score(remote_ip, self._automation_points("dns"), "reverse-dns-failed")

        provider = str(payload.get("provider", "")).lower()
        if any(token in provider for token in ("vpn", "proxy", "tor")):
            self._update_behavioral_score(remote_ip, self._automation_points("dns"), f"provider:{provider[:40]}")

    def clear_filters(self) -> None:
        self.status_filter_var.set("All Ports")
        self.risk_filter_var.set("All Risk")
        self.established_only_var.set(False)
        self._rerender_table()

    def _on_table_select(self, _event: object | None = None) -> None:
        selection = self.results_table.selection()
        if not selection:
            return

        selected_item = selection[-1]
        payload = self._table_item_lookup.get(selected_item, {})
        values = self.results_table.item(selected_item, "values")
        if len(values) < 3 and not payload:
            return

        selected_ip = str(payload.get("remote_ip") or values[2]).strip()
        selected_port = None
        try:
            selected_port = int(payload.get("port") or str(values[0]).strip())
        except (TypeError, ValueError):
            selected_port = None
        if not selected_ip:
            return

        self.selected_remote_ip = selected_ip
        self.selected_port = selected_port
        self._render_packet_slice(selected_ip)

    def _open_table_context_menu(self, event: object) -> None:
        if not hasattr(event, "x") or not hasattr(event, "y"):
            return
        item = self.results_table.identify_row(event.y)
        if item and item not in self.results_table.selection():
            self.results_table.selection_add(item)

        menu = Menu(self, tearoff=0)
        menu.add_command(label="Keep eye on selected connections", command=self.watch_selected_connections)
        if self.packet_service.is_running:
            menu.add_command(label="Stop packet scanning", command=self.stop_live_packet_stream)
        else:
            menu.add_command(label="Start packet scanning", command=self.start_live_packet_stream)
        menu.tk_popup(int(getattr(event, "x_root", 0)), int(getattr(event, "y_root", 0)))

    def watch_selected_connections(self) -> None:
        selection = self.results_table.selection()
        if not selection:
            self._log("Select one or more rows first.")
            return
        added = 0
        for item in selection:
            payload = self._table_item_lookup.get(item, {})
            values = self.results_table.item(item, "values")
            ip = str(payload.get("remote_ip") or (values[2] if len(values) > 2 else "")).strip()
            if ip and ip not in self.packet_watchlist:
                self.packet_watchlist.add(ip)
                added += 1
        self._log(f"Watchlist updated: +{added} connection(s), total={len(self.packet_watchlist)}")

    def _on_packet_scope_changed(self, *_args: object) -> None:
        mode = self.packet_stream_mode_var.get()
        if mode == "Local Network":
            self.packet_scope_hint_var.set("Scope: local interface traffic in/out (requires elevated privileges)")
        elif mode == "Target Host":
            self.packet_scope_hint_var.set("Scope: host in Target field")
        else:
            self.packet_scope_hint_var.set("Scope: selected table row connection")

    def _ensure_scapy_available(self) -> tuple[bool, str]:
        if importlib.util.find_spec("scapy") is not None:
            return True, "Scapy already available"

        python_executable = sys.executable or "python"
        os_name = platform.system().lower()
        if os_name == "windows":
            self._packet_log("Scapy missing: installing for Windows (requires Npcap driver separately).")
        elif os_name == "linux":
            self._packet_log("Scapy missing: installing for Linux (capture still requires CAP_NET_RAW/CAP_NET_ADMIN).")
        elif os_name == "darwin":
            self._packet_log("Scapy missing: installing for macOS (capture still requires elevated permissions).")
        else:
            self._packet_log("Scapy missing: attempting generic pip installation.")

        proc = subprocess.run(
            [python_executable, "-m", "pip", "install", "scapy"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            return False, err or "Failed to install scapy"
        if importlib.util.find_spec("scapy") is None:
            return False, "pip install reported success but scapy import was not found"
        if os_name == "windows":
            self._packet_log("Scapy installed. If capture still yields no packets, install/repair Npcap with WinPcap compatibility mode.")
        return True, "Scapy installed"

    def start_live_packet_stream(self) -> None:
        mode = self.packet_stream_mode_var.get()
        selected_ip = self.selected_remote_ip
        target_ip = selected_ip or self.target_var.get().strip()
        capture_port = self.selected_port if selected_ip else None
        network_cidr: str | None = None
        self.local_ipv4, self.local_ipv6 = self._detect_local_ip()

        try:
            parsed_target = ipaddress.ip_address(target_ip) if target_ip else None
        except ValueError:
            parsed_target = None

        if parsed_target and (parsed_target.is_loopback or parsed_target.is_global) and mode != "Local Network":
            mode = "Local Network"
            self.packet_stream_mode_var.set(mode)
            self._on_packet_scope_changed()
            if parsed_target.is_loopback:
                self._packet_log("Target 127.0.0.1 captures only loopback traffic. Switched to Local Network mode for practical monitoring.")
            else:
                self._packet_log("Public IP selected. Switched to Local Network mode so local inbound/outbound traffic is visible.")

        if mode == "Target Host":
            target_ip = self.target_var.get().strip()
            capture_port = None
            if target_ip and target_ip == self.local_ipv4:
                network_cidr = derive_lan_cidr(self.local_ipv4)
                mode = "Local Network"
        elif mode == "Local Network":
            network_cidr = None
            target_ip = self.local_ipv4 if self.local_ipv4 != "n/a" else "0.0.0.0"
            capture_port = None

        if not target_ip:
            self._log("Select a row first (or set target) before starting packet stream")
            return

        self._packet_log(
            "Live stream guide: 1) choose stream scope, 2) run app with Administrator/root rights, "
            "3) ensure Npcap + WinPcap compatibility (Windows) or CAP_NET_RAW/CAP_NET_ADMIN (Linux/macOS)."
        )
        try:
            self.packet_service.start(
                target_ip,
                port=capture_port,
                network_cidr=network_cidr,
                mode="local_network" if mode == "Local Network" else "remote",
            )
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            if "Scapy is unavailable" in message:
                self._packet_log("Scapy dependency missing. Attempting automatic installation...")
                ok, status = self._ensure_scapy_available()
                if ok:
                    self._packet_log("Scapy installed successfully. Retrying stream startup...")
                    try:
                        self.packet_service.start(
                            target_ip,
                            port=capture_port,
                            network_cidr=network_cidr,
                            mode="local_network" if mode == "Local Network" else "remote",
                        )
                    except Exception as retry_exc:  # noqa: BLE001
                        self.packet_stream_status_var.set("Live stream failed")
                        self._packet_log(f"Live packet stream failed after installation retry: {retry_exc}")
                        return
                else:
                    self.packet_stream_status_var.set("Live stream failed")
                    self._packet_log(f"Automatic Scapy installation failed: {status}")
                    return
            else:
                self.packet_stream_status_var.set("Live stream failed")
                self._packet_log(f"Live packet stream failed to start for {target_ip}: {exc}")
                self._packet_log("Fix checklist: run elevated, install capture driver, disable strict endpoint security hook blocking.")
                return

        if not self.packet_service.is_running:
            self.packet_stream_status_var.set("Live stream failed")
            self._packet_log("Live packet stream did not activate. Check OS permissions and capture backend.")
            return

        self.packet_alert_cache.clear()
        stream_target = network_cidr if mode == "Local Network" else (f"{target_ip}:{capture_port}" if capture_port else target_ip)
        self.packet_stream_status_var.set(f"Streaming {stream_target}")
        panel_scope = "local network" if mode == "Local Network" else target_ip
        self._packet_log(
            f"Live packet stream started for {stream_target} on iface={self.packet_service.capture_interface} filter={self.packet_service.capture_filter or 'none'}. "
            "Logs appear below with IN/OUT direction, endpoint, and PID when available."
        )
        self._notify_popup(f"Packet filter started: {stream_target}", tab="Packet Filtering")
        self.after(350, self._poll_packet_stream)
        self.after(4000, self._check_packet_flow)

    def _check_packet_flow(self) -> None:
        if not self.packet_service.is_running:
            return
        samples = self.packet_service.get_packets(limit=20)
        if samples:
            return
        self._packet_log(
            "No packets seen yet. Verify: (1) elevated privileges, (2) packet capture driver/backend, "
            "(3) choose Local Network mode for host-wide visibility, (4) generate traffic on another LAN host/device."
        )
        self._packet_log(
            "If using 127.0.0.1 or your public IP as target: prefer One-click LAN Capture for Wireshark-like live subnet capture."
        )
        self._packet_log(
            f"Current capture iface={self.packet_service.capture_interface} filter={self.packet_service.capture_filter or 'none'}"
        )

    def stop_live_packet_stream(self) -> None:
        stopped = self.packet_service.stop()
        if not stopped:
            self._packet_log("Live packet stream stop timed out")
        self.packet_stream_status_var.set("Live stream idle")
        self._packet_log("Live packet stream stopped")
        self._notify_popup("Packet filter stopped", tab="Packet Filtering")

    def export_packet_slice(self) -> None:
        ip = None if self.packet_service.mode == "local_network" else (self.selected_remote_ip or self.packet_service.remote_ip)
        if not ip:
            self._packet_log("Exporting full local stream slice")

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return

        count = self.packet_service.export_packets(path, remote_ip=ip, limit=PACKET_SLICE_LIMIT)
        scope = ip or "local-network"
        self._packet_log(f"Exported {count} packets for {scope} to {path}")

    def _poll_packet_stream(self) -> None:
        if not self.packet_service.is_running:
            return

        active_ip = self.packet_service.remote_ip or self.selected_remote_ip or ""
        self._render_packet_slice(active_ip)

        self.after(350, self._poll_packet_stream)

    def _render_packet_slice(self, remote_ip: str) -> None:
        packet_filter = None if self.packet_service.mode == "local_network" else remote_ip
        packets = self.packet_service.get_packets(remote_ip=packet_filter, limit=PACKET_SLICE_LIMIT)
        if not packets:
            self.packet_stream_console.delete("1.0", "end")
            if self.packet_service.mode == "local_network":
                self.packet_stream_console.insert("1.0", "No packets captured yet for local network scope. Try generating traffic from another device or run as Administrator/root.")
            else:
                self.packet_stream_console.insert("1.0", "No packets captured yet for this host. Tip: use One-click LAN Capture for easier host-wide monitoring.")
            return

        lines = []
        for packet in packets[-24:]:
            src = str(packet.get("src") or "")
            direction = "OUT" if src in {self.local_ipv4, self.local_ipv6} else "IN"
            pid = packet.get("pid")
            proc = packet.get("process_name") or "unknown"
            lines.append(
                f"{packet.get('timestamp')} | {direction} | {packet.get('proto')} | "
                f"{packet.get('src')}:{packet.get('raw', {}).get('src_port')} -> "
                f"{packet.get('dst')}:{packet.get('raw', {}).get('dst_port')} | "
                f"len={packet.get('packet_length')} flags={packet.get('tcp_flags')} "
                f"pid={pid} proc={proc} malformed={packet.get('malformed')} error={packet.get('parse_error')}"
            )
            self._dispatch_packet_event(packet)
        self.packet_stream_console.delete("1.0", "end")
        self.packet_stream_console.insert("1.0", "\n \n".join(lines))

        alert_target = remote_ip if remote_ip else "local-network"
        alerts = evaluate_packet_signals(alert_target, packets)
        if alerts:
            self._escalate_risk_for_ip(remote_ip)

        for alert in alerts:
            if alert not in self.packet_alert_cache:
                self.packet_alert_cache.add(alert)
                self._packet_log(f"[Packet Alert] {alert}")

        self._refresh_packet_filtering_table()

    def _dispatch_packet_event(self, packet: dict[str, object]) -> None:
        ip = str(packet.get("src") or packet.get("dst") or "")
        if not ip:
            return
        try:
            self.packet_alert_input.put_nowait({"ip": ip, "when": time.time()})
        except Exception:
            return

    def _classify_packet_row(self, packet: dict[str, object]) -> tuple[str, str]:
        malformed = bool(packet.get("malformed"))
        flags = str(packet.get("tcp_flags") or "")
        proto = str(packet.get("proto") or "Unknown")
        risk = "Low"
        behavior = "Normal"
        if malformed or "F" in flags or "S" in flags and "A" not in flags:
            behavior = "Weird"
            risk = "High"
        elif proto == "ICMP":
            risk = "Average"
        return risk, behavior

    def _refresh_packet_filtering_table(self) -> None:
        table = getattr(self, "packet_filter_table", None)
        if table is None:
            return
        table.delete(*table.get_children())
        packets = self.packet_service.get_packets(limit=PACKET_SLICE_LIMIT)
        self.packet_filtered_packets = []
        for index, packet in enumerate(packets[-PACKET_SLICE_LIMIT:]):
            risk, behavior = self._classify_packet_row(packet)
            if self.packet_risk_filter_var.get() != "All" and risk != self.packet_risk_filter_var.get():
                continue
            if self.packet_behavior_filter_var.get() != "All" and behavior != self.packet_behavior_filter_var.get():
                continue
            self.packet_filtered_packets.append(packet)
            conn = f"{packet.get('src')}:{packet.get('raw', {}).get('src_port')} -> {packet.get('dst')}:{packet.get('raw', {}).get('dst_port')}"
            iid = f"pkt-{index}"
            pkt_time = str(packet.get("timestamp") or "")[:19].replace("T", " ")
            table.insert("", "end", iid=iid, values=(pkt_time, conn, packet.get("proto"), risk, behavior, packet.get("process_name") or "unknown"), tags=(f"pkt_risk_{risk.lower()}", f"pkt_behavior_{behavior.lower()}"))

    def _on_packet_filter_select(self, _event: object = None) -> None:
        selected = self.packet_filter_table.selection()
        if not selected:
            return
        idx = self.packet_filter_table.index(selected[0])
        if idx >= len(self.packet_filtered_packets):
            return
        packet = self.packet_filtered_packets[idx]
        self.packet_selected_packet = packet
        remote_ip = str(packet.get("dst") or "")
        self.packet_selected_summary_var.set(f"Focused connection: {packet.get('src')} -> {packet.get('dst')} ({packet.get('proto')})")
        self.packet_detail_box.delete("1.0", "end")
        self.packet_detail_box.insert("1.0", str(packet))
        if remote_ip:
            self.selected_remote_ip = remote_ip

    def block_selected_packet_ip(self) -> None:
        if not self.packet_selected_packet:
            return
        ip = str(self.packet_selected_packet.get("dst") or self.packet_selected_packet.get("src") or "")
        if not ip:
            return
        result = enforce_ip_policy(ip, action="block")
        if result.get("success"):
            self.blocked_packet_ips.add(ip)
        self._packet_log(f"Block request for {ip}: {result.get('message')}")

    def unblock_selected_packet_ip(self) -> None:
        if not self.packet_selected_packet:
            return
        ip = str(self.packet_selected_packet.get("dst") or self.packet_selected_packet.get("src") or "")
        if not ip:
            return
        result = unbanish_ip(ip)
        if result.get("success") and ip in self.blocked_packet_ips:
            self.blocked_packet_ips.remove(ip)
        self._append_threat_event(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "unban",
                "status": "success" if bool(result.get("success")) else "failed",
                "reason": str(result.get("message", "")),
            }
        )
        self._refresh_threats_table()
        self._packet_log(f"Unblock request for {ip}: {result.get('message')}")

    def _open_packet_filter_context_menu(self, event: object) -> None:
        row_y = getattr(event, "y", 0)
        row_id = self.packet_filter_table.identify_row(row_y)
        if row_id:
            self.packet_filter_table.selection_set(row_id)
        menu = Menu(self, tearoff=0)
        menu.add_command(label="Inspect packet details", command=self._open_packet_investigation_popup)
        menu.tk_popup(int(getattr(event, "x_root", 0)), int(getattr(event, "y_root", 0)))

    def _open_packet_investigation_popup(self) -> None:
        if not self.packet_selected_packet:
            return
        popup = ctk.CTkToplevel(self)
        popup.title("Packet Investigation")
        popup.geometry("760x520")
        popup.grid_columnconfigure(0, weight=1)
        popup.grid_rowconfigure(1, weight=1)
        pkt = self.packet_selected_packet
        headline = (
            f"Connection: {pkt.get('src')}:{pkt.get('raw', {}).get('src_port')} -> "
            f"{pkt.get('dst')}:{pkt.get('raw', {}).get('dst_port')} | proto={pkt.get('proto')}"
        )
        ctk.CTkLabel(popup, text=headline, anchor="w", justify="left").grid(row=0, column=0, padx=10, pady=8, sticky="ew")
        detail = ctk.CTkTextbox(popup, corner_radius=10)
        detail.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        risk, behavior = self._classify_packet_row(pkt)
        detail.insert(
            "1.0",
            "\n".join(
                [
                    f"timestamp: {pkt.get('timestamp')}",
                    f"risk: {risk}",
                    f"behavior: {behavior}",
                    f"process: {pkt.get('process_name')} (pid={pkt.get('pid')})",
                    f"tcp_flags: {pkt.get('tcp_flags')}",
                    f"packet_length: {pkt.get('packet_length')}",
                    f"malformed: {pkt.get('malformed')} parse_error={pkt.get('parse_error')}",
                    f"raw: {pkt.get('raw')}",
                ]
            ),
        )

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
            self._evaluate_conditional_automation(payload)

            if processed % 4 == 0:
                self._log(f"Port {payload['port']} on {payload['remote_ip']}: {payload['status']} | Risk {payload['risk']}")
            processed += 1

        if processed > 0:
            self._rerender_table()

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
            self._behavioral_scheduler_tick,
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
        if self.firewall_refresh_in_progress:
            self._intel_log("Firewall insight refresh already running")
            return
        self.firewall_refresh_in_progress = True
        self.firewall_status_var.set("Refreshing firewall status...")
        for button_name in ("firewall_refresh_button", "ops_refresh_firewall_button"):
            button = getattr(self, button_name, None)
            if button is not None:
                button.configure(state="disabled")
        threading.Thread(target=self._refresh_firewall_worker, daemon=True, name="firewall-insight").start()

    def toggle_firewall_from_ui(self, enabled: bool) -> None:
        action = "enable" if enabled else "disable"
        confirm = messagebox.askyesno("Confirm Firewall Toggle", f"Do you want to {action} the firewall?")
        if not confirm:
            self._intel_log(f"Firewall toggle cancelled ({action}).")
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
            self._intel_log(f"Firewall preset cancelled ({preset}).")
            return
        threading.Thread(target=self._apply_preset_worker, args=(preset,), daemon=True, name="firewall-preset").start()

    def _apply_preset_worker(self, preset: str) -> None:
        result = apply_firewall_preset(preset)
        self.after(0, lambda: self._log_operation_result("apply_firewall_preset", result))

    def add_custom_rule_from_ui(self) -> None:
        rule_name = self.firewall_rule_name_var.get().strip()
        if not rule_name:
            self._intel_log("Firewall custom rule: name is required.")
            return

        port_text = self.firewall_rule_port_var.get().strip()
        port: int | None = None
        if port_text:
            try:
                port = int(port_text)
            except ValueError:
                self._intel_log("Firewall custom rule: port must be an integer.")
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
            self._intel_log("Firewall custom rule removal: name is required.")
            return

        confirm = messagebox.askyesno(
            "Remove Firewall Rule",
            f"Remove firewall rule '{rule_name}'? Rollback hint: re-add with the same name and settings.",
        )
        if not confirm:
            self._intel_log(f"Firewall custom rule removal cancelled ({rule_name}).")
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
            self._intel_log("Panic button cancelled.")
            return
        threading.Thread(target=self._panic_button_worker, daemon=True, name="firewall-panic").start()

    def _panic_button_worker(self) -> None:
        result = panic_button()
        self.after(0, lambda: self._log_operation_result("panic_button", result))

    def _log_operation_result(self, operation: str, result: dict[str, object]) -> None:
        message = str(result.get("message", result))
        status = "SUCCESS" if bool(result.get("success")) else "FAIL"
        self._intel_log(f"🛡️ Firewall {operation} [{status}]: {message}")

        steps = result.get("steps")
        if isinstance(steps, list):
            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    continue
                step_name = str(step.get("step", f"step-{idx}"))
                step_ok = "OK" if bool(step.get("success")) else "WARN"
                note = str(step.get("message") or step.get("action") or "completed")
                self._intel_log(f"  🧩 {step_name}: {step_ok} ({note})")

        self.after(0, self.refresh_firewall_insight)

    def _refresh_firewall_worker(self) -> None:
        try:
            result = get_firewall_status()
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self._intel_log(f"Firewall insight failed: {exc}"))
            self.after(0, self._finish_firewall_refresh)
            return

        if result.get("success"):
            status_text = (
                f"enabled={result.get('enabled')} | rules={result.get('active_rules_count')} | "
                f"in={result.get('default_inbound_action')} / out={result.get('default_outbound_action')}"
            )
        else:
            status_text = str(result.get("message") or result)
        self.after(0, lambda: self.firewall_status_var.set(status_text[:120]))
        self.after(0, lambda: self._intel_log(f"Firewall insight updated: {status_text}"))
        self.after(0, self._finish_firewall_refresh)

    def _finish_firewall_refresh(self) -> None:
        self.firewall_refresh_in_progress = False
        for button_name in ("firewall_refresh_button", "ops_refresh_firewall_button"):
            button = getattr(self, button_name, None)
            if button is not None:
                button.configure(state="normal")

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
            self.after(0, lambda: self._notify_popup(f"Blocked {ip} by firewall policy", tab="Intelligence"))
        self._append_threat_event(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "block",
                "status": "success" if bool(result.get("success")) else "failed",
                "reason": str(result.get("message", "")),
            }
        )
        self.after(0, self._refresh_threats_table)
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
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "quarantine",
            "ip": ip,
            "sinkhole": f"{self.honeypot.host}:{self.honeypot.port}",
            "success": bool(result.get("success")),
        }
        self.quarantine_events.append(event)
        self._append_threat_event(
            {
                "timestamp": str(event.get("timestamp", "")),
                "ip": ip,
                "action": "quarantine",
                "status": "success" if bool(result.get("success")) else "failed",
                "reason": str(result.get("message", "")),
            }
        )
        append_quarantine_interaction({**event, "result": result})

        if result.get("success"):
            self.after(0, lambda: self._apply_containment_state(ip, "Quarantined"))
            self.after(0, lambda: self._notify_popup(f"Quarantined {ip} to sinkhole", tab="Intelligence"))
        self.after(0, self._refresh_threats_table)
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
        rendered = self._format_log_message(message)
        self.dashboard_console.insert("end", f"[{timestamp}] {rendered}\n")
        self.dashboard_console.see("end")
        self.log_line_count += 1

        if self.log_line_count > MAX_LOG_LINES:
            self.dashboard_console.delete("1.0", "200.0")
            self.log_line_count -= 199

    def _intel_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        rendered = self._format_log_message(message)
        self.intelligence_console.insert("end", f"[{timestamp}] {rendered}\n")
        self.intelligence_console.see("end")
        self.intel_log_line_count += 1
        if self.intel_log_line_count > MAX_LOG_LINES:
            self.intelligence_console.delete("1.0", "200.0")
            self.intel_log_line_count -= 199

    def _packet_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%S")
        rendered = self._format_log_message(message)
        self.packet_stream_console.insert("end", f"[{timestamp}] {rendered}\n \n")
        self.packet_stream_console.see("end")
        self.packet_log_line_count += 1
        if self.packet_log_line_count > MAX_LOG_LINES:
            self.packet_stream_console.delete("1.0", "200.0")
            self.packet_log_line_count -= 199

    def _format_log_message(self, message: str) -> str:
        if self.log_detail_mode_var.get() == "Expert":
            return message
        simplified = message.replace("ESTABLISHED", "connected").replace("consensus", "risk match")
        simplified = simplified.replace("iface", "interface")
        if "unassigned-port" in simplified:
            simplified += " | Why: uncommon port behavior can indicate probing."
        if "reverse-dns-failed" in simplified:
            simplified += " | Why: unresolved host identity may be suspicious."
        if "Behavioral automation triggered" in simplified:
            simplified += " | Why: multiple suspicious signals crossed the safety threshold."
        return simplified

    def clear_intelligence_logs(self) -> None:
        self.intelligence_console.delete("1.0", "end")
        self.intel_log_line_count = 0

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
                    encoding="utf-8",
                    errors="replace",
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
                encoding="utf-8",
                errors="replace",
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
        ctk.CTkEntry(controls, textvariable=self.timeline_source_ip_var, width=160, placeholder_text="Filter source IP").grid(row=0, column=5, padx=6, pady=8)

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
        rows = self._rows_for_ai_analysis()
        if not rows:
            self._log("No results to export with current filters")
            return

        ready = ensure_ai_readiness(console=self._log)
        if not ready:
            self._log("AI audit export skipped: local model unavailable")
            return

        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not path:
            return

        context = resolve_local_network_context()
        analyst_prompt = self.prompt_templates.get("Port Scan") or build_analyst_prompt()
        engine_prompt = self.prompt_templates.get("Packet Scan") or build_network_engine_prompt(context)
        export_ai_audit_report(
            rows,
            path,
            analyst_prompt=analyst_prompt,
            network_prompt=engine_prompt,
            quarantine_logs=self.quarantine_events,
        )
        self._log(f"Exported AI audit report to {path}")

    def export_xlsx(self) -> None:
        rows = self._rows_for_ai_analysis()
        if not rows:
            self._log("No results to export with current filters")
            return

        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if not path:
            return

        export_session_to_xlsx(rows, path, quarantine_logs=self.quarantine_events)
        self._log(f"Exported XLSX to {path}")

    def clear_ai_logs(self) -> None:
        self.ai_feedback_box.delete("1.0", "end")
        self.ai_status_var.set("AI output cleared.")
        self.ai_elapsed_var.set("Elapsed: 00:00")

    def _load_saved_prompt_templates(self) -> None:
        self.prompt_templates = {
            "Port Scan": str(get_preference("prompt.port_scan", build_analyst_prompt())),
            "Packet Scan": str(get_preference("prompt.packet_scan", build_network_engine_prompt())),
        }
        self._load_prompt_editor_text()

    def _load_runtime_preferences(self) -> None:
        self.target_var.set(str(get_preference("settings.target", self.target_var.get())))
        self.port_range_var.set(str(get_preference("settings.ports", self.port_range_var.get())))
        self.abuseipdb_key_var.set(str(get_preference("settings.abuseipdb_key", self.abuseipdb_key_var.get())))
        self.virustotal_key_var.set(str(get_preference("settings.virustotal_key", self.virustotal_key_var.get())))
        self.otx_key_var.set(str(get_preference("settings.otx_key", self.otx_key_var.get())))
        self.reputation_threshold_var.set(str(get_preference("settings.reputation_threshold", self.reputation_threshold_var.get())))
        self.reputation_timeout_var.set(str(get_preference("settings.reputation_timeout", self.reputation_timeout_var.get())))
        self.ai_timeout_var.set(str(get_preference("settings.ai_timeout", self.ai_timeout_var.get())))
        self.automation_enabled_var.set(bool(get_preference("settings.automation_enabled", self.automation_enabled_var.get())))
        self.automation_threshold_var.set(str(get_preference("settings.automation_threshold", self.automation_threshold_var.get())))
        self.automation_action_var.set(str(get_preference("settings.automation_action", self.automation_action_var.get())))
        self.log_detail_mode_var.set(str(get_preference("settings.log_mode", self.log_detail_mode_var.get())))
        self.save_ports_var.set(bool(get_preference("settings.save_ports", self.save_ports_var.get())))
        self.save_packets_var.set(bool(get_preference("settings.save_packets", self.save_packets_var.get())))
        self.save_intel_var.set(bool(get_preference("settings.save_intel", self.save_intel_var.get())))
        self.save_ai_var.set(bool(get_preference("settings.save_ai", self.save_ai_var.get())))
        self.popup_notifications_var.set(bool(get_preference("settings.popup_notifications", self.popup_notifications_var.get())))
        self.automation_scope_var.set(str(get_preference("settings.automation_scope", self.automation_scope_var.get())))
        self.automation_points_unassigned_var.set(str(get_preference("settings.automation_points_unassigned", self.automation_points_unassigned_var.get())))
        self.automation_points_frequency_var.set(str(get_preference("settings.automation_points_frequency", self.automation_points_frequency_var.get())))
        self.automation_points_dns_var.set(str(get_preference("settings.automation_points_dns", self.automation_points_dns_var.get())))

    def _load_prompt_editor_text(self) -> None:
        if not hasattr(self, "prompt_editor_box"):
            return
        key = self.prompt_type_var.get()
        self.prompt_editor_box.delete("1.0", "end")
        self.prompt_editor_box.insert("1.0", self.prompt_templates.get(key, ""))

    def save_prompt_editor(self) -> None:
        key = self.prompt_type_var.get()
        value = self.prompt_editor_box.get("1.0", "end").strip()
        self.prompt_templates[key] = value
        pref_key = "prompt.port_scan" if key == "Port Scan" else "prompt.packet_scan"
        set_preference(pref_key, value)
        self.ai_status_var.set(f"Saved {key} prompt.")

    def save_settings_preferences(self) -> None:
        set_preference("settings.target", self.target_var.get().strip())
        set_preference("settings.ports", self.port_range_var.get().strip())
        set_preference("settings.log_mode", self.log_detail_mode_var.get())
        set_preference("settings.abuseipdb_key", self.abuseipdb_key_var.get().strip())
        set_preference("settings.virustotal_key", self.virustotal_key_var.get().strip())
        set_preference("settings.otx_key", self.otx_key_var.get().strip())
        set_preference("settings.reputation_threshold", self.reputation_threshold_var.get().strip())
        set_preference("settings.reputation_timeout", self.reputation_timeout_var.get().strip())
        set_preference("settings.ai_timeout", self.ai_timeout_var.get().strip())
        set_preference("settings.automation_enabled", bool(self.automation_enabled_var.get()))
        set_preference("settings.automation_threshold", self.automation_threshold_var.get().strip())
        set_preference("settings.automation_action", self.automation_action_var.get())
        set_preference("settings.save_ports", bool(self.save_ports_var.get()))
        set_preference("settings.save_packets", bool(self.save_packets_var.get()))
        set_preference("settings.save_intel", bool(self.save_intel_var.get()))
        set_preference("settings.save_ai", bool(self.save_ai_var.get()))
        set_preference("settings.popup_notifications", bool(self.popup_notifications_var.get()))
        set_preference("settings.automation_scope", self.automation_scope_var.get())
        set_preference("settings.automation_points_unassigned", self.automation_points_unassigned_var.get().strip())
        set_preference("settings.automation_points_frequency", self.automation_points_frequency_var.get().strip())
        set_preference("settings.automation_points_dns", self.automation_points_dns_var.get().strip())
        self.settings_save_feedback_var.set("All settings saved.")
        self.after(2500, lambda: self.settings_save_feedback_var.set(""))
        self._log("Settings saved.")

    def clear_db_logs(self) -> None:
        import sqlite3

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM scan_history")
        self._log("Database scan history cleared.")

    def clear_prompt_prefs(self) -> None:
        set_preference("prompt.port_scan", "")
        set_preference("prompt.packet_scan", "")
        self.prompt_templates["Port Scan"] = build_analyst_prompt()
        self.prompt_templates["Packet Scan"] = build_network_engine_prompt()
        self._load_prompt_editor_text()
        self._log("Prompt preferences reset to defaults.")

    def save_logs_to_db(self, source: str) -> None:
        summary: dict[str, object] = {"source": source, "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if self.save_ports_var.get():
            summary["port_rows"] = len(self.scan_results)
        if self.save_packets_var.get():
            summary["packet_rows"] = len(self.packet_service.get_packets(limit=PACKET_SLICE_LIMIT))
        if self.save_intel_var.get():
            summary["intel_mode"] = self.firewall_status_var.get()
        if self.save_ai_var.get():
            summary["ai_status"] = self.ai_status_var.get() if hasattr(self, "ai_status_var") else "n/a"
        record_scan_history(source, summary)
        self._log(f"Saved selected log categories to DB from {source}.")

    def _load_threat_events_from_db(self) -> None:
        try:
            loaded = list_threat_events(limit=1000)
        except Exception as exc:  # noqa: BLE001
            self._log(f"Threat history DB load failed: {exc}")
            return
        if loaded:
            self.threat_events = [event for event in loaded if isinstance(event, dict)]

    def _append_threat_event(self, event: dict[str, str | bool]) -> None:
        event.setdefault("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.threat_events.append(event)
        try:
            record_threat_event(event)
        except Exception as exc:  # noqa: BLE001
            self._log(f"Threat DB save failed: {exc}")

    def _refresh_threats_table(self) -> None:
        if not hasattr(self, "threats_table"):
            return
        self.threats_table.delete(*self.threats_table.get_children())
        self.threat_event_lookup = {}
        events = self.threat_events[-600:]
        for idx, event in enumerate(events):
            iid = f"threat-{idx}"
            self.threat_event_lookup[iid] = event
            self.threats_table.insert(
                "",
                "end",
                iid=iid,
                values=(
                    event.get("timestamp", ""),
                    event.get("ip", ""),
                    event.get("action", ""),
                    event.get("status", ""),
                    event.get("reason", ""),
                    event.get("expires_at", ""),
                ),
            )

    def _selected_threat_ip(self) -> str | None:
        event = self._selected_threat_event()
        if not event:
            return None
        ip = str(event.get("ip") or "").strip()
        return ip or None

    def _selected_threat_event(self) -> dict[str, str | bool] | None:
        if not hasattr(self, "threats_table"):
            return None
        selected = self.threats_table.selection()
        if not selected:
            return None
        return self.threat_event_lookup.get(selected[0])

    def _on_threat_selected(self, _event: object = None) -> None:
        event = self._selected_threat_event()
        self.selected_threat_event = event
        if not event:
            return
        ip = str(event.get("ip") or "").strip()
        related = [e for e in self.threat_events if str(e.get("ip") or "").strip() == ip][-12:]
        self.threat_timeline_box.delete("1.0", "end")
        if related:
            lines = [
                f"{e.get('timestamp', '')} | {e.get('action', '')} | {e.get('status', '')} | {e.get('reason', '')}"
                for e in related
            ]
            self.threat_timeline_box.insert("1.0", "\n".join(lines))

        detail_lines = self._build_threat_detail_lines(event)
        self.threat_detail_box.delete("1.0", "end")
        self.threat_detail_box.insert("1.0", "\n".join(detail_lines))
        self.threat_action_hint_var.set("Safety actions: use Temp Ban for reversible containment, or Unban + Watch for likely false positives.")

    def _copy_threat_detail(self) -> None:
        if not hasattr(self, "threat_detail_box"):
            return
        text = self.threat_detail_box.get("1.0", "end").strip()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.threat_action_hint_var.set("Threat detail copied to clipboard.")

    def _build_threat_detail_lines(self, event: dict[str, str | bool]) -> list[str]:
        ip = str(event.get("ip") or "").strip()
        packet_hits = [p for p in self.packet_service.get_packets(limit=PACKET_SLICE_LIMIT) if str(p.get("dst") or "") == ip or str(p.get("src") or "") == ip]
        scan_rows = [r for r in self.scan_results if str(r.get("remote_ip") or "") == ip]
        statuses = Counter(str(r.get("status") or "unknown") for r in scan_rows)
        top_status = ", ".join(f"{k}:{v}" for k, v in statuses.most_common(3)) or "n/a"
        flags = Counter(str(p.get("tcp_flags") or "") for p in packet_hits)
        top_flags = ", ".join(f"{k or 'none'}:{v}" for k, v in flags.most_common(3)) or "n/a"
        reason_text = str(event.get("reason") or "")
        explain = []
        lower = reason_text.lower()
        if "ipset" in lower or "block" in lower:
            explain.append("Containment reached firewall-level blocking path")
        if "quarantine" in lower or "sinkhole" in lower:
            explain.append("Connection redirected to sinkhole quarantine")
        if "dns" in lower or "vpn" in lower:
            explain.append("Intel/routing anomaly indicator contributed")
        if not explain:
            explain.append("Triggered by automation/manual operator action; inspect timeline for sequence")

        internal_ips: set[str] = set()
        pids = Counter()
        process_names = Counter()
        accessed_ports: set[str] = set()
        for pkt in packet_hits:
            src = str(pkt.get("src") or "")
            dst = str(pkt.get("dst") or "")
            local_candidate = dst if src == ip else src
            try:
                obj = ipaddress.ip_address(local_candidate)
                if obj.is_private or obj.is_loopback or obj.is_link_local:
                    internal_ips.add(local_candidate)
            except ValueError:
                pass
            pid = pkt.get("pid")
            if pid:
                pids[str(pid)] += 1
            pname = str(pkt.get("process_name") or "").strip()
            if pname:
                process_names[pname] += 1
            raw = pkt.get("raw", {}) if isinstance(pkt.get("raw"), dict) else {}
            if src == ip and raw.get("dst_port"):
                accessed_ports.add(str(raw.get("dst_port")))
            if dst == ip and raw.get("src_port"):
                accessed_ports.add(str(raw.get("src_port")))

        for row in scan_rows:
            pid = row.get("pid")
            if pid:
                pids[str(pid)] += 1
            pname = str(row.get("process_name") or "").strip()
            if pname:
                process_names[pname] += 1
            local_hint = str(row.get("local_ip") or "").strip()
            if local_hint:
                internal_ips.add(local_hint)

        top_pid = ", ".join(f"{k}:{v}" for k, v in pids.most_common(3)) or "n/a"
        top_proc = ", ".join(f"{k}:{v}" for k, v in process_names.most_common(3)) or "n/a"
        internal_text = ", ".join(sorted(internal_ips)) or self.local_ipv4
        ports_text = ", ".join(sorted(accessed_ports)) or "n/a"

        return [
            f"IP: {ip}",
            f"Last Action: {event.get('action', '')} | Status: {event.get('status', '')}",
            f"Reason: {reason_text}",
            f"Expires At: {event.get('expires_at', 'n/a')}",
            "",
            "Explainability:",
            *[f"- {item}" for item in explain],
            "",
            "Observed Activity Snapshot:",
            f"- Internal network IP(s) accessed: {internal_text}",
            f"- Attempt count in packet buffer: {len(packet_hits)}",
            f"- Scan rows linked: {len(scan_rows)}",
            f"- Dominant statuses: {top_status}",
            f"- Frequent TCP flags: {top_flags}",
            f"- Local process names: {top_proc}",
            f"- Process IDs observed: {top_pid}",
            f"- Accessed port set: {ports_text}",
            f"- Watchlisted: {'yes' if ip in self.packet_watchlist else 'no'}",
            "",
            "Suggested Follow-up:",
            "1) Keep temp-ban (15m) if uncertain.",
            "2) Use Unban + Watch when likely false positive.",
            "3) Review process attribution in Packet Filtering investigate popup.",
        ]

    def _threat_block_selected(self) -> None:
        ip = self._selected_threat_ip()
        if not ip:
            return
        threading.Thread(target=self._banish_ip_worker, args=(ip,), daemon=True, name="threat-block").start()

    def _threat_quarantine_selected(self) -> None:
        ip = self._selected_threat_ip()
        if not ip:
            return
        threading.Thread(target=self._quarantine_ip_worker, args=(ip,), daemon=True, name="threat-quarantine").start()

    def _threat_temp_ban_selected(self) -> None:
        ip = self._selected_threat_ip()
        if not ip:
            return
        dialog = ctk.CTkInputDialog(text="Temporary ban duration (minutes)", title="Temp Ban")
        value = (dialog.get_input() or "").strip()
        try:
            minutes = max(1, min(240, int(value or "15")))
        except ValueError:
            minutes = 15
        expires = datetime.now().timestamp() + minutes * 60
        threading.Thread(target=self._banish_ip_worker, args=(ip,), daemon=True, name="threat-temp-ban").start()

        existing = self.temp_ban_timers.pop(ip, None)
        if existing:
            existing.cancel()

        timer = threading.Timer(minutes * 60, lambda: self.after(0, lambda: self._expire_temp_ban(ip)))
        timer.daemon = True
        timer.start()
        self.temp_ban_timers[ip] = timer
        self._append_threat_event(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "temp_ban",
                "status": "scheduled",
                "reason": f"Temporary ban scheduled for {minutes} minute(s)",
                "expires_at": datetime.fromtimestamp(expires).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        self._refresh_threats_table()
        self._log(f"Temporary ban armed for {ip}: {minutes} minute(s).")

    def _expire_temp_ban(self, ip: str) -> None:
        self.temp_ban_timers.pop(ip, None)
        result = unbanish_ip(ip)
        self._append_threat_event(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "temp_unban",
                "status": "success" if bool(result.get("success")) else "failed",
                "reason": str(result.get("message", "Temporary ban expired")),
            }
        )
        self._refresh_threats_table()
        self._notify_popup(f"Temporary ban expired for {ip}", tab="Possible Threats")

    def _threat_unban_watch_selected(self) -> None:
        ip = self._selected_threat_ip()
        if not ip:
            return
        result = unbanish_ip(ip)
        self.packet_watchlist.add(ip)
        self._append_threat_event(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "unban_watch",
                "status": "success" if bool(result.get("success")) else "failed",
                "reason": f"{result.get('message', '')} | Added to watchlist for follow-up",
            }
        )
        self._refresh_threats_table()
        self._log(f"Unban + Watch for {ip}: {result.get('message')}")

    def _threat_unban_selected(self) -> None:
        ip = self._selected_threat_ip()
        if not ip:
            return
        result = unbanish_ip(ip)
        self._append_threat_event(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "action": "unban",
                "status": "success" if bool(result.get("success")) else "failed",
                "reason": str(result.get("message", "")),
            }
        )
        self._refresh_threats_table()
        self._log(f"Threat list unban {ip}: {result.get('message')}")

    def _rows_for_ai_analysis(self) -> list[dict[str, str | int | list[str]]]:
        rows = list(self._scan_rows_for_reporting())
        if self.ai_data_type_var.get() == "Packet Scan":
            rows = self.packet_service.get_packets(limit=PACKET_SLICE_LIMIT)

        if self.ai_log_source_var.get() == "External File":
            path = self.ai_external_log_path_var.get().strip()
            if path and os.path.exists(path):
                try:
                    import json
                    with open(path, "r", encoding="utf-8") as handle:
                        loaded = json.load(handle)
                    if isinstance(loaded, list):
                        rows = loaded
                except Exception as exc:  # noqa: BLE001
                    self._log(f"Failed to parse external file: {exc}")
        filtered: list[dict[str, str | int | list[str]]] = []
        for row in rows:
            risk = str(row.get("risk", "")).lower()
            status = str(row.get("status", "")).lower()
            alerts = row.get("alerts", [])
            alert_text = ", ".join(str(a) for a in alerts) if isinstance(alerts, list) else str(alerts)

            if self.ai_high_risk_only_var.get() and risk != "high":
                continue
            if self.ai_open_ports_only_var.get() and status != "open":
                continue
            if self.ai_alerts_only_var.get() and not alert_text.strip():
                continue
            filtered.append(row)

        try:
            max_rows = max(50, int(self.ai_max_rows_var.get().strip()))
        except ValueError:
            max_rows = 600
        if len(filtered) > max_rows:
            filtered = filtered[:max_rows]
        return filtered

    def _start_ai_stopwatch(self) -> None:
        self.ai_started_at = datetime.now().timestamp()
        self.ai_timer_token += 1
        token = self.ai_timer_token

        def tick() -> None:
            if token != self.ai_timer_token or self.ai_started_at is None:
                return
            elapsed = int(datetime.now().timestamp() - self.ai_started_at)
            mins, secs = divmod(elapsed, 60)
            self.ai_elapsed_var.set(f"Elapsed: {mins:02d}:{secs:02d}")
            self.after(1000, tick)

        tick()

    def _stop_ai_stopwatch(self) -> None:
        self.ai_started_at = None
        self.ai_timer_token += 1

    def analyze_logs(self) -> None:
        rows = self._rows_for_ai_analysis()
        if not rows:
            self._log("No filtered results available for AI analysis")
            self.ai_status_var.set("No filtered scan data available. Adjust filters or run a scan.")
            return

        if self.ai_job_thread and self.ai_job_thread.is_alive():
            self._log("AI analysis already running")
            return

        self.ai_cancel_event.clear()
        self.ai_progress.set(0.05)
        self._start_ai_stopwatch()
        self.ai_status_var.set("Checking local AI readiness...")
        self._show_workspace_tab("AI Auditor")
        self.ai_job_thread = threading.Thread(
            target=self._analyze_logs_worker,
            kwargs={"rows": rows, "filter_model": self._current_filter_model()},
            daemon=True,
            name="ai-analyze-worker",
        )
        self.ai_job_thread.start()

    def _analyze_logs_worker(self, *, rows: list[dict[str, str | int | list[str]]], filter_model: dict[str, str | bool]) -> None:
        ready = ensure_ai_readiness(console=self._log)
        if not ready:
            self.after(0, lambda: self.ai_status_var.set("AI readiness failed. Install/enable Ollama and llama3.2:3b."))
            self.after(0, self._stop_ai_stopwatch)
            return

        if self.ai_cancel_event.is_set():
            self.after(0, lambda: self.ai_status_var.set("AI analysis cancelled."))
            self.after(0, self._stop_ai_stopwatch)
            return

        context = resolve_local_network_context()
        self.after(0, lambda: self.ai_status_var.set("Running Ollama analysis..."))
        self.after(0, lambda: self.ai_progress.set(0.25))
        ok, output = analyze_logs_with_ollama(
            rows,
            context=context,
            timeout_seconds=self._ai_timeout(),
            filter_model=filter_model,
            progress_callback=lambda pct, msg: self.after(0, lambda p=pct, m=msg: self._set_ai_progress(p, m)),
            cancel_event=self.ai_cancel_event,
            analyst_prompt_override=self.prompt_templates.get("Port Scan"),
            network_prompt_override=self.prompt_templates.get("Packet Scan"),
        )

        def publish() -> None:
            self.ai_feedback_box.delete("1.0", "end")
            self.ai_progress.set(1.0 if ok else 0)
            self._stop_ai_stopwatch()
            if ok:
                self.ai_feedback_box.insert("1.0", output)
                self.ai_status_var.set("AI analysis complete.")
                self._log("AI analysis complete (see AI tab).")
            else:
                self.ai_feedback_box.insert("1.0", output)
                if self.ai_cancel_event.is_set():
                    self.ai_status_var.set("AI analysis cancelled.")
                    self._log("AI analysis cancelled by user")
                else:
                    self.ai_status_var.set("AI analysis failed. Try reducing rows or increasing timeout.")
                    self._log(f"AI analysis failed: {output}")

        self.after(0, publish)

    def _set_ai_progress(self, progress: float, message: str) -> None:
        bounded = max(0.0, min(1.0, progress))
        self.ai_progress.set(bounded)
        if message:
            self.ai_status_var.set(message)

    def cancel_ai_analysis(self) -> None:
        if self.ai_job_thread and self.ai_job_thread.is_alive():
            self.ai_cancel_event.set()
            self.ai_status_var.set("Cancelling AI analysis...")
        else:
            self.ai_status_var.set("No active AI analysis job.")
            self._stop_ai_stopwatch()

    def show_charts(self) -> None:
        if not self.scan_results:
            self._log("No results available for charting")
            return
        threading.Thread(target=self._show_charts_worker, daemon=True, name="charts-worker").start()

    def _ensure_tray_icon(self) -> None:
        if getattr(self, "_tray_started", False):
            return
        if importlib.util.find_spec("pystray") is None or importlib.util.find_spec("PIL") is None:
            return
        import pystray
        from PIL import Image, ImageDraw

        image = Image.new("RGB", (64, 64), color="#1E3A8A")
        draw = ImageDraw.Draw(image)
        draw.rectangle((16, 16, 48, 48), fill="#0EA5E9")

        def on_restore(_icon: object, _item: object) -> None:
            self.after(0, self._restore_from_tray)

        def on_quit(_icon: object, _item: object) -> None:
            self.after(0, self._shutdown_application)

        menu = pystray.Menu(
            pystray.MenuItem("Restore", on_restore),
            pystray.MenuItem("Quit", on_quit),
        )
        self._tray_icon = pystray.Icon("NetScouter", image, "NetScouter", menu)
        threading.Thread(target=self._tray_icon.run, daemon=True, name="tray-icon").start()
        self._tray_started = True

    def _restore_from_tray(self) -> None:
        self.deiconify()
        self.lift()
        self.focus_force()

    def _minimize_to_background(self) -> None:
        self._ensure_tray_icon()
        self._notify_popup("NetScouter is still running in the background tray.", tab="Dashboard")
        self.withdraw()

    def _shutdown_application(self) -> None:
        if self.scan_job:
            self.scan_job.cancel()
        self.packet_service.stop(timeout=0.8)
        self._hide_table_tooltip()
        self.honeypot.stop(timeout=0.8)
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        if hasattr(self, "packet_alert_stop"):
            self.packet_alert_stop.set()
        if hasattr(self, "packet_alert_proc") and self.packet_alert_proc.is_alive():
            self.packet_alert_proc.join(timeout=0.8)
        for timer in self.temp_ban_timers.values():
            timer.cancel()
        self.temp_ban_timers.clear()
        if getattr(self, "_tray_started", False) and hasattr(self, "_tray_icon"):
            self._tray_icon.stop()
        self.intel_executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()

    def _on_close(self) -> None:
        self._minimize_to_background()


def launch_dashboard() -> None:
    """Start the NetScouter dashboard."""
    app = NetScouterApp()
    app.mainloop()
