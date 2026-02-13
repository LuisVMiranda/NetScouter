"""Operations tab layout builder."""

from __future__ import annotations

from tkinter import ttk

import customtkinter as ctk


CLEAR_AMBER = "#B45309"
CLEAR_AMBER_HOVER = "#92400E"


def build_operations_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_rowconfigure(5, weight=1)

    schedule_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    schedule_label.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
    ctk.CTkLabel(schedule_label, text="Scheduling", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    app.ops_row = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    app.ops_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkLabel(app.ops_row, text="Task").grid(row=0, column=0, padx=6, pady=8)
    ctk.CTkOptionMenu(app.ops_row, values=["Port Scanning", "Packet Filtering"], variable=app.schedule_task_type_var, width=150).grid(row=0, column=1, padx=6, pady=8)
    ctk.CTkLabel(app.ops_row, text="Every (hours)").grid(row=0, column=2, padx=6, pady=8)
    ctk.CTkEntry(app.ops_row, width=70, textvariable=app.schedule_hours_var, placeholder_text="6").grid(row=0, column=3, padx=6, pady=8)
    ctk.CTkButton(app.ops_row, text="Start Recurring", corner_radius=10, command=app.start_recurring_scan, width=130).grid(row=0, column=4, padx=6, pady=8)
    ctk.CTkButton(app.ops_row, text="Stop Recurring", corner_radius=10, command=app.stop_recurring_scan, width=120).grid(row=0, column=5, padx=6, pady=8)
    ctk.CTkButton(app.ops_row, text="Delete Schedule", corner_radius=10, command=app.delete_selected_schedule_task, width=130, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=6, padx=6, pady=8)

    app.scheduled_tasks_table = ttk.Treeview(app.ops_row, columns=("task", "frequency", "status", "summary"), show="headings", height=3)
    for col, width in {"task": 130, "frequency": 110, "status": 90, "summary": 480}.items():
        app.scheduled_tasks_table.heading(col, text=col.title())
        app.scheduled_tasks_table.column(col, width=width, anchor="center")
    app.scheduled_tasks_table.tag_configure("active", foreground="#10B981")
    app.scheduled_tasks_table.grid(row=1, column=0, columnspan=7, sticky="ew", padx=8, pady=(0, 8))

    app.ops_refresh_firewall_button = ctk.CTkButton(app.ops_row, text="Refresh Firewall", corner_radius=10, command=app.refresh_firewall_insight, width=140)
    app.ops_refresh_firewall_button.grid(row=2, column=0, padx=6, pady=8, sticky="w")
    ctk.CTkButton(app.ops_row, text="STOP ALL", corner_radius=10, command=app.stop_all_tasks, width=110, fg_color="#DC2626", hover_color="#B91C1C").grid(row=2, column=1, padx=6, pady=8, sticky="w")
    ctk.CTkLabel(app.ops_row, text="Firewall:").grid(row=2, column=2, padx=(10, 4), pady=8, sticky="w")
    ctk.CTkLabel(app.ops_row, textvariable=app.firewall_status_var, width=300, anchor="w").grid(row=2, column=3, columnspan=3, padx=4, pady=8, sticky="w")

    automation_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    automation_label.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkLabel(automation_label, text="Conditional Automations", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    automation_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    automation_card.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkCheckBox(automation_card, text="Enable auto-response", variable=app.automation_enabled_var).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkLabel(automation_card, text="Point threshold").grid(row=0, column=2, padx=(12, 4), pady=6)
    ctk.CTkEntry(automation_card, width=70, textvariable=app.automation_threshold_var, placeholder_text="80").grid(row=0, column=3, padx=4, pady=6)
    ctk.CTkLabel(automation_card, text="Action").grid(row=0, column=4, padx=(12, 4), pady=6)
    ctk.CTkOptionMenu(automation_card, values=["quarantine", "banish"], variable=app.automation_action_var, width=120).grid(row=0, column=5, padx=4, pady=6)
    ctk.CTkOptionMenu(automation_card, values=["All Connections", "Open Ports Only", "Established Only"], variable=app.automation_scope_var, width=150).grid(row=0, column=6, padx=4, pady=6)
    ctk.CTkLabel(automation_card, text="Pts: unassigned").grid(row=1, column=0, padx=(10, 4), pady=(0, 6), sticky="w")
    ctk.CTkEntry(automation_card, width=55, textvariable=app.automation_points_unassigned_var, placeholder_text="20").grid(row=1, column=1, padx=4, pady=(0, 6), sticky="w")
    ctk.CTkLabel(automation_card, text="freq").grid(row=1, column=2, padx=(10, 4), pady=(0, 6), sticky="w")
    ctk.CTkEntry(automation_card, width=55, textvariable=app.automation_points_frequency_var, placeholder_text="50").grid(row=1, column=3, padx=4, pady=(0, 6), sticky="w")
    ctk.CTkLabel(automation_card, text="dns/vpn").grid(row=1, column=4, padx=(10, 4), pady=(0, 6), sticky="w")
    ctk.CTkEntry(automation_card, width=55, textvariable=app.automation_points_dns_var, placeholder_text="30").grid(row=1, column=5, padx=4, pady=(0, 6), sticky="w")
    ctk.CTkLabel(automation_card, text="Auto-clear Port Table").grid(row=2, column=0, padx=(10, 4), pady=(0, 6), sticky="w")
    ctk.CTkOptionMenu(automation_card, values=["Disabled", "Enabled"], variable=app.auto_clear_port_var, width=110).grid(row=2, column=1, padx=4, pady=(0, 6), sticky="w")
    ctk.CTkLabel(automation_card, text="Auto-clear Packet Table").grid(row=2, column=2, padx=(10, 4), pady=(0, 6), sticky="w")
    ctk.CTkOptionMenu(automation_card, values=["Disabled", "Enabled"], variable=app.auto_clear_packet_var, width=110).grid(row=2, column=3, padx=4, pady=(0, 6), sticky="w")
    ctk.CTkLabel(automation_card, text="Clear every (minutes)").grid(row=2, column=4, padx=(10, 4), pady=(0, 6), sticky="w")
    ctk.CTkEntry(automation_card, width=70, textvariable=app.auto_clear_minutes_var, placeholder_text="15").grid(row=2, column=5, padx=4, pady=(0, 6), sticky="w")

    lan_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    lan_label.grid(row=4, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkLabel(lan_label, text="LAN Device Monitor", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    lan_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    lan_card.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))
    lan_card.grid_columnconfigure(0, weight=1)
    lan_card.grid_rowconfigure(2, weight=1)

    header = app._register_card(ctk.CTkFrame(lan_card, corner_radius=10))
    header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
    ctk.CTkLabel(header, text="LAN Controls").grid(row=0, column=0, padx=8, pady=6, sticky="w")
    ctk.CTkButton(header, text="Discover Devices", width=130, command=app.refresh_lan_devices).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkButton(header, text="Show IoT Anomalies", width=140, command=app.show_lan_anomalies).grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkButton(header, text="Quarantine Device IP", width=150, command=app.quarantine_selected_lan_device).grid(row=0, column=3, padx=6, pady=6)
    ctk.CTkButton(header, text="Banish Device IP", width=130, command=app.banish_selected_lan_device).grid(row=0, column=4, padx=6, pady=6)

    app.lan_status_var = ctk.StringVar(value="No LAN scan yet")
    ctk.CTkLabel(lan_card, textvariable=app.lan_status_var, anchor="w").grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))

    app.lan_table = ttk.Treeview(lan_card, columns=("ip", "host", "mac", "vendor", "class", "risk", "status"), show="headings", height=10)
    lan_widths = {"ip": 140, "host": 180, "mac": 140, "vendor": 180, "class": 120, "risk": 80, "status": 180}
    for col in ("ip", "host", "mac", "vendor", "class", "risk", "status"):
        app.lan_table.heading(col, text=col.upper())
        app.lan_table.column(col, width=lan_widths[col], anchor="center")
    app.lan_table.grid(row=2, column=0, sticky="nsew", padx=(10, 0), pady=(0, 10))
    lan_scroll = ttk.Scrollbar(lan_card, orient="vertical", command=app.lan_table.yview, style="NetScouter.Vertical.TScrollbar")
    app.lan_table.configure(yscrollcommand=lan_scroll.set)
    lan_scroll.grid(row=2, column=1, sticky="ns", padx=(0, 10), pady=(0, 10))

    export_row = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    export_row.grid(row=6, column=0, sticky="ew", padx=8, pady=(0, 8))
    ctk.CTkButton(export_row, text="Export AI Audit", width=140, command=app.export_ai_audit).grid(row=0, column=0, padx=6, pady=6)
    ctk.CTkButton(export_row, text="Export XLSX", width=120, command=app.export_xlsx).grid(row=0, column=1, padx=6, pady=6)
