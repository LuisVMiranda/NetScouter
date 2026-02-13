"""Possible Threats tab layout builder."""

from __future__ import annotations

from tkinter import ttk

import customtkinter as ctk


def build_possible_threats_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_rowconfigure(1, weight=1)
    pane.grid_rowconfigure(2, weight=1)

    header = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
    ctk.CTkLabel(header, text="Possible Threats", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")
    ctk.CTkButton(header, text="Refresh", width=92, command=app._refresh_threats_table).grid(row=0, column=1, padx=4, pady=6)
    ctk.CTkButton(header, text="Drop/Block IP", width=108, command=app._threat_block_selected).grid(row=0, column=2, padx=4, pady=6)
    ctk.CTkButton(header, text="Quarantine IP", width=118, command=app._threat_quarantine_selected).grid(row=0, column=3, padx=4, pady=6)
    ctk.CTkButton(header, text="Temp Ban", width=96, command=app._threat_temp_ban_selected).grid(row=0, column=4, padx=4, pady=6)
    ctk.CTkButton(header, text="Unban + Watch", width=116, command=app._threat_unban_watch_selected).grid(row=0, column=5, padx=4, pady=6)
    ctk.CTkButton(header, text="Unban IP", width=92, command=app._threat_unban_selected).grid(row=0, column=6, padx=4, pady=6)
    ctk.CTkButton(header, text="Remove Entry", width=104, command=app._threat_remove_selected).grid(row=0, column=7, padx=4, pady=6)
    app.threat_country_filter = ctk.CTkOptionMenu(header, values=["All Countries"], variable=app.threat_country_filter_var, width=150, command=lambda _v: app._refresh_threats_table())
    app.threat_country_filter.grid(row=0, column=8, padx=4, pady=6)
    app.threat_reason_filter = ctk.CTkOptionMenu(header, values=["All Reasons"], variable=app.threat_reason_filter_var, width=170, command=lambda _v: app._refresh_threats_table())
    app.threat_reason_filter.grid(row=0, column=9, padx=4, pady=6)

    cols = ("timestamp", "ip", "action", "status", "reason", "expires")
    app.threats_table = ttk.Treeview(pane, columns=cols, show="headings", height=10, selectmode="extended")
    widths = {"timestamp": 165, "ip": 170, "action": 105, "status": 100, "reason": 360, "expires": 150}
    for col in cols:
        app.threats_table.heading(col, text=col.title())
        app.threats_table.column(col, width=widths[col], anchor="center")
    y_scroll = ttk.Scrollbar(pane, orient="vertical", command=app.threats_table.yview, style="NetScouter.Vertical.TScrollbar")
    app.threats_table.configure(yscrollcommand=y_scroll.set)
    app.threats_table.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 6))
    y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 6))
    app.threats_table.bind("<<TreeviewSelect>>", app._on_threat_selected)

    bottom = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    bottom.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
    bottom.grid_columnconfigure(0, weight=1)
    bottom.grid_columnconfigure(1, weight=2)
    bottom.grid_rowconfigure(1, weight=1)

    ctk.CTkLabel(bottom, text="Evidence Timeline", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))
    ctk.CTkLabel(bottom, text="Threat Detail", font=ctk.CTkFont(weight="bold")).grid(row=0, column=1, sticky="w", padx=10, pady=(8, 4))

    app.threat_timeline_box = ctk.CTkTextbox(bottom, corner_radius=10)
    app.threat_timeline_box.grid(row=1, column=0, sticky="nsew", padx=(10, 6), pady=(0, 8))
    app.threat_detail_box = ctk.CTkTextbox(bottom, corner_radius=10)
    app.threat_detail_box.grid(row=1, column=1, sticky="nsew", padx=(6, 10), pady=(0, 8))
    ctk.CTkButton(bottom, text="⧉ Copy Threat Detail", width=150, command=app._copy_threat_detail).grid(row=2, column=1, sticky="e", padx=10, pady=(0, 4))
    ctk.CTkLabel(bottom, textvariable=app.threat_action_hint_var, anchor="w").grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 8))
