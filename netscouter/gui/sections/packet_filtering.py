"""Packet Filtering tab layout builder."""

from __future__ import annotations

from tkinter import ttk

import customtkinter as ctk

STOP_RED = "#7F1D1D"
STOP_RED_HOVER = "#991B1B"
CLEAR_AMBER = "#B45309"
CLEAR_AMBER_HOVER = "#92400E"


def build_packet_filtering_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_rowconfigure(2, weight=1)

    controls = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    controls.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
    ctk.CTkOptionMenu(controls, values=["Selected Row", "Target Host", "Local Network"], variable=app.packet_stream_mode_var, width=140, command=app._on_packet_scope_changed).grid(row=0, column=0, padx=6, pady=6)
    ctk.CTkButton(controls, text="Start Live Packet Stream", corner_radius=10, width=180, command=app.start_live_packet_stream).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkButton(controls, text="Stop", corner_radius=10, width=90, command=app.stop_live_packet_stream, fg_color=STOP_RED, hover_color=STOP_RED_HOVER).grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkButton(controls, text="Export packet slice", corner_radius=10, width=140, command=app.export_packet_slice).grid(row=0, column=3, padx=6, pady=6)
    ctk.CTkButton(controls, text="Save Log (DB)", corner_radius=10, width=120, command=lambda: app.save_logs_to_db("packet_filtering")).grid(row=0, column=6, padx=6, pady=6)
    ctk.CTkButton(controls, text="Clear Table", corner_radius=10, width=110, command=app.clear_packet_filter_table, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=7, padx=6, pady=6)
    ctk.CTkOptionMenu(controls, values=["All", "High", "Average", "Low"], variable=app.packet_risk_filter_var, width=100, command=lambda _x: app._refresh_packet_filtering_table()).grid(row=0, column=4, padx=6, pady=6)
    ctk.CTkOptionMenu(controls, values=["All", "Weird", "Normal"], variable=app.packet_behavior_filter_var, width=100, command=lambda _x: app._refresh_packet_filtering_table()).grid(row=0, column=5, padx=6, pady=6)
    ctk.CTkLabel(controls, textvariable=app.packet_stream_status_var).grid(row=1, column=0, columnspan=3, padx=8, pady=(0, 6), sticky="w")
    ctk.CTkLabel(controls, textvariable=app.packet_scope_hint_var).grid(row=1, column=3, columnspan=3, padx=8, pady=(0, 6), sticky="e")

    app.packet_filter_table = ttk.Treeview(pane, columns=("time", "connection", "proto", "risk", "behavior", "process"), show="headings", height=12, selectmode="extended")
    for col, width in {"time": 180, "connection": 380, "proto": 90, "risk": 90, "behavior": 140, "process": 220}.items():
        app.packet_filter_table.heading(col, text=col.title())
        app.packet_filter_table.column(col, width=width, anchor="center")
    pkt_y_scroll = ttk.Scrollbar(pane, orient="vertical", command=app.packet_filter_table.yview, style="NetScouter.Vertical.TScrollbar")
    app.packet_filter_table.configure(yscrollcommand=pkt_y_scroll.set)
    app.packet_filter_table.grid(row=1, column=0, sticky="nsew", padx=(8, 0), pady=(0, 6))
    pkt_y_scroll.grid(row=1, column=1, sticky="ns", padx=(0, 8), pady=(0, 6))
    app.packet_filter_table.bind("<<TreeviewSelect>>", app._on_packet_filter_select)
    app.packet_filter_table.bind("<Button-3>", app._open_packet_filter_context_menu)

    detail = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    detail.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
    detail.grid_columnconfigure(0, weight=1)
    detail.grid_rowconfigure(1, weight=1)
    ctk.CTkLabel(detail, textvariable=app.packet_selected_summary_var, anchor="w", justify="left").grid(row=0, column=0, sticky="ew", padx=8, pady=6)
    app.packet_detail_box = ctk.CTkTextbox(detail, corner_radius=10, height=180)
    app.packet_detail_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=6)
    app.packet_stream_console = app.packet_detail_box
    action_row = ctk.CTkFrame(detail, fg_color="transparent")
    action_row.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8))
    ctk.CTkButton(action_row, text="Block Selected IP", width=140, command=app.block_selected_packet_ip).grid(row=0, column=0, padx=4, pady=4)
    ctk.CTkButton(action_row, text="Unblock Selected IP", width=160, command=app.unblock_selected_packet_ip).grid(row=0, column=1, padx=4, pady=4)
