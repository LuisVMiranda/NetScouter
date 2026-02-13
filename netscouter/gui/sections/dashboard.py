"""Dashboard tab layout builder."""

from __future__ import annotations

import customtkinter as ctk

STOP_RED = "#7F1D1D"
STOP_RED_HOVER = "#991B1B"


def build_dashboard_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_rowconfigure(2, weight=1)

    app.scan_row = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    app.scan_row.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
    app.scan_row.grid_columnconfigure(2, weight=1)
    ctk.CTkLabel(app.scan_row, text="Target").grid(row=0, column=0, padx=(6, 2), pady=8, sticky="w")
    ctk.CTkEntry(app.scan_row, textvariable=app.target_var, placeholder_text="127.0.0.1 or hostname").grid(row=0, column=1, columnspan=2, padx=(2, 6), pady=8, sticky="ew")
    ctk.CTkLabel(app.scan_row, text="Port Range").grid(row=0, column=4, padx=6, pady=8, sticky="w")
    ctk.CTkEntry(app.scan_row, width=140, textvariable=app.port_range_var, placeholder_text="20-1024").grid(row=0, column=5, padx=6, pady=8)
    app.scan_button = ctk.CTkButton(app.scan_row, text="Scan", corner_radius=10, command=app.start_scan, width=110)
    app.scan_button.grid(row=0, column=6, padx=6, pady=8, sticky="w")
    app.scan_established_button = ctk.CTkButton(app.scan_row, text="Scan Established", corner_radius=10, command=app.start_established_scan, width=150)
    app.scan_established_button.grid(row=0, column=7, padx=6, pady=8, sticky="w")

    ctk.CTkButton(app.scan_row, text="Stop All", corner_radius=10, width=110, command=app.stop_all_tasks, fg_color=STOP_RED, hover_color=STOP_RED_HOVER).grid(row=0, column=8, padx=6, pady=8, sticky="w")
    ctk.CTkButton(app.scan_row, text="Show Charts", corner_radius=10, command=app.show_charts, width=110).grid(row=1, column=0, padx=6, pady=8, sticky="w")
    ctk.CTkButton(app.scan_row, text="Save Log (DB)", corner_radius=10, width=120, command=lambda: app.save_logs_to_db("dashboard")).grid(row=1, column=1, padx=6, pady=8, sticky="w")
    app.local_info_button = ctk.CTkButton(app.scan_row, text="Local IP", corner_radius=10, command=app.toggle_local_network_info, width=120)
    app.local_info_button.grid(row=2, column=0, padx=6, pady=(2, 8), sticky="w")

    ctk.CTkLabel(
        app.scan_row,
        textvariable=app.local_info_var,
        anchor="w",
        justify="left",
        wraplength=980,
    ).grid(row=2, column=1, columnspan=8, padx=8, pady=(0, 8), sticky="ew")

    app._build_results_table(pane, row=2)
