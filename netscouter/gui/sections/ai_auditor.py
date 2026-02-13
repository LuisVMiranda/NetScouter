"""AI Auditor tab layout builder."""

from __future__ import annotations

import customtkinter as ctk

STOP_RED = "#7F1D1D"
STOP_RED_HOVER = "#991B1B"
CLEAR_AMBER = "#B45309"
CLEAR_AMBER_HOVER = "#92400E"


def build_ai_auditor_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_columnconfigure(1, weight=0)
    pane.grid_rowconfigure(6, weight=1)

    ai_header = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    ai_header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
    ctk.CTkLabel(ai_header, text="AI Feedback from Logs").grid(row=0, column=0, sticky="w", padx=6, pady=6)
    ctk.CTkButton(ai_header, text="Analyze Logs", corner_radius=10, command=app.analyze_logs, width=120).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkButton(ai_header, text="Cancel", corner_radius=10, command=app.cancel_ai_analysis, width=90, fg_color=STOP_RED, hover_color=STOP_RED_HOVER).grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkButton(ai_header, text="Clear Logs", corner_radius=10, command=app.clear_ai_logs, width=100, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=3, padx=6, pady=6)

    ai_filter_row = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    ai_filter_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkCheckBox(ai_filter_row, text="High risk only", variable=app.ai_high_risk_only_var).grid(row=0, column=0, padx=6, pady=6)
    ctk.CTkCheckBox(ai_filter_row, text="Open ports only", variable=app.ai_open_ports_only_var).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkCheckBox(ai_filter_row, text="Alerts only", variable=app.ai_alerts_only_var).grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkOptionMenu(ai_filter_row, values=["App Logs", "External File"], variable=app.ai_log_source_var, width=120).grid(row=0, column=3, padx=6, pady=6)
    ctk.CTkOptionMenu(ai_filter_row, values=["Port Scan", "Packet Scan"], variable=app.ai_data_type_var, width=110).grid(row=0, column=4, padx=6, pady=6)
    ctk.CTkEntry(ai_filter_row, width=220, textvariable=app.ai_external_log_path_var, placeholder_text="External log path (.json/.txt)").grid(row=0, column=5, padx=6, pady=6)
    ctk.CTkLabel(ai_filter_row, text="Max rows").grid(row=0, column=6, padx=(10, 4), pady=6)
    ctk.CTkEntry(ai_filter_row, width=80, textvariable=app.ai_max_rows_var, placeholder_text="600").grid(row=0, column=7, padx=4, pady=6)
    ctk.CTkLabel(ai_filter_row, textvariable=app.ai_elapsed_var).grid(row=0, column=8, padx=(12, 6), pady=6)

    prompt_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    prompt_card.grid(row=0, column=1, rowspan=2, sticky="ne", padx=(0, 8), pady=(8, 6))
    ctk.CTkLabel(prompt_card, text="PROMPT EDITOR", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=8, pady=6, sticky="w")
    ctk.CTkOptionMenu(prompt_card, values=["Port Scan", "Packet Scan"], variable=app.prompt_type_var, width=110, command=lambda _v: app._load_prompt_editor_text()).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkButton(prompt_card, text="Save Prompt", width=110, command=app.save_prompt_editor).grid(row=0, column=2, padx=6, pady=6)
    app.prompt_editor_box = ctk.CTkTextbox(prompt_card, corner_radius=10, height=100, width=420)
    app.prompt_editor_box.grid(row=1, column=0, columnspan=3, sticky="ew", padx=8, pady=(0, 8))

    app.ai_status_var = ctk.StringVar(value="Run scans, choose AI filters, then Analyze Logs.")
    ctk.CTkLabel(pane, textvariable=app.ai_status_var, anchor="w", justify="left").grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 6))
    app.ai_progress = ctk.CTkProgressBar(pane)
    app.ai_progress.grid(row=4, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 6))
    app.ai_progress.set(0)
    app.ai_feedback_box = ctk.CTkTextbox(pane, corner_radius=10)
    app.ai_feedback_box.grid(row=6, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 8))
