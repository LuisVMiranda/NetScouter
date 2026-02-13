"""Settings tab layout builder."""

from __future__ import annotations

import customtkinter as ctk

CLEAR_AMBER = "#B45309"
CLEAR_AMBER_HOVER = "#92400E"


def build_settings_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_rowconfigure(8, weight=1)

    dashboard_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    dashboard_label.grid(row=0, column=0, sticky="ew", padx=8, pady=(10, 5))
    ctk.CTkLabel(dashboard_label, text="Dashboard Settings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    dashboard_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    dashboard_card.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 10))
    ctk.CTkEntry(dashboard_card, textvariable=app.target_var, width=180, placeholder_text="Persistent target IP/hostname").grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkEntry(dashboard_card, textvariable=app.port_range_var, width=120, placeholder_text="Persistent port range").grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkOptionMenu(dashboard_card, values=["Layman", "Expert"], variable=app.log_detail_mode_var, width=110).grid(row=0, column=3, padx=6, pady=6)
    ctk.CTkCheckBox(dashboard_card, text="Popup notifications", variable=app.popup_notifications_var).grid(row=0, column=4, padx=6, pady=6)

    packet_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    packet_label.grid(row=2, column=0, sticky="ew", padx=8, pady=(5, 5))
    ctk.CTkLabel(packet_label, text="Packet Filtering Settings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    packet_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    packet_card.grid(row=3, column=0, sticky="ew", padx=8, pady=(0, 10))
    ctk.CTkCheckBox(packet_card, text="Save Port Scan logs", variable=app.save_ports_var).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkCheckBox(packet_card, text="Save Packet logs", variable=app.save_packets_var).grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkCheckBox(packet_card, text="Save Intel events", variable=app.save_intel_var).grid(row=0, column=3, padx=6, pady=6)
    ctk.CTkCheckBox(packet_card, text="Save AI output", variable=app.save_ai_var).grid(row=0, column=4, padx=6, pady=6)

    intel_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    intel_label.grid(row=4, column=0, sticky="ew", padx=8, pady=(5, 5))
    ctk.CTkLabel(intel_label, text="Intelligence/API Settings", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    intel_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    intel_card.grid(row=5, column=0, sticky="ew", padx=8, pady=(0, 10))
    ctk.CTkEntry(intel_card, textvariable=app.abuseipdb_key_var, width=220, placeholder_text="AbuseIPDB API key").grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkEntry(intel_card, textvariable=app.virustotal_key_var, width=220, placeholder_text="VirusTotal API key").grid(row=0, column=2, padx=6, pady=6)
    ctk.CTkEntry(intel_card, textvariable=app.otx_key_var, width=220, placeholder_text="AlienVault OTX key").grid(row=0, column=3, padx=6, pady=6)
    ctk.CTkButton(intel_card, text="Apply Intel Keys", width=130, command=app.apply_settings).grid(row=0, column=4, padx=6, pady=6)

    ai_label = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    ai_label.grid(row=6, column=0, sticky="ew", padx=8, pady=(5, 5))
    ctk.CTkLabel(ai_label, text="AI Auditor/Database", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")

    ai_card = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    ai_card.grid(row=7, column=0, sticky="ew", padx=8, pady=(0, 10))
    ctk.CTkButton(ai_card, text="Clear DB Logs", width=130, command=app.clear_db_logs, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=0, padx=6, pady=6)
    ctk.CTkButton(ai_card, text="Clear Prompt Prefs", width=150, command=app.clear_prompt_prefs, fg_color=CLEAR_AMBER, hover_color=CLEAR_AMBER_HOVER).grid(row=0, column=1, padx=6, pady=6)
    ctk.CTkButton(ai_card, text="Save All Settings", width=150, command=app.save_settings_preferences, fg_color="#0F766E", hover_color="#115E59").grid(row=0, column=2, padx=(16, 6), pady=6)
    ctk.CTkLabel(ai_card, textvariable=app.settings_save_feedback_var, anchor="w").grid(row=0, column=3, padx=(4, 6), pady=6, sticky="w")
    ctk.CTkLabel(ai_card, text="Use Save All Settings to persist every option above.", anchor="w").grid(row=1, column=0, columnspan=4, padx=10, pady=(0, 6), sticky="w")
