"""Intelligence tab layout builder."""

from __future__ import annotations

import customtkinter as ctk


def build_intelligence_tab(app: ctk.CTk, pane: ctk.CTkFrame) -> None:
    pane.grid_columnconfigure(0, weight=1)
    pane.grid_rowconfigure(8, weight=1)

    guide = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
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

    app.settings_row = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    app.settings_row.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkLabel(app.settings_row, text="AbuseIPDB key").grid(row=0, column=0, padx=(8, 4), pady=8, sticky="w")
    ctk.CTkEntry(app.settings_row, width=260, textvariable=app.abuseipdb_key_var, placeholder_text="e.g. 1f2a...abuseipdb-token").grid(row=0, column=1, padx=4, pady=8)
    ctk.CTkLabel(app.settings_row, text="VirusTotal key").grid(row=0, column=2, padx=(8, 4), pady=8, sticky="w")
    ctk.CTkEntry(app.settings_row, width=260, textvariable=app.virustotal_key_var, placeholder_text="e.g. 5ab3...virustotal-api-key").grid(row=0, column=3, padx=4, pady=8)
    ctk.CTkLabel(app.settings_row, text="(API v3 key from VirusTotal profile)", anchor="w").grid(row=0, column=8, padx=(4, 8), pady=8, sticky="w")
    ctk.CTkLabel(app.settings_row, text="AlienVault OTX key").grid(row=1, column=0, padx=(8, 4), pady=8, sticky="w")
    ctk.CTkEntry(app.settings_row, width=260, textvariable=app.otx_key_var, placeholder_text="e.g. 7cd9...otx-token").grid(row=1, column=1, padx=4, pady=8)
    ctk.CTkLabel(app.settings_row, text="Consensus Threshold").grid(row=1, column=2, padx=(8, 4), pady=8)
    ctk.CTkEntry(app.settings_row, width=70, textvariable=app.reputation_threshold_var, placeholder_text="3").grid(row=1, column=3, padx=4, pady=8, sticky="w")
    ctk.CTkLabel(app.settings_row, text="Intel timeout (s)").grid(row=0, column=4, padx=(8, 4), pady=8)
    ctk.CTkEntry(app.settings_row, width=80, textvariable=app.reputation_timeout_var, placeholder_text="4").grid(row=0, column=5, padx=4, pady=8)
    ctk.CTkLabel(app.settings_row, text="AI timeout (s)").grid(row=1, column=4, padx=(8, 4), pady=8)
    ctk.CTkEntry(app.settings_row, width=80, textvariable=app.ai_timeout_var, placeholder_text="120").grid(row=1, column=5, padx=4, pady=8)
    ctk.CTkCheckBox(app.settings_row, text="Auto-block by consensus", variable=app.auto_block_consensus_var).grid(row=0, column=6, rowspan=2, padx=10, pady=8)
    ctk.CTkButton(app.settings_row, text="Apply Intel Keys", command=app.apply_settings, width=130).grid(row=0, column=7, rowspan=2, padx=(4, 10), pady=8)

    firewall_frame = app._register_card(ctk.CTkFrame(pane, corner_radius=10))
    firewall_frame.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 6))
    ctk.CTkLabel(firewall_frame, text="Firewall Operations", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=6, sticky="w")
    app._build_firewall_controls(firewall_frame, start_row=1)

    app._build_console(pane, row=3, compact=True)
