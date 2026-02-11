"""GUI bootstrap for NetScouter."""

from __future__ import annotations

import customtkinter as ctk


def launch_dashboard() -> None:
    """Start a minimal CustomTkinter dashboard shell."""
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")

    app = ctk.CTk()
    app.title("NetScouter")
    app.geometry("900x600")

    label = ctk.CTkLabel(app, text="NetScouter dashboard initialized")
    label.pack(padx=24, pady=24)

    app.mainloop()
