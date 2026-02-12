# NetScouter

NetScouter is a Python desktop app scaffold for network scanning, intel enrichment, firewall integration, exports, and scheduled scans.

## Updated architecture

```text
netscouter/
  __init__.py
  main.py
  gui/
    app.py              # Sidebar shell + workspace panes (Dashboard/Intel/Firewall/AI/Ops)
  scanner/
  intel/
  firewall/
  alerts/
    voice.py            # Voice alerts with pluggable TTS backends + severity thresholds
    remote.py           # Remote /BLOCK channel + secure command authorization
  export/
  scheduler/
pyproject.toml
README.md
assets/screenshots/
```

### GUI redesign summary

- `NetScouterApp` now uses a **left vertical sidebar** to switch between five panes:
  - Dashboard
  - Intelligence
  - Firewall
  - AI Auditor
  - Ops/Schedule
- The right side is now a single workspace frame that swaps pane content.
- Existing monolithic UI builders were split into per-pane builders for cleaner maintenance.

### Alerting and remote response

- `netscouter.alerts.voice.VoiceAlertService`
  - Accepts any backend implementing `speak(text)`.
  - Enforces severity thresholds (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `netscouter.alerts.remote.RemoteActionChannel`
  - Supports mobile-triggered command flows such as `/BLOCK <ip>`.
  - Includes shared-secret HMAC signatures, sender allowlist, timestamp windows, and nonce replay protection.

## Redesigned layout asset

![NetScouter redesigned workspace](assets/screenshots/redesign-layout.svg)

## Prerequisites

- Python 3.10+
- `pip`

## Install

### Windows (PowerShell)

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

### Linux (bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

### macOS (zsh/bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

## Run

From the repository root (with virtual environment active):

```bash
python -m netscouter.main
```

## Dependencies

Defined in `pyproject.toml`:

- customtkinter
- psutil
- requests
- pandas
- apscheduler
- matplotlib
- scapy

### Live packet stream quick usage

1. Run a scan in **Dashboard** and click a row, or set a target IP manually.
2. Click **Start Live Packet Stream**.
3. Read updates in the packet detail panel (double-click a row for full report).
4. Use **Export packet slice** for JSON evidence capture.
5. Use **Clear Scan Logs** to wipe both table rows and console logs when starting a fresh investigation.
6. Use **Local Info** in Dashboard to display current LAN/WAN addresses.

If the stream does not start, run with elevated privileges and ensure packet-capture drivers are present:
- Windows: run shell as Administrator and install Npcap.
- Linux/macOS: run with sudo or grant packet capabilities.


### Ops automation and LAN monitor

- **Conditional Automations** (Ops/Schedule): optional auto-response for repeated high-risk activity.
  - Toggle **Enable auto-response** on/off.
  - Set high-risk hit threshold.
  - Choose action (`quarantine` or `banish`).
- **LAN Device Monitor** (Ops/Schedule): discover local devices, inspect IoT anomalies, and trigger per-device containment actions.

## Live packet streaming permissions

NetScouter can stream packets live with Scapy. Raw packet sniffing generally requires elevated privileges:

- **Linux/macOS:** run the app with `sudo`, or grant packet-capture capabilities to your Python runtime (`CAP_NET_RAW` / `CAP_NET_ADMIN`).
- **Windows:** run the app from an Administrator shell (Npcap/WinPcap recommended for capture support).

Without elevated permissions, packet stream start may fail with permission errors.
