# NetScouter

NetScouter is a Python desktop app scaffold for network scanning, intel enrichment, firewall integration, exports, and scheduled scans.

## Project layout

```text
netscouter/
  __init__.py
  main.py
  gui/
  scanner/
  intel/
  firewall/
  export/
  scheduler/
pyproject.toml
README.md
```

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


## Live packet streaming permissions

NetScouter can stream packets live with Scapy. Raw packet sniffing generally requires elevated privileges:

- **Linux/macOS:** run the app with `sudo`, or grant packet-capture capabilities to your Python runtime (`CAP_NET_RAW` / `CAP_NET_ADMIN`).
- **Windows:** run the app from an Administrator shell (Npcap/WinPcap recommended for capture support).

Without elevated permissions, packet stream start may fail with permission errors.

## Reputation intelligence configuration

NetScouter can enrich each scanned IP using AbuseIPDB, VirusTotal, and AlienVault OTX. Configure API keys with environment variables (or in-app settings panel and click **Apply Settings**):

- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY` (or `VT_API_KEY`)
- `OTX_API_KEY`

Consensus scoring is displayed per row as `flagged/3`. Auto-blocking only runs when:

1. **Auto-block by consensus** is enabled in settings.
2. The configured threshold is met (default `3`).
3. Firewall action executes successfully.

## IoT Map and anomaly detection

The dashboard includes an **IoT Map** tab that can:

- Discover LAN assets with a ping + ARP sweep.
- Build an in-memory inventory keyed by MAC/IP with `device_type`, `first_seen`, and `last_seen`.
- Correlate established outbound flows from IoT-class devices to external destinations.
- Flag suspicious country/provider/port behavior via IoT-specific risk rules.
- Export inventory and anomalies to JSON.
