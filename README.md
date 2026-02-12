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
