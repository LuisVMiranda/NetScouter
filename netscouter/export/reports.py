"""AI audit report exports, model readiness checks, and prompt builders."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Iterable

import pandas as pd
import requests

PUBLIC_IP_LOOKUP_URL = "http://ip-api.com/json/"
AI_AUDIT_HEADER = "TIMESTAMP | PORT | REMOTE_IP | RISK_LEVEL | COUNTRY | CITY | PROVIDER"


def _as_timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, str) and value.strip():
        return value
    return datetime.now(timezone.utc).isoformat()


def export_ai_audit_report(
    scan_results: Iterable[dict[str, Any]],
    output_path: str | Path,
    *,
    analyst_prompt: str | None = None,
    network_prompt: str | None = None,
) -> Path:
    """Export scan results to a text file formatted for downstream AI audit."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    if analyst_prompt:
        lines.extend(["SYSTEM PROMPT A", analyst_prompt, ""])
    if network_prompt:
        lines.extend(["SYSTEM PROMPT B", network_prompt, ""])

    lines.append(AI_AUDIT_HEADER)
    for entry in scan_results:
        lines.append(
            " | ".join(
                [
                    _as_timestamp(entry.get("timestamp")),
                    str(entry.get("port", "")),
                    str(entry.get("remote_ip") or entry.get("ip") or ""),
                    str(entry.get("risk_level", "")),
                    str(entry.get("country", "")),
                    str(entry.get("city", "")),
                    str(entry.get("provider", "")),
                ]
            )
        )

    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def _models_from_registry(registry_path: str | Path) -> set[str]:
    path = Path(registry_path)
    if not path.exists() or path.stat().st_size == 0:
        return set()

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        candidates = data.get("models", [])
    elif isinstance(data, list):
        candidates = data
    else:
        candidates = []

    return {str(item).strip() for item in candidates if str(item).strip()}


def detect_local_model(
    model_name: str = "llama3.2:3b",
    *,
    registry_path: str | Path | None = None,
) -> bool:
    """Detect whether a local AI model is available via Ollama or a registry file."""
    executable = shutil.which("ollama")
    if executable:
        proc = subprocess.run(
            [executable, "list"],
            check=False,
            capture_output=True,
            text=True,
        )
        listed = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode == 0 and model_name in listed:
            return True

    lookup_path = registry_path or os.environ.get("NETSCOUTER_MODEL_REGISTRY")
    if lookup_path:
        return model_name in _models_from_registry(lookup_path)

    return False


def _prompt_install_ai_features() -> bool:
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        try:
            return bool(
                messagebox.askyesno(
                    title="NetScouter AI Setup",
                    message="Install AI-Ready features?",
                )
            )
        finally:
            root.destroy()
    except Exception:
        return False


def install_local_model(model_name: str = "llama3.2:3b") -> bool:
    """Attempt to install/download the selected local model automatically."""
    executable = shutil.which("ollama")
    if not executable:
        return False

    proc = subprocess.run(
        [executable, "pull", model_name],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def ensure_ai_readiness(
    model_name: str = "llama3.2:3b",
    *,
    registry_path: str | Path | None = None,
    console: Any = print,
) -> bool:
    """Ensure AI-ready components are available and report readiness to console."""
    if detect_local_model(model_name, registry_path=registry_path):
        console(f"[AI] Ready: local model available ({model_name}).")
        return True

    console(f"[AI] Missing model: {model_name}.")
    if not _prompt_install_ai_features():
        console("[AI] User declined AI-ready feature installation.")
        return False

    installed = install_local_model(model_name)
    if installed and detect_local_model(model_name, registry_path=registry_path):
        console(f"[AI] Ready: {model_name} installed successfully.")
        return True

    console(f"[AI] Not ready: failed to install {model_name}.")
    return False


def resolve_local_network_context(timeout_seconds: int = 5) -> dict[str, str]:
    """Resolve city/provider context from current public IP lookup."""
    try:
        response = requests.get(PUBLIC_IP_LOOKUP_URL, timeout=timeout_seconds)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException:
        return {"city": "Unknown", "provider": "Unknown", "public_ip": "Unknown"}

    return {
        "city": str(data.get("city") or "Unknown"),
        "provider": str(data.get("isp") or data.get("org") or "Unknown"),
        "public_ip": str(data.get("query") or "Unknown"),
    }


def build_analyst_prompt() -> str:
    """Prompt template for the security analyst workflow."""
    return (
        "You are a Security Analyst. I will provide network logs. Your task is to look "
        "for 'Lateral Movement' or 'Vertical Scans'. Identify if any single IP has "
        "appeared across multiple ports and recommend if a firewall drop rule is necessary."
    )


def build_network_engine_prompt(public_ip_lookup: dict[str, Any] | None = None) -> str:
    """Prompt template for network engine with dynamic ISP and city insertion."""
    context = public_ip_lookup or resolve_local_network_context()
    city = str(context.get("city") or "Unknown")
    provider = str(context.get("provider") or "Unknown")

    return (
        "You are a specialized Network Security Engine. I am providing a log of "
        "ESTABLISHED connections. Cross-reference the IPs. If an IP is not from my ISP "
        f"({provider}) or my City ({city}), flag it for manual review. Focus on identifying "
        "'Scanning' behavior where one IP hits multiple ports."
    )


def build_rag_lines(scan_results: Iterable[dict[str, Any]], limit: int = 300) -> list[str]:
    """Build normalized AI-audit log lines with a fixed header."""
    lines = [AI_AUDIT_HEADER]
    for index, entry in enumerate(scan_results):
        if index >= limit:
            break
        lines.append(
            " | ".join(
                [
                    _as_timestamp(entry.get("timestamp")),
                    str(entry.get("port", "")),
                    str(entry.get("remote_ip") or entry.get("ip") or ""),
                    str(entry.get("risk_level", "")),
                    str(entry.get("country", "")),
                    str(entry.get("city", "")),
                    str(entry.get("provider", "")),
                ]
            )
        )
    return lines


def analyze_logs_with_ollama(
    scan_results: Iterable[dict[str, Any]],
    *,
    context: dict[str, Any] | None = None,
    model_name: str = "llama3.2:3b",
    timeout_seconds: int = 120,
) -> tuple[bool, str]:
    """Run a local Ollama model against NetScouter logs and return analysis text."""
    executable = shutil.which("ollama")
    if not executable:
        return False, "Ollama CLI was not found in PATH."

    runtime_context = context or resolve_local_network_context()
    system_prompt_a = build_analyst_prompt()
    system_prompt_b = build_network_engine_prompt(runtime_context)
    rag_lines = build_rag_lines(scan_results)
    prompt = "\n".join(
        [
            "SYSTEM PROMPT A:",
            system_prompt_a,
            "",
            "SYSTEM PROMPT B:",
            system_prompt_b,
            "",
            "NETWORK LOGS:",
            *rag_lines,
            "",
            "Provide concise findings, suspicious IPs, and recommended firewall actions.",
        ]
    )

    try:
        proc = subprocess.run(
            [executable, "run", model_name, prompt],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return False, f"Ollama analysis timed out after {timeout_seconds} seconds."
    except Exception as exc:  # noqa: BLE001
        return False, f"Ollama analysis failed to start: {exc}"

    output = (proc.stdout or "").strip()
    if proc.returncode != 0:
        err = (proc.stderr or output or "unknown error").strip()
        return False, f"Ollama analysis failed: {err}"
    if not output:
        return False, "Ollama returned empty output."
    return True, output


def export_session_to_xlsx(
    scan_results: Iterable[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Export a scan session to XLSX using pandas DataFrame.to_excel."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    dataframe = pd.DataFrame(list(scan_results))
    dataframe.to_excel(target, index=False)
    return target
