"""Cross-platform firewall status and block controls."""

from __future__ import annotations

import ipaddress
import platform
import subprocess
from typing import Any


def detect_os() -> str:
    """Return normalized OS key derived from platform.system()."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    return "unsupported"


def _run_command(command: list[str]) -> dict[str, Any]:
    """Execute command and return a GUI-friendly structured result."""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=True)
        return {
            "success": True,
            "command": " ".join(command),
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "command_not_found",
            "command": " ".join(command),
            "message": f"Firewall command not found: {command[0]}",
        }
    except PermissionError:
        return {
            "success": False,
            "error": "permission_denied",
            "command": " ".join(command),
            "message": "Insufficient permissions to run firewall command.",
        }
    except subprocess.CalledProcessError as exc:
        return {
            "success": False,
            "error": "command_failed",
            "command": " ".join(command),
            "returncode": exc.returncode,
            "stdout": (exc.stdout or "").strip(),
            "stderr": (exc.stderr or "").strip(),
            "message": "Firewall command failed.",
        }
    except OSError as exc:
        return {
            "success": False,
            "error": "os_error",
            "command": " ".join(command),
            "message": str(exc),
        }


def get_firewall_status() -> dict[str, Any]:
    """Get firewall status for the current operating system."""
    os_name = detect_os()

    if os_name == "windows":
        result = _run_command(["netsh", "advfirewall", "show", "allprofiles"])
    elif os_name == "linux":
        result = _run_command(["ufw", "status", "verbose"])
    elif os_name == "macos":
        result = _run_command(["pfctl", "-s", "info"])
        if not result["success"]:
            return {
                "success": False,
                "platform": os_name,
                "error": result.get("error", "unsupported"),
                "message": (
                    "Unable to query pf status. Ensure pfctl is available and run with elevated permissions."
                ),
                "details": result,
            }
    else:
        return {
            "success": False,
            "platform": os_name,
            "error": "unsupported_platform",
            "message": "Firewall status is unsupported on this operating system.",
        }

    result["platform"] = os_name
    return result


def _validate_ip(ip: str) -> dict[str, Any] | None:
    """Validate IP address input for firewall commands."""
    try:
        parsed = ipaddress.ip_address(ip)
        return {"success": True, "ip": str(parsed)}
    except ValueError:
        return {
            "success": False,
            "error": "invalid_ip",
            "message": f"Invalid IP address: {ip}",
        }


def banish_ip(ip: str) -> dict[str, Any]:
    """Add firewall rules to block traffic for the provided IP address."""
    validated = _validate_ip(ip)
    if validated is None or not validated["success"]:
        return validated or {
            "success": False,
            "error": "invalid_ip",
            "message": "Invalid IP address.",
        }

    clean_ip = validated["ip"]
    os_name = detect_os()

    if os_name == "windows":
        inbound = _run_command(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=NetScouter Block {clean_ip} Inbound",
                "dir=in",
                "action=block",
                f"remoteip={clean_ip}",
            ]
        )
        outbound = _run_command(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=NetScouter Block {clean_ip} Outbound",
                "dir=out",
                "action=block",
                f"remoteip={clean_ip}",
            ]
        )

        return {
            "success": inbound["success"] and outbound["success"],
            "platform": os_name,
            "ip": clean_ip,
            "results": {"inbound": inbound, "outbound": outbound},
            "message": "Firewall rules applied on Windows." if inbound["success"] and outbound["success"] else "Failed to apply one or more Windows firewall rules.",
        }

    if os_name == "linux":
        ufw = _run_command(["ufw", "deny", "from", clean_ip])
        if ufw["success"]:
            return {
                "success": True,
                "platform": os_name,
                "ip": clean_ip,
                "message": "UFW deny rule applied.",
                "result": ufw,
            }

        if ufw.get("error") == "command_not_found":
            iptables = _run_command(["iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP"])
            return {
                "success": iptables["success"],
                "platform": os_name,
                "ip": clean_ip,
                "message": "iptables fallback rule applied." if iptables["success"] else "Failed to apply iptables fallback rule.",
                "result": iptables,
            }

        return {
            "success": False,
            "platform": os_name,
            "ip": clean_ip,
            "message": "Failed to apply UFW deny rule.",
            "result": ufw,
        }

    if os_name == "macos":
        pf_status = _run_command(["pfctl", "-s", "info"])
        if not pf_status["success"]:
            return {
                "success": False,
                "platform": os_name,
                "ip": clean_ip,
                "message": "Unable to query pf status. Run with elevated permissions.",
                "result": pf_status,
            }

        return {
            "success": False,
            "platform": os_name,
            "ip": clean_ip,
            "error": "manual_step_required",
            "message": (
                "pf is available. Add an anchor rule manually, for example: "
                f"echo 'block drop from {clean_ip} to any' | sudo pfctl -a com.netscouter -f - "
                "then ensure the anchor is loaded from /etc/pf.conf and reload pf."
            ),
            "result": pf_status,
        }

    return {
        "success": False,
        "platform": os_name,
        "ip": clean_ip,
        "error": "unsupported_platform",
        "message": "IP blocking is unsupported on this operating system.",
    }
