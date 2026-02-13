"""Cross-platform firewall status and block controls."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Any

from .quarantine import build_quarantine_plan


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
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=8,
        )
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
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "timeout",
            "command": " ".join(command),
            "message": "Firewall command timed out.",
        }
    except OSError as exc:
        return {
            "success": False,
            "error": "os_error",
            "command": " ".join(command),
            "message": str(exc),
        }


def _parse_windows_profiles(raw_output: str) -> dict[str, Any]:
    profiles: dict[str, dict[str, str | bool | None]] = {}
    current_profile: str | None = None

    for line in raw_output.splitlines():
        clean = line.strip()
        if clean.endswith("Profile Settings:"):
            current_profile = clean.split(" Profile Settings:")[0].strip().lower()
            profiles[current_profile] = {
                "enabled": None,
                "default_inbound": None,
                "default_outbound": None,
            }
            continue

        if current_profile is None or not clean:
            continue

        state_match = re.match(r"State\s+(ON|OFF)", clean, flags=re.IGNORECASE)
        if state_match:
            profiles[current_profile]["enabled"] = state_match.group(1).upper() == "ON"
            continue

        policy_match = re.match(r"Firewall Policy\s+([^,]+),(.+)", clean, flags=re.IGNORECASE)
        if policy_match:
            inbound = policy_match.group(1).strip().lower().replace("inbound", "")
            outbound = policy_match.group(2).strip().lower().replace("outbound", "")
            profiles[current_profile]["default_inbound"] = inbound or None
            profiles[current_profile]["default_outbound"] = outbound or None

    enabled = any(bool(v.get("enabled")) for v in profiles.values())
    return {"enabled": enabled, "profile_modes": profiles}


def _parse_linux_ufw(raw_output: str) -> dict[str, Any]:
    enabled_match = re.search(r"Status:\s*(active|inactive)", raw_output, flags=re.IGNORECASE)
    defaults_match = re.search(
        r"Default:\s*([^,]+)\s*\(incoming\),\s*([^,]+)\s*\(outgoing\)",
        raw_output,
        flags=re.IGNORECASE,
    )

    enabled = (enabled_match.group(1).lower() == "active") if enabled_match else False
    default_inbound = defaults_match.group(1).strip().lower() if defaults_match else None
    default_outbound = defaults_match.group(2).strip().lower() if defaults_match else None

    return {
        "enabled": enabled,
        "profile_modes": {
            "default": {
                "enabled": enabled,
                "default_inbound": default_inbound,
                "default_outbound": default_outbound,
            }
        },
    }


def _parse_macos_pf(raw_output: str) -> dict[str, Any]:
    status_match = re.search(r"Status:\s*(Enabled|Disabled)", raw_output, flags=re.IGNORECASE)
    enabled = (status_match.group(1).lower() == "enabled") if status_match else False

    return {
        "enabled": enabled,
        "profile_modes": {
            "pf": {
                "enabled": enabled,
                "default_inbound": None,
                "default_outbound": None,
            }
        },
    }


def get_firewall_status() -> dict[str, Any]:
    """Get firewall status for the current operating system."""
    os_name = detect_os()

    if os_name == "windows":
        status_result = _run_command(["netsh", "advfirewall", "show", "allprofiles"])
        if not status_result["success"]:
            return {
                "success": False,
                "platform": os_name,
                "message": "Unable to query Windows firewall profiles.",
                "details": status_result,
            }

        parsed = _parse_windows_profiles(status_result.get("stdout", ""))
        active_rules_count = None

        return {
            "success": True,
            "platform": os_name,
            "enabled": parsed["enabled"],
            "profile_modes": parsed["profile_modes"],
            "active_rules_count": active_rules_count,
            "default_inbound_action": next(
                (v.get("default_inbound") for v in parsed["profile_modes"].values() if v.get("default_inbound") is not None),
                None,
            ),
            "default_outbound_action": next(
                (v.get("default_outbound") for v in parsed["profile_modes"].values() if v.get("default_outbound") is not None),
                None,
            ),
            "details": {"status": status_result},
            "message": "Windows firewall status collected.",
        }

    if os_name == "linux":
        status_result = _run_command(["ufw", "status", "verbose"])
        if not status_result["success"]:
            return {
                "success": False,
                "platform": os_name,
                "message": "Unable to query UFW firewall status.",
                "details": status_result,
            }

        parsed = _parse_linux_ufw(status_result.get("stdout", ""))
        rules_result = _run_command(["ufw", "status", "numbered"])
        active_rules_count = 0
        if rules_result["success"]:
            active_rules_count = len(re.findall(r"^\[\s*\d+\]", rules_result.get("stdout", ""), flags=re.MULTILINE))

        return {
            "success": True,
            "platform": os_name,
            "enabled": parsed["enabled"],
            "profile_modes": parsed["profile_modes"],
            "active_rules_count": active_rules_count,
            "default_inbound_action": parsed["profile_modes"]["default"].get("default_inbound"),
            "default_outbound_action": parsed["profile_modes"]["default"].get("default_outbound"),
            "details": {"status": status_result, "rules": rules_result},
            "message": "UFW firewall status collected.",
        }

    if os_name == "macos":
        status_result = _run_command(["pfctl", "-s", "info"])
        if not status_result["success"]:
            return {
                "success": False,
                "platform": os_name,
                "error": status_result.get("error", "unsupported"),
                "message": (
                    "Unable to query pf status. Ensure pfctl is available and run with elevated permissions."
                ),
                "details": status_result,
            }

        parsed = _parse_macos_pf(status_result.get("stdout", ""))
        return {
            "success": True,
            "platform": os_name,
            "enabled": parsed["enabled"],
            "profile_modes": parsed["profile_modes"],
            "active_rules_count": 0,
            "default_inbound_action": None,
            "default_outbound_action": None,
            "details": {"status": status_result},
            "message": "pf firewall status collected.",
        }

    return {
        "success": False,
        "platform": os_name,
        "error": "unsupported_platform",
        "message": "Firewall status is unsupported on this operating system.",
    }


def toggle_firewall(enabled: bool, confirmed: bool = False, safe_mode: bool = True) -> dict[str, Any]:
    """Toggle firewall state with explicit confirmation guard."""
    if safe_mode and not confirmed:
        return {
            "success": False,
            "error": "confirmation_required",
            "message": "Firewall toggle requires explicit confirmation.",
        }

    os_name = detect_os()
    desired = "on" if enabled else "off"

    if os_name == "windows":
        command = ["netsh", "advfirewall", "set", "allprofiles", "state", desired]
    elif os_name == "linux":
        command = ["ufw", "--force", "enable"] if enabled else ["ufw", "disable"]
    elif os_name == "macos":
        command = ["pfctl", "-e"] if enabled else ["pfctl", "-d"]
    else:
        return {
            "success": False,
            "platform": os_name,
            "error": "unsupported_platform",
            "message": "Firewall toggle is unsupported on this operating system.",
        }

    result = _run_command(command)
    return {
        "success": result["success"],
        "platform": os_name,
        "desired_state": enabled,
        "confirmed": confirmed,
        "safe_mode": safe_mode,
        "result": result,
        "message": f"Firewall toggled {desired}." if result["success"] else f"Failed to toggle firewall {desired}.",
    }


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


def add_custom_rule(
    *,
    name: str,
    direction: str,
    action: str,
    protocol: str = "tcp",
    port: int | None = None,
    remote_ip: str | None = None,
) -> dict[str, Any]:
    """Add a custom firewall rule."""
    os_name = detect_os()
    clean_direction = direction.lower().strip()
    clean_action = action.lower().strip()
    clean_protocol = protocol.lower().strip()

    if clean_direction not in {"in", "out"}:
        return {"success": False, "error": "invalid_direction", "message": "Direction must be 'in' or 'out'."}
    if clean_action not in {"allow", "block", "deny"}:
        return {"success": False, "error": "invalid_action", "message": "Action must be allow/block/deny."}

    validated_ip: dict[str, Any] | None = None
    if remote_ip:
        validated_ip = _validate_ip(remote_ip)
        if not validated_ip or not validated_ip["success"]:
            return validated_ip or {"success": False, "error": "invalid_ip", "message": "Invalid IP address."}

    if os_name == "windows":
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            f"dir={clean_direction}",
            f"action={'allow' if clean_action == 'allow' else 'block'}",
            f"protocol={clean_protocol.upper()}",
        ]
        if port is not None:
            command.append(f"localport={port}")
        if validated_ip:
            command.append(f"remoteip={validated_ip['ip']}")
    elif os_name == "linux":
        if port is None:
            return {"success": False, "error": "missing_port", "message": "Linux UFW custom rule requires a port."}
        ufw_action = "allow" if clean_action == "allow" else "deny"
        command = ["ufw", ufw_action, f"{port}/{clean_protocol}"]
        if validated_ip:
            command.extend(["from", validated_ip["ip"]])
    else:
        return {
            "success": False,
            "platform": os_name,
            "error": "unsupported_platform",
            "message": "Custom rule add is unsupported on this operating system.",
        }

    result = _run_command(command)
    return {
        "success": result["success"],
        "platform": os_name,
        "operation": "add_custom_rule",
        "rule": {
            "name": name,
            "direction": clean_direction,
            "action": clean_action,
            "protocol": clean_protocol,
            "port": port,
            "remote_ip": validated_ip["ip"] if validated_ip else None,
        },
        "result": result,
        "message": "Custom firewall rule added." if result["success"] else "Failed to add custom firewall rule.",
    }


def remove_custom_rule(name: str) -> dict[str, Any]:
    """Remove a custom firewall rule by name."""
    os_name = detect_os()

    if os_name == "windows":
        command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
    elif os_name == "linux":
        command = ["ufw", "--force", "delete", name]
    else:
        return {
            "success": False,
            "platform": os_name,
            "error": "unsupported_platform",
            "message": "Custom rule removal is unsupported on this operating system.",
        }

    result = _run_command(command)
    return {
        "success": result["success"],
        "platform": os_name,
        "operation": "remove_custom_rule",
        "rule_name": name,
        "result": result,
        "message": "Custom firewall rule removed." if result["success"] else "Failed to remove custom firewall rule.",
    }


def apply_firewall_preset(preset: str) -> dict[str, Any]:
    """Apply one of the firewall profiles: soft, normal, paranoid."""
    clean_preset = preset.lower().strip()
    if clean_preset not in {"soft", "normal", "paranoid"}:
        return {
            "success": False,
            "error": "invalid_preset",
            "message": "Preset must be one of: soft, normal, paranoid.",
        }

    os_name = detect_os()
    steps: list[dict[str, Any]] = []

    if os_name == "windows":
        policy_map = {
            "soft": "allowinbound,allowoutbound",
            "normal": "blockinbound,allowoutbound",
            "paranoid": "blockinbound,blockoutbound",
        }
        steps.append(_run_command(["netsh", "advfirewall", "set", "allprofiles", "state", "on"]))
        steps.append(
            _run_command(
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy_map[clean_preset]]
            )
        )
    elif os_name == "linux":
        preset_defaults = {
            "soft": ("allow", "allow"),
            "normal": ("deny", "allow"),
            "paranoid": ("deny", "deny"),
        }
        inbound, outbound = preset_defaults[clean_preset]
        steps.append(_run_command(["ufw", "--force", "enable"]))
        steps.append(_run_command(["ufw", "default", inbound, "incoming"]))
        steps.append(_run_command(["ufw", "default", outbound, "outgoing"]))
    elif os_name == "macos":
        return {
            "success": False,
            "platform": os_name,
            "error": "manual_step_required",
            "message": "pf preset profiles require manual /etc/pf.conf anchor management.",
        }
    else:
        return {
            "success": False,
            "platform": os_name,
            "error": "unsupported_platform",
            "message": "Firewall presets are unsupported on this operating system.",
        }

    success = all(step.get("success") for step in steps)
    return {
        "success": success,
        "platform": os_name,
        "preset": clean_preset,
        "steps": steps,
        "message": f"Applied '{clean_preset}' firewall preset." if success else f"Failed to apply '{clean_preset}' firewall preset.",
    }


def panic_button(essential_ports: list[int] | None = None) -> dict[str, Any]:
    """Emergency hardening sequence with per-step results."""
    os_name = detect_os()
    essential = essential_ports or [22, 53, 80, 443]
    steps: list[dict[str, Any]] = []

    close_ports_result = apply_firewall_preset("paranoid")
    steps.append({"step": "close_non_essential_ports", **close_ports_result})

    if os_name == "windows":
        dns_result = _run_command(["ipconfig", "/flushdns"])
    elif os_name == "linux":
        dns_result = _run_command(["resolvectl", "flush-caches"])
        if not dns_result["success"]:
            dns_result = _run_command(["systemd-resolve", "--flush-caches"])
    elif os_name == "macos":
        flush_cache = _run_command(["dscacheutil", "-flushcache"])
        mdns = _run_command(["killall", "-HUP", "mDNSResponder"])
        dns_result = {"success": flush_cache["success"] and mdns["success"], "steps": [flush_cache, mdns]}
    else:
        dns_result = {"success": False, "error": "unsupported_platform", "message": "DNS cache clear unsupported."}
    steps.append({"step": "clear_dns_cache", "success": dns_result.get("success", False), "details": dns_result})

    if os_name == "windows":
        tcp_reset = _run_command(["netsh", "int", "ip", "reset"])
    elif os_name == "linux":
        tcp_reset = _run_command(["conntrack", "-F"])
        if not tcp_reset["success"]:
            tcp_reset = _run_command(["ss", "-K", "state", "established"])
    elif os_name == "macos":
        tcp_reset = {"success": False, "error": "unsupported_platform", "message": "No standard tcp-state flush command for macOS."}
    else:
        tcp_reset = {"success": False, "error": "unsupported_platform", "message": "TCP reset unsupported."}
    steps.append({"step": "reset_tcp_state", "success": tcp_reset.get("success", False), "details": tcp_reset})

    strict_profile = apply_firewall_preset("paranoid")
    if strict_profile.get("success") and os_name == "linux":
        for port in essential:
            allow_step = _run_command(["ufw", "allow", str(port)])
            strict_profile.setdefault("steps", []).append(allow_step)
            if not allow_step["success"]:
                strict_profile["success"] = False
                strict_profile["message"] = "Paranoid profile applied, but essential port allow-list had failures."
    steps.append({"step": "restart_strict_profile", **strict_profile})

    success = all(step.get("success", False) for step in steps)
    return {
        "success": success,
        "platform": os_name,
        "essential_ports": essential,
        "steps": steps,
        "message": "Panic button sequence complete." if success else "Panic button sequence completed with failures.",
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
            "message": "Firewall rules applied on Windows."
            if inbound["success"] and outbound["success"]
            else "Failed to apply one or more Windows firewall rules.",
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


def unbanish_ip(ip: str) -> dict[str, Any]:
    """Remove firewall rules that block traffic for the provided IP address."""
    validated = _validate_ip(ip)
    if validated is None or not validated["success"]:
        return validated or {"success": False, "error": "invalid_ip", "message": "Invalid IP address."}

    clean_ip = validated["ip"]
    os_name = detect_os()

    if os_name == "windows":
        inbound = _run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=NetScouter Block {clean_ip} Inbound"])
        outbound = _run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=NetScouter Block {clean_ip} Outbound"])
        return {
            "success": inbound.get("success", False) and outbound.get("success", False),
            "platform": os_name,
            "ip": clean_ip,
            "results": {"inbound": inbound, "outbound": outbound},
            "message": "Firewall unblock rules removed." if inbound.get("success", False) and outbound.get("success", False) else "Failed to remove one or more Windows unblock rules.",
        }

    if os_name == "linux":
        ufw = _run_command(["ufw", "--force", "delete", "deny", "from", clean_ip])
        if ufw.get("success", False):
            return {"success": True, "platform": os_name, "ip": clean_ip, "message": "UFW deny rule removed.", "result": ufw}
        iptables = _run_command(["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"])
        return {
            "success": iptables.get("success", False),
            "platform": os_name,
            "ip": clean_ip,
            "message": "iptables fallback delete applied." if iptables.get("success", False) else "Failed to remove deny rule.",
            "result": iptables,
        }

    return {
        "success": False,
        "platform": os_name,
        "ip": clean_ip,
        "error": "unsupported_platform",
        "message": "Unblock is unsupported on this operating system.",
    }


def is_sinkhole_healthy(host: str = "127.0.0.1", port: int = 25252, timeout: float = 0.6) -> bool:
    """Check if the local sinkhole listener is reachable."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, int(port))) == 0
    except OSError:
        return False


def quarantine_ip(ip: str, *, sinkhole_host: str = "127.0.0.1", sinkhole_port: int = 25252) -> dict[str, Any]:
    """Redirect quarantined source traffic to local sinkhole when healthy."""
    validated = _validate_ip(ip)
    if validated is None or not validated["success"]:
        return validated or {
            "success": False,
            "error": "invalid_ip",
            "message": "Invalid IP address.",
        }

    if not is_sinkhole_healthy(host=sinkhole_host, port=sinkhole_port):
        return {
            "success": False,
            "ip": validated["ip"],
            "error": "sinkhole_unhealthy",
            "message": f"Quarantine aborted: sinkhole service {sinkhole_host}:{sinkhole_port} is not healthy.",
        }

    os_name = detect_os()
    plan = build_quarantine_plan(
        platform=os_name,
        source_ip=validated["ip"],
        sinkhole_host=sinkhole_host,
        sinkhole_port=sinkhole_port,
    )
    if not plan.commands:
        return {
            "success": False,
            "platform": os_name,
            "ip": validated["ip"],
            "error": "unsupported_platform",
            "message": plan.notes,
        }

    step_results = [_run_command(command) for command in plan.commands]
    success = all(step.get("success") for step in step_results)
    return {
        "success": success,
        "platform": os_name,
        "ip": validated["ip"],
        "action": "quarantine",
        "sinkhole": f"{sinkhole_host}:{sinkhole_port}",
        "steps": step_results,
        "notes": plan.notes,
        "message": "Quarantine redirect rules applied." if success else "Failed to apply one or more quarantine rules.",
    }


def enforce_ip_policy(
    ip: str,
    *,
    action: str = "block",
    sinkhole_host: str = "127.0.0.1",
    sinkhole_port: int = 25252,
) -> dict[str, Any]:
    """Firewall action abstraction for block/quarantine controls."""
    clean_action = action.lower().strip()
    if clean_action == "block":
        result = banish_ip(ip)
        result["action"] = "block"
        return result
    if clean_action == "quarantine":
        return quarantine_ip(ip, sinkhole_host=sinkhole_host, sinkhole_port=sinkhole_port)
    return {
        "success": False,
        "ip": ip,
        "error": "invalid_action",
        "message": "Action must be 'block' or 'quarantine'.",
    }
