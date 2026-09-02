from __future__ import annotations

from dataclasses import dataclass
import re

from .models import Host


@dataclass(frozen=True, slots=True)
class AssetProfile:
    device_type: str = "Unknown device"
    operating_system: str = ""
    os_version: str = ""
    model: str = ""
    confidence: str = "Low"


def _metadata(host: Host) -> str:
    values = [host.hostname, host.manufacturer]
    values.extend(host.services)
    for details in host.service_info.values():
        values.extend(details.values())
    return " ".join(values)


def infer_asset_profile(host: Host) -> AssetProfile:
    """Infer a conservative, explainable device profile from discovered facts.

    This is deliberately heuristic: no credentials, agents, OS probes, or exploit
    payloads are used. Empty OS/model fields are preferable to a confident guess.
    """
    text = _metadata(host)
    lower = text.casefold()
    services = set(host.services)

    device_type = "Unknown device"
    if services & {"printer", "ipp"} or 9100 in host.ports or any(
            name in lower for name in ("laserjet", "officejet", "epson", "brother printer")):
        device_type = "Printer"
    elif services & {"nfs", "rsync"} or any(name in lower for name in ("synology", "qnap", "diskstation")):
        device_type = "NAS / storage"
    elif services & {"rdp", "smb", "rpc"}:
        device_type = "Computer / server"
    elif any(name in lower for name in ("router", "gateway", "mikrotik", "openwrt", "ubiquiti", "unifi")):
        device_type = "Network device"
    elif services & {"postgresql", "mysql", "mssql", "oracle", "mongodb", "redis", "elasticsearch"}:
        device_type = "Database server"
    elif services & {"http", "https"}:
        device_type = "Web device / server"
    elif "ssh" in services:
        device_type = "Computer / server"

    operating_system = ""
    os_version = ""
    patterns = (
        (r"microsoft-iis/([\w.]+)", "Windows / IIS"),
        (r"windows(?: server)?[ /-]*([\w.]+)?", "Windows"),
        (r"ubuntu[ /-]*([\w.]+)?", "Ubuntu Linux"),
        (r"debian[ /-]*([\w.]+)?", "Debian Linux"),
        (r"openwrt[ /-]*([\w.]+)?", "OpenWrt Linux"),
        (r"freebsd[ /-]*([\w.]+)?", "FreeBSD"),
        (r"macos|mac os x|darwin", "macOS"),
    )
    for pattern, name in patterns:
        match = re.search(pattern, lower)
        if match:
            operating_system = name
            if match.lastindex and match.group(1):
                os_version = match.group(1).strip("-_/.")[:64]
            break
    if not operating_system and "dropbear" in lower:
        operating_system = "Embedded Linux"
    if not operating_system and "openssh" in lower and services & {"smb", "rdp", "rpc"}:
        operating_system = "Windows"
    elif not operating_system and "openssh" in lower:
        operating_system = "Linux / Unix"

    model = ""
    model_patterns = (
        r"(?:synology|diskstation)\s+([a-z]{1,4}\d{2,5}[a-z0-9+.-]*)",
        r"(?:hp|hewlett-packard)\s+((?:laserjet|officejet)\s+[a-z0-9 .-]{2,40})",
        r"(?:model|product)[:= ]+([a-z0-9][a-z0-9 ._+/-]{1,50})",
    )
    for pattern in model_patterns:
        match = re.search(pattern, lower, re.IGNORECASE)
        if match:
            model = " ".join(match.group(1).split()).strip(" -_/.")[:64]
            break

    confidence_points = sum((device_type != "Unknown device", bool(operating_system), bool(model)))
    confidence = ("High" if confidence_points >= 2 and bool(host.service_info)
                  else "Medium" if confidence_points or bool(host.service_info) else "Low")
    return AssetProfile(device_type, operating_system, os_version, model, confidence)
