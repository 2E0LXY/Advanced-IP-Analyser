"""Read-only, explainable Windows endpoint posture checks.

The collector deliberately uses Windows' own status providers and never changes a
setting.  Collection failures become ``unknown`` findings instead of optimistic
"safe" results.
"""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class PostureFinding:
    key: str
    title: str
    status: str
    summary: str
    recommendation: str = ""


@dataclass(frozen=True)
class PostureReport:
    collected_at: str
    platform: str
    findings: tuple[PostureFinding, ...]

    @property
    def attention_count(self) -> int:
        return sum(item.status == "attention" for item in self.findings)


def _enabled(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        folded = value.strip().casefold()
        if folded in {"true", "yes", "on", "enabled", "1"}:
            return True
        if folded in {"false", "no", "off", "disabled", "0"}:
            return False
    return None


def _finding(key: str, title: str, value: bool | None, good: str, bad: str,
             recommendation: str = "") -> PostureFinding:
    if value is True:
        return PostureFinding(key, title, "good", good)
    if value is False:
        return PostureFinding(key, title, "attention", bad, recommendation)
    return PostureFinding(key, title, "unknown", "Windows did not return a conclusive status.")


def analyse_windows_snapshot(snapshot: dict[str, Any]) -> tuple[PostureFinding, ...]:
    """Turn a Windows status snapshot into conservative, explainable findings."""
    firewall = snapshot.get("firewall") or []
    if isinstance(firewall, dict):
        firewall = [firewall]
    enabled_profiles = [str(item.get("Name", "Unknown")) for item in firewall
                        if _enabled(item.get("Enabled")) is True]
    disabled_profiles = [str(item.get("Name", "Unknown")) for item in firewall
                         if _enabled(item.get("Enabled")) is False]
    if disabled_profiles:
        firewall_finding = PostureFinding(
            "firewall", "Windows Firewall", "attention",
            f"Disabled for: {', '.join(disabled_profiles)}.",
            "Review the disabled profile in Windows Security before using an untrusted network.")
    elif enabled_profiles:
        firewall_finding = PostureFinding(
            "firewall", "Windows Firewall", "good",
            f"Enabled for: {', '.join(enabled_profiles)}.")
    else:
        firewall_finding = PostureFinding(
            "firewall", "Windows Firewall", "unknown", "Firewall profile status was unavailable.")

    defender = snapshot.get("defender") or {}
    security_products = snapshot.get("antivirusProducts") or []
    if isinstance(security_products, dict):
        security_products = [security_products]
    product_names = [str(item.get("displayName", "")).strip() for item in security_products
                     if str(item.get("displayName", "")).strip()]
    av_enabled = _enabled(defender.get("AntivirusEnabled"))
    realtime = _enabled(defender.get("RealTimeProtectionEnabled"))
    if av_enabled is False and product_names:
        av_finding = PostureFinding(
            "antivirus", "Antivirus provider", "good",
            "Windows reports: " + ", ".join(product_names) + ".")
    else:
        av_finding = _finding(
            "antivirus", "Antivirus provider", av_enabled,
            "Microsoft Defender Antivirus is enabled.",
            "No enabled antivirus was confirmed.",
            "Open Windows Security and confirm that a trusted antivirus provider is active.")
    rt_finding = _finding(
        "realtime", "Real-time protection", realtime if av_enabled is not False else None,
        "Microsoft Defender real-time protection is enabled.",
        "Microsoft Defender real-time protection is disabled.",
        "Review Virus & threat protection settings in Windows Security.")

    smb = str(snapshot.get("smb1State", "")).strip().casefold()
    if smb == "disabled":
        smb_finding = PostureFinding("smb1", "Legacy SMB 1.0", "good", "SMB 1.0 is disabled.")
    elif smb == "enabled":
        smb_finding = PostureFinding(
            "smb1", "Legacy SMB 1.0", "attention", "SMB 1.0 is enabled.",
            "Remove SMB 1.0 unless a known legacy device genuinely requires it.")
    else:
        smb_finding = PostureFinding("smb1", "Legacy SMB 1.0", "unknown",
                                     "The optional-feature state was unavailable.")

    uac_finding = _finding(
        "uac", "User Account Control", _enabled(snapshot.get("uacEnabled")),
        "User Account Control is enabled.", "User Account Control is disabled.",
        "Turn UAC back on unless this is a deliberately isolated test machine.")

    profiles = snapshot.get("networkProfiles") or []
    if isinstance(profiles, dict):
        profiles = [profiles]
    category_names = {0: "Public", 1: "Private", 2: "Domain authenticated",
                      "0": "Public", "1": "Private", "2": "Domain authenticated"}
    categories = sorted({category_names.get(item.get("NetworkCategory"),
                                            str(item.get("NetworkCategory", "Unknown")))
                         for item in profiles})
    network_summary = ("Active profile categories: " + ", ".join(categories) + "."
                       if categories else "No active network profile was returned.")
    network_status = "info" if categories else "unknown"
    network_finding = PostureFinding("network-profile", "Network profile", network_status,
                                     network_summary)

    dns = snapshot.get("dnsServers") or []
    servers: list[str] = []
    for item in dns if isinstance(dns, list) else [dns]:
        values = item.get("ServerAddresses", []) if isinstance(item, dict) else []
        servers.extend(str(value) for value in values if value)
    dns_finding = PostureFinding(
        "dns", "DNS configuration", "info" if servers else "unknown",
        ("Configured resolvers: " + ", ".join(dict.fromkeys(servers)) + "."
         if servers else "No resolver addresses were returned."),
        "Use the DNS Benchmark tab to compare responsiveness; speed alone does not prove security.")

    return (firewall_finding, av_finding, rt_finding, smb_finding, uac_finding,
            network_finding, dns_finding)


_POWERSHELL = r"""
$ErrorActionPreference = 'SilentlyContinue'
$fw = @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction)
$def = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
$av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,productState)
$smbEnabled = (Get-SmbServerConfiguration).EnableSMB1Protocol
$smb = if ($null -eq $smbEnabled) { $null } elseif ($smbEnabled) { 'Enabled' } else { 'Disabled' }
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
$profiles = @(Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,NetworkCategory,IPv4Connectivity)
$dns = @(Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object InterfaceAlias,AddressFamily,ServerAddresses)
[ordered]@{firewall=$fw;defender=$def;antivirusProducts=$av;smb1State=$smb;uacEnabled=$uac;networkProfiles=$profiles;dnsServers=$dns} | ConvertTo-Json -Depth 5 -Compress
"""


def collect_endpoint_posture(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> PostureReport:
    """Collect a read-only report. No firewall, privacy, DNS or AV setting is changed."""
    system = platform.system()
    now = datetime.now(UTC).isoformat()
    if system != "Windows":
        finding = PostureFinding(
            "platform", "Windows endpoint posture", "unknown",
            "These checks use Windows Security providers and are unavailable on this platform.")
        return PostureReport(now, system, (finding,))
    try:
        result = runner(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL],
            capture_output=True, text=True, timeout=20, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError(result.stderr.strip() or "Windows returned no status data")
        snapshot = json.loads(result.stdout)
        findings = analyse_windows_snapshot(snapshot)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, RuntimeError) as error:
        findings = (PostureFinding(
            "collection", "Windows endpoint posture", "unknown",
            f"Status collection failed: {error}"),)
    return PostureReport(now, system, findings)
