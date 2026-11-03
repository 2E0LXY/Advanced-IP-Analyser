"""Supported links into Windows network settings."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable

from .network import active_ipv4_networks

ETHERNET_SETTINGS_URI = "ms-settings:network-ethernet"
WIFI_SETTINGS_URI = "ms-settings:network-wifi"


def dns_settings_uri(interface_names: Iterable[str]) -> str:
    """Choose the supported Settings page for the active adapter names."""
    names = " ".join(interface_names).casefold().replace("-", "")
    if any(marker in names for marker in ("wifi", "wireless", "wlan")):
        return WIFI_SETTINGS_URI
    return ETHERNET_SETTINGS_URI


def open_windows_dns_settings(
    launcher: Callable[[str], object] | None = None,
) -> str:
    """Open the active adapter's Windows page where DNS can be edited."""
    if os.name != "nt":
        raise RuntimeError("Windows DNS settings are available only on Windows 10 and 11.")
    try:
        interfaces = [name for name, _network, _broadcast in active_ipv4_networks()]
    except RuntimeError:
        interfaces = []
    uri = dns_settings_uri(interfaces)
    opener = launcher or os.startfile
    opener(uri)
    return uri
