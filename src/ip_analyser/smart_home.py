"""Local TP-Link Kasa/Tapo discovery and control helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Any


class SmartHomeError(RuntimeError):
    """Raised when a smart-home operation cannot be completed."""


@dataclass(frozen=True, slots=True)
class SmartHomeDevice:
    address: str
    alias: str
    model: str
    kind: str
    is_on: bool | None
    brightness: int | None
    signal: int | None
    mac: str
    can_power: bool
    can_brightness: bool
    provider: str = "TP-Link"
    entity_id: str = ""
    controller: str = ""
    can_deactivate: bool = True
    hostname: str = ""
    services: tuple[tuple[int, str], ...] = ()
    service_info: tuple[tuple[int, tuple[tuple[str, str], ...]], ...] = ()


SMART_HOME_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http",
    443: "https", 445: "smb", 554: "rtsp", 8080: "http",
    8443: "https", 8888: "http", 9999: "kasa", 10443: "https",
    20002: "tapo-discovery",
}


def _kasa_api():
    try:
        from kasa import Credentials, Discover
        from kasa.exceptions import KasaException
    except ImportError as error:
        raise SmartHomeError(
            "TP-Link support is not installed. Install the Windows edition or "
            "run: pip install 'python-kasa>=0.11,<0.12'") from error
    return Credentials, Discover, KasaException


def _credentials(username: str, password: str):
    username = username.strip()
    if bool(username) != bool(password):
        raise ValueError("Enter both the TP-Link account email and password, or leave both blank.")
    if not username:
        return None
    Credentials, _Discover, _KasaException = _kasa_api()
    return Credentials(username, password)


def _safe_value(source: Any, name: str, default: Any = None) -> Any:
    try:
        value = getattr(source, name)
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
        return default
    return default if value is None else value


def _has_callable(source: Any, name: str) -> bool:
    try:
        return callable(getattr(source, name))
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return False


def _snapshot(device: Any) -> SmartHomeDevice:
    features = _safe_value(device, "features", {})
    brightness_feature = features.get("brightness") if isinstance(features, dict) else None
    state_feature = features.get("state") if isinstance(features, dict) else None
    device_type = _safe_value(device, "device_type", "unknown")
    kind = _safe_value(device_type, "value", str(device_type))
    brightness = _safe_value(brightness_feature, "value") if brightness_feature else None
    return SmartHomeDevice(
        address=str(_safe_value(device, "host", "")),
        alias=str(_safe_value(device, "alias", "Unnamed TP-Link device")),
        model=str(_safe_value(device, "model", "Unknown")),
        kind=str(kind).replace("_", " ").title(),
        is_on=_safe_value(device, "is_on"),
        brightness=int(brightness) if isinstance(brightness, int | float) else None,
        signal=_safe_value(device, "rssi"),
        mac=str(_safe_value(device, "mac", "")),
        can_power=bool(state_feature and _safe_value(state_feature, "attribute_setter")) or
        _has_callable(device, "turn_on"),
        can_brightness=bool(
            brightness_feature and _safe_value(brightness_feature, "attribute_setter")),
        can_deactivate=_has_callable(device, "turn_off") or bool(
            state_feature and _safe_value(state_feature, "attribute_setter")),
    )


def inspect_network_services(device: SmartHomeDevice, *, timeout: float = 0.3) -> SmartHomeDevice:
    """Resolve a device name and inspect a small, relevant TCP service set."""
    from .scanner import Scanner

    scanner = Scanner(timeout=timeout, workers=8, ports=SMART_HOME_PORTS)
    host = scanner.discover(scanner.inspect(device.address))
    services = tuple(zip(host.ports, host.services))
    service_info = tuple(
        (int(port), tuple(sorted(details.items())))
        for port, details in sorted(host.service_info.items(), key=lambda item: int(item[0]))
    )
    alias = device.alias.strip()
    if not alias or alias.casefold().startswith("unnamed tp-link"):
        alias = host.hostname or f"{device.model} · {device.address}"
    return replace(
        device, alias=alias, hostname=host.hostname, services=services,
        service_info=service_info)


async def _inspect_network_services(devices: list[SmartHomeDevice]) -> list[SmartHomeDevice]:
    inspected = await asyncio.gather(*(
        asyncio.to_thread(inspect_network_services, device) for device in devices
    ), return_exceptions=True)
    return [result if isinstance(result, SmartHomeDevice) else device
            for device, result in zip(devices, inspected)]


async def _updated_snapshot(device: Any) -> SmartHomeDevice:
    try:
        await device.update()
        return _snapshot(device)
    finally:
        await device.disconnect()


async def discover_devices(username: str = "", password: str = "", *,
                           target: str = "255.255.255.255",
                           timeout: int = 5,
                           include_services: bool = False) -> list[SmartHomeDevice]:
    """Discover supported TP-Link devices using bounded local UDP broadcasts."""
    credentials = _credentials(username, password)
    _Credentials, Discover, KasaException = _kasa_api()
    try:
        found = await Discover.discover(
            target=target.strip() or "255.255.255.255", credentials=credentials,
            discovery_timeout=timeout, timeout=timeout)
        devices = []
        for device in found.values():
            try:
                devices.append(await _updated_snapshot(device))
            except KasaException:
                # Discovery metadata remains useful if authentication fails.
                devices.append(_snapshot(device))
        if include_services:
            devices = await _inspect_network_services(devices)
        return sorted(devices, key=lambda item: (item.alias.casefold(), item.address))
    except (OSError, KasaException) as error:
        raise SmartHomeError(str(error)) from error


async def inspect_device(address: str, username: str = "", password: str = "",
                         *, timeout: int = 5,
                         include_services: bool = False) -> SmartHomeDevice:
    """Connect to one LAN or VPN-routed device and return its current state."""
    host = address.strip()
    if not host or len(host) > 253 or any(character.isspace() for character in host):
        raise ValueError("Enter a valid device IP address or VPN-routed hostname.")
    credentials = _credentials(username, password)
    _Credentials, Discover, KasaException = _kasa_api()
    try:
        device = await Discover.discover_single(
            host, credentials=credentials, discovery_timeout=timeout, timeout=timeout)
        if device is None:
            raise SmartHomeError(f"No supported TP-Link device responded at {host}.")
        snapshot = await _updated_snapshot(device)
        return (await _inspect_network_services([snapshot]))[0] if include_services else snapshot
    except (OSError, KasaException) as error:
        raise SmartHomeError(str(error)) from error


async def set_power(address: str, enabled: bool, username: str = "", password: str = "",
                    *, timeout: int = 5) -> SmartHomeDevice:
    """Turn one directly reachable TP-Link device on or off."""
    credentials = _credentials(username, password)
    _Credentials, Discover, KasaException = _kasa_api()
    device = None
    try:
        device = await Discover.discover_single(
            address, credentials=credentials, discovery_timeout=timeout, timeout=timeout)
        if device is None:
            raise SmartHomeError(f"No supported TP-Link device responded at {address}.")
        await device.update()
        await (device.turn_on() if enabled else device.turn_off())
        await device.update()
        return _snapshot(device)
    except (OSError, KasaException) as error:
        raise SmartHomeError(str(error)) from error
    finally:
        if device is not None:
            await device.disconnect()


async def set_brightness(address: str, brightness: int, username: str = "",
                         password: str = "", *, timeout: int = 5) -> SmartHomeDevice:
    """Set brightness on a directly reachable compatible bulb or dimmer."""
    if not 1 <= brightness <= 100:
        raise ValueError("Brightness must be between 1 and 100 percent.")
    credentials = _credentials(username, password)
    _Credentials, Discover, KasaException = _kasa_api()
    device = None
    try:
        device = await Discover.discover_single(
            address, credentials=credentials, discovery_timeout=timeout, timeout=timeout)
        if device is None:
            raise SmartHomeError(f"No supported TP-Link device responded at {address}.")
        await device.update()
        feature = device.features.get("brightness")
        if feature is None or feature.attribute_setter is None:
            raise SmartHomeError(f"{device.alias} does not support brightness control.")
        await feature.set_value(brightness)
        await device.update()
        return _snapshot(device)
    except (OSError, KasaException) as error:
        raise SmartHomeError(str(error)) from error
    finally:
        if device is not None:
            await device.disconnect()
