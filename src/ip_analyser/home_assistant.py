"""Local Home Assistant REST client for broad smart-device control."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .smart_home import SmartHomeDevice, SmartHomeError

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
SERVICE_PATTERN = re.compile(r"[a-z0-9_]+\.[a-z0-9_]+")
CONTROLLABLE_DOMAINS = {
    "alarm_control_panel", "automation", "button", "climate", "cover", "fan",
    "humidifier", "input_boolean", "lawn_mower", "light", "lock", "media_player",
    "number", "remote", "scene", "script", "select", "siren", "switch", "vacuum",
    "valve", "water_heater",
}
ACTION_MAP: dict[str, tuple[str, str | None]] = {
    "button": ("press", None),
    "cover": ("open_cover", "close_cover"),
    "lawn_mower": ("start_mowing", "dock"),
    "lock": ("unlock", "lock"),
    "scene": ("turn_on", None),
    "vacuum": ("start", "return_to_base"),
    "valve": ("open_valve", "close_valve"),
}
NO_GENERIC_POWER = {"alarm_control_panel", "number", "select"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_local(request: Request, timeout: int):
    return build_opener(_NoRedirect).open(request, timeout=timeout)


def _is_local_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    carrier_grade_nat = ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")
    return ip.is_private or ip.is_loopback or ip.is_link_local or carrier_grade_nat


def validate_local_url(value: str) -> str:
    """Normalize a URL and prevent sending a Home Assistant token to the public internet."""
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a local Home Assistant URL beginning with http:// or https://.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("The Home Assistant URL must not contain credentials, a query, or a fragment.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Enter the Home Assistant base URL without an API path.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 0)}
    except OSError as error:
        raise ValueError(f"The Home Assistant host could not be resolved: {error}") from error
    if not addresses or any(not _is_local_ip(address) for address in addresses):
        raise ValueError(
            "Home Assistant must resolve only to a private, local, or VPN address; "
            "the access token will not be sent to a public host.")
    netloc = parsed.hostname
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, "", "", "")).rstrip("/")


def _validate_token(token: str) -> str:
    if not 20 <= len(token) <= 8192 or token != token.strip():
        raise ValueError("Enter a valid Home Assistant long-lived access token.")
    if any(ord(character) < 32 for character in token):
        raise ValueError("The Home Assistant token contains control characters.")
    return token


def _request(base_url: str, token: str, path: str, *, data: dict[str, Any] | None = None,
             timeout: int = 10) -> Any:
    base_url = validate_local_url(base_url)
    token = _validate_token(token)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    request = Request(
        f"{base_url}{path}", data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST" if body is not None else "GET")
    try:
        # Refuse redirects so an authenticated local request cannot be bounced
        # to a public host with the bearer token attached.
        with _open_local(request, timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise SmartHomeError(f"Home Assistant returned HTTP {error.code}.") from error
    except (OSError, URLError) as error:
        raise SmartHomeError(f"Home Assistant could not be reached: {error}") from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise SmartHomeError("Home Assistant returned more data than the safety limit allows.")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmartHomeError("Home Assistant returned an invalid JSON response.") from error


def _state_value(state: str) -> bool | None:
    if state in {"unknown", "unavailable", "none", "None"}:
        return None
    if state in {"off", "closed", "locked", "idle", "docked", "paused", "standby"}:
        return False
    if state in {"on", "open", "opening", "unlocked", "playing", "cleaning", "mowing"}:
        return True
    return None


def _entity_snapshot(base_url: str, entity: dict[str, Any]) -> SmartHomeDevice:
    entity_id = str(entity.get("entity_id", ""))
    domain = entity_id.partition(".")[0]
    attributes = entity.get("attributes") if isinstance(entity.get("attributes"), dict) else {}
    brightness = attributes.get("brightness")
    brightness_percent = None
    if isinstance(brightness, int | float):
        brightness_percent = max(0, min(100, round(float(brightness) / 255 * 100)))
    action_pair = ACTION_MAP.get(domain, ("turn_on", "turn_off"))
    can_activate = domain not in NO_GENERIC_POWER
    return SmartHomeDevice(
        address=entity_id,
        alias=str(attributes.get("friendly_name") or entity_id),
        model=str(attributes.get("device_class") or attributes.get("model") or "Home Assistant"),
        kind=domain.replace("_", " ").title(),
        is_on=_state_value(str(entity.get("state", "unknown"))),
        brightness=brightness_percent,
        signal=None,
        mac="",
        can_power=can_activate,
        can_brightness=domain == "light",
        provider="Home Assistant",
        entity_id=entity_id,
        controller=base_url,
        can_deactivate=can_activate and action_pair[1] is not None,
    )


def list_entities(base_url: str, token: str) -> list[SmartHomeDevice]:
    """Return every entity whose domain provides a local control surface."""
    base_url = validate_local_url(base_url)
    payload = _request(base_url, token, "/api/states")
    if not isinstance(payload, list):
        raise SmartHomeError("Home Assistant returned an unexpected states response.")
    devices = [
        _entity_snapshot(base_url, entity)
        for entity in payload
        if isinstance(entity, dict)
        and str(entity.get("entity_id", "")).partition(".")[0] in CONTROLLABLE_DOMAINS
    ]
    return sorted(devices, key=lambda item: (item.kind, item.alias.casefold(), item.entity_id))


def call_service(base_url: str, token: str, service: str, entity_id: str,
                 data: dict[str, Any] | None = None) -> list[SmartHomeDevice]:
    """Call any local Home Assistant action with a selected entity target."""
    service = service.strip().lower()
    if not SERVICE_PATTERN.fullmatch(service):
        raise ValueError("Enter an action as domain.service, for example light.turn_on.")
    if not entity_id or "." not in entity_id:
        raise ValueError("Select a Home Assistant entity first.")
    action_data = dict(data or {})
    action_data["entity_id"] = entity_id
    domain, action = service.split(".", 1)
    _request(base_url, token, f"/api/services/{domain}/{action}", data=action_data)
    return list_entities(base_url, token)


def set_entity_power(base_url: str, token: str, entity_id: str,
                     enabled: bool) -> list[SmartHomeDevice]:
    domain = entity_id.partition(".")[0]
    activate, deactivate = ACTION_MAP.get(domain, ("turn_on", "turn_off"))
    action = activate if enabled else deactivate
    if action is None or domain in NO_GENERIC_POWER:
        raise SmartHomeError(f"{entity_id} does not provide that generic action.")
    return call_service(base_url, token, f"{domain}.{action}", entity_id)


def set_entity_brightness(base_url: str, token: str, entity_id: str,
                          brightness: int) -> list[SmartHomeDevice]:
    if entity_id.partition(".")[0] != "light":
        raise SmartHomeError("Brightness is available only for Home Assistant light entities.")
    if not 1 <= brightness <= 100:
        raise ValueError("Brightness must be between 1 and 100 percent.")
    return call_service(
        base_url, token, "light.turn_on", entity_id, {"brightness_pct": brightness})
