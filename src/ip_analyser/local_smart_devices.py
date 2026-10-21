"""Adapters for common local-first smart-device protocols."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPBasicAuthHandler,
    HTTPDigestAuthHandler,
    HTTPPasswordMgrWithDefaultRealm,
    Request,
    build_opener,
)

from .home_assistant import MAX_RESPONSE_BYTES, _NoRedirect, validate_local_url
from .smart_home import SmartHomeDevice, SmartHomeError

PROVIDERS = ("Smart Life / Tuya", "Shelly", "Tasmota", "WLED", "Philips Hue")
RPC_METHOD = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,127}")


def _base_url(host: str) -> str:
    value = host.strip()
    if "://" not in value:
        value = f"http://{value}"
    return validate_local_url(value)


def _http_json(host: str, path: str, *, data: dict[str, Any] | None = None,
               username: str = "", password: str = "", timeout: int = 8,
               method: str | None = None) -> Any:
    base_url = _base_url(host)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    request = Request(
        f"{base_url}{path}", data=body, method=method or ("POST" if body is not None else "GET"),
        headers={"Content-Type": "application/json"})
    handlers: list[Any] = [_NoRedirect()]
    if username or password:
        manager = HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, base_url, username or "admin", password)
        handlers.extend((HTTPDigestAuthHandler(manager), HTTPBasicAuthHandler(manager)))
    try:
        with build_opener(*handlers).open(request, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise SmartHomeError(f"{host} returned HTTP {error.code}.") from error
    except (OSError, URLError) as error:
        raise SmartHomeError(f"The local device at {host} could not be reached: {error}") from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise SmartHomeError("The local device response exceeded the safety limit.")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmartHomeError(f"{host} returned invalid JSON.") from error


def _tuya_config(config: str) -> tuple[float, str, str]:
    parts = [part.strip() for part in (config or "3.3,1,3").split(",")]
    if not parts or parts[0] not in {"3.1", "3.2", "3.3", "3.4", "3.5"}:
        raise ValueError("Tuya configuration must start with version 3.1, 3.2, 3.3, 3.4, or 3.5.")
    if len(parts) > 3 or any(not part.isdigit() for part in parts[1:]):
        raise ValueError("Use Tuya configuration version,power-DP,brightness-DP; for example 3.3,1,3.")
    return float(parts[0]), parts[1] if len(parts) > 1 else "1", parts[2] if len(parts) > 2 else "3"


def _tuya_device(host: str, device_id: str, local_key: str, version: float):
    if not device_id.strip() or not local_key:
        raise ValueError("Smart Life/Tuya requires the device ID and local key.")
    try:
        import tinytuya
    except ImportError as error:
        raise SmartHomeError(
            "Smart Life/Tuya support is not installed; install the Windows 2.6 edition "
            "or run: pip install 'tinytuya>=1.20,<2'.") from error
    device = tinytuya.Device(device_id.strip(), host.strip(), local_key, version=version)
    device.set_socketTimeout(5)
    device.set_socketRetryLimit(1)
    return device


def _tuya_status(host: str, device_id: str, local_key: str,
                 config: str) -> tuple[dict[str, Any], float, str, str]:
    version, power_dp, brightness_dp = _tuya_config(config)
    status = _tuya_device(host, device_id, local_key, version).status()
    if not isinstance(status, dict) or status.get("Error") or not isinstance(status.get("dps"), dict):
        raise SmartHomeError(str(status.get("Error", "The Tuya device returned no datapoints.")))
    return status["dps"], version, power_dp, brightness_dp


def _tuya_snapshot(host: str, device_id: str, local_key: str, config: str) -> SmartHomeDevice:
    dps, version, power_dp, brightness_dp = _tuya_status(host, device_id, local_key, config)
    power = dps.get(power_dp)
    brightness = dps.get(brightness_dp)
    if isinstance(brightness, int | float):
        brightness = round(brightness / 10) if brightness > 100 else round(brightness)
        brightness = max(0, min(100, brightness))
    else:
        brightness = None
    return SmartHomeDevice(
        address=host.strip(), alias=f"Tuya {device_id[-6:]}", model=f"Protocol {version}",
        kind="Smart Life / Tuya", is_on=power if isinstance(power, bool) else None,
        brightness=brightness, signal=None, mac="", can_power=power_dp in dps,
        can_brightness=brightness_dp in dps, provider="Smart Life / Tuya",
        entity_id=device_id.strip(), controller=host.strip())


def _shelly_snapshot(host: str, username: str, password: str,
                     config: str) -> SmartHomeDevice:
    channel = int(config.strip() or "0")
    if not 0 <= channel <= 99:
        raise ValueError("Shelly channel must be between 0 and 99.")
    try:
        info = _http_json(host, "/rpc/Shelly.GetDeviceInfo", username=username, password=password)
        status = _http_json(host, "/rpc/Shelly.GetStatus", username=username, password=password)
        component = status.get(f"switch:{channel}") or status.get(f"light:{channel}") or {}
        is_light = f"light:{channel}" in status
        signal = (status.get("wifi") or {}).get("rssi")
    except SmartHomeError:
        # Gen1 devices expose the older /shelly and /status resources.
        info = _http_json(host, "/shelly", username=username, password=password)
        status = _http_json(host, "/status", username=username, password=password)
        lights = status.get("lights") or []
        relays = status.get("relays") or []
        is_light = channel < len(lights)
        component = lights[channel] if is_light else relays[channel] if channel < len(relays) else {}
        if "ison" in component:
            component = {**component, "output": component["ison"]}
        signal = (status.get("wifi_sta") or {}).get("rssi")
    return SmartHomeDevice(
        address=host.strip(), alias=str(info.get("name") or info.get("id") or "Shelly"),
        model=str(info.get("model") or info.get("app") or "Shelly"), kind="Shelly",
        is_on=component.get("output") if isinstance(component.get("output"), bool) else None,
        brightness=component.get("brightness") if isinstance(component.get("brightness"), int) else None,
        signal=signal, mac=str(info.get("mac", "")),
        can_power=bool(component), can_brightness=is_light, provider="Shelly",
        entity_id=str(channel), controller=host.strip())


def _tasmota_command(host: str, command: str, username: str, password: str) -> Any:
    query = {"cmnd": command}
    if username:
        query["user"] = username
    if password:
        query["password"] = password
    return _http_json(host, f"/cm?{urlencode(query)}")


def _tasmota_snapshot(host: str, username: str, password: str,
                      config: str) -> SmartHomeDevice:
    relay = int(config.strip() or "1")
    if not 1 <= relay <= 32:
        raise ValueError("Tasmota relay number must be between 1 and 32.")
    payload = _tasmota_command(host, "Status 0", username, password)
    status = payload.get("Status") or {}
    state = payload.get("StatusSTS") or {}
    power = state.get(f"POWER{relay}", state.get("POWER"))
    name = status.get("FriendlyName") or status.get("DeviceName") or "Tasmota"
    if isinstance(name, list):
        name = name[min(relay - 1, len(name) - 1)] if name else "Tasmota"
    return SmartHomeDevice(
        address=host.strip(), alias=str(name), model=str(status.get("Module") or "Tasmota"),
        kind="Tasmota", is_on=str(power).upper() == "ON" if power is not None else None,
        brightness=state.get("Dimmer") if isinstance(state.get("Dimmer"), int) else None,
        signal=(state.get("Wifi") or {}).get("RSSI"), mac=str(status.get("Mac", "")),
        can_power=power is not None, can_brightness="Dimmer" in state, provider="Tasmota",
        entity_id=str(relay), controller=host.strip())


def _wled_snapshot(host: str) -> SmartHomeDevice:
    payload = _http_json(host, "/json")
    state = payload.get("state") or {}
    info = payload.get("info") or {}
    brightness = state.get("bri")
    return SmartHomeDevice(
        address=host.strip(), alias=str(info.get("name") or "WLED"),
        model=str(info.get("product") or info.get("ver") or "WLED"), kind="WLED",
        is_on=state.get("on") if isinstance(state.get("on"), bool) else None,
        brightness=round(brightness / 255 * 100) if isinstance(brightness, int) else None,
        signal=(info.get("wifi") or {}).get("rssi"), mac=str((info.get("wifi") or {}).get("bssid", "")),
        can_power=True, can_brightness=True, provider="WLED", controller=host.strip())


def _hue_snapshot(host: str, application_key: str, config: str) -> SmartHomeDevice:
    if not application_key.strip():
        raise ValueError("Philips Hue requires a locally authorized bridge application key.")
    light_id = config.strip() or "1"
    if not light_id.isdigit():
        raise ValueError("Philips Hue light ID must be a number.")
    lights = _http_json(host, f"/api/{application_key.strip()}/lights")
    if isinstance(lights, list) and lights and isinstance(lights[0], dict) and "error" in lights[0]:
        raise SmartHomeError(str(lights[0]["error"].get("description", "Hue bridge rejected the key.")))
    if not isinstance(lights, dict) or light_id not in lights:
        raise SmartHomeError(f"Philips Hue light {light_id} was not found on the bridge.")
    light = lights[light_id]
    state = light.get("state") or {}
    brightness = state.get("bri")
    return SmartHomeDevice(
        address=host.strip(), alias=str(light.get("name") or f"Hue light {light_id}"),
        model=str(light.get("productname") or light.get("modelid") or "Philips Hue"),
        kind=str(light.get("type") or "Philips Hue"),
        is_on=state.get("on") if isinstance(state.get("on"), bool) else None,
        brightness=round(brightness / 254 * 100) if isinstance(brightness, int) else None,
        signal=None, mac=str(light.get("uniqueid", "")), can_power=True,
        can_brightness="bri" in state, provider="Philips Hue", entity_id=light_id,
        controller=host.strip())


def inspect_local_device(provider: str, host: str, identifier: str = "", secret: str = "",
                         config: str = "") -> SmartHomeDevice:
    if provider == "Smart Life / Tuya":
        return _tuya_snapshot(host, identifier, secret, config)
    if provider == "Shelly":
        return _shelly_snapshot(host, identifier, secret, config)
    if provider == "Tasmota":
        return _tasmota_snapshot(host, identifier or "admin", secret, config)
    if provider == "WLED":
        return _wled_snapshot(host)
    if provider == "Philips Hue":
        return _hue_snapshot(host, identifier, config)
    raise ValueError("Unsupported local smart-device provider.")


def set_local_power(provider: str, host: str, enabled: bool, identifier: str = "",
                    secret: str = "", config: str = "") -> SmartHomeDevice:
    if provider == "Smart Life / Tuya":
        version, power_dp, _brightness_dp = _tuya_config(config)
        result = _tuya_device(host, identifier, secret, version).set_value(power_dp, enabled)
        if isinstance(result, dict) and result.get("Error"):
            raise SmartHomeError(str(result["Error"]))
    elif provider == "Shelly":
        channel = int(config.strip() or "0")
        try:
            _http_json(host, "/rpc/Switch.Set", data={"id": channel, "on": enabled},
                       username=identifier, password=secret)
        except SmartHomeError:
            _http_json(host, f"/relay/{channel}?turn={'on' if enabled else 'off'}",
                       username=identifier, password=secret)
    elif provider == "Tasmota":
        relay = int(config.strip() or "1")
        _tasmota_command(host, f"Power{relay} {'ON' if enabled else 'OFF'}", identifier, secret)
    elif provider == "WLED":
        _http_json(host, "/json/state", data={"on": enabled})
    elif provider == "Philips Hue":
        light_id = config.strip() or "1"
        _http_json(host, f"/api/{identifier.strip()}/lights/{light_id}/state",
                   data={"on": enabled}, method="PUT")
    else:
        raise ValueError("Unsupported local smart-device provider.")
    return inspect_local_device(provider, host, identifier, secret, config)


def set_local_brightness(provider: str, host: str, brightness: int, identifier: str = "",
                         secret: str = "", config: str = "") -> SmartHomeDevice:
    if not 1 <= brightness <= 100:
        raise ValueError("Brightness must be between 1 and 100 percent.")
    if provider == "Smart Life / Tuya":
        dps, version, _power_dp, brightness_dp = _tuya_status(host, identifier, secret, config)
        current = dps.get(brightness_dp)
        value = brightness * 10 if isinstance(current, int | float) and current > 100 else brightness
        _tuya_device(host, identifier, secret, version).set_value(brightness_dp, value)
    elif provider == "Shelly":
        channel = int(config.strip() or "0")
        try:
            _http_json(
                host, "/rpc/Light.Set",
                data={"id": channel, "on": True, "brightness": brightness},
                username=identifier, password=secret)
        except SmartHomeError:
            _http_json(host, f"/light/{channel}?turn=on&brightness={brightness}",
                       username=identifier, password=secret)
    elif provider == "Tasmota":
        _tasmota_command(host, f"Dimmer {brightness}", identifier, secret)
    elif provider == "WLED":
        _http_json(host, "/json/state", data={"on": True, "bri": round(brightness / 100 * 255)})
    elif provider == "Philips Hue":
        light_id = config.strip() or "1"
        _http_json(host, f"/api/{identifier.strip()}/lights/{light_id}/state",
                   data={"on": True, "bri": round(brightness / 100 * 254)}, method="PUT")
    else:
        raise SmartHomeError(f"{provider} does not provide brightness control.")
    return inspect_local_device(provider, host, identifier, secret, config)


def run_local_action(provider: str, host: str, action: str, data: dict[str, Any],
                     identifier: str = "", secret: str = "", config: str = "") -> SmartHomeDevice:
    if provider == "Smart Life / Tuya":
        if not action.startswith("dp.") or not action[3:].isdigit() or "value" not in data:
            raise ValueError("Tuya actions use dp.NUMBER with JSON data containing a value field.")
        version, _power_dp, _brightness_dp = _tuya_config(config)
        _tuya_device(host, identifier, secret, version).set_value(action[3:], data["value"])
    elif provider == "Shelly":
        if not RPC_METHOD.fullmatch(action):
            raise ValueError("Enter a valid Shelly RPC method, such as Switch.Toggle.")
        _http_json(host, f"/rpc/{action}", data=data, username=identifier, password=secret)
    elif provider == "Tasmota":
        value = data.get("value", "")
        _tasmota_command(host, f"{action} {value}".strip(), identifier, secret)
    elif provider == "WLED":
        if action != "state":
            raise ValueError("WLED advanced actions use action 'state' and a JSON state object.")
        _http_json(host, "/json/state", data=data)
    elif provider == "Philips Hue":
        if action != "state":
            raise ValueError("Philips Hue advanced actions use action 'state' and a JSON state object.")
        light_id = config.strip() or "1"
        _http_json(host, f"/api/{identifier.strip()}/lights/{light_id}/state",
                   data=data, method="PUT")
    else:
        raise ValueError("Unsupported local smart-device provider.")
    return inspect_local_device(provider, host, identifier, secret, config)
