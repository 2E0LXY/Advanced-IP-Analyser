"""OS credential storage for the persistent desktop/Android LAN pairing secret."""

from __future__ import annotations

import json
import secrets

SERVICE = "Advanced IP Analyser LAN Pairing"
ACCOUNT = "android-peer"


def _keyring():
    try:
        import keyring
    except ImportError as error:
        raise RuntimeError("Secure credential storage is unavailable.") from error
    return keyring


def load_or_create_pairing() -> dict[str, str]:
    keyring = _keyring()
    value = keyring.get_password(SERVICE, ACCOUNT)
    if value:
        try:
            data = json.loads(value)
            if isinstance(data, dict) and isinstance(data.get("token"), str) and len(data["token"]) >= 32:
                return {"token": data["token"], "device_id": str(data.get("device_id", "")),
                        "peer_address": str(data.get("peer_address", ""))}
        except (ValueError, TypeError):
            pass
    data = {"token": secrets.token_urlsafe(32), "device_id": "", "peer_address": ""}
    save_pairing(data)
    return data


def save_pairing(data: dict[str, str]) -> None:
    payload = {key: str(data.get(key, "")) for key in ("token", "device_id", "peer_address")}
    _keyring().set_password(SERVICE, ACCOUNT, json.dumps(payload, separators=(",", ":")))


def rotate_pairing() -> dict[str, str]:
    data = {"token": secrets.token_urlsafe(32), "device_id": "", "peer_address": ""}
    save_pairing(data)
    return data
