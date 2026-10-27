"""Secure storage for the optional TP-Link smart-home account."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SECRET_TOOL = Path("/usr/bin/secret-tool")
WINDOWS_SERVICE = "Advanced IP Analyser Smart Home"
WINDOWS_ACCOUNT = "tp-link-account"
SECRET_LABEL = "Advanced IP Analyser · TP-Link smart-home account"


class SmartHomeCredentialError(RuntimeError):
    """Raised when the operating-system credential store cannot be used."""


def validate_credentials(username: str, password: str) -> tuple[str, str]:
    username = username.strip()
    if not 1 <= len(username) <= 320:
        raise ValueError("Enter the TP-Link account email or username.")
    if not 1 <= len(password) <= 1_024:
        raise ValueError("Enter a TP-Link account password.")
    if any(ord(character) < 32 for character in username + password):
        raise ValueError("Smart-home credentials must not contain control characters.")
    return username, password


def _payload(username: str, password: str) -> str:
    username, password = validate_credentials(username, password)
    return json.dumps({"username": username, "password": password}, separators=(",", ":"))


def _decode_payload(value: str) -> tuple[str, str]:
    try:
        data = json.loads(value)
    except (json.JSONDecodeError, TypeError) as error:
        raise SmartHomeCredentialError("The saved smart-home credential is invalid.") from error
    if not isinstance(data, dict) or set(data) != {"username", "password"}:
        raise SmartHomeCredentialError("The saved smart-home credential is invalid.")
    try:
        return validate_credentials(data["username"], data["password"])
    except (TypeError, ValueError) as error:
        raise SmartHomeCredentialError("The saved smart-home credential is invalid.") from error


def _windows_keyring():
    try:
        import keyring
    except ImportError as error:
        raise SmartHomeCredentialError("Windows Credential Manager support is unavailable.") from error
    return keyring


def _attributes() -> tuple[str, ...]:
    return ("application", "advanced-ip-analyser", "credential", "smart-home", "provider", "tp-link")


def _run_secret_tool(arguments: list[str], *, input_text: str | None = None,
                     tool: Path = SECRET_TOOL) -> subprocess.CompletedProcess[str]:
    if not tool.is_file():
        raise SmartHomeCredentialError("Secure credential storage is unavailable; install libsecret-tools.")
    try:
        return subprocess.run(
            [str(tool), *arguments, *_attributes()], input=input_text,
            capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmartHomeCredentialError("The desktop credential store did not respond.") from error


def save_smart_home_credentials(username: str, password: str, *, tool: Path = SECRET_TOOL) -> None:
    value = _payload(username, password)
    if sys.platform == "win32" and tool == SECRET_TOOL:
        try:
            _windows_keyring().set_password(WINDOWS_SERVICE, WINDOWS_ACCOUNT, value)
            return
        except Exception as error:
            raise SmartHomeCredentialError(
                "Windows Credential Manager could not save the smart-home account.") from error
    result = _run_secret_tool(["store", f"--label={SECRET_LABEL}"], input_text=value, tool=tool)
    if result.returncode != 0:
        raise SmartHomeCredentialError("The desktop credential store could not save the smart-home account.")


def load_smart_home_credentials(*, tool: Path = SECRET_TOOL) -> tuple[str, str] | None:
    if sys.platform == "win32" and tool == SECRET_TOOL:
        try:
            value = _windows_keyring().get_password(WINDOWS_SERVICE, WINDOWS_ACCOUNT)
        except Exception as error:
            raise SmartHomeCredentialError(
                "Windows Credential Manager could not read the smart-home account.") from error
        return _decode_payload(value) if value is not None else None
    result = _run_secret_tool(["lookup"], tool=tool)
    if result.returncode == 1:
        return None
    if result.returncode != 0 or not result.stdout:
        raise SmartHomeCredentialError("The desktop credential store could not read the smart-home account.")
    return _decode_payload(result.stdout.rstrip("\r\n"))


def clear_smart_home_credentials(*, tool: Path = SECRET_TOOL) -> None:
    if sys.platform == "win32" and tool == SECRET_TOOL:
        try:
            keyring = _windows_keyring()
            if keyring.get_password(WINDOWS_SERVICE, WINDOWS_ACCOUNT) is not None:
                keyring.delete_password(WINDOWS_SERVICE, WINDOWS_ACCOUNT)
            return
        except Exception as error:
            raise SmartHomeCredentialError(
                "Windows Credential Manager could not delete the smart-home account.") from error
    result = _run_secret_tool(["clear"], tool=tool)
    if result.returncode not in {0, 1}:
        raise SmartHomeCredentialError("The desktop credential store could not delete the smart-home account.")
