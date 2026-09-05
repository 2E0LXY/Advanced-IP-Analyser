from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

SETTINGS_LIMIT = 32_768
SECRET_TOOL = Path("/usr/bin/secret-tool")
SECRET_LABEL_PREFIX = "Advanced IP Analyser AI API key"
PROVIDERS = ("OpenAI", "Gemini", "OpenRouter")
PROVIDER_SLUGS = {"OpenAI": "openai", "Gemini": "gemini", "OpenRouter": "openrouter"}
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")


class SecretStoreError(RuntimeError):
    """Raised when the desktop Secret Service keyring cannot be used."""


@dataclass(frozen=True, slots=True)
class AISettings:
    provider: str = "OpenAI"
    models: dict[str, str] = field(default_factory=dict)
    max_request_chars: int = 16_000

    def selected_model(self, provider: str | None = None) -> str:
        return self.models.get(provider or self.provider, "")


def default_settings_path() -> Path:
    return Path.home() / ".config" / "advanced-ip-analyser" / "ai-settings.json"


def validate_provider(provider: str) -> str:
    if provider not in PROVIDERS:
        raise ValueError("unsupported AI provider")
    return provider


def validate_model(model: str) -> str:
    clean = model.strip()
    if clean and not _MODEL.fullmatch(clean):
        raise ValueError("model name contains unsupported characters")
    return clean


def validate_settings(settings: AISettings) -> AISettings:
    provider = validate_provider(settings.provider)
    if not isinstance(settings.models, dict) or set(settings.models) - set(PROVIDERS):
        raise ValueError("AI model selections are invalid")
    models: dict[str, str] = {}
    for name, model in settings.models.items():
        validate_provider(name)
        if not isinstance(model, str):
            raise ValueError("AI model selections must be text")  # noqa: TRY004
        clean = validate_model(model)
        if clean:
            models[name] = clean
    if not isinstance(settings.max_request_chars, int) or not 1_000 <= settings.max_request_chars <= 100_000:
        raise ValueError("AI request limit must be between 1,000 and 100,000 characters")
    return AISettings(provider, models, settings.max_request_chars)


def validate_api_key(api_key: str) -> str:
    if not 8 <= len(api_key) <= 4_096:
        raise ValueError("API key must be between 8 and 4,096 characters")
    if api_key != api_key.strip() or any(ord(character) < 32 for character in api_key):
        raise ValueError("API key must not contain surrounding whitespace or control characters")
    return api_key


def load_ai_settings(path: Path | None = None) -> AISettings:
    path = path or default_settings_path()
    if not path.exists():
        return AISettings()
    if path.stat().st_size > SETTINGS_LIMIT:
        raise ValueError("AI settings file is too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"provider", "models", "max_request_chars"}:
        raise ValueError("AI settings file is invalid")
    return validate_settings(AISettings(**data))


def save_ai_settings(settings: AISettings, path: Path | None = None) -> None:
    clean = validate_settings(settings)
    path = path or default_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.parent.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".ai-settings-", dir=path.parent, text=True)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(asdict(clean), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            path.chmod(0o600)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def _secret_attributes(provider: str) -> tuple[str, ...]:
    slug = PROVIDER_SLUGS[validate_provider(provider)]
    return ("application", "advanced-ip-analyser", "credential", "ai-api-key", "provider", slug)


def _run_secret_tool(provider: str, arguments: list[str], *, input_text: str | None = None,
                     tool: Path = SECRET_TOOL) -> subprocess.CompletedProcess[str]:
    if not tool.is_file():
        raise SecretStoreError("Secure key storage is unavailable; install libsecret-tools.")
    try:
        return subprocess.run(
            [str(tool), *arguments, *_secret_attributes(provider)], input=input_text,
            capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SecretStoreError("The desktop keyring did not respond.") from error


def save_api_key(provider: str, api_key: str, *, tool: Path = SECRET_TOOL) -> None:
    provider = validate_provider(provider)
    key = validate_api_key(api_key)
    result = _run_secret_tool(
        provider, ["store", f"--label={SECRET_LABEL_PREFIX} · {provider}"],
        input_text=key, tool=tool)
    if result.returncode != 0:
        raise SecretStoreError(f"The desktop keyring could not save the {provider} API key.")


def has_api_key(provider: str, *, tool: Path = SECRET_TOOL) -> bool:
    result = _run_secret_tool(validate_provider(provider), ["lookup"], tool=tool)
    if result.returncode not in {0, 1}:
        raise SecretStoreError("The desktop keyring could not read the API key status.")
    return result.returncode == 0 and bool(result.stdout.rstrip("\r\n"))


def load_api_key(provider: str, *, tool: Path = SECRET_TOOL) -> str:
    result = _run_secret_tool(validate_provider(provider), ["lookup"], tool=tool)
    if result.returncode != 0 or not result.stdout:
        raise SecretStoreError(f"No {provider} API key is saved in the desktop keyring.")
    try:
        # secret-tool prints a line terminator after the stored bytes. Remove
        # only that transport delimiter; embedded controls remain invalid.
        return validate_api_key(result.stdout.rstrip("\r\n"))
    except ValueError as error:
        raise SecretStoreError(f"The saved {provider} API key is invalid.") from error


def clear_api_key(provider: str, *, tool: Path = SECRET_TOOL) -> None:
    result = _run_secret_tool(validate_provider(provider), ["clear"], tool=tool)
    if result.returncode != 0:
        raise SecretStoreError(f"The desktop keyring could not delete the {provider} API key.")
