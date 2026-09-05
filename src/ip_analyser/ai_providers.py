from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .ai_settings import validate_api_key, validate_model, validate_provider

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_MODELS = 5_000
REQUEST_TIMEOUT = 30
PROVIDER_ENDPOINTS = {
    "OpenAI": "https://api.openai.com/v1",
    "Gemini": "https://generativelanguage.googleapis.com/v1beta",
    "OpenRouter": "https://openrouter.ai/api/v1",
}
_NON_TEXT_OPENAI_MARKERS = (
    "audio", "dall-e", "embedding", "image", "moderation", "realtime",
    "search-preview", "transcribe", "tts", "whisper",
)


class AIProviderError(RuntimeError):
    """A safe, user-facing provider request failure."""


@dataclass(frozen=True, slots=True)
class ModelChoice:
    identifier: str
    display_name: str
    context_tokens: int | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _headers(provider: str, api_key: str) -> dict[str, str]:
    key = validate_api_key(api_key)
    headers = {"Accept": "application/json", "User-Agent": "Advanced-IP-Analyser/AI"}
    if provider == "Gemini":
        headers["x-goog-api-key"] = key
    else:
        headers["Authorization"] = f"Bearer {key}"
    if provider == "OpenRouter":
        headers["X-Title"] = "Advanced IP Analyser"
    return headers


def _request_json(provider: str, path: str, api_key: str, *, method: str = "GET",
                  payload: dict[str, Any] | None = None,
                  opener: Any | None = None) -> dict[str, Any]:
    provider = validate_provider(provider)
    if not path.startswith("/") or ".." in path:
        raise ValueError("invalid provider API path")
    url = PROVIDER_ENDPOINTS[provider] + path
    body = None
    headers = _headers(provider, api_key)
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    client = opener or urllib.request.build_opener(_NoRedirect())
    try:
        with client.open(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise AIProviderError(f"{provider} rejected the request (HTTP {error.code}).") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise AIProviderError(f"Could not connect securely to {provider}.") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AIProviderError(f"{provider} returned an unexpectedly large response.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AIProviderError(f"{provider} returned an invalid response.") from error
    if not isinstance(data, dict):
        raise AIProviderError(f"{provider} returned an invalid response object.")
    return data


def list_models(provider: str, api_key: str, *, opener: Any | None = None) -> list[ModelChoice]:
    provider = validate_provider(provider)
    if provider == "Gemini":
        choices = _list_gemini_models(api_key, opener=opener)
    else:
        data = _request_json(provider, "/models", api_key, opener=opener)
        choices = _parse_openai_style_models(provider, data)
    if not choices:
        raise AIProviderError(f"{provider} did not return any usable text-generation models.")
    return sorted(choices, key=lambda item: (item.display_name.casefold(), item.identifier.casefold()))


def _parse_openai_style_models(provider: str, data: dict[str, Any]) -> list[ModelChoice]:
    items = data.get("data")
    if not isinstance(items, list) or len(items) > MAX_MODELS:
        raise AIProviderError(f"{provider} returned an invalid model list.")
    choices: list[ModelChoice] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        identifier = item["id"].strip()
        try:
            validate_model(identifier)
        except ValueError:
            continue
        if not identifier or identifier in seen:
            continue
        if provider == "OpenAI" and any(marker in identifier.casefold()
                                         for marker in _NON_TEXT_OPENAI_MARKERS):
            continue
        if provider == "OpenRouter":
            architecture = item.get("architecture")
            if isinstance(architecture, dict):
                output = architecture.get("output_modalities")
                if isinstance(output, list) and "text" not in output:
                    continue
        name = item.get("name") if isinstance(item.get("name"), str) else identifier
        context = item.get("context_length")
        context = context if isinstance(context, int) and context > 0 else None
        choices.append(ModelChoice(identifier, name.strip()[:256] or identifier, context))
        seen.add(identifier)
    return choices


def _list_gemini_models(api_key: str, *, opener: Any | None = None) -> list[ModelChoice]:
    choices: list[ModelChoice] = []
    seen: set[str] = set()
    page_token = ""
    for _page in range(10):
        query = {"pageSize": "1000"}
        if page_token:
            query["pageToken"] = page_token
        data = _request_json("Gemini", "/models?" + urllib.parse.urlencode(query),
                             api_key, opener=opener)
        items = data.get("models")
        if not isinstance(items, list) or len(items) > 1_000:
            raise AIProviderError("Gemini returned an invalid model list.")
        for item in items:
            if not isinstance(item, dict):
                continue
            methods = item.get("supportedGenerationMethods")
            identifier = item.get("name")
            if not isinstance(identifier, str) or not isinstance(methods, list) or "generateContent" not in methods:
                continue
            identifier = identifier.removeprefix("models/").strip()
            try:
                validate_model(identifier)
            except ValueError:
                continue
            if not identifier or identifier in seen or len(choices) >= MAX_MODELS:
                continue
            name = item.get("displayName") if isinstance(item.get("displayName"), str) else identifier
            context = item.get("inputTokenLimit")
            context = context if isinstance(context, int) and context > 0 else None
            choices.append(ModelChoice(identifier, name.strip()[:256] or identifier, context))
            seen.add(identifier)
        next_token = data.get("nextPageToken", "")
        if not isinstance(next_token, str) or len(next_token) > 2_048:
            raise AIProviderError("Gemini returned an invalid pagination token.")
        if not next_token:
            break
        page_token = next_token
    else:
        raise AIProviderError("Gemini returned too many model-list pages.")
    return choices


def generate_text(provider: str, model: str, api_key: str, system: str, prompt: str,
                  *, max_output_tokens: int = 2_000, opener: Any | None = None) -> str:
    provider = validate_provider(provider)
    model = validate_model(model)
    if not model:
        raise ValueError("select a model first")
    if not 64 <= max_output_tokens <= 8_192:
        raise ValueError("AI output limit is outside the supported range")
    if provider == "OpenAI":
        data = _request_json(provider, "/responses", api_key, method="POST", opener=opener,
                             payload={"model": model, "instructions": system, "input": prompt,
                                      "max_output_tokens": max_output_tokens, "store": False})
        text = data.get("output_text")
        if not isinstance(text, str):
            text = _openai_output_text(data)
    elif provider == "OpenRouter":
        data = _request_json(provider, "/chat/completions", api_key, method="POST", opener=opener,
                             payload={"model": model, "messages": [
                                 {"role": "system", "content": system},
                                 {"role": "user", "content": prompt}],
                                      "max_completion_tokens": max_output_tokens})
        text = _openrouter_output_text(data)
    else:
        encoded_model = urllib.parse.quote(model, safe="._-/")
        data = _request_json(provider, f"/models/{encoded_model}:generateContent", api_key,
                             method="POST", opener=opener, payload={
                                 "systemInstruction": {"parts": [{"text": system}]},
                                 "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                                 "generationConfig": {"maxOutputTokens": max_output_tokens}})
        text = _gemini_output_text(data)
    if not text or len(text) > 1_000_000:
        raise AIProviderError(f"{provider} returned no usable text output.")
    return text.strip()


def _openai_output_text(data: dict[str, Any]) -> str:
    pieces: list[str] = []
    output = data.get("output")
    if isinstance(output, list):
        for item in output[:100]:
            if not isinstance(item, dict) or not isinstance(item.get("content"), list):
                continue
            for content in item["content"][:100]:
                if isinstance(content, dict) and content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    pieces.append(content["text"])
    return "\n".join(pieces)


def _openrouter_output_text(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message")
    return message.get("content", "") if isinstance(message, dict) and isinstance(message.get("content"), str) else ""


def _gemini_output_text(data: dict[str, Any]) -> str:
    pieces: list[str] = []
    candidates = data.get("candidates")
    if isinstance(candidates, list):
        for candidate in candidates[:10]:
            content = candidate.get("content") if isinstance(candidate, dict) else None
            parts = content.get("parts") if isinstance(content, dict) else None
            if not isinstance(parts, list):
                continue
            for part in parts[:100]:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    pieces.append(part["text"])
    return "\n".join(pieces)
