import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ip_analyser.ai_settings import (
    AISettings,
    SecretStoreError,
    clear_api_key,
    has_api_key,
    load_ai_settings,
    load_api_key,
    save_ai_settings,
    save_api_key,
    validate_api_key,
    validate_settings,
)


class AISettingsTests(unittest.TestCase):
    def test_settings_round_trip_contains_no_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ai-settings.json"
            settings = AISettings("Gemini", {"Gemini": "gemini-safe-1"}, 12_000)
            save_ai_settings(settings, path)
            self.assertEqual(load_ai_settings(path), settings)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(set(data), {"provider", "models", "max_request_chars"})
            self.assertNotIn("key", json.dumps(data).casefold())
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rejects_unknown_provider_model_and_request_limit(self):
        for settings in (
            AISettings("Unknown"), AISettings(models={"Unknown": "model"}),
            AISettings(models={"OpenAI": "model name"}), AISettings(max_request_chars=999),
        ):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                validate_settings(settings)

    def test_rejects_unsafe_key_text(self):
        for key in ("short", " leading-key", "trailing-key ", "line\nbreak-key"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_api_key(key)

    def test_rejects_unknown_fields_and_oversized_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ai-settings.json"
            path.write_text('{"provider":"OpenAI","api_key":"secret-value"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_ai_settings(path)
            path.write_text("x" * 32_769, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_ai_settings(path)

    @patch("ip_analyser.ai_settings.subprocess.run")
    def test_provider_key_is_passed_only_on_stdin(self, run):
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "secret-tool"
            tool.touch()
            save_api_key("Gemini", "api-secret-value", tool=tool)
        arguments = run.call_args.args[0]
        self.assertNotIn("api-secret-value", arguments)
        self.assertEqual(run.call_args.kwargs["input"], "api-secret-value")
        self.assertNotIn("\n", run.call_args.kwargs["input"])
        self.assertEqual(arguments[-2:], ["provider", "gemini"])

    @patch("ip_analyser.ai_settings.subprocess.run")
    def test_provider_keys_are_isolated_for_lookup_and_clear(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "stored-secret\n"
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "secret-tool"
            tool.touch()
            self.assertTrue(has_api_key("OpenRouter", tool=tool))
            self.assertEqual(load_api_key("OpenRouter", tool=tool), "stored-secret")
            clear_api_key("OpenRouter", tool=tool)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][-2:], ["provider", "openrouter"])

    def test_missing_secret_tool_has_no_plaintext_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-secret-tool"
            with self.assertRaises(SecretStoreError):
                save_api_key("OpenAI", "api-secret-value", tool=missing)


if __name__ == "__main__":
    unittest.main()
