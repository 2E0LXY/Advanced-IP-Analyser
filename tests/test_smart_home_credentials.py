import json
import unittest
from pathlib import Path
from unittest.mock import patch

from ip_analyser.smart_home_credentials import (
    SmartHomeCredentialError,
    clear_smart_home_credentials,
    load_smart_home_credentials,
    save_smart_home_credentials,
)


class SmartHomeCredentialTests(unittest.TestCase):
    @patch("ip_analyser.smart_home_credentials._windows_keyring")
    def test_windows_credential_manager_round_trip(self, keyring):
        saved = {}
        keyring.return_value.set_password.side_effect = lambda service, account, value: saved.update(value=value)
        keyring.return_value.get_password.side_effect = lambda service, account: saved.get("value")
        keyring.return_value.delete_password.side_effect = lambda service, account: saved.clear()
        with patch("ip_analyser.smart_home_credentials.sys.platform", "win32"):
            save_smart_home_credentials("owner@example.com", "correct horse battery staple")
            self.assertEqual(
                load_smart_home_credentials(),
                ("owner@example.com", "correct horse battery staple"),
            )
            clear_smart_home_credentials()
            self.assertIsNone(load_smart_home_credentials())

    def test_incomplete_credentials_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "password"):
            save_smart_home_credentials("owner@example.com", "", tool=Path("unused"))

    @patch("ip_analyser.smart_home_credentials._run_secret_tool")
    def test_invalid_saved_payload_is_rejected(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = json.dumps({"username": "owner@example.com"})
        with self.assertRaises(SmartHomeCredentialError):
            load_smart_home_credentials(tool=Path("mock-secret-tool"))


if __name__ == "__main__":
    unittest.main()
