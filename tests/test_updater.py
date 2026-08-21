import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ip_analyser.updater import Update, check_for_update, download_update, version_key
from ip_analyser import update_helper


class _Response(io.BytesIO):
    def __init__(self, content: bytes):
        super().__init__(content)
        self.headers = {"Content-Length": str(len(content))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class UpdaterTests(unittest.TestCase):
    def test_version_comparison_is_numeric(self):
        self.assertGreater(version_key("0.10.0"), version_key("0.9.9"))

    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_latest_debian_asset_is_selected(self, urlopen):
        payload = {"tag_name": "v0.5.1", "assets": [{
            "name": "advanced-ip-analyser_0.5.1_all.deb",
            "browser_download_url": "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/v0.5.1/package.deb",
            "digest": "sha256:abc123",
        }]}
        urlopen.return_value = _Response(json.dumps(payload).encode())
        update = check_for_update("0.5.0")
        self.assertEqual(update, Update("0.5.1", payload["assets"][0]["browser_download_url"],
                                        "advanced-ip-analyser_0.5.1_all.deb", "abc123"))

    @patch("ip_analyser.updater.subprocess.run")
    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_download_is_hashed_and_debian_identity_is_checked(self, urlopen, run):
        package = b"synthetic deb package"
        urlopen.return_value = _Response(package)
        run.return_value = Mock(returncode=0, stdout="Package: advanced-ip-analyser\nVersion: 0.5.1\n")
        update = Update("0.5.1", "https://github.com/example/package.deb",
                        "advanced-ip-analyser_0.5.1_all.deb", hashlib.sha256(package).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            result = download_update(update, Path(directory))
            self.assertEqual(result.read_bytes(), package)
            self.assertFalse((Path(directory) / "advanced-ip-analyser_0.5.1_all.deb.part").exists())

    @patch("ip_analyser.updater.subprocess.run")
    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_bad_digest_is_rejected_and_partial_file_removed(self, urlopen, run):
        urlopen.return_value = _Response(b"wrong")
        update = Update("0.5.1", "https://github.com/example/package.deb",
                        "advanced-ip-analyser_0.5.1_all.deb", "0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                download_update(update, Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])
        run.assert_not_called()

    @patch("ip_analyser.update_helper.time.sleep")
    @patch("ip_analyser.update_helper.subprocess.Popen")
    @patch("ip_analyser.update_helper.subprocess.run")
    @patch("ip_analyser.update_helper.shutil.which")
    def test_helper_installs_then_relaunches(self, which, run, popen, _sleep):
        which.side_effect = ["/usr/bin/pkexec", "/usr/bin/advanced-ip-analyser-gui"]
        run.return_value = Mock(returncode=0)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "advanced-ip-analyser_0.5.1_all.deb"
            package.write_bytes(b"test")
            with patch("ip_analyser.update_helper.sys.argv", ["update_helper", str(package)]):
                self.assertEqual(update_helper.main(), 0)
        run.assert_called_once_with(["/usr/bin/pkexec", "apt-get", "install", "-y", str(package.resolve())])
        popen.assert_called_once_with(["/usr/bin/advanced-ip-analyser-gui"], start_new_session=True, close_fds=True)


if __name__ == "__main__":
    unittest.main()
