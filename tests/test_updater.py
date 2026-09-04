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

    def test_non_release_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "X.Y.Z"):
            version_key("2.1.0rc1")

    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_latest_debian_asset_is_selected(self, urlopen):
        digest = "a" * 64
        payload = {"tag_name": "v0.5.1", "assets": [{
            "name": "advanced-ip-analyser_0.5.1_all.deb",
            "browser_download_url": "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/v0.5.1/advanced-ip-analyser_0.5.1_all.deb",
            "digest": f"sha256:{digest}",
        }]}
        urlopen.return_value = _Response(json.dumps(payload).encode())
        update = check_for_update("0.5.0")
        self.assertEqual(update, Update("0.5.1", payload["assets"][0]["browser_download_url"],
                                        "advanced-ip-analyser_0.5.1_all.deb", digest))

    @patch("ip_analyser.updater.subprocess.run")
    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_download_is_hashed_and_debian_identity_is_checked(self, urlopen, run):
        package = b"synthetic deb package"
        urlopen.return_value = _Response(package)
        run.return_value = Mock(returncode=0, stdout="Package: advanced-ip-analyser\nVersion: 0.5.1\n")
        update = Update("0.5.1", "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/v0.5.1/advanced-ip-analyser_0.5.1_all.deb",
                        "advanced-ip-analyser_0.5.1_all.deb", hashlib.sha256(package).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            result = download_update(update, Path(directory))
            self.assertEqual(result.read_bytes(), package)
            self.assertFalse(list(Path(directory).glob("*.part")))
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/dpkg-deb")

    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_release_without_valid_digest_is_not_installable(self, urlopen):
        payload = {"tag_name": "v0.5.1", "assets": [{
            "name": "advanced-ip-analyser_0.5.1_all.deb",
            "browser_download_url": "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/v0.5.1/advanced-ip-analyser_0.5.1_all.deb",
            "digest": "",
        }]}
        urlopen.return_value = _Response(json.dumps(payload).encode())
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            check_for_update("0.5.0")

    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_invalid_release_document_is_rejected(self, urlopen):
        urlopen.return_value = _Response(b"[]")
        with self.assertRaisesRegex(ValueError, "release record"):
            check_for_update("0.5.0")

    @patch("ip_analyser.updater.subprocess.run")
    @patch("ip_analyser.updater.urllib.request.urlopen")
    def test_bad_digest_is_rejected_and_partial_file_removed(self, urlopen, run):
        urlopen.return_value = _Response(b"wrong")
        update = Update("0.5.1", "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/v0.5.1/advanced-ip-analyser_0.5.1_all.deb",
                        "advanced-ip-analyser_0.5.1_all.deb", "0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                download_update(update, Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])
        run.assert_not_called()

    @patch("ip_analyser.update_helper.time.sleep")
    @patch("ip_analyser.update_helper.os.kill", side_effect=ProcessLookupError)
    @patch("ip_analyser.update_helper.subprocess.Popen")
    @patch("ip_analyser.update_helper.subprocess.run")
    @patch("ip_analyser.update_helper.shutil.which")
    @patch("ip_analyser.update_helper._trusted_helper_path")
    def test_helper_waits_for_old_process_then_installs_and_relaunches(
            self, trusted_helper, which, run, popen, kill, _sleep):
        trusted_helper.return_value = Path(update_helper.__file__).resolve()
        which.side_effect = ["/usr/bin/pkexec", "/usr/bin/advanced-ip-analyser-gui"]
        run.side_effect = [Mock(returncode=0, stdout="Package: advanced-ip-analyser\nVersion: 0.5.1\n"),
                           Mock(returncode=0)]
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "advanced-ip-analyser_0.5.1_all.deb"
            package.write_bytes(b"test")
            digest = hashlib.sha256(b"test").hexdigest()
            with patch("ip_analyser.update_helper.sys.argv",
                       ["update_helper", str(package), "0.5.1", digest, "1234"]):
                self.assertEqual(update_helper.main(), 0)
        kill.assert_called_once_with(1234, 0)
        self.assertEqual(run.call_args_list[0].args[0],
                         ["/usr/bin/dpkg-deb", "--field", str(package.resolve()), "Package", "Version"])
        self.assertEqual(run.call_args_list[1].args[0],
                         ["/usr/bin/pkexec", "/usr/bin/python3", "-I",
                          str(Path(update_helper.__file__).resolve()), "--install",
                          str(package.resolve()), "0.5.1", digest])
        popen.assert_called_once_with(["/usr/bin/advanced-ip-analyser-gui"], start_new_session=True, close_fds=True)

    @patch("ip_analyser.update_helper.os.geteuid", return_value=0, create=True)
    @patch("ip_analyser.update_helper.subprocess.run")
    def test_privileged_install_uses_root_owned_staged_copy(self, run, _geteuid):
        run.side_effect = [Mock(returncode=0, stdout="Package: advanced-ip-analyser\nVersion: 0.5.1\n"),
                           Mock(returncode=0)]
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "download.deb"
            package.write_bytes(b"verified package")
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            result = update_helper._install_as_root(
                package, "0.5.1", digest, Path(directory))
        self.assertEqual(result, 0)
        install_command = run.call_args_list[1].args[0]
        self.assertEqual(install_command[:3], ["/usr/bin/apt-get", "install", "-y"])
        self.assertNotEqual(Path(install_command[3]), package)
        self.assertIn("advanced-ip-analyser-update-", install_command[3])

    @patch("ip_analyser.update_helper.os.geteuid", return_value=0, create=True)
    def test_privileged_install_rejects_path_like_version(self, _geteuid):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "download.deb"
            package.write_bytes(b"package")
            with self.assertRaisesRegex(ValueError, "metadata"):
                update_helper._install_as_root(
                    package, "../../escape", "0" * 64, Path(directory))
            self.assertEqual({path.name for path in Path(directory).iterdir()}, {"download.deb"})


if __name__ == "__main__":
    unittest.main()
