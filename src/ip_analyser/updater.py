from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

RELEASE_API = "https://api.github.com/repos/2E0LXY/Advanced-IP-Analyser/releases/latest"
MAX_PACKAGE_BYTES = 50 * 1024 * 1024
MAX_RELEASE_METADATA_BYTES = 1024 * 1024
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DEBIAN_PACKAGE_PATTERN = re.compile(r"^advanced-ip-analyser_([0-9]+\.[0-9]+\.[0-9]+)_all\.deb$")
WINDOWS_PACKAGE_PATTERN = re.compile(r"^Advanced-IP-Analyser-Setup-([0-9]+\.[0-9]+\.[0-9]+)\.exe$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DOWNLOAD_PREFIX = "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/"


@dataclass(frozen=True, slots=True)
class Update:
    version: str
    download_url: str
    filename: str
    sha256: str = ""
    installer_kind: str = "debian"


def _installer_pattern(kind: str) -> re.Pattern[str]:
    if kind == "debian":
        return DEBIAN_PACKAGE_PATTERN
    if kind == "windows":
        return WINDOWS_PACKAGE_PATTERN
    raise ValueError("unsupported update installer kind")


def version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    """Create a dependency-free comparison key for this project's release versions."""
    value = value.strip().removeprefix("v")
    if not VERSION_PATTERN.fullmatch(value):
        raise ValueError("release version must use the X.Y.Z format")
    return tuple((0, int(part)) for part in value.split("."))


def check_for_update(current_version: str, timeout: float = 5.0,
                     installer_kind: str | None = None) -> Update | None:
    installer_kind = installer_kind or ("windows" if sys.platform == "win32" else "debian")
    package_pattern = _installer_pattern(installer_kind)
    request = urllib.request.Request(RELEASE_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": f"Advanced-IP-Analyser/{current_version}",
    })
    # RELEASE_API is a fixed HTTPS GitHub API endpoint.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        encoded = response.read(MAX_RELEASE_METADATA_BYTES + 1)
    if len(encoded) > MAX_RELEASE_METADATA_BYTES:
        raise ValueError("GitHub release metadata exceeds the 1 MiB safety limit")
    try:
        payload = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("GitHub returned invalid release metadata") from error
    if not isinstance(payload, dict):
        raise ValueError("GitHub returned an invalid release record")
    latest = str(payload.get("tag_name", "")).removeprefix("v")
    if not VERSION_PATTERN.fullmatch(latest):
        return None
    if version_key(latest) <= version_key(current_version):
        return None
    assets = payload.get("assets", [])
    if not isinstance(assets, list):
        raise ValueError("GitHub release assets are invalid")
    for asset in assets[:1_000]:
        if not isinstance(asset, dict):
            continue
        filename = str(asset.get("name", ""))
        match = package_pattern.fullmatch(filename)
        url = str(asset.get("browser_download_url", ""))
        expected_url = f"{DOWNLOAD_PREFIX}v{latest}/{filename}"
        if match and match.group(1) == latest and url == expected_url:
            digest = str(asset.get("digest", ""))
            sha256 = digest.removeprefix("sha256:") if digest.startswith("sha256:") else ""
            if not SHA256_PATTERN.fullmatch(sha256):
                raise ValueError("the GitHub release does not publish a valid SHA-256 package digest")
            return Update(latest, url, filename, sha256, installer_kind)
    return None


def download_update(update: Update, cache_dir: Path | None = None, timeout: float = 30.0) -> Path:
    match = _installer_pattern(update.installer_kind).fullmatch(update.filename)
    expected_url = f"{DOWNLOAD_PREFIX}v{update.version}/{update.filename}"
    if (not match or match.group(1) != update.version or
            update.download_url != expected_url or
            not SHA256_PATTERN.fullmatch(update.sha256)):
        raise ValueError("update metadata is incomplete or untrusted")
    directory = cache_dir or Path.home() / ".cache" / "advanced-ip-analyser" / "updates"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / update.filename
    request = urllib.request.Request(update.download_url, headers={"User-Agent": "Advanced-IP-Analyser updater"})
    digest = hashlib.sha256()
    total = 0
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{update.filename}.", suffix=".part", dir=directory)
    temporary = Path(temporary_name)
    try:
        # The URL was matched exactly against this project's fixed HTTPS release prefix above.
        with urllib.request.urlopen(request, timeout=timeout) as response, os.fdopen(descriptor, "wb") as stream:  # nosec B310
            length = response.headers.get("Content-Length")
            if length:
                try:
                    declared_length = int(length)
                except ValueError as error:
                    raise ValueError("update server returned an invalid package size") from error
                if declared_length < 0 or declared_length > MAX_PACKAGE_BYTES:
                    raise ValueError("update package exceeds the 50 MiB safety limit")
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > MAX_PACKAGE_BYTES:
                    raise ValueError("update package exceeds the 50 MiB safety limit")
                stream.write(chunk)
                digest.update(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if digest.hexdigest() != update.sha256:
            raise ValueError("downloaded update failed its SHA-256 integrity check")
        if update.installer_kind == "debian":
            result = subprocess.run(
                ["/usr/bin/dpkg-deb", "--field", str(temporary), "Package", "Version"],
                text=True, capture_output=True, timeout=10, check=False)
            fields = dict(line.split(":", 1) for line in result.stdout.splitlines() if ":" in line)
            if (result.returncode or fields.get("Package", "").strip() != "advanced-ip-analyser" or
                    fields.get("Version", "").strip() != update.version):
                raise ValueError("download is not the expected Advanced IP Analyser package")
        else:
            with temporary.open("rb") as stream:
                if stream.read(2) != b"MZ":
                    raise ValueError("download is not a Windows executable installer")
        os.replace(temporary, destination)
        return destination
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)


def launch_installer(package: Path, update: Update) -> None:
    """Start the detached privileged installer; the caller can then close the GUI."""
    package = package.resolve()
    match = _installer_pattern(update.installer_kind).fullmatch(package.name)
    if (not match or match.group(1) != update.version or
            not SHA256_PATTERN.fullmatch(update.sha256)):
        raise ValueError("update installer metadata is invalid")
    if not package.is_file() or package.stat().st_size > MAX_PACKAGE_BYTES:
        raise ValueError("update installer file is invalid")
    with package.open("rb") as stream:
        actual_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if not hmac.compare_digest(actual_digest, update.sha256):
        raise ValueError("update installer failed its final SHA-256 integrity check")
    if update.installer_kind == "windows":
        with package.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise ValueError("update installer is not a Windows executable")
        subprocess.Popen(
            [str(package), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
             "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS", "/RELAUNCH=1"],
            close_fds=True)
        return
    subprocess.Popen([sys.executable, "-m", "ip_analyser.update_helper", str(package),
                      update.version, update.sha256, str(os.getpid())],
                     start_new_session=True, close_fds=True)
