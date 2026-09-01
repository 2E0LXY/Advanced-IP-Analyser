from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

RELEASE_API = "https://api.github.com/repos/2E0LXY/Advanced-IP-Analyser/releases/latest"
MAX_PACKAGE_BYTES = 50 * 1024 * 1024
PACKAGE_PATTERN = re.compile(r"^advanced-ip-analyser_([0-9][0-9A-Za-z.+~-]*)_all\.deb$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DOWNLOAD_PREFIX = "https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/"


@dataclass(frozen=True, slots=True)
class Update:
    version: str
    download_url: str
    filename: str
    sha256: str = ""


def version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    """Create a dependency-free comparison key for this project's release versions."""
    value = value.strip().removeprefix("v")
    return tuple((0, int(part)) if part.isdigit() else (1, part.casefold())
                 for part in re.findall(r"[0-9]+|[A-Za-z]+", value))


def check_for_update(current_version: str, timeout: float = 5.0) -> Update | None:
    request = urllib.request.Request(RELEASE_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": f"Advanced-IP-Analyser/{current_version}",
    })
    # RELEASE_API is a fixed HTTPS GitHub API endpoint.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        payload = json.load(response)
    latest = str(payload.get("tag_name", "")).removeprefix("v")
    if not latest or version_key(latest) <= version_key(current_version):
        return None
    for asset in payload.get("assets", []):
        filename = str(asset.get("name", ""))
        match = PACKAGE_PATTERN.fullmatch(filename)
        url = str(asset.get("browser_download_url", ""))
        expected_url = f"{DOWNLOAD_PREFIX}v{latest}/{filename}"
        if match and match.group(1) == latest and url == expected_url:
            digest = str(asset.get("digest", ""))
            sha256 = digest.removeprefix("sha256:") if digest.startswith("sha256:") else ""
            if not SHA256_PATTERN.fullmatch(sha256):
                raise ValueError("the GitHub release does not publish a valid SHA-256 package digest")
            return Update(latest, url, filename, sha256)
    return None


def download_update(update: Update, cache_dir: Path | None = None, timeout: float = 30.0) -> Path:
    match = PACKAGE_PATTERN.fullmatch(update.filename)
    expected_url = f"{DOWNLOAD_PREFIX}v{update.version}/{update.filename}"
    if (not match or match.group(1) != update.version or
            update.download_url != expected_url or
            not SHA256_PATTERN.fullmatch(update.sha256)):
        raise ValueError("update metadata is incomplete or untrusted")
    directory = cache_dir or Path.home() / ".cache" / "advanced-ip-analyser" / "updates"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / update.filename
    temporary = destination.with_suffix(".deb.part")
    request = urllib.request.Request(update.download_url, headers={"User-Agent": "Advanced-IP-Analyser updater"})
    digest = hashlib.sha256()
    total = 0
    try:
        # The URL was matched exactly against this project's fixed HTTPS release prefix above.
        with urllib.request.urlopen(request, timeout=timeout) as response, temporary.open("wb") as stream:  # nosec B310
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_PACKAGE_BYTES:
                raise ValueError("update package exceeds the 50 MiB safety limit")
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > MAX_PACKAGE_BYTES:
                    raise ValueError("update package exceeds the 50 MiB safety limit")
                stream.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != update.sha256:
            raise ValueError("downloaded update failed its SHA-256 integrity check")
        result = subprocess.run(["dpkg-deb", "--field", str(temporary), "Package", "Version"],
                                text=True, capture_output=True, timeout=10)
        fields = dict(line.split(":", 1) for line in result.stdout.splitlines() if ":" in line)
        if (result.returncode or fields.get("Package", "").strip() != "advanced-ip-analyser" or
                fields.get("Version", "").strip() != update.version):
            raise ValueError("download is not the expected Advanced IP Analyser package")
        os.replace(temporary, destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def launch_installer(package: Path, update: Update) -> None:
    """Start the detached privileged installer; the caller can then close the GUI."""
    subprocess.Popen([sys.executable, "-m", "ip_analyser.update_helper", str(package),
                      update.version, update.sha256, str(os.getpid())],
                     start_new_session=True, close_fds=True)
