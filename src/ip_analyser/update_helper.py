from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


MAX_PACKAGE_BYTES = 50 * 1024 * 1024
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_NAME = "advanced-ip-analyser"


def _open_package(package: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(package, flags)
    metadata = os.fstat(descriptor)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1 or
            metadata.st_size > MAX_PACKAGE_BYTES):
        os.close(descriptor)
        raise ValueError("update package is not a bounded regular file")
    return descriptor


def _copy_and_hash(package: Path, destination: Path | None = None) -> str:
    source = _open_package(package)
    target = None
    checksum = hashlib.sha256()
    try:
        if destination is not None:
            target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(source, "rb") as stream, \
                (os.fdopen(target, "wb") if target is not None else open(os.devnull, "wb")) as output:
            source = -1
            target = None
            while chunk := stream.read(64 * 1024):
                checksum.update(chunk)
                if destination is not None:
                    output.write(chunk)
            if destination is not None:
                output.flush()
                os.fsync(output.fileno())
        return checksum.hexdigest()
    finally:
        if source >= 0:
            os.close(source)
        if target is not None:
            os.close(target)


def _package_metadata(package: Path) -> dict[str, str]:
    result = subprocess.run(
        ["/usr/bin/dpkg-deb", "--field", str(package), "Package", "Version"],
        text=True, capture_output=True, timeout=10, check=False)
    if result.returncode:
        raise ValueError("update is not a readable Debian package")
    return dict(line.split(":", 1) for line in result.stdout.splitlines() if ":" in line)


def _verify_package(package: Path, version: str, expected_digest: str) -> None:
    if not VERSION_PATTERN.fullmatch(version) or not SHA256_PATTERN.fullmatch(expected_digest):
        raise ValueError("update metadata is invalid")
    digest = _copy_and_hash(package)
    metadata = _package_metadata(package)
    if (not hmac.compare_digest(digest, expected_digest) or
            metadata.get("Package", "").strip() != PACKAGE_NAME or
            metadata.get("Version", "").strip() != version):
        raise ValueError("update package failed its identity or integrity check")


def _install_as_root(package: Path, version: str, expected_digest: str,
                     staging_parent: Path | None = None) -> int:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError("update installation requires administrator authorization")
    if not VERSION_PATTERN.fullmatch(version) or not SHA256_PATTERN.fullmatch(expected_digest):
        raise ValueError("update metadata is invalid")
    parent = staging_parent or Path("/var/tmp")
    with tempfile.TemporaryDirectory(prefix="advanced-ip-analyser-update-", dir=parent) as directory:
        staged = Path(directory) / f"advanced-ip-analyser_{version}_all.deb"
        digest = _copy_and_hash(package, staged)
        metadata = _package_metadata(staged)
        if (not hmac.compare_digest(digest, expected_digest) or
                metadata.get("Package", "").strip() != PACKAGE_NAME or
                metadata.get("Version", "").strip() != version):
            raise ValueError("update package failed its identity or integrity check")
        result = subprocess.run(
            ["/usr/bin/apt-get", "install", "-y", str(staged)], check=False)
        return result.returncode


def _trusted_helper_path() -> Path:
    helper = Path(__file__).resolve()
    if os.name == "posix":
        metadata = helper.stat()
        if (metadata.st_uid != 0 or not stat.S_ISREG(metadata.st_mode) or
                metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise PermissionError("the installed update helper failed its ownership check")
    return helper


def _relaunch() -> None:
    launcher = shutil.which("advanced-ip-analyser-gui") or "/usr/bin/advanced-ip-analyser-gui"
    subprocess.Popen([launcher], start_new_session=True, close_fds=True)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if arguments[:1] == ["--install"]:
            if len(arguments) != 4:
                return 2
            return _install_as_root(Path(arguments[1]).resolve(), arguments[2], arguments[3])
        if len(arguments) != 4:
            return 2
        package = Path(arguments[0]).resolve()
        version, expected_digest, parent_value = arguments[1:]
        if not parent_value.isdigit() or int(parent_value) < 1:
            return 2
        _verify_package(package, version, expected_digest)

        parent_pid = int(parent_value)
        for _attempt in range(150):
            try:
                os.kill(parent_pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                pass
            time.sleep(0.1)
        else:
            return 4

        pkexec = shutil.which("pkexec")
        if not pkexec:
            _relaunch()
            return 3
        helper = _trusted_helper_path()
        result = subprocess.run(
            [pkexec, "/usr/bin/python3", "-I", str(helper), "--install", str(package),
             version, expected_digest], check=False)
        time.sleep(0.5)
        _relaunch()
        return result.returncode
    except (OSError, subprocess.SubprocessError, ValueError):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
