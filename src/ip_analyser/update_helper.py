from __future__ import annotations

import shutil
import subprocess
import sys
import time
import hashlib
import os
import re
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    package = Path(sys.argv[1]).resolve()
    version, expected_digest, parent_value = sys.argv[2:]
    if (not package.is_file() or package.suffix != ".deb" or
            not re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*", version) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or
            not parent_value.isdigit() or int(parent_value) < 1):
        return 2
    if package.stat().st_size > 50 * 1024 * 1024:
        return 2
    checksum = hashlib.sha256()
    with package.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            checksum.update(chunk)
    digest = checksum.hexdigest()
    fields = subprocess.run(["dpkg-deb", "--field", str(package), "Package", "Version"],
                            text=True, capture_output=True, timeout=10)
    metadata = dict(line.split(":", 1) for line in fields.stdout.splitlines() if ":" in line)
    if (digest != expected_digest or fields.returncode or
            metadata.get("Package", "").strip() != "advanced-ip-analyser" or
            metadata.get("Version", "").strip() != version):
        return 2
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
        launcher = shutil.which("advanced-ip-analyser-gui") or "/usr/bin/advanced-ip-analyser-gui"
        subprocess.Popen([launcher], start_new_session=True, close_fds=True)
        return 3
    result = subprocess.run([pkexec, "apt-get", "install", "-y", str(package)])
    time.sleep(0.5)
    launcher = shutil.which("advanced-ip-analyser-gui") or "/usr/bin/advanced-ip-analyser-gui"
    subprocess.Popen([launcher], start_new_session=True, close_fds=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
