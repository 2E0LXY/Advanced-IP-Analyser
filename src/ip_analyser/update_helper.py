from __future__ import annotations

import shutil
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    package = Path(sys.argv[1]).resolve()
    if not package.is_file() or package.suffix != ".deb":
        return 2
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
