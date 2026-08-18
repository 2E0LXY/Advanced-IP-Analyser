from __future__ import annotations

import re
import threading
from pathlib import Path


DEFAULT_DATABASES = (
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/usr/share/nmap/nmap-mac-prefixes"),
)


class MacVendorLookup:
    """Offline OUI lookup using standard Debian data files."""

    def __init__(self, databases: tuple[Path, ...] = DEFAULT_DATABASES):
        self.databases = databases
        self._vendors: dict[str, str] | None = None
        self._load_lock = threading.Lock()

    def lookup(self, mac: str) -> str:
        prefix = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6]
        if len(prefix) != 6:
            return ""
        if self._vendors is None:
            with self._load_lock:
                if self._vendors is None:
                    self._vendors = self._load()
        return self._vendors.get(prefix, "Unknown")

    def _load(self) -> dict[str, str]:
        vendors: dict[str, str] = {}
        for path in self.databases:
            try:
                for line in path.read_text(errors="replace").splitlines():
                    ieee = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    nmap = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                    if ieee:
                        vendors.setdefault("".join(ieee.group(1, 2, 3)).upper(), ieee.group(4).strip())
                    elif nmap:
                        vendors.setdefault(nmap.group(1).upper(), nmap.group(2).strip())
            except OSError:
                continue
        return vendors
