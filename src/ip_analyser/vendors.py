from __future__ import annotations

import csv
import io
import os
import re
import threading
import urllib.request
from pathlib import Path

VENDOR_CACHE = Path.home() / ".config" / "advanced-ip-analyser" / "oui.csv"
MAM_CACHE = VENDOR_CACHE.with_name("mam.csv")
OUI36_CACHE = VENDOR_CACHE.with_name("oui36.csv")
DEFAULT_DATABASES = (
    OUI36_CACHE,
    MAM_CACHE,
    VENDOR_CACHE,
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark" / "manuf",
)


class MacVendorLookup:
    """Cached IEEE OUI lookup, with local system databases as fallbacks."""

    def __init__(self, databases: tuple[Path, ...] = DEFAULT_DATABASES):
        self.databases = databases
        self._use_public_registry = databases == DEFAULT_DATABASES
        self._vendors: dict[str, str] | None = None
        self._load_lock = threading.Lock()

    def lookup(self, mac: str) -> str:
        value = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(value) < 6:
            return ""
        self.preload()
        assert self._vendors is not None
        for length in (9, 7, 6):
            if value[:length] in self._vendors:
                return self._vendors[value[:length]]
        return "Private / randomized MAC" if int(value[:2], 16) & 2 else "Unknown"

    def preload(self) -> None:
        """Load local registry data, fetching missing public data only once."""
        if self._vendors is None:
            with self._load_lock:
                if self._vendors is None:
                    self._vendors = self._load()

    def _load(self) -> dict[str, str]:
        vendors: dict[str, str] = {}
        for path in self.databases:
            try:
                content = path.read_text(encoding="utf-8-sig", errors="replace")
                if path.suffix.lower() == ".csv":
                    for row in csv.DictReader(io.StringIO(content)):
                        prefix = re.sub(r"[^0-9A-Fa-f]", "", row.get("Assignment", "")).upper()
                        name = row.get("Organization Name", "").strip()
                        if len(prefix) in {6, 7, 9} and name:
                            vendors.setdefault(prefix, name)
                    continue
                for line in content.splitlines():
                    ieee = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    nmap = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                    if ieee:
                        vendors.setdefault("".join(ieee.group(1, 2, 3)).upper(), ieee.group(4).strip())
                    elif nmap:
                        vendors.setdefault(nmap.group(1).upper(), nmap.group(2).strip())
            except OSError:
                continue
        if self._use_public_registry:
            for path, url in ((VENDOR_CACHE, "https://standards-oui.ieee.org/oui/oui.csv"),
                              (MAM_CACHE, "https://standards-oui.ieee.org/oui28/mam.csv"),
                              (OUI36_CACHE, "https://standards-oui.ieee.org/oui36/oui36.csv")):
                if path.exists():
                    continue
                self._download_registry(path, url, vendors)
        return vendors

    @staticmethod
    def _download_registry(path: Path, url: str, vendors: dict[str, str]) -> None:
        """Download only public registry data; MAC addresses are never sent."""
        try:
            request = urllib.request.Request(url,
                                             headers={"User-Agent": "Advanced-IP-Analyser/2"})
            with urllib.request.urlopen(request, timeout=8) as response:
                content = response.read(10_000_001)
            if len(content) > 10_000_000:
                raise ValueError("IEEE OUI file exceeds expected size")
            rows = csv.DictReader(io.StringIO(content.decode("utf-8-sig", "replace")))
            found = 0
            for row in rows:
                prefix = re.sub(r"[^0-9A-Fa-f]", "", row.get("Assignment", "")).upper()
                name = row.get("Organization Name", "").strip()
                if len(prefix) in {6, 7, 9} and name:
                    vendors.setdefault(prefix, name)
                    found += 1
            if found < 100:
                raise ValueError("IEEE OUI file did not contain expected assignments")
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.write_bytes(content)
            temporary.replace(path)
        except (OSError, ValueError, UnicodeError):
            pass
