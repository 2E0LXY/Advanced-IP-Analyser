# Advanced IP Analyser

Advanced IP Analyser is an independently implemented Debian network inventory
application. It discovers reachable hosts, resolves names and local neighbour
MAC addresses, identifies common TCP services, exports inventories, and sends
Wake-on-LAN packets. It contains no Angry IP Scanner source code, history, or
assets.

Use it only on networks and computers you own or are authorized to administer.

## Run from source

Debian 13 needs Python 3 and Tk for the desktop interface:

```sh
sudo apt install python3 python3-tk iputils-ping iproute2
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/advanced-ip-analyser-gui
```

The CLI works without Tk:

```sh
.venv/bin/advanced-ip-analyser scan 192.168.1.0/24 --output inventory.csv
.venv/bin/advanced-ip-analyser scan 192.168.1.10-192.168.1.30
.venv/bin/advanced-ip-analyser wake AA:BB:CC:DD:EE:FF
```

## Debian package

Download `advanced-ip-analyser_0.3.0_all.deb` from the GitHub Release and install
it with:

```sh
sudo apt install ./advanced-ip-analyser_0.3.0_all.deb
```

Maintainers can reproduce the package locally with `./packaging/build-deb.sh`.

Targets are limited to 65,536 addresses per invocation. The scanner checks a
small, explicit set of common service ports and does not attempt authentication,
exploitation, or remote power operations.

## Current scope

- IPv4/IPv6 single addresses, CIDRs, and inclusive ranges
- Concurrent reachability and common-service checks
- Reverse DNS and local neighbour-table MAC lookup
- Offline MAC manufacturer lookup from Debian's IEEE or Nmap OUI database
- Clickable HTTP and HTTPS links for selected hosts
- Ascending and descending sorting from every results-table heading
- Reachable-host-only table and exports; down addresses remain progress-only
- Live filtering across addresses, names, MACs, manufacturers, and services
- Custom TCP port ranges, timeout, and concurrency controls
- Current-interface IPv4 subnet shortcut
- Cancellable scans with partial-result retention
- Persistent device favorites stored under the user's configuration directory
- Atomic saved-device updates with MAC-first identity and IP refresh
- Safe JSON and XML inventory import plus CSV, JSON, XML, and HTML export
- Active-interface subnet and broadcast discovery
- Non-interactive, confirmation-ready SSH shutdown and reboot operations
- Copy-IP, selection-aware export, and confirmed Wake-on-LAN actions
- Double-click a host row to open HTTPS, with HTTP as fallback

Copyright © 2026 Daren Loxley (2E0LXY).

The device refresh, inventory import, and remote-power APIs added in v0.3.0 are
currently foundations for the next desktop-interface update. Remote power always
uses non-interactive SSH and never stores passwords.

## Independence and licensing

This project is a clean implementation based on general network-administration
requirements and public protocol behaviour. It is not affiliated with Angry IP
Scanner or Famatech Advanced IP Scanner, and those projects' code, branding,
documentation text, and assets are not included.

Copyright (C) 2026 2E0LXY. Licensed under GPL-3.0-or-later; see `LICENSE`.
