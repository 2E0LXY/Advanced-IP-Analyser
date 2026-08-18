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

Targets are limited to 65,536 addresses per invocation. The scanner checks a
small, explicit set of common service ports and does not attempt authentication,
exploitation, or remote power operations.

## Current scope

- IPv4/IPv6 single addresses, CIDRs, and inclusive ranges
- Concurrent reachability and common-service checks
- Reverse DNS and local neighbour-table MAC lookup
- CSV, JSON, and escaped HTML export
- Versioned local favorites storage API
- Wake-on-LAN
- Original Tk desktop interface plus a scriptable CLI

Planned work includes a favorites tab, interface-aware subnet presets, richer
service detail, Debian packaging, and accessibility/polish passes.

## Independence and licensing

This project is a clean implementation based on general network-administration
requirements and public protocol behaviour. It is not affiliated with Angry IP
Scanner or Famatech Advanced IP Scanner, and those projects' code, branding,
documentation text, and assets are not included.

Copyright (C) 2026 2E0LXY. Licensed under GPL-3.0-or-later; see `LICENSE`.
