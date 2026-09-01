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
sudo apt install python3 python3-tk iputils-ping iproute2 pkexec iw
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/advanced-ip-analyser-gui
```

The CLI works without Tk:

```sh
.venv/bin/advanced-ip-analyser scan 192.168.1.0/24 --output inventory.csv
.venv/bin/advanced-ip-analyser scan 192.168.1.10-192.168.1.30
.venv/bin/advanced-ip-analyser wake AA:BB:CC:DD:EE:FF
.venv/bin/advanced-ip-analyser capture 192.168.1.20 --interface enp1s0 --port 443
.venv/bin/advanced-ip-analyser open-capture capture.pcapng --host 192.168.1.20
.venv/bin/advanced-ip-analyser open-capture capture.pcap --filter 'dns && ip.addr == 192.168.1.20'
.venv/bin/advanced-ip-analyser watch --interface any --duration 900 --report watch.html
.venv/bin/advanced-ip-analyser analyse-capture capture.pcap --report analysis.json
```

## Debian package

Download `advanced-ip-analyser_2.0.0_all.deb` from the GitHub Release and install
it with:

```sh
sudo apt install ./advanced-ip-analyser_2.0.0_all.deb
```

Maintainers can reproduce the package locally with `./packaging/build-deb.sh`.

Version 0.5.1 introduced automatic updates. Older releases do not contain the
update checker, so install 0.5.1 or later manually once. Later releases are detected after
startup: click the flashing update button to download the verified package,
authorize Debian installation, close the current process, and reopen the updated
application automatically. Help also includes a manual **Check for updates** action.

Targets are limited to 65,536 addresses per invocation. The scanner checks a
small, explicit set of common service ports. Fingerprinting is bounded and
unauthenticated. Remote power is a separate, explicit, confirmed SSH-key action,
and the application never attempts exploitation.

## Current scope

- IPv4/IPv6 single addresses, CIDRs, and inclusive ranges
- Concurrent reachability and common-service checks
- Two-stage scanning: show every host and open port first, then discover server
  metadata with separate progress and a flashing please-wait indicator
- Reverse DNS and local neighbour-table MAC lookup
- Offline MAC manufacturer lookup from Debian's IEEE or Nmap OUI database
- Clickable HTTP and HTTPS links for selected hosts
- Ascending and descending sorting from every results-table heading
- Reachable-host-only table and exports; down addresses remain progress-only
- Live filtering across addresses, names, MACs, manufacturers, and services
- Expandable host rows showing every detected TCP port and its service detail
- Nested service fingerprints showing HTTP status, server software, page title,
  content type, redirects, authentication realm, TLS details, and safe protocol greetings when exposed
- Automatic GitHub release checks with a flashing update button, verified `.deb`
  download, Debian authorization, application restart, and a manual Help-window check
- Alternating white and light-blue inventory rows for easier scanning
- Clickable HTTP, HTTPS, FTP, SMB, SSH, and RDP service rows
- SSH username prompt before terminal launch, retaining the last username for the current session
- Double-click, Enter, and right-click service activation plus expand/collapse-all controls
- Keyboard shortcuts: F5 scan, Escape cancel, Ctrl+F filter, Ctrl+O import, Ctrl+S export, Ctrl+Shift+C copy detail
- Custom TCP port ranges, timeout, and concurrency controls
- Right-click TCP presets for common services, web/application ports, or all 65,535 TCP ports
- Current-interface IPv4 subnet shortcut
- Direct class-C-style `/24` subnet shortcut
- Cancellable scans with partial-result retention
- Persistent device favorites stored under the user's configuration directory
- Atomic saved-device updates with MAC-first identity and IP refresh
- Safe JSON and XML inventory import plus CSV, JSON, XML, and HTML export
- Active-interface subnet and broadcast discovery
- Non-interactive, confirmation-ready SSH shutdown and reboot operations
- Delayed remote shutdown/reboot with an abort-shutdown action
- Safe Ping, Tracepath, and Telnet launchers using fixed argument vectors
- Built-in packet capture and analysis: capture selected host or service traffic,
  list Linux interfaces, inspect saved PCAP/PCAPNG files, and filter IPv4/IPv6 traffic
- Wireshark-style display filters for addresses/CIDRs, ports, DNS, HTTP, TLS,
  ICMP, ARP, TCP flags and lengths, with comparisons, combinations, 20 presets,
  validity feedback, and persistent named filters
- Network Watch sessions up to 24 hours with timelines, conversations, device and
  DNS history, traffic baselines, TCP health diagnostics, explainable findings,
  optional desktop notifications, alert rules, bookmarks, retention, and reports
- Passive Wi-Fi Watch for compatible monitor-mode adapters, showing access points,
  channels, signal, advertised security, associated clients, probes, and observed
  EAPOL traffic without deauthentication, injection, or password attempts
- Copy-IP, selection-aware export, and confirmed Wake-on-LAN actions
- Double-click a host row to open HTTPS, with HTTP as fallback

Copyright © 2026 Daren Loxley (2E0LXY).

## Desktop workflow

1. Choose an active interface from the subnet list or enter an IP, range, or CIDR.
2. Select the TCP ports to inspect, then press **Scan**. Address and open-port
   results finish first; server-detail discovery then runs as a clearly labelled
   second phase without delaying the initial host list.
   Right-click the TCP-port field for common, web/application, and full-port presets.
   Full-port scans use bounded concurrency but should still be limited to a small
   number of authorized targets because filtered ports can take a long time.
3. Select discovered rows to copy addresses, save favorites, send Wake-on-LAN,
   open detected services, or export an inventory.
   Expand a host to inspect individual ports, then expand a port to inspect any
   server metadata it safely exposed. Open supported service rows with a
   double-click, Enter, the right-click menu, or the links below the table.
   Opening SSH asks for the remote username before the terminal asks for that
   account's password. The username is retained only for the current app session.
4. Use **Refresh favorites** to rescan saved addresses. Devices with a discovered
   MAC address retain their identity, notes, and updated IP address.
5. Use **Import** for inventories previously exported as JSON or XML. Imported
   devices are merged into both the visible inventory and favorites.

The **Shutdown**, **Reboot**, and **Abort shutdown** buttons require an explicit
confirmation and use non-interactive SSH. Configure key-based SSH access and
passwordless `sudo shutdown` permission on machines you administer. Shutdown and
reboot are scheduled one minute ahead so the abort action remains useful. The
application does not request, retain, or pass passwords.

Wake-on-LAN and remote administration should only be used on devices and networks
you own or are authorized to manage.

## Built-in packet analysis

Wireshark is not required. Use **Packets → Capture selected host/service** after
selecting a host or service row. Live capture is restricted to the selected IP
addresses and, for a single selected service, its TCP or UDP port. Captures are
bounded to 1–300 seconds and at most 100,000 packets. Debian may show a PolicyKit
administrator prompt because raw packet access requires elevated permission; the
desktop application itself remains unprivileged and should not be run as root.

**Open capture file for selection** reads Ethernet PCAP, PCAPNG, and gzip-compressed
captures in the built-in viewer. It displays endpoints, TCP/UDP ports, common IP
protocols, TCP flags, packet lengths, and a bounded byte preview. Its display-filter
bar understands the common investigation filters documented in
[`docs/DISPLAY_FILTERS.md`](docs/DISPLAY_FILTERS.md). Saved captures can also be
restricted to selected IPv4/IPv6 hosts and a service port. Payload decryption,
stream reassembly, and Wireshark's full dissector library remain outside this
focused analyser's scope.

## Network Watch and passive Wi-Fi

Use **Packets → Network Watch** to watch an authorized interface over time. Header
capture is the recommended privacy-preserving mode; protocol-detail and full-packet
modes are explicit choices. Results include traffic-over-time, conversations,
devices, DNS queries, protocol/service totals, TCP health estimates, findings,
custom alert rules, local history, reports, and recording bookmarks. See
[`docs/NETWORK_WATCH.md`](docs/NETWORK_WATCH.md).

Use **Packets → Passive Wi-Fi Watch** with a Linux adapter that supports monitor
mode. The application creates a temporary virtual monitor interface through its
narrow PolicyKit helper and observes radio headers without disturbing the adapter's
managed interface. This feature is deliberately passive: it does not disconnect
clients, inject frames, capture passwords, or crack keys. See
[`docs/PASSIVE_WIFI.md`](docs/PASSIVE_WIFI.md).

## Built-in help

Press **Help** beside the footer version number for illustrated guidance covering
target selection, scanning, expandable port rows, clickable services, favorites,
inventory import/export, Wake-on-LAN, SSH power actions, and every keyboard
shortcut. The Help centre is included in the Debian package and works offline.

## Independence and licensing

This project is a clean implementation based on general network-administration
requirements and public protocol behaviour. It is not affiliated with Angry IP
Scanner or Famatech Advanced IP Scanner, and those projects' code, branding,
documentation text, and assets are not included.

Copyright (C) 2026 2E0LXY. Licensed under GPL-3.0-or-later; see `LICENSE`.

Feature-by-feature Linux parity and documented platform limitations are tracked
in [`docs/FEATURE_PARITY.md`](docs/FEATURE_PARITY.md). Packet-analysis scope and
safety boundaries are documented in
[`docs/PACKET_ANALYSIS.md`](docs/PACKET_ANALYSIS.md).
Instructions for the signed Debian 13 APT feed are in
[`docs/APT_REPOSITORY.md`](docs/APT_REPOSITORY.md).
