# Advanced IP Analyser

![Advanced IP Analyser icon](src/ip_analyser/assets/advanced-ip-analyser.png)

Advanced IP Analyser is an original, Debian 13-only desktop and command-line
network inventory, bounded web security auditing, packet analysis, long-term monitoring, and passive Wi-Fi
observation application. It is designed for home labs, support teams, system
administrators, and authorized network troubleshooting without requiring
Wireshark.

> Use Advanced IP Analyser only on networks, systems, and radio traffic you own
> or are explicitly authorized to inspect.

[Download the latest release](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/latest)
· [Read the instruction book](output/pdf/Advanced-IP-Analyser-Instruction-Book.pdf)
· [Report a problem](https://github.com/2E0LXY/Advanced-IP-Analyser/issues)

## Application overview

![Scanner overview](docs/images/scanner-overview.png)

The main window combines target selection, scan profiles, TCP-port controls,
live progress, expandable service results, favorites, inventory exchange, remote
actions, packet tools, and verified updates in one interface.

## Feature map

| Area | Features |
| --- | --- |
| Network discovery | IPv4/IPv6 addresses, CIDRs, inclusive ranges, exclusions, recurring scans, active-interface presets, `/24` shortcut, reachability, latency, DNS names, local MAC addresses, offline vendor lookup |
| Asset profiles | Conservative device type, operating system/version, model, and confidence inferred from manufacturer, services, HTTP metadata, and protocol banners without credentials or agents |
| TCP services | Custom ports/ranges, common and web presets, optional all-65,535-port scan, expandable port rows, safe HTTP/TLS/banner metadata, cancellable two-stage discovery |
| Results workflow | Live filtering and sorting, alternating rows, clickable services, copy IP/detail, selection-aware export, keyboard and context-menu actions |
| Favorites | Persistent saved devices, MAC-first identity, refreshed IP observations, editable notes, rescan, removal, import, selected export |
| Inventory | CSV/JSON/XML/escaped-HTML export, bounded JSON/XML import, spreadsheet-formula protection, atomic favorites updates |
| Device access | HTTP, HTTPS, FTP, SMB, SSH, RDP and Telnet launchers; Ping, Tracepath, Wake-on-LAN; confirmed delayed SSH shutdown/reboot and abort |
| Packet engine | Native Linux `AF_PACKET` capture, selected-host/service scope, interface discovery, Ethernet PCAP/PCAPNG/gzip reading, endpoint/port/protocol summaries, byte preview |
| Display filters | IP/CIDR, TCP/UDP ports, DNS, HTTP, TLS, ICMP, ARP, TCP flags, lengths, comparisons, text/regex matching, boolean expressions, 20 quick filters, saved named filters |
| Network Watch | Up to 24-hour sessions, minute timeline, conversations, devices, DNS, protocols/services, TCP diagnostics, baselines, findings, alerts, bookmarks, reports, retention, history |
| Passive Wi-Fi | Monitor-mode virtual interface, AP/client discovery, SSID/BSSID, channel, signal, security advertisement, beacons/data, probes, passive EAPOL observation, PCAP/JSON save |
| Web Security Audit | Same-host bounded crawler, path exclusions, extra allowed hosts, custom headers, page/form/technology inventory, TLS fingerprint, security-header, cookie, cleartext, mixed-content, directory-listing, CORS, and password-form observations, HTML/JSON reports |
| Updates | Automatic GitHub release check, flashing button, trusted release URL, SHA-256 verification, Debian package identity check, close/install/restart workflow |
| Debian packaging | Reproducible `.deb`, Lintian/AppStream/desktop validation, install/GUI/remove smoke test, release checksum, optional signed GitHub Pages APT feed |

## Debian 13 installation

Download the newest `advanced-ip-analyser_VERSION_all.deb` from the
[Releases page](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/latest),
then run:

```sh
cd ~/Downloads
sudo apt install ./advanced-ip-analyser_2.1.1_all.deb
```

Launch it from the desktop application menu or run:

```sh
advanced-ip-analyser-gui
```

The package installs Python, Tk, hardened XML parsing, ping, IP-route tools,
desktop integration, and PolicyKit dependencies. `iw` is recommended for Passive
Wi-Fi Watch. Optional service launchers use Debian packages such as OpenSSH,
FreeRDP, GVfs, Tracepath, and Telnet when installed.

### Run from source

```sh
sudo apt update
sudo apt install python3 python3-venv python3-tk python3-defusedxml \
  iputils-ping iproute2 pkexec iw xdg-utils
git clone https://github.com/2E0LXY/Advanced-IP-Analyser.git
cd Advanced-IP-Analyser
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e .
.venv/bin/advanced-ip-analyser-gui
```

Raw packet capture and temporary Wi-Fi monitor interfaces require elevated Linux
capabilities. The desktop remains unprivileged and asks PolicyKit to run only the
installed, root-owned, narrowly validated helper when necessary. Do not launch
the complete GUI with `sudo`.

## Scanning and service discovery

1. Select an interface subnet, enter one address/range/CIDR, or use the `/24`
   shortcut.
2. Optionally enter excluded addresses/ranges/CIDRs and choose an in-app repeat
   interval for scheduled inventory refreshes.
3. Choose Fast, Balanced, or Accurate, or set timeout/workers manually.
4. Enter TCP ports and ranges. Right-click the field for common, web/application,
   all-port, or clear presets.
5. Press **Scan**. Reachable hosts and ports appear first; bounded service-detail
   discovery follows as a separate phase.
6. Expand a host to inspect ports, asset type, inferred OS/model, and available metadata.

Detected details can include HTTP status, Server and Powered-By headers, page
title, content type, redirects, authentication realm, TLS protocol/cipher, and
safe protocol greetings. Discovery is unauthenticated and does not exploit or
log in to a service.

Supported targets are single IPv4/IPv6 addresses, CIDRs, and inclusive ranges.
Each invocation is limited to 65,536 addresses. Full TCP-port scans should be
restricted to a small number of authorized targets.

## Favorites, inventories, and device actions

- **Add favorite** stores selected devices under
  `~/.config/advanced-ip-analyser/favorites.json`.
- MAC-first identity retains the device note when DHCP changes an address.
- **Refresh favorites** rescans saved addresses.
- **Export** writes selected visible rows, or all visible rows when none are
  selected, to CSV, JSON, XML, or escaped HTML.
- **Import** accepts bounded Advanced IP Analyser JSON and XML inventories.
- Double-click or press Enter on supported services to open them with Debian's
  native application handlers.
- Wake-on-LAN uses the matching active-interface broadcast where possible.
- Shutdown/reboot/abort require confirmation and non-interactive SSH keys;
passwords are never requested or stored.

## Native Web Security Audit

![Web Security Audit](docs/images/web-security-audit.png)

Select a discovered HTTP/HTTPS host and press **Web audit**, or open the tool and
enter an authorized URL. The audit requires an explicit authorization checkbox.
It uses read-only `GET` requests, remains on the initial/allowed hosts, follows at
most five link levels, reads at most 100 pages and 20 MiB total, and supports path
exclusions, custom request headers, and additional allowed hostnames.
Credential-bearing headers (`Authorization`, `Cookie`, and `Proxy-Authorization`)
are confined to the original scheme, hostname, and port and are stripped from
cross-origin links and redirects.

The results include crawled pages, titles, links, forms, disclosed technologies,
TLS certificate validation, protocol/cipher/certificate fingerprint, errors, and prioritized observations
for transport, headers, cookies, framing, CORS, mixed content, directory indexes,
and password forms. Reports export as escaped HTML or structured JSON.

This is a defensive configuration and exposure review. It does not send SQL
injection/XSS payloads, brute-force credentials, exploit vulnerabilities, upload
files, change server data, bypass authentication, or claim Acunetix/Invicti
commercial scanner parity. See the [feature comparison](docs/FEATURE_PARITY.md).

## Built-in packet analysis

![Packet display filters](docs/images/packet-display-filters.png)

Wireshark, tshark, tcpdump, libpcap, and third-party packet Python libraries are
not required. **Packets → Capture selected host/service** records only the selected
IP scope and optional selected port for 1-300 seconds and no more than 100,000
packets. **Open capture file for selection** reads bounded Ethernet PCAP, PCAPNG,
and gzip-compressed captures.

The viewer shows packet number/time, endpoints, TCP/UDP ports, protocol, original
length, summary, and the first 512 captured bytes. Supported summaries include
VLAN, IPv4/IPv6 extension headers and fragments, ARP, TCP, UDP, DNS/mDNS, DHCP,
SSDP, NTP, NBNS, ICMP/ICMPv6, GRE, ESP, AH and OSPF.

### Display-filter language

```text
ip.addr == 192.168.1.10
ip.addr == 192.168.1.0/24 && (http || dns)
tcp.port == 443
tcp.flags.syn == 1 && tcp.flags.ack == 0
dns.flags.response == 0
dns.qry.name contains "example.com"
http.request.method == "GET"
http.host contains "example.com"
http.request.uri contains "/login"
http.response.code == 404
tls.handshake.type == 1
frame.len > 1000
```

Operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `matches`, `&&`,
`||`, `!`, and parentheses. Filters alter displayed rows only, never the capture.
The expression and regex parsers are bounded and do not call `eval`.

See [the complete filter reference](docs/DISPLAY_FILTERS.md).

## Network Watch

![Network Watch dashboard](docs/images/network-watch-dashboard.png)

Open **Packets → Network Watch** for continuous analysis. Choose an interface,
duration, and capture detail:

- **Headers only (recommended):** retain 128 bytes per packet.
- **Protocol details:** retain 512 bytes per packet.
- **Full packets:** retain complete payloads within the global safety bounds.

Network Watch provides:

- per-minute packet and byte timeline;
- bidirectional flows, duration, packets, bytes, and TCP health;
- device traffic, peers, external peers, ports, protocols, and DNS names;
- DNS query/response history and failure codes;
- protocol and service totals;
- handshake timing, resets, zero windows, and conservative retransmission and
  out-of-order estimates;
- new-device, fan-out, traffic-baseline, DNS-failure, regular-timing, reset,
  retransmission and unanswered-SYN findings;
- user rules for new devices, traffic, unanswered connections, destination,
  port, and DNS text;
- optional desktop notifications, reports, bookmarks, seven-day/250 MiB ordinary
  capture retention, and SQLite history.

Findings are explainable indicators for investigation, not declarations that a
system is compromised. Encrypted payloads remain encrypted.

See [Network Watch documentation](docs/NETWORK_WATCH.md).

## Passive Wi-Fi Watch

![Passive Wi-Fi Watch](docs/images/passive-wifi-watch.png)

Open **Packets → Passive Wi-Fi Watch** with a compatible Linux wireless adapter.
The helper creates a temporary virtual monitor interface and validates every
adapter, monitor name, channel, and duration argument. The managed interface is
left in place where the driver supports concurrent interfaces.

Passive Wi-Fi Watch can display SSID, BSSID, channel, driver-provided signal,
Open/WEP/WPA/WPA2/WPA3 advertisement, beacon/data counts, client MAC addresses,
probe-request names, and passive EAPOL presence. Captures can be retained as
radiotap PCAP and observations exported as JSON.

It intentionally does **not** deauthenticate clients, inject frames, create rogue
access points, capture credentials, crack passwords/keys, or perform denial of
service. Signal and security labels depend on adapter metadata and advertised
information elements.

See [Passive Wi-Fi Watch documentation](docs/PASSIVE_WIFI.md).

## Automatic verified updates

After startup the application checks the latest GitHub release. If a newer tag
contains the expected Debian package and GitHub SHA-256 digest, a button flashes
in the footer. After confirmation the app:

1. downloads from the exact project release URL with a 50 MiB limit;
2. verifies SHA-256 and Debian package name/version;
3. starts the detached updater and closes the current process;
4. requests PolicyKit authorization for `apt-get install`; and
5. reopens the installed application.

Use **Help → Check for updates** for a manual check.

## Command-line interface

```sh
# Scan and export
advanced-ip-analyser scan 192.168.1.0/24 --output inventory.csv
advanced-ip-analyser scan 192.168.1.10-192.168.1.30

# Wake-on-LAN
advanced-ip-analyser wake AA:BB:CC:DD:EE:FF

# Interfaces and selected-host capture
advanced-ip-analyser capture-interfaces
advanced-ip-analyser capture 192.168.1.20 --interface enp1s0 --port 443 \
  --duration 10 --output host.pcap

# Read and display-filter a recording
advanced-ip-analyser open-capture host.pcap \
  --filter 'ip.addr == 192.168.1.20 && tcp.port == 443'

# Watch and analyze over time
advanced-ip-analyser watch --interface any --duration 900 --snaplen 128 \
  --report watch.html
advanced-ip-analyser analyse-capture host.pcap --report analysis.json

# Bounded read-only website audit
advanced-ip-analyser web-audit https://server.example \
  --max-pages 25 --max-depth 2 --exclude /logout --report web-audit.html
```

Run `advanced-ip-analyser COMMAND --help` for every option.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `F5` | Start scan |
| `Escape` | Cancel active scan |
| `Ctrl+F` | Focus results filter |
| `Ctrl+O` | Import inventory |
| `Ctrl+S` | Export inventory |
| `Ctrl+Shift+C` | Copy selected host/service detail |
| `Enter` | Open selected supported service |
| Double-click | Open service or preferred web endpoint |
| Right-click | Service action, copy, expand/collapse, or port preset |

## Files and privacy

| Path | Purpose |
| --- | --- |
| `~/.config/advanced-ip-analyser/favorites.json` | Saved devices and notes |
| `~/.config/advanced-ip-analyser/packet-filters.json` | Named display filters |
| `~/.config/advanced-ip-analyser/alert-rules.json` | Network Watch rules |
| `~/.local/share/advanced-ip-analyser/network-watch.sqlite3` | Session history and baselines |
| `~/.local/share/advanced-ip-analyser/captures/` | Ordinary Network Watch recordings |
| `~/.local/share/advanced-ip-analyser/bookmarks/` | Bookmarked recordings and notes |
| `~/.local/share/advanced-ip-analyser/wifi-captures/` | Passive Wi-Fi recordings |

The application has no analytics or telemetry service. Network inventories,
captures, rules, favorites, and reports stay on the computer unless the user
explicitly exports or copies them. The update checker contacts this project's
GitHub Releases API.

## Troubleshooting

- **No hosts:** verify the target/subnet and try Accurate; firewalls may block
  ping while TCP ports remain reachable.
- **Packet authorization unavailable:** install the `.deb`; source-tree helpers
  are deliberately refused for privileged execution.
- **No wireless adapters:** confirm `/sys/class/net/INTERFACE/wireless`, install
  `iw`, and use an adapter/driver supporting virtual monitor interfaces.
- **A Wi-Fi channel fails:** remove unsupported channels from the channel list.
- **SSH action fails:** configure key authentication and required remote `sudo`
  permission; interactive passwords are intentionally unsupported.
- **Service will not open:** install its Debian client/desktop handler.
- **Update fails:** download the package from Releases and use `sudo apt install
  ./PACKAGE.deb`; verification failures should never be bypassed.

## Build, test, and release

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
sh packaging/build-deb.sh
```

Tag CI runs the complete suite in Debian 13, builds the `.deb`, runs Lintian,
validates desktop/AppStream metadata, installs and launches the GUI under Xvfb,
removes the package, generates `SHA256SUMS`, publishes release assets, and
deploys the public signed APT feed described in
[APT_REPOSITORY.md](docs/APT_REPOSITORY.md).

The separate official-Debian candidate uses a non-native `3.0 (quilt)` source
package and Debian unstable CI. It builds source and binary artifacts, runs
Lintian and autopkgtest, and disables the upstream self-updater so archive
packages remain managed by APT. See the [official Debian inclusion
guide](docs/DEBIAN_INCLUSION.md) for the ITP and sponsorship stages.

## Documentation

- [Complete instruction book (PDF)](output/pdf/Advanced-IP-Analyser-Instruction-Book.pdf)
- [Instruction book source](docs/USER_GUIDE.md)
- [Display filters](docs/DISPLAY_FILTERS.md)
- [Network Watch](docs/NETWORK_WATCH.md)
- [Passive Wi-Fi Watch](docs/PASSIVE_WIFI.md)
- [Packet engine and safety boundaries](docs/PACKET_ANALYSIS.md)
- [Feature parity](docs/FEATURE_PARITY.md)
- [APT repository publishing](docs/APT_REPOSITORY.md)
- [Official Debian inclusion and sponsorship](docs/DEBIAN_INCLUSION.md)

## Independence, license, and scope

This is a clean, independent GPL-3.0-or-later implementation. It contains no
Angry IP Scanner or Famatech Advanced IP Scanner source, history, branding, or
assets and is not affiliated with those projects. Radmin is Windows-only and is
not bundled; Debian-native SSH, RDP, SMB, HTTP(S), FTP and Telnet workflows are
provided instead.

Copyright © 2026 Daren Loxley (2E0LXY).
