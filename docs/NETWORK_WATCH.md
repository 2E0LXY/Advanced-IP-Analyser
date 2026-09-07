# Network Security Monitor

The Network Security Monitor provides local, time-based analysis without Wireshark.
Open it from **Packets → Network Security Monitor**, select `any` for all available
interfaces or choose one interface, then choose a duration and capture detail.
It applies no port or direction filter: every inbound and outbound packet visible
to the selected Linux capture interface is considered. Confirm the authorized capture.

- **Headers only (recommended)** retains 128 bytes per packet, enough for most
  endpoint, service, DNS, and TCP-health observations while limiting payload data.
- **Protocol details** retains 512 bytes for DNS names, HTTP request lines, and TLS
  server-name hints where these are visible and unencrypted.
- **Full packets** is an explicit privacy-sensitive choice and retains complete
  packet payloads within the global 100,000-packet and 512 MiB analysis bounds.

The live tabs show minute traffic, bidirectional conversations, devices and peers,
DNS activity, protocols/services, findings, and previous sessions. TCP diagnostics
include resets, zero windows, handshake time, and conservative retransmission and
out-of-order estimates. Findings explain why they appeared; they do not claim to be
proof of compromise.

Colour-coded built-in findings cover port-scan patterns, public inbound connection
attempts, large outbound transfers, uncommon outbound ports, clear-text remote
protocols, long or high-variety DNS activity, new devices, fan-out, multiple DHCP
responders, ARP ownership changes, baseline deviations, TCP health, and regular
timing. Legitimate administration, software updates, CDNs, and security tools can
produce similar patterns, so every finding includes investigative context.

The Network Security Monitor can compare device traffic with the median of recent sessions,
identify saved-device baseline changes, bookmark recordings with notes, export
HTML/JSON/CSV reports, and send optional `notify-send` desktop alerts. User rules can
match a new device, traffic threshold, unanswered connection attempts, destination,
port, or DNS text.

Sessions are stored in
`~/.local/share/advanced-ip-analyser/network-watch.sqlite3`. Ordinary watch captures
are retained for seven days and capped at 250 MiB; oldest captures are removed first.
Bookmarked recordings are in a separate directory and are not removed by routine
retention. Database session history older than seven days is pruned.

This feature is a bounded visibility and alerting monitor, not an IDS/IPS. It does
not block connections, prove a breach, decrypt protected traffic, identify the
local process that owns a flow, or see packets that the selected interface and
network topology do not expose. Each session stops at 100,000 packets.

The CLI equivalents are:

```sh
advanced-ip-analyser watch --interface any --duration 900 --snaplen 128 --report watch.html
advanced-ip-analyser analyse-capture recording.pcap --report analysis.json
```

Only capture networks and traffic you own or are authorized to monitor.
