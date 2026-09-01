# Built-in packet analysis

Advanced IP Analyser includes a small Debian-native packet engine. Wireshark,
tcpdump, tshark, libpcap, and third-party Python packet libraries are not required.

## Live capture

Live capture uses Linux `AF_PACKET` raw sockets. The application always limits a
capture to explicitly selected IP addresses, an optional selected service port,
1–300 seconds, and at most 100,000 packets. It writes standard Ethernet PCAP.

The desktop and CLI try the capture as the current user first. If Debian denies
raw-socket access, an installed, root-owned, non-writable helper is started through
PolicyKit. The helper accepts only fixed validated options and verifies that its
output is a single-link regular file owned by the requesting user before writing.
The main application is never relaunched as root.

## Saved captures

The reader accepts classic PCAP and PCAPNG using Ethernet link type 1, including
gzip-compressed files. Analysis is bounded to 512 MiB expanded data, 100,000
packets, and 262,144 bytes per packet record. Selected-host and port filters are
applied in-process.

The viewer summarizes Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, DNS, ICMP,
ICMPv6, GRE, ESP, AH, and OSPF metadata. It shows only the first 512 bytes of a
packet in the byte preview. A bounded parser provides IP/CIDR, port, DNS, HTTP,
TLS, TCP flag, frame-length, comparison, text, regular-expression, and boolean
display filters. See [DISPLAY_FILTERS.md](DISPLAY_FILTERS.md).

Network Watch extends the same engine to captures up to 24 hours with local
session history, timelines, flows, DNS activity, device baselines, TCP diagnostics,
findings, alerts, and reports. Passive Wi-Fi Watch separately handles radiotap PCAP
from a temporary monitor-mode interface. Neither feature requires Wireshark.

## Deliberate limits

This is a focused network-inventory companion, not a replacement for every
Wireshark feature. It does not decrypt encrypted traffic, reconstruct streams,
decode hundreds of application protocols, reconstruct application objects, decrypt
TLS, or edit/inject packets. Captures can be saved and inspected with another tool if deeper
forensics are required.

Capture only traffic you own or are authorized to inspect.
