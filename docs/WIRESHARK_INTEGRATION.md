# Wireshark integration

Advanced IP Analyser delegates packet capture and protocol analysis to Debian's
Wireshark package. This keeps Wireshark's maintained dissectors, capture engine,
file-format support, display filters, statistics, stream following, expert
information, and export tools available without duplicating them.

## Integrated workflows

- Discover capture interfaces using Wireshark's `-D` interface listing.
- Start live capture immediately with `-i`, a generated libpcap `-f` capture
  filter, and `-k`.
- Generate host filters for up to 64 selected IPv4 and IPv6 addresses.
- Limit a single selected service row to its detected TCP port.
- Open an existing Wireshark-supported capture using `-r`.
- Apply a generated IPv4/IPv6 host and optional TCP-port display filter using
  `-Y` when a saved capture is opened from a selection.
- Offer the same core operations through the Debian desktop and CLI.

Capture filters and display filters have different syntax. The application
constructs each from validated IP addresses and ports and passes every value as
a distinct subprocess argument. It does not invoke a shell or accept arbitrary
Wireshark command-line options.

## Deliberate boundaries

Advanced IP Analyser does not embed Wireshark, copy its source, parse packet
payloads, change capture permissions, enable monitor mode, decrypt traffic, or
capture in the background. Once Wireshark opens, its own interface provides
packet details, statistics, conversations, endpoints, protocol hierarchy,
expert information, stream following, filtering, saving, merging, and export.

Debian administrators remain responsible for configuring dumpcap permissions.
Neither Advanced IP Analyser nor its package runs Wireshark as root or grants
packet-capture capabilities.

See the official [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html/)
and [wireshark(1) manual](https://www.wireshark.org/docs/man-pages/wireshark.html).
