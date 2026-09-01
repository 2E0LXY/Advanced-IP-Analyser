# Packet display filters

Display filters select rows already present in a recording. They never alter what
is captured or delete packets. Press **Apply** or Enter in the packet viewer; a
green field means the expression is valid and a red field explains an error.

## Common filters

| Purpose | Filter |
| --- | --- |
| Traffic to or from an address | `ip.addr == 192.168.1.10` |
| Traffic inside a subnet | `ip.addr == 192.168.1.0/24` |
| One source or destination | `ip.src == 192.168.1.10`, `ip.dst == 8.8.8.8` |
| Any TCP or UDP port | `tcp.port == 443`, `udp.port == 53` |
| Directional port | `tcp.srcport == 443`, `tcp.dstport == 22` |
| DNS packets, queries, responses | `dns`, `dns.flags.response == 0`, `dns.flags.response == 1` |
| DNS name text | `dns.qry.name contains "example.com"` |
| HTTP packets | `http`, `http.request`, `http.response` |
| HTTP details | `http.request.method == "GET"`, `http.host contains "example.com"` |
| HTTP path or status | `http.request.uri contains "/login"`, `http.response.code == 404` |
| TLS Client Hello | `tls.handshake.type == 1` or `ssl.handshake.type == 1` |
| Connection attempts | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| TCP termination/reset | `tcp.flags.fin == 1`, `tcp.flags.rst == 1` |
| TCP data or frame size | `tcp.len > 0`, `frame.len > 1000` |
| Other protocols | `icmp`, `icmpv6`, `arp`, `mdns`, `ssdp`, `dhcp`, `ntp`, `nbns` |

Comparisons are `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, and `matches`.
Combine conditions with `&&` (AND), `||` (OR), `!` (NOT), and parentheses:

```text
ip.addr == 192.168.1.10 && (http || dns)
http.request && !(ip.addr == 192.168.1.0/24)
tcp.port == 80 || tcp.port == 443
```

`matches` supports bounded, case-insensitive regular expressions. Advanced
lookaround, backreferences, and counted repetitions are rejected so an imported or
pasted filter cannot consume unbounded analysis time.

The **Quick filters** menu contains 20 common presets. **Save filter** stores a
validated named filter in `~/.config/advanced-ip-analyser/packet-filters.json`.
Saved filters can be applied or removed from the same menu.

The CLI accepts the same language:

```sh
advanced-ip-analyser open-capture recording.pcap \
  --filter 'ip.addr == 192.168.1.10 && (http || dns)'
```
