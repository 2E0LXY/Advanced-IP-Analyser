# Advanced IP Analyser feature parity

Advanced IP Analyser provides Debian-native equivalents for the workflows in
the [Advanced IP Scanner help](https://www.advanced-ip-scanner.com/help/). It is
an independent GPL implementation and is not affiliated with Famatech.

| Reference workflow | Debian 13 implementation |
| --- | --- |
| IP, range, and subnet scanning | IPv4/IPv6 addresses, inclusive ranges, CIDRs, active-interface presets, and a direct `/24` shortcut |
| Favorites tab | Persistent Favorites tab with MAC-first identity, refreshed IP observations, editable notes, removal, import, and selected export |
| Save/load lists | CSV, JSON, XML, and escaped HTML export; bounded and validated JSON/XML import |
| Expandable resources | Host, TCP-port/service, and bounded fingerprint-detail rows |
| HTTP/HTTPS/FTP/SMB | Debian desktop handlers through fixed argument vectors |
| SSH/Telnet/RDP | OpenSSH/Telnet terminal launchers and FreeRDP 3 with validated arguments |
| Ping and route tracing | `ping` and `tracepath` in the Debian terminal emulator |
| Wake-on-LAN | Sends magic packets through the matching active-interface broadcast |
| Remote shutdown/reboot/abort | Explicitly confirmed, key-based, non-interactive SSH; shutdown/reboot are delayed one minute and cancellable |
| Performance controls | Fast, Balanced, and Accurate profiles plus explicit timeout, worker, and port controls |
| Automatic updates | Detects newer GitHub tags, flashes the Update button, requires the GitHub SHA-256 digest, validates package identity, requests PolicyKit authorization, and restarts |

## Linux-specific limitation

Radmin Viewer and Radmin Server are Windows products and have no native Debian
client. The Debian implementation exposes native SSH, RDP, SMB, HTTP(S), FTP,
and Telnet actions instead. Radmin under Wine may be added by an administrator as
an external desktop integration, but it is not bundled, downloaded, or granted
special privileges by this application.
