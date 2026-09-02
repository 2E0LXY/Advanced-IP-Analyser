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
| Packet capture and analysis | Built-in Linux interface discovery, bounded selected-host/service capture, PCAP/PCAPNG reading, Wireshark-style display filters, protocol summaries, and byte previews; no Wireshark dependency |
| Monitoring over time | Network Watch timelines, conversations, devices, DNS, TCP health estimates, baselines, findings, alert rules, reports, bookmarks, retention, and local history |
| Passive wireless discovery | Compatible monitor-mode adapters can observe access points, security advertisements, clients, probe requests, signal, and EAPOL presence; disruptive and password-attack functions are deliberately excluded |

## Lansweeper free IP scanner comparison

The [Lansweeper free IP scanner page](https://www.lansweeper.com/resources/free-tools/ip-scanner/)
describes credential-free IP/range discovery, detailed device information,
custom scope/frequency controls, open-port discovery, and a lightweight app.

| Reference capability | Advanced IP Analyser 2.1 implementation |
| --- | --- |
| Credential-free agentless discovery | Native IPv4/IPv6 reachability, DNS, TCP, neighbour MAC, and offline manufacturer discovery |
| Whole IP ranges and drill-down | Single addresses, inclusive ranges, CIDRs up to 65,536 addresses, expandable hosts, ports, and metadata |
| IP, MAC, manufacturer | Included in the inventory and all structured exports |
| Device type, OS/version, model | Conservative confidence-labelled inference from manufacturer, services, HTTP metadata, and banners; no credentials or agents |
| Custom ranges and scan types | Target, exclusions, arbitrary TCP ports/ranges, service presets, all-port confirmation, Fast/Balanced/Accurate profiles |
| Scan frequency | Optional in-app repeat every 5, 15, 30, or 60 minutes; runs only while the desktop app remains open |
| Open ports and risk visibility | TCP-port inventory plus service detail and selected-host Web Security Audit |
| Lightweight Linux installation | One Debian `all` package with no Wireshark requirement; narrow PolicyKit helpers are used only for capture/monitor mode |

Lansweeper's separate paid platform advertises credentialed hardware/software
inventory, NIST vulnerability correlation, lifecycle intelligence, topology,
enterprise dashboards, report libraries, and managed integrations. Those are
not features of its free IP-scanner executable and are not claimed as parity.

## Acunetix/Invicti comparison and safety boundary

The [Acunetix documentation](https://www.acunetix.com/support/) covers a large
commercial web/API vulnerability-management platform, not an IP-scanner feature
list. Advanced IP Analyser implements the following defensive subset natively:

| Reference workflow | Advanced IP Analyser 2.1 implementation |
| --- | --- |
| Target configuration | HTTP/HTTPS URL, maximum pages/depth, timeout, excluded path prefixes, additional allowed hosts, custom headers |
| Website discovery/crawling | Same-host bounded link crawler with status/title/content/form/technology inventory |
| Scan scope | Explicit authorization, same-host default, approved extra hosts only, 100-page/5-depth/20-MiB hard ceilings |
| Transport/TLS review | Cleartext HTTP observation plus certificate validation, TLS protocol, cipher, and certificate SHA-256 fingerprint |
| Configuration checks | Security headers, framing, CORS, cookies, disclosure, mixed content, directory listing, and password-form transport/method checks |
| Review results | Prioritized High/Medium/Low/Info table with evidence and remediation guidance |
| Reports/API-friendly output | Escaped standalone HTML and structured JSON reports; CLI automation through `web-audit` |

Advanced IP Analyser deliberately does **not** claim complete Acunetix/Invicti
parity. It does not perform active SQL injection/XSS/SSRF/XXE/command-injection
payload testing, credential brute force, forced browsing, malware execution,
file upload, form submission, destructive verification, out-of-band callbacks,
browser automation, AcuSensor-style server instrumentation, multi-user issue
management, WAF rule generation, or cloud/CI issue-tracker orchestration. Those
features require a dedicated vulnerability-scanning product, continuous rule
research, legal controls, and a substantially different threat model.

## Linux-specific limitation

Radmin Viewer and Radmin Server are Windows products and have no native Debian
client. The Debian implementation exposes native SSH, RDP, SMB, HTTP(S), FTP,
and Telnet actions instead. Radmin under Wine may be added by an administrator as
an external desktop integration, but it is not bundled, downloaded, or granted
special privileges by this application.
