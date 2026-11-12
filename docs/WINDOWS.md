# Windows 10/11 edition

Download `Advanced-IP-Analyser-Setup-VERSION.exe` from the project's GitHub
release and run it. The x64 installer is per-user, installs beneath Local AppData,
and does not require a separate Python installation. It creates a Start-menu
shortcut and offers an optional desktop shortcut.

During upgrades and removal, the installer stops every running GUI, background
monitor, and ChatGPT Desktop MCP process before replacing application files.
This also covers processes that remain active after the visible window closes.

## Available on Windows

- simultaneous IPv4 target and bounded local IPv6-neighbour scanning, plus explicit
  IPv4/IPv6 address, range, and CIDR targets;
- Windows interface/subnet presets through `Get-NetIPAddress`;
- TCP service discovery, safe banners, device profiles, inventory, and favourites;
- Wake-on-LAN, web audit, reports, imports, and exports;
- Windows Ping, Traceroute, SMB, OpenSSH, and Remote Desktop launchers;
- native Wi-Fi adapter and nearby-network scanning with signal and security details;
- saved Wi-Fi profile inventory and confirmation-gated reveal of one locally stored key;
- OpenAI, Gemini, and OpenRouter model discovery and consent-gated analysis;
- API keys stored through Windows Credential Manager;
- live inbound, outbound and listening connection inventory with process/PID,
  filtering, export and a movable/zoomable public-destination map;
- local Network Intelligence with duplicate-device resolution, explainable
  exposure scoring, zone classification, structured queries and GraphML/JSON export;
- a read-only Security Posture tab for Windows firewall profiles, registered
  antivirus, Defender real-time status, SMB 1.0, UAC, network category and DNS,
  with explicit unknown states and local report export;
- real UDP DNS resolver benchmarking with adjustable rounds, delay and timeout,
  average/jitter/reply ranking, partial stop, a copyable report and a post-test
  shortcut to the active adapter type's Windows DNS settings page;
- local CPU, memory, storage and network monitoring with bounded JSON history;
- bounded read-only disk-usage analysis with largest-file/folder views, a
  proportional size map, cancellation and CSV export;
- bounded PCAP, PCAPNG, and compressed capture-file analysis and display filters;
- live selected-host/service capture through built-in Microsoft Packet Monitor,
  with installed Npcap plus Wireshark/dumpcap or TShark as an optional fallback;
- a Network Operations workspace with inventory change detection, neighbour-cache
  conflict review, SNMPv2c/SNMPv3, LLDP/CDP evidence, local service discovery,
  top talkers, capture-provider status, TCP quality, iPerf3, CISA KEV review and
  persistent scan/report/webhook policy;
- platform-specific verified update download, silent replacement, and relaunch.

## Contextual Help Centre

Every main workspace has a `? Help` button at the top. It opens the Help Centre
directly at the guide for the current tab. The header **Help** button opens the
complete reference, where **Find help** searches guide titles, summaries and full
article text. Select any topic in the left navigation to read it, or use **Copy
this guide** to place the displayed instructions on the clipboard.

Each guide explains the feature's purpose, the local or remote data it uses, how
to operate every major control, why and when the tool is useful, how to interpret
its results, and the important accuracy, permission, privacy and safety limits.
The guides cover Dashboard, Network Scan, Smart Home, System, Disk Usage, DNS
Benchmark, Connections, Intelligence, Network Operations, Security Posture, Diagnostics, Favorites,
Wi-Fi Analyzer, Packet Analysis, Web Security, Local AI, and settings/updates.
Help is available without an internet connection.

## Deliberately Debian-only

Network Security Monitor long sessions and passive monitor-mode Wi-Fi use Linux
kernel `AF_PACKET`, PolicyKit, `iw`, and related interfaces. Their menu entries
remain disabled on Windows. Selected-host/service live capture uses Windows'
built-in Microsoft Packet Monitor (`pktmon`) and immediately rewrites its bounded
temporary result to contain only the selected host/port records. Some Windows
configurations require running the capture with administrator rights. Installed
Npcap with Wireshark/dumpcap or TShark is an optional per-interface fallback. The
application does not bundle a kernel driver or separately licensed capture
software. Existing capture files can always be opened and analysed on Windows.

## Wi-Fi Analyzer

Open the top-level **Wi-Fi Analyzer** tab. The complete analyzer appears in the
main application; it does not open a second window.
Nearby-network scanning and adapter status are
read-only and use the Windows WLAN service. Signal history retains and horizontally
scrolls through up to two hours of measured dBm samples at a selected 1–5 second
interval. Channel graph shows access points by 2.4, 5, or 6 GHz channel and uses
advertised HT/VHT bandwidth; missing bandwidth is labelled rather than inferred.
CSV exports contain SSID, BSSID, frequency, channel, bandwidth, signal,
security, cautious configuration review, connection, saved-profile, and adapter
fields; they exclude passwords. Open and legacy security advertisements are
highlighted for verification.

The Saved profiles tab masks every key by default. Revealing a selected profile
requires confirmation and asks Windows for that one locally stored key. Revealed
values remain in application memory until hidden or the window closes. A copied
key is cleared after 30 seconds when the clipboard still contains the same value.
Windows can deny clear-text retrieval unless the signed-in account has the
required permission.

## Live Connections and destination map

Open **Connections** and select **Start monitoring**. The
table refreshes every two seconds and shows the owning application, PID,
protocol, local and remote endpoint, direction, state and approximate public
destination.

The map uses OpenStreetMap tiles and displays only public remote endpoints:

- blue markers are outbound and orange markers are inbound;
- a numbered marker clusters destinations that overlap at the current zoom;
- click a marker or cluster for all available application, executable, PID,
  direction, protocol, endpoint, state, organisation and location details;
- drag with the left mouse button to move the map;
- use the mouse wheel or the `+` and `−` buttons to zoom;
- select **Fit destinations** to return every current marker to view; and
- filtering the table also filters the visible markers.

Select the `?` beside the map title for the same instructions inside the app,
including how the feature works and why it exists. Public destination IPs are
sent to `ipwho.is` for approximate coordinates, and visible map tiles are
requested from OpenStreetMap. Process names, PIDs, private/local addresses and
the complete connection table are not sent to either service. Locations often
represent a provider or data centre and are not proof of a person, device or
malicious activity.

## Release integrity

Each build publishes `SHA256SUMS-WINDOWS.txt`. GitHub Actions also creates a build
provenance attestation for branch and tagged builds. A commercial Authenticode
certificate is not included in the repository; until the maintainer configures
one, Windows may show a Microsoft Defender SmartScreen reputation warning. Verify
the checksum and GitHub provenance before installing.

Only scan systems and networks that you own or are explicitly authorized to test.
