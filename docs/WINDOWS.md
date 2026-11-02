# Windows 10/11 edition

Download `Advanced-IP-Analyser-Setup-VERSION.exe` from the project's GitHub
release and run it. The x64 installer is per-user, installs beneath Local AppData,
and does not require a separate Python installation. It creates a Start-menu
shortcut and offers an optional desktop shortcut.

During upgrades and removal, the installer stops every running GUI, background
monitor, and ChatGPT Desktop MCP process before replacing application files.
This also covers processes that remain active after the visible window closes.

## Available on Windows

- IPv4 and IPv6 target, range, and CIDR scanning;
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
- real UDP DNS resolver benchmarking with adjustable rounds, delay and timeout,
  average/jitter/reply ranking, partial stop and a copyable report;
- bounded PCAP, PCAPNG, and compressed capture-file analysis and display filters;
- platform-specific verified update download, silent replacement, and relaunch.

## Deliberately Debian-only

Live packet capture, Network Security Monitor live capture, and passive
monitor-mode Wi-Fi use Linux kernel `AF_PACKET`, PolicyKit, `iw`, and related
interfaces. Their menu entries are visibly disabled on Windows. The application
does not bundle Npcap, WinPcap, Wireshark, a kernel driver, or any software with a
separate capture-driver licence. Existing capture files can still be opened and
analysed on Windows.

## Wi-Fi Analyzer

Open **Wi-Fi** in the sidebar. Nearby-network scanning and adapter status are
read-only and use the Windows WLAN service. CSV exports contain SSID, signal,
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

Open **Diagnostics → Live Connections** and select **Start monitoring**. The
table refreshes every two seconds and shows the owning application, PID,
protocol, local and remote endpoint, direction, state and approximate public
destination.

The map uses OpenStreetMap tiles and displays only public remote endpoints:

- blue markers are outbound and orange markers are inbound;
- a numbered marker clusters destinations that overlap at the current zoom;
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
