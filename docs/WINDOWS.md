# Windows 10/11 edition

Download `Advanced-IP-Analyser-Setup-VERSION.exe` from the project's GitHub
release and run it. The x64 installer is per-user, installs beneath Local AppData,
and does not require a separate Python installation. It creates a Start-menu
shortcut and offers an optional desktop shortcut.

## Available on Windows

- IPv4 and IPv6 target, range, and CIDR scanning;
- Windows interface/subnet presets through `Get-NetIPAddress`;
- TCP service discovery, safe banners, device profiles, inventory, and favourites;
- Wake-on-LAN, web audit, reports, imports, and exports;
- Windows Ping, Traceroute, SMB, OpenSSH, and Remote Desktop launchers;
- OpenAI, Gemini, and OpenRouter model discovery and consent-gated analysis;
- API keys stored through Windows Credential Manager;
- bounded PCAP, PCAPNG, and compressed capture-file analysis and display filters;
- platform-specific verified update download, silent replacement, and relaunch.

## Deliberately Debian-only

Live packet capture, Network Security Monitor live capture, and passive
monitor-mode Wi-Fi use Linux kernel `AF_PACKET`, PolicyKit, `iw`, and related
interfaces. Their menu entries are visibly disabled on Windows. The application
does not bundle Npcap, WinPcap, Wireshark, a kernel driver, or any software with a
separate capture-driver licence. Existing capture files can still be opened and
analysed on Windows.

## Release integrity

Each build publishes `SHA256SUMS-WINDOWS.txt`. GitHub Actions also creates a build
provenance attestation for branch and tagged builds. A commercial Authenticode
certificate is not included in the repository; until the maintainer configures
one, Windows may show a Microsoft Defender SmartScreen reputation warning. Verify
the checksum and GitHub provenance before installing.

Only scan systems and networks that you own or are explicitly authorized to test.
