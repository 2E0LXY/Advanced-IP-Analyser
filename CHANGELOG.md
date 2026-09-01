# Changelog

## 2.0.0 - 2026-09-01

- Add Network Watch for bounded captures up to 24 hours with minute timelines,
  bidirectional conversations, device and DNS activity, protocol/service totals,
  TCP handshake timing, resets, retransmission/out-of-order estimates, baselines,
  findings, desktop alerts, custom alert rules, bookmarks, reports, and history.
- Add passive Airgorah-inspired Wi-Fi observation for compatible monitor-mode
  adapters: access points, channels, signal, security, clients, probe requests,
  and passive EAPOL presence. No deauthentication, injection, or password cracking.
- Add a safe Wireshark-style display-filter language for IPs and CIDRs, TCP/UDP
  ports, DNS, HTTP, TLS, ICMP, ARP, TCP flags, payload/frame length, comparisons,
  text matching, boolean combinations, 20 quick presets, and saved named filters.
- Centre the green scan progress bar in the main-window footer.
- Add CLI watch, deep capture analysis, display filtering, signed APT repository
  generation, and expanded regression and packaging checks.

## 1.2.0 - 2026-08-29

- Replace the optional Wireshark integration with a native Debian packet engine.
- Add bounded selected-host/service live capture through Linux raw sockets and a
  narrow PolicyKit-authorized helper while keeping the desktop process unprivileged.
- Add an in-app PCAP/PCAPNG viewer with IPv4/IPv6, ARP, TCP, UDP, DNS, ICMP,
  common IP protocol summaries, filtering, capture export, and byte previews.
- Add PCAP, PCAPNG, and gzip input bounds, secure output ownership checks, CLI
  capture controls, and packet-parser regression coverage.

## 1.1.0 - 2026-08-24

- Add optional Wireshark live capture for selected IPv4/IPv6 hosts and service ports.
- Add saved-capture opening with generated host and TCP-port display filters.
- Add Wireshark capture-interface discovery in both the desktop and CLI interfaces.
- Keep packet operations behind explicit user actions, bounded selections, validated
  inputs, fixed subprocess arguments, and Debian-managed capture permissions.

## 1.0.0 - 2026-08-21

- Completed the Debian 13 desktop workflow with Scan results and Favorites tabs,
  editable notes, MAC-first identity, current-interface and `/24` shortcuts.
- Hardened JSON/XML import validation and spreadsheet exports against untrusted
  network values and formula execution.
- Blocked SSH option injection and added safe Ping, Tracepath, Telnet, delayed
  shutdown/reboot, and abort-shutdown actions.
- Required GitHub's SHA-256 release digest, revalidated the package before the
  PolicyKit handoff, and retained automatic close/install/reopen behavior.
- Added original project artwork, Debian copyright/changelog/manual/AppStream
  metadata, and tag-driven Debian 13 test, package, smoke, checksum, and release CI.

## 0.5.2 - 2026-08-21

- Split scanning into a fast host/port phase followed by server-detail discovery.
- Populate the complete reachable-host table before HTTP, TLS, and banner probes begin.
- Add a flashing blue Please wait discovery indicator with completed/total progress.
- Keep the populated table usable during discovery and retain partial details when cancelled.
- Prompt for the remote SSH username before opening a terminal, pre-filled with
  the local or most recently used session username.
- Pass SSH destinations safely as `username@address`, including custom SSH ports.

## 0.5.1 - 2026-08-21

- Check the latest GitHub Release automatically after startup.
- Show a flashing update button only when a newer Debian package is available.
- Download the release with a size bound and published SHA-256 verification.
- Validate the downloaded Debian package name and version before installation.
- Close the running application, request administrator authorization through
  Debian PolicyKit, install the package, and reopen the application automatically.
- Add a manual Check for updates action to the Help window.

## 0.5.0 - 2026-08-21

- Add bounded, unauthenticated fingerprinting for already-open HTTP, HTTPS, SSH,
  FTP, SMTP, POP3, and IMAP services.
- Discover HTTP status, server software, powered-by header, content type, page
  title, redirects, authentication realm, TLS protocol/cipher, and safe greetings
  when the remote service exposes them.
- Add a third expandable table level beneath ports for named service metadata.
- Include detected server details in filtering, favorites, JSON/XML inventory,
  and CSV exports.
- Extend the built-in Help centre with fingerprinting behavior and safety limits.

## 0.4.0 - 2026-08-20

- Add a blue desktop colour system with clear action and danger states.
- Alternate inventory rows between white and light blue for readability.
- Make every host expandable, with a child row for each detected TCP port and service.
- Persist port numbers in JSON/XML models and include them in CSV/XML interchange.
- Make supported service rows clickable by mouse, keyboard, context menu, and links below the table.
- Add copy-detail and expand/collapse-all table actions.
- Add scan, cancel, filter, import, export, and copy keyboard shortcuts.
- Add an illustrated in-app help centre covering every major workflow.
- Display the synchronized application version in the main-window footer.
- Expand the normal scan preset with common mail, database, admin, alternate-web, printer, and storage ports.
- Add right-click common, web/application, and all-65,535-TCP-port scan presets with workload confirmation.
- Use bounded port concurrency for full-port scans and preserve non-default ports in service launch URLs.

## 0.3.1 - 2026-08-20

- Integrate active-interface subnet presets into the desktop scanner.
- Add desktop JSON/XML inventory import and XML export controls.
- Automatically merge successful scans into existing favorites by stable device identity.
- Add a dedicated favorites refresh workflow.
- Add confirmed, asynchronous SSH shutdown and reboot controls with per-host failures.
- Document the complete desktop workflow and remote-access prerequisites.

## 0.3.0 - 2026-08-20

- Preserve saved-device notes while refreshing IP addresses and observations by MAC identity.
- Add bounded JSON and XML inventory import and XML inventory export.
- Write the favourites database atomically to protect it from interrupted saves.
- Discover every active IPv4 subnet and its Wake-on-LAN broadcast address.
- Add non-interactive SSH shutdown and reboot operations without credential storage.
- Expand regression coverage for device merging, XML interchange, network discovery, and SSH argument safety.

## 0.2.1 - 2026-08-18

- Fix desktop web launch actions and add copyright details.
