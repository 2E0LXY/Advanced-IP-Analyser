# Advanced IP Scanner replica for Debian 13

## Product goal

Build a Debian-native network discovery and remote-access desktop application on
top of Angry IP Scanner. The goal is feature parity with the documented Advanced
IP Scanner workflow, not a pixel-for-pixel copy or use of Famatech branding.

The application remains a local desktop utility. It does not require a server,
cloud account, privileged daemon, or database for basic scanning.

## How the inherited application works

### Startup and composition

`Main` initializes labels and Java Preferences, constructs a small custom
dependency-injection container, registers the core and SWT GUI components, loads
external plugins, processes command-line options, and opens the main event loop.

The source is approximately 12,000 lines of Java split across 162 source files,
with 74 test files. It targets Java 21 and Eclipse SWT, uses JNA only for native
network integration, Gradle for builds, and ProGuard plus platform packaging for
releases.

### Scan pipeline

The runtime pipeline is:

1. A **feeder** produces `ScanningSubject` instances. Built-ins cover a range,
   smart textual ranges/CIDR, random addresses, text files, and rescanning.
2. `ScannerDispatcherThread` owns a bounded fixed thread pool. It submits one
   address task at a time, throttles task creation, skips likely broadcast
   addresses when configured, and emits progress no more than every 150 ms.
3. `Scanner` executes the selected **fetchers** in their configured order for
   each address. Fetchers share cached intermediate values through the subject.
4. The ping fetcher classifies the host and can stop further work on a dead host.
   Its timing result also adapts later port timeouts.
5. Results are stored in `ScanningResultList` and displayed through an SWT
   virtual table, so very large result sets do not require one fully materialized
   widget per row.
6. **Exporters** write TXT, CSV, XML, IP:port, or SQL. **Openers** substitute
   values such as `${fetcher.ip}` and launch URLs or external programs.

The scanner is a mediator between independent extension points. Feeder, fetcher,
pinger, and exporter plugins are loaded from JAR manifests, making new resource
probes a natural addition rather than a rewrite of the dispatcher.

### Existing discovery capability

- IPv4 and IPv6 address generation, ranges, CIDR-like smart input, random input,
  file input, and rescanning.
- ICMP/Java, TCP, UDP, combined unprivileged, ARP, and Windows-specific pingers.
- Ping time, packet loss, TTL, reverse DNS hostname, MAC, MAC vendor, NetBIOS
  information, comments, open ports, filtered ports, HTTP detection/proxy checks,
  and last-alive time.
- User-selected columns/fetchers, sorting, result details, copy/delete/rescan,
  scan-range favorites, configurable openers, and five export formats.
- Configurable concurrency, launch delay, ping count/timeouts, port timeouts,
  timeout adaptation, port lists, dead-host behavior, and broadcast skipping.

### Architectural constraints and risks

- `Scanner` runs fetchers sequentially within each host but hosts concurrently.
  This is simple and predictable; resource enumeration that performs many slow
  probes should use a single efficient fetcher rather than one fetcher per port.
- The dispatcher uses a fixed platform thread pool. It is adequate for typical
  LAN ranges, but future high-concurrency work should measure virtual threads or
  asynchronous I/O rather than assuming either is faster.
- Persistent configuration uses `java.util.prefs`. It is suitable for settings
  and small favorites lists, but not for durable device inventory or scan history.
- Current “favorites” save scan definitions, whereas Advanced IP Scanner saves
  selected computers. A separate device-favorites model is required.
- MAC discovery is local-L2 only. Wake-on-LAN therefore depends on a prior local
  scan or a saved device record containing a MAC address.
- Advanced IP Scanner is Windows-centric. Radmin and Windows remote shutdown do
  not have direct Debian equivalents, so compatibility must be explicit rather
  than silently claiming parity.

## Feature comparison and Debian mapping

| Advanced IP Scanner workflow | Existing foundation | Debian 13 implementation |
| --- | --- | --- |
| Scan entered IP range | Complete | Reuse range/smart feeders |
| Detect IP, hostname, MAC | Complete | Reuse fetchers; prefer ARP/neighbour data on LAN |
| Current subnet and class-C shortcuts | Complete | Interface-aware subnet preset and `/24` shortcut |
| Computer favorites tab | Complete | Persistent records keyed by MAC, with IP fallback |
| Save selected as XML/HTML/CSV | Complete | Selection-aware XML, CSV, and HTML export |
| Load favorites XML | Complete | Versioned import with hardened XML parsing |
| Ping and trace route | Complete | Existing configurable openers (`ping`, `tracepath`) |
| SSH, Telnet, HTTP, HTTPS, FTP | Mostly complete | Linux openers; HTTPS added in milestone 1 |
| Browse computer/resources | Complete | Open `smb://host/` through the desktop/GIO |
| RDP | Complete | Launch FreeRDP (`xfreerdp3`) |
| Radmin | No native Linux client | Optional Wine/custom-command adapter, clearly marked |
| Wake-on-LAN | Missing | Native UDP magic packet; added in milestone 1 |
| Remote shutdown/reboot/abort | Complete | Confirmed, key/agent-based non-interactive SSH actions |
| Accuracy and scan-rate controls | Complete | Fast, Balanced, and Accurate presets over detailed settings |
| Resource selection | Complete | Named service fetcher backed by conservative TCP probes |
| Alternating row colors | Complete | Applied to scan and saved-device tables |
| Portable/custom clients | Complete | Argument-safe profiles with dependency availability checks |

## Completed delivery roadmap

### Milestone 1 — Debian remote-access baseline (complete)

- Native Wake-on-LAN action for one or many selected devices.
- Default HTTPS, RDP, and SMB openers alongside existing HTTP, FTP, SSH, ping,
  trace route, and Whois actions.
- Debian 13 build and runtime documentation.
- Preserve all upstream scanner behavior and plugin compatibility.

### Milestone 2 — device-centric experience (complete)

- Add Scan Results and Favorites tabs.
- Create immutable saved-device records with display name, IP, MAC, comment,
  last-seen time, and discovered services.
- Add/remove selected computers, refresh favorites, and resolve changed IPs by
  MAC after each LAN scan.
- Add XML import plus XML/CSV/HTML export for selected or full tabs.

### Milestone 3 — resource discovery and actions (complete)

- Introduce a resource/service fetcher that identifies SSH, HTTP(S), FTP, SMB,
  and RDP with conservative connection probes.
- Show services as child rows or a details panel and make double-click launch the
  relevant client.
- Add current-interface subnet selection and a `/24` toolbar shortcut.
- Add action availability rules so unsupported actions are disabled instead of
  failing after launch.

### Milestone 4 — managed remote power (complete)

- Add SSH-based shutdown/reboot with a preview, explicit confirmation, per-host
  outcome reporting, and cancellation of scheduled shutdown where supported.
- Use SSH agents/keys and system credential facilities; never persist plaintext
  passwords in Java Preferences.
- Keep Radmin as an optional custom adapter and document its Linux limitations.

### Milestone 5 — product polish and packaging (complete)

- Restructure the SWT shell into a compact toolbar, range controls, tabbed device
  table, status/progress region, and configurable columns/actions.
- Add alternating rows, keyboard navigation, accessible labels, high-DPI icons,
  empty/error states, and a first-run dependency check.
- Produce a Debian package with a desktop file, icon, AppStream metadata, bundled
  runtime, license/source offer, and smoke tests on a clean Debian 13 VM.

## Debian 13 dependencies

Required to build: OpenJDK 21. The SWT library is resolved by Gradle and packaged
by the existing Linux target.

Recommended runtime integrations: `iputils-ping`, `iproute2`, `traceroute` or
`tracepath`, `openssh-client`, `freerdp3-x11`, and a desktop handler/GVfs backend
for HTTP(S), FTP, and SMB URLs. Missing optional clients should produce a concise
install hint, not a scanner failure.

## Safety and scope

Network discovery and remote actions must be used only on networks and computers
the operator is authorized to manage. Destructive actions are deliberately kept
out of the first milestone. When implemented, shutdown/reboot will require an
explicit confirmation and will report each target independently.

Because the base project is GPLv2, distributed derivative binaries must retain
the license notices and provide corresponding source under GPLv2. Product names,
logos, screenshots, and wording from Advanced IP Scanner should not be copied;
feature behavior can be implemented with an original Debian-oriented interface.
