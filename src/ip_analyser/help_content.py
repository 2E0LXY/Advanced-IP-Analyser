from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HelpSection:
    key: str
    title: str
    summary: str
    body: str


def _section(key: str, title: str, summary: str, body: str) -> HelpSection:
    return HelpSection(key, title, summary, body.strip())


HELP_SECTIONS = (
    _section("dashboard", "Dashboard", "Understand the live overview, totals, traffic and activity evidence.", """
WHAT IT DOES
The Dashboard is the read-only starting point for the current session. It summarises discovered hosts, online devices, open ports, distinct services, the selected network range, recent tool activity, favourite hosts and local system information. The traffic charts show this computer's interface throughput; they are not a packet capture and do not represent the whole LAN.

HOW IT WORKS
Host, port and service cards are calculated from the latest completed or running scan. Coverage compares responsive and identified devices with the bounded target list. Recent activity records actions performed in this application. Network throughput is sampled from operating-system counters and converted to rates between samples. System information comes from local interface and route data.

WHY AND WHEN TO USE IT
Use the Dashboard to answer: Has a scan run? How many devices responded? Is the inventory well identified? Are new tools still active? Is this computer currently transferring substantial traffic? It is useful for orientation and trend awareness before opening a specialist workspace.

HOW TO INTERPRET IT
Online means the scanner received a valid response or found strong local-neighbour evidence; it does not guarantee every service is healthy. Open ports are reachable TCP listeners, not automatically vulnerabilities. Active Services counts distinct service labels. Coverage is evidence completeness, not a security score. A traffic spike means more bytes crossed the selected local interface, not necessarily malicious activity.

LIMITS AND PRIVACY
The page does not modify the network, capture payloads or upload telemetry. Values can change when adapters, VPNs or routes change. Run Network Scan for fresh inventory and use Connections or Packet Analysis when you need process or packet-level evidence.
"""),
    _section("network_scan", "Network Scan", "Discover IPv4 and IPv6 devices, ports, identities and service details.", """
WHAT IT DOES
Network Scan inventories authorised targets. It finds responsive IPv4 and IPv6 hosts, tests selected TCP ports, measures a bounded connection/ping response, resolves names and neighbour MAC addresses, performs offline manufacturer lookup, and safely enriches detected services. Results can be filtered, expanded, exported, favourited or used by diagnostics and device actions.

HOW IT WORKS
Target accepts one address, an inclusive range, a CIDR, or multiple scopes separated by commas, semicolons or new lines. Interface presets provide active IPv4 subnets; /24 derives a local class-C-style range. Include local IPv6 uses bounded multicast/NDP discovery because a normal /64 cannot be brute-force enumerated. IPv4 and discovered IPv6 targets share one worker pool, progress bar, Stop action and discovery phase. Duplicates are removed and one invocation is limited to 65,536 addresses.

CONTROLS
TCP ports accepts comma-separated ports and ranges; right-click it for presets. Timeout controls connection patience. Workers controls bounded host concurrency. Fast favours speed, Accurate waits longer, Balanced is the normal choice, and Adaptive reduces pressure when probes fail. Exclude removes exact addresses, ranges or CIDRs. Repeat schedules the same scan while the app remains open. Filter changes visible rows only. Scan starts; Cancel stops pending work safely. Export uses selected rows when present, otherwise visible results. Topology PNG saves the current discovered-host layout as a lossless image suitable for reports and sharing.

RESULTS AND MEANING
State Up means valid reachability evidence. Connect/ping is a short probe measurement, not end-to-end application performance. A blank completed hostname means no trustworthy unique name was resolved; Tailscale MagicDNS tailnet suffixes are hidden in the table for readability while the resolved name remains stored. Manufacturer is inferred from a locally cached MAC prefix and may be absent or refer to the network-interface supplier. Device type and operating system are cautious fingerprints, not guarantees. Model evidence is retained in inventory/export data when available rather than occupying a mostly empty scan column. Expand Ports to see services and safely collected metadata. An open port is exposure, not proof of weakness.

WHY USE IT
Use it for asset inventory, troubleshooting missing devices, locating management services, documenting address changes and establishing a baseline before security review. Scan only networks you own or are explicitly authorised to administer.

FAILURES AND LIMITS
Firewalls, sleeping devices, client isolation, randomized MAC addresses, VPN routes and rate limiting can hide devices. IPv6 discovery only covers usable local interfaces and learned neighbours. If IPv6 is unavailable, a combined scan continues with IPv4. Service discovery does not authenticate, exploit or bypass encryption.
"""),
    _section("smart_home", "Smart Home", "Discover and control authorised local smart-home devices and controllers.", """
WHAT IT DOES
Smart Home brings supported local-device discovery and control into one inventory. It can discover TP-Link Kasa/Tapo devices on the LAN, load entities from a user-supplied Home Assistant instance, and inspect explicitly configured common local devices such as Tuya/Smart Life, Shelly, Tasmota, WLED and Philips Hue where supported.

HOW IT WORKS
LAN discovery sends bounded provider-specific local requests and reads device replies. Account credentials, tokens, local keys or device passwords are used only for the provider and action you configure. TP-Link account secrets are stored through the desktop credential manager. Home Assistant uses the supplied local URL and long-lived token. Direct adapters use the address and credentials entered in their row. Refresh Selected queries the chosen device; controls use its supported local protocol.

HOW TO USE IT
Save the TP-Link credentials securely before discovery when cloud-assisted authentication is required. Use Discover LAN for local TP-Link broadcasts. For Home Assistant, enter a reachable local URL and a token with only the permissions needed, then load devices. For a direct provider, choose the provider, enter its address and required identity/key fields, then Add / inspect. Select a row before Connect, Refresh or device-specific actions.

RESULTS AND MEANING
Name may be the device alias or a cautious fallback. Provider identifies the protocol adapter. Model and Type come from the device response. State, brightness and signal are shown only when the device exposes them. A dash means unavailable, not zero. Signal is approximate radio evidence reported by the device and may lag.

SAFETY AND LIMITS
Actions change real devices. Confirm the selected address and device before power or state changes. Protocol and firmware differences mean not every control is available on every model. The app does not defeat pairing, recover credentials or bypass vendor security. Prefer local, least-privilege credentials and revoke tokens no longer required.
"""),
    _section("system", "System Monitor", "Measure local resource pressure and identify contributing processes.", """
WHAT IT DOES
System Monitor displays local CPU, memory, storage throughput, network throughput and process activity. It is a diagnostic flight recorder for the computer running the app, not a remote host monitor.

HOW IT WORKS
The page samples operating-system counters at a bounded interval. Rates are calculated from differences between samples. Per-process CPU is normalised across logical processors. A process row is identified by PID plus creation time so a recycled PID is not silently treated as the old process. Missing platform counters remain unavailable instead of being converted to false zeroes.

HOW TO USE IT
Leave monitoring running while reproducing a slowdown. Pause freezes the visible evidence for inspection; it does not stop the operating system. Search narrows the process table. Sort selects the most useful pressure dimension. Export flight recorder writes the bounded in-memory samples to local JSON for later comparison.

WHAT THE VALUES MEAN
CPU is processing demand during the sample. Memory is current working allocation, not necessarily a leak. Disk and network rates show bytes per second between samples. A single spike can be normal; sustained pressure that correlates with a process is stronger evidence. The strongest-pressure label is a prioritisation hint, not a diagnosis.

LIMITS AND PRIVACY
Permissions and platform APIs determine which process details are visible. Short-lived processes may disappear between samples. This page cannot terminate processes, change priorities or upload telemetry. Correlate resource data with Connections and application logs before assigning cause.
"""),
    _section("disk_usage", "Disk Usage", "Find large local folders and files through a bounded read-only scan.", """
WHAT IT DOES
Disk Usage analyses a chosen folder and shows the largest folders, largest files and a proportional size map. It helps explain storage pressure without deleting or moving anything.

HOW IT WORKS
The scanner walks normal files beneath the selected folder, sums sizes and retains a bounded list of the largest items. Symbolic links are not followed, preventing loops and unintended traversal into another tree. Inaccessible files are counted separately. The visual map is proportional to the measured bytes in the bounded result.

HOW TO USE IT
Choose a folder you are authorised to inspect, set a sensible file-result limit and select Analyze. Cancel stops after the current filesystem operation. Use Filter to narrow the largest-file table. Export CSV saves the measured evidence for review.

WHAT THE RESULTS MEAN
Folder size is the sum of successfully measured descendants, so access errors can make it lower than Explorer or system totals. File size is allocated content length reported by the filesystem; compressed, sparse, deduplicated or cloud-placeholder files may consume different physical storage. The map shows relative size, not importance or safety.

LIMITS AND SAFETY
Results are a point-in-time snapshot and can change while applications write files. The tool does not delete, compress, upload or classify content. Review ownership, backups and application requirements before manually removing anything.
"""),
    _section("dns_benchmark", "DNS Benchmark", "Compare resolver latency, reliability and jitter using real DNS queries.", """
WHAT IT DOES
DNS Benchmark sends real UDP A-record questions to the configured resolvers and ranks successful responses by average latency and then jitter. It measures this computer's current path to those resolvers.

HOW IT WORKS
Each request uses a random transaction ID and accepts only a matching DNS response. Up to eight resolver queries run concurrently. Rounds repeat the measurement; delay spaces rounds; timeout bounds each attempt. Jitter is the population standard deviation of successful samples. A timeout reduces the reply count rather than becoming a fake latency value.

HOW TO USE IT
Choose a normal test hostname, configure one to five rounds, the inter-round delay and timeout, then Start benchmark. Stop retains completed samples. Skip wait begins the next round early. Filter narrows the table; Copy report copies the complete ranking; double-clicking a resolver copies its address.

HOW TO INTERPRET IT
Average is typical response time during this run. Minimum and maximum show spread. Lower jitter means more consistent timing. Replies/attempts is reliability evidence. A fast resolver is not automatically the best choice: privacy policy, filtering, DNSSEC, encrypted DNS, cache behaviour and geographic resilience are separate considerations.

LIMITS
This tests unencrypted UDP port 53 and one record type. Firewalls, VPNs, Wi-Fi congestion and resolver caching affect results. Run several times at representative hours before changing system DNS.
"""),
    _section("connections", "Connections", "See which local processes are listening or communicating and where public peers map.", """
WHAT IT DOES
Connections inventories current TCP/UDP listening, inbound and outbound endpoints with the owning application and PID where the operating system exposes them. Public remote endpoints appear on a movable, zoomable world map.

HOW IT WORKS
The table refreshes from local socket ownership data. Direction is inferred from listener and endpoint state. Public addresses are enriched through ipwho.is for approximate city, country and provider coordinates. Map tiles come from OpenStreetMap. Blue markers are outbound, orange markers are inbound and numbered markers cluster nearby points.

HOW TO USE IT
Start monitoring to refresh every two seconds. Filter by application, PID, protocol, address, state or destination. Select Fit destinations to frame current markers. Drag to pan; use the wheel or +/− to zoom. Click a marker or numbered cluster to open every represented application's name, executable path, PID, direction, protocol, local/remote endpoint, state, organisation and approximate location. Stop freezes collection. Export preserves the visible evidence.

WHAT IT MEANS
Listening means a local program is ready to receive traffic; it does not prove the port is reachable through a firewall. Established means a transport session exists, not that it is trustworthy. A public location usually identifies a provider or data centre, not a person or precise device. Frequent endpoints can be normal CDNs, updates, DNS or cloud APIs.

PRIVACY AND LIMITS
Only public remote IP addresses are sent for geolocation. Private addresses, process names, PIDs and the full table are not sent. Encrypted traffic remains encrypted. Short connections can occur between refreshes. Use Packet Analysis, DNS evidence and application logs before deciding what caused a connection.
"""),
    _section("intelligence", "Intelligence", "Turn scan inventory into explainable local network relationships and priorities.", """
WHAT IT DOES
Intelligence analyses the current host inventory for duplicates, identity conflicts, zones, service exposure and topology relationships. It provides structured search and export without sending the inventory to a cloud service.

HOW IT WORKS
Evidence is derived from addresses, MAC identity, names, manufacturers, services, favourite history and cautious device fingerprints. Duplicate resolution favours stable MAC identity while preserving uncertainty. Exposure scores are explainable weighted hints based on reachable services and context; they are not vulnerability scans. Zone classification groups local, infrastructure, IoT and other cautious categories when evidence supports it.

HOW TO USE IT
Run Network Scan first, then Refresh Intelligence. Use the query field to narrow by device, service, manufacturer, address or classification. Inspect the evidence behind a score or relationship before acting. GraphML exports topology for graph tools; JSON preserves structured evidence for automation or comparison.

WHAT IT MEANS
A duplicate can be DHCP address change, repeated discovery, virtualization or identity ambiguity. A high exposure score means review reachable services sooner; it does not prove compromise. Unknown means insufficient evidence and should remain unknown rather than being guessed. A topology edge represents observed or inferred relationship, not necessarily physical cabling.

LIMITS AND PRIVACY
Accuracy depends on scan completeness and device disclosures. Randomised MACs, proxies, mesh systems and NAT can obscure identity. The analysis is local and read-only. Validate priorities with configuration and service-specific evidence.
"""),
    _section("security_posture", "Security Posture", "Review local operating-system protections with explicit unknown states.", """
WHAT IT DOES
Security Posture collects read-only evidence about this computer's firewall profiles, registered antivirus, Defender real-time status, SMB 1.0, UAC, network category and DNS configuration where supported.

HOW IT WORKS
The page queries documented local operating-system facilities and normalises results into Pass, Review, Warning or Unknown. It does not infer that a missing measurement is safe. Refresh takes a new snapshot; export saves the local report.

HOW TO USE IT
Refresh after security-policy, network-profile or antivirus changes. Expand or select each item to read its evidence and recommended validation. Compare unexpected findings with your organisation's policy before changing anything.

WHAT THE STATES MEAN
Pass means the collected evidence matches the tool's conservative baseline. Review means context is required. Warning highlights a commonly risky condition such as legacy SMB, but still requires confirmation. Unknown means the platform, permissions or provider did not expose reliable evidence. Unknown is not Pass and not proof of failure.

LIMITS AND SAFETY
This is posture inventory, not malware detection, compliance certification or penetration testing. Third-party controls may supersede Windows settings. The page never enables, disables or repairs a setting. Make changes through approved administration tools with rollback plans.
"""),
    _section("diagnostics", "Diagnostics", "Run focused connectivity, DNS, email, TLS and HTTP checks.", """
WHAT IT DOES
Diagnostics runs one bounded check against the host, domain or URL you enter. Connectivity tools include Ping, Traceroute and local Connections. DNS/email tools include A, AAAA, MX, CNAME, TXT, SPF, DMARC and DKIM. Security tools inspect TLS certificates and HTTP requests.

HOW IT WORKS
Ping measures ICMP reachability when permitted. Traceroute observes routing hops and timeouts. DNS queries ask the configured resolver for the selected record type. SPF and DMARC read published TXT policy. DKIM requires the selector because it is part of the DNS name. TLS opens a bounded handshake and reports certificate/chain/timing evidence. HTTP sends a normal request and displays response metadata.

HOW TO USE IT
Enter only the hostname for DNS and most connectivity tests; use a full URL for HTTP when a path matters. Enter the DKIM selector supplied by the mail system. Select one tool and read the status and text result. A selected scan host can prefill the target.

INTERPRETING RESULTS
No ping reply can mean filtering rather than offline. Traceroute asterisks mean a hop did not answer, not necessarily failure. DNS absence may be intentional. SPF/DMARC syntax must be judged with the domain's mail design. Certificate expiry, hostname and chain evidence are separate. HTTP status codes describe the request outcome, not overall security.

LIMITS
Results reflect this computer's resolver, route, proxy and trust store at that moment. Checks are read-only and unauthenticated. They do not exploit services, send mail or alter DNS.
"""),
    _section("favorites", "Favorites", "Maintain a durable, annotated inventory of important devices.", """
WHAT IT DOES
Favorites stores selected devices and notes for later comparison. It provides a smaller operational inventory independent of the current scan table.

HOW IT WORKS
Saved records live locally in ~/.config/advanced-ip-analyser/favorites.json. MAC address is preferred as stable identity, allowing a later scan to update an IP address without losing the note. When no reliable MAC exists, address identity is used more cautiously. Refresh devices rescans saved addresses with the current scan settings.

HOW TO USE IT
Select scan rows and choose Add favorite. Open Favorites to edit a note, remove selected records, export selected records or refresh devices. Use notes for ownership, location, expected role and change-control context; avoid storing passwords or other secrets.

WHAT THE FIELDS MEAN
Seen records the latest observation represented by the stored item. Services and fingerprints are snapshots and can become stale. Manufacturer is interface-vendor evidence, not legal ownership. A missing refreshed device may be asleep, moved, filtered or assigned a new address.

LIMITS AND PRIVACY
Favorites are not automatically synchronised or backed up. Exported inventories can contain IP, MAC and hostname identifiers; protect them appropriately. Removal affects only the local favourite record and never changes the device.
"""),
    _section("wifi_analyzer", "Wi-Fi Analyzer", "Inspect nearby Wi-Fi networks, signal history, channel use and saved profiles.", """
WHAT IT DOES
The Windows Wi-Fi Analyzer shows local adapters, the current connection, nearby SSIDs/BSSIDs, channel, advertised bandwidth, measured signal, security, risk notes and saved-profile status. It also provides a scrollable two-hour signal history and channel-overlap graph.

HOW IT WORKS
The app reads the Windows Native Wi-Fi API. Refresh asks Windows for its latest adapter, BSS and profile data; Windows may reuse a recent radio scan. Approximate dBm and bandwidth come from exposed radio information and are not guessed when absent. Monitoring samples every 1–5 seconds and retains at most two hours in memory. Channel curves use centre frequency and advertised width.

HOW TO USE IT
Refresh for a snapshot. Nearby networks compares signal and security. Start monitoring on Signal history, choose the interval and scroll backward in time. Use 2.4/5/6 GHz selectors on Channel graph. Saved profiles lists credentials already stored by Windows. Select one profile and explicitly confirm Reveal; Hide removes revealed values from app memory. Export scan excludes passwords.

INTERPRETING RESULTS
dBm nearer zero is stronger: roughly −30 is very strong, −67 is generally usable, and below −80 is weak. Percentage is a Windows-derived convenience value. Overlapping wide curves suggest contention, but channel occupancy and client load also matter. Open/legacy security deserves review; a saved profile simply means Windows has configuration for it.

PRIVACY AND LIMITS
Nearby scanning is passive/read-only. Password reveal requests one locally stored key and may require Windows permission. Revealed keys are never exported; copied values are cleared after 30 seconds when unchanged. Signal is location- and hardware-dependent, so compare repeated samples rather than one reading.
"""),
    _section("packet_analysis", "Packet Analysis", "Open, filter and inspect authorised packet captures in the main workspace.", """
WHAT IT DOES
Packet Analysis reads bounded PCAP, PCAPNG, CAP and supported gzip captures. It shows time, endpoints, ports, protocol, length, summary and the first 512 bytes of the selected packet. Debian uses native AF_PACKET capture. Windows uses built-in Microsoft Packet Monitor by default, with Npcap/Wireshark or TShark as an optional per-interface fallback.

HOW IT WORKS
The parser decodes supported Ethernet, VLAN, IPv4/IPv6, ARP, TCP, UDP, DNS, ICMP and common metadata without requiring Wireshark. Selecting a host scopes capture to that IP; selecting a service also scopes the port. Display filters compile into local predicates and never modify the capture. Quick filters and saved named filters accelerate repeated analysis.

HOW TO USE IT
Choose capture file, then use the display filter and Apply. Clear restores all loaded records. Select a row for the byte view. Save capture as copies the original capture. Useful filters cover addresses/CIDRs, TCP/UDP ports, DNS, HTTP, TLS, ICMP, ARP, flags, length, comparisons, text, AND, OR, NOT and parentheses.

WHAT IT MEANS
Source/destination describe the packet direction, not necessarily client/server intent. Retransmission, reset or unanswered traffic can result from loss, filtering or normal application behaviour. Payload bytes may contain sensitive data. TLS and other encryption remain encrypted.

SAFETY AND LIMITS
Capture only traffic you are authorised to inspect. Debian raw capture uses a narrow privileged helper while the GUI remains unprivileged. Windows Packet Monitor may require administrator rights; its temporary all-adapter capture is immediately reduced to selected host/port records before the viewer can save it. The bounded parser does not decrypt traffic, bypass authentication or prove malicious intent. Correlate packets with Connections, DNS and host logs.
"""),
    _section("web_security", "Web Security", "Run a bounded read-only review of a web property you control.", """
WHAT IT DOES
Web Security crawls a bounded same-host set of pages and reports observable TLS, header, cookie, cleartext, mixed-content, CORS, directory-listing, password-form and technology evidence. It produces HTML or JSON reports.

HOW IT WORKS
The crawler begins at the authorised URL, follows same-host links up to the page and depth limits, respects excluded paths, and only contacts extra hosts you explicitly allow. Timeout bounds requests. Custom headers support test environments but are sent to every in-scope request, so do not add secrets unnecessarily. Findings are based on response evidence; no exploit payloads are sent.

HOW TO USE IT
Enter a full http:// or https:// URL. Set Pages, Depth and Timeout conservatively. Add comma-separated excluded paths or allowed hosts only when needed. Custom headers use Name: value separated by |. Confirm ownership/authorisation, then Start audit. Review severity counts, Findings, Crawled pages, and Errors and TLS. Save report when required.

WHAT SEVERITY MEANS
High, Medium, Low and Info prioritise observable configuration risk; they are not proof of exploitability. Missing headers can be acceptable for some content. Technology fingerprints can be incomplete. TLS evidence applies to the observed endpoint and trust path at scan time.

SAFETY AND LIMITS
Use only on sites you own or have explicit permission to test. Authentication, JavaScript execution and business logic are outside this crawler. Rate limits, CDNs, bot controls and dynamic applications can change results. Validate findings manually before remediation.
"""),
    _section("local_ai", "Local AI", "Pair trusted local clients through a private, revocable LAN session.", """
WHAT IT DOES
Local AI Control exposes a bounded local dashboard and scanner operations to this computer's browser or a paired Android app on the same private LAN. It uses a persistent revocable session token and shows pairing and peer-scan state.

HOW IT WORKS
Enable local access starts an HTTP listener on the selected private LAN address. A high-entropy token authorises requests and is stored in the operating-system credential store. The Android identity is paired to that token. Revoke rotates the token, removes pairing and stops the listener. Router-changing operations still require separate desktop approval.

HOW TO USE IT
Select Enable local access and review the confirmation. Use the displayed desktop address from a trusted same-LAN client. Show or Copy token only when pairing; treat it like a password. Open dashboard launches the local page. Scan from Android asks the paired device for its LAN view. Revoke immediately if a token is exposed or a device is lost.

WHAT THE STATES MEAN
Disabled means no listener is running. Active means the local service is accepting authorised requests. No Android device paired means the token exists but no mobile identity is linked. Scan failures can mean pairing, reachability, Android background restrictions or changed LAN addressing.

PRIVACY AND SAFETY
No public tunnel, VPN or automatic cloud upload is created. Anyone with the token and LAN reachability may use authorised endpoints, so do not share it. Closing the app stops the listener; persistent pairing remains until revoked. Use trusted private networks, local firewalls and device lock screens.
"""),
    _section("operations", "Network Operations", "Monitor change, infrastructure, traffic, performance, exposure and automation.", """
WHAT IT DOES
Network Operations turns individual scans into an operational workflow. Changes & conflicts compares completed inventories and checks the current ARP/NDP neighbour cache. SNMP & topology reads standard device identity and LLDP/CDP neighbour evidence from authorised infrastructure. Traffic attribution surfaces top talkers from Network Security Monitor history and detects available capture providers. Quality & throughput measures TCP setup quality and runs optional iPerf3 tests. Vulnerability lifecycle searches the current CISA Known Exploited Vulnerabilities catalogue. Schedules & alerts stores a bounded monitoring policy.

HOW IT WORKS
Baseline changes come from the latest two locally stored scan snapshots using stable MAC-first identity. Conflict review parses the operating system's neighbour cache; it is not a DHCP lease database. Native SNMPv2c reads four bounded standard objects. LLDP/CDP tables use an installed Net-SNMP snmpwalk client so authenticated SNMPv3 is available without storing credentials. DNS/mDNS and SSDP perform short, bounded discovery requests. Top talkers use locally captured Network Watch evidence. CISA KEV is downloaded directly from CISA only when requested.

HOW TO USE IT
Run at least two comparable Network Scans, then refresh baseline comparison. Inspect conflicts and confirm suspicious entries on the router or DHCP server. In SNMP & topology enter one authorised management IP and temporary credentials; prefer SNMPv3. Use DNS/mDNS or SSDP when normal hostnames are missing. Start Network Security Monitor at a suitable observation point before expecting top-talkers data. For quality tests enter a reachable TCP service. Run iPerf3 only against a server you operate. Search KEV using a vendor and product, then verify exact model, firmware and version independently.

WHAT RESULTS MEAN
New, missing and changed describe the difference between two observations, not necessarily an incident. Duplicate IP means multiple MACs were observed for one cached address and requires confirmation because caches can be stale. LLDP/CDP links are device-reported physical/logical neighbour evidence. Loss in TCP quality means the selected port did not accept a connection within the bound; it may be closed or filtered. p95 represents a slow-end latency estimate and jitter is variation between successful samples. A KEV match is a review lead, never proof that a host is vulnerable.

AUTOMATION, PRIVACY AND LIMITS
The saved policy controls interval, quiet hours, change categories, an optional HTTPS webhook and report folder. It never stores SNMP credentials. External communication occurs only when you explicitly refresh CISA KEV, configure a webhook, use public name resolution, or target a remote service. Accurate per-device traffic requires a capture point that can observe traffic; switched networks normally hide traffic between other clients. Windows uses built-in pktmon, with Npcap/Wireshark or TShark only as optional fallbacks. Scan and monitor only systems you own or are authorised to administer.
"""),
    _section("settings_updates", "Settings, Updates and Shortcuts", "Configure AI providers, understand updates and use keyboard navigation.", """
SETTINGS
AI Settings supports OpenAI, Gemini and OpenRouter. Each provider has separate credentials. Refresh models asks that provider for models available to the supplied key. Non-secret preferences are stored locally; API keys use Windows Credential Manager or Debian Secret Service. Delete saved key removes the selected provider secret. AI analysis always shows the exact bounded outbound preview and requires explicit approval before transmission.

UPDATES
The app checks the project's verified GitHub release metadata. When a newer compatible release exists, an Update button appears in the footer. Downloaded installers are checked against published SHA-256 data before launch. Windows upgrades stop running application/MCP processes before replacement; Debian uses the installed update helper and normal administrator approval. Check for updates in Help performs a manual check.

KEYBOARD SHORTCUTS
F5 starts Network Scan. Escape cancels the active scan. Ctrl+F focuses the scan filter. Ctrl+O imports bounded JSON/XML inventory. Ctrl+S exports inventory. Ctrl+Shift+C copies selected host/service detail. Enter opens a selected supported service. Double-click opens a service or preferred web endpoint. Right-click exposes row-specific actions.

GENERAL SAFETY
Use network, capture, web and device controls only with authorisation. A finding is evidence to investigate, not proof of compromise. Exported inventories, captures, reports and tokens can contain sensitive identifiers; store and share them appropriately. Help describes current behaviour for the displayed version—check the release notes after updating.
"""),
)


HELP_BY_KEY = {section.key: section for section in HELP_SECTIONS}

TAB_HELP = {
    "dashboard": "dashboard",
    "network_scan": "network_scan",
    "smart_home": "smart_home",
    "system": "system",
    "disk_usage": "disk_usage",
    "dns_benchmark": "dns_benchmark",
    "connections": "connections",
    "intelligence": "intelligence",
    "operations": "operations",
    "security_posture": "security_posture",
    "diagnostics": "diagnostics",
    "favorites": "favorites",
    "wifi_analyzer": "wifi_analyzer",
    "packet_analysis": "packet_analysis",
    "web_security": "web_security",
    "local_ai": "local_ai",
}
