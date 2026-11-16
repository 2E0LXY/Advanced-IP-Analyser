# Cyber Platform — comparison and implementation plan

Reference: RoboShadow CyberOS / Cyber Platform official product pages, reviewed 2026-11-16.
This project uses independent implementation and branding, not RoboShadow assets, API,
proprietary code or logos.

## Already available in Advanced IP Analyser v3.0.2

- IPv4/IPv6 local network discovery, port/service inventory and timeline
- Network Intelligence: explainable, heuristic LAN exposure scoring; asset zoning and deduplication
- Windows Security Posture: read-only firewall, Defender, UAC and SMB observations
- Web Security Audit: TLS, headers, mixed content and related non-exploit checks
- Windows/De​​bian diagnostics, connections, packet views, report export and local monitoring
- MCP local tools and separate approval gates for router changes

## This pull request: Cyber Platform overview

- Dark charcoal, tile-and-chart security landing page with native Tkinter widgets
- Actual inventory/port/priority/change counts from local SQLite history
- Severity distribution, local scan history and per-device explanation
- Navigation into existing scanner, Intelligence and Security Posture workspaces
- No new background networking, cloud upload, exploitation attempts, CVE assertions
- Does not replace or remove any original application workspaces

## Next stages for feature parity

1. **Evidence-backed vulnerability management.** Correlate authoritative
   product/version/CPE evidence against CVE feeds, distinguish confirmed,
   potential and not assessed, and mark feed freshness. Offline cached feed
   optional. Do not infer a CVE solely from an open port.
2. **Endpoint security coverage.** Expand the existing Windows posture view to
   display missing OS patches, BitLocker/Device Encryption, Defender status
   and enrolled endpoint coverage. Other machines require approved local agents
   or authenticated read access.
3. **Remediation and approvals.** Add a local queue of suggested actions, explicit
   device-by-device approval, backup/rollback where applicable, clear results,
   and local audit log. No automatic router changes or broad remote execution.
4. **Report centre.** Generate clearly sourced PDF/HTML cyber assessments with
   current assets, changes, evidence, limitations, and recommended actions.
5. **External surface (optional).** Check only assets explicitly owned or
   authorised. Genuine Internet-facing exposure requires an external vantage
   point and cannot be established by an internal-only scan.
6. **Third-party integrations (optional).** Microsoft 365/Intune, vulnerability
   feeds and breach data require their own API connectivity/consent; disabled
   by default. Do not represent cloud data as purely local.

## Safety and privacy

- Scanner evidence is local, and presenting a report in ChatGPT requires
  invoking an authorised tool.
- WAN exposure, compromise and specific CVEs are not verified by this view.
- A low LAN-exposure score does not mean a device is free of vulnerabilities.
- Persisted router changes continue to require separate approval.
- No VPN, tunnel or automatic cloud telemetry is introduced.
