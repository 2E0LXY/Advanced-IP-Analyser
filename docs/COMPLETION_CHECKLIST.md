# Product completion checklist

Advanced IP Analyser is complete when the following Debian 13 amd64 acceptance
criteria are satisfied.

## Safety and reliability

- Scanned values cannot change the executable or argument structure of an action.
- Remote power requires explicit confirmation and uses SSH keys or an agent.
- Update checks are bounded and cannot keep the process alive.
- Configuration migrations persist their data before completion markers.
- The launcher preserves the Java process exit status.
- The application sends no analytics or crash telemetry.

## Device workflow

- Scan results and saved devices have separate tabs.
- Selected results can be added to a persistent device inventory.
- Saved records contain name, IP, MAC, comment, last-seen time, and services.
- Records prefer normalized MAC identity and fall back to IP identity.
- XML import is versioned and rejects unsafe XML constructs.
- XML, CSV, and HTML export support selected or complete device sets.

## Discovery and actions

- Named probes detect SSH, FTP, HTTP, HTTPS, SMB, and RDP.
- Current-interface subnet and `/24` scan shortcuts are available.
- Actions are enabled only when their required client is installed.
- RDP, SSH, browser, SMB, Wake-on-LAN, and confirmed SSH power actions report
  useful per-host outcomes.

## Debian product quality

- The SWT interface has accessible names, keyboard navigation, result/favorites
  tabs, alternating rows where supported, dependency guidance, and original
  project metadata.
- CI runs unit tests, launcher tests, package validation, package install/remove,
  and a headless startup smoke test in Debian 13.
- The release contains a versioned amd64 `.deb`, source/license information,
  installation documentation, and a published checksum.
