# AI Network Monitor (local-only)

This opt-in feature makes network health results easy to review locally or share
manually with ChatGPT. It **does not** connect to ChatGPT, launch a server,
open a listening port, send telemetry, register for startup, or upload files.
AI providers configured elsewhere in Advanced IP Analyser are not invoked.

## Windows usage

Open PowerShell on a computer connected to your own LAN and run the installed
`advanced-ip-analyser` command (or run `python -m ip_analyser.cli` from source):

```powershell
advanced-ip-analyser local-monitor 192.168.1.0/24 --count 1 --report "$env:USERPROFILE\Documents\network-health.json"
```

For repeated checks while a terminal remains open:

```powershell
advanced-ip-analyser local-monitor 192.168.1.0/24 --interval 300 --count 0
```

Press Ctrl+C to stop. Checks are bounded to 1,024 private/link-local addresses,
32 TCP ports, at most 32 workers, and at least 60 seconds between scans.
Service banner and HTTP discovery is disabled for these low-impact checks.
No admin rights or packet capture driver is required.

History is stored locally using the application's existing SQLite scan-history
store. It retains at most 1,000 snapshots; monitoring does not run unless
invoked. To export a report after collecting history:

```powershell
advanced-ip-analyser local-monitor-report --output "$env:USERPROFILE\Documents\network-health.json"
```

The default report excludes IP addresses, hostnames and MAC addresses. If
ChatGPT needs to assess a specific host or correlate router rules, you may
**explicitly** choose `--include-identifiers` when exporting. Review the JSON
before sharing it. Device types and open ports can still reveal aspects of
your network; reports are not automatically shared.

## Limitations

- Checks observe TCP reachability and a bounded set of ports, not all protocols.
- A missing response does not prove a device is offline or compromised.
- Historical changes are comparisons of observations, not a security verdict.
- IPv6 addresses can be scanned if explicitly provided as local/private targets;
  a global IPv6 prefix is not eligible for unattended monitoring by default.
- This feature does not run in the background after the terminal is closed.
- The CLI feature is available from source until a new Windows release bundles it.
