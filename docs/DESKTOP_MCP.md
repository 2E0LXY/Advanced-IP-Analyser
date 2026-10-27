# v2.8.4 — ChatGPT Desktop MCP and persistent Windows monitoring

**No API key, VPN, tunnel, browser control, cloud telemetry, or inbound port is
required.** The MCP executable uses JSON-RPC over standard input/output; the
ChatGPT desktop host starts it only when needed. Network reports are stored
locally until a user invokes an MCP tool. An invoked tool's result can be sent
to ChatGPT to answer the user's request.

## Install and connect (one-time setup)

1. Install `Advanced-IP-Analyser-Setup-2.8.4.exe`.
2. During setup, select **Start local network monitoring automatically when I
   sign in**. This creates a per-user Windows Startup shortcut; it can be
   removed to disable automatic monitoring. The background monitor runs after
   your next sign-in (no elevated permissions required).
3. Open ChatGPT Desktop → **Settings → MCP servers → Add server**.
4. Name: `Advanced IP Analyser`. Type: **STDIO**.
5. Select the installed executable, normally:

   `%LOCALAPPDATA%\Programs\Advanced IP Analyser\Advanced-IP-Analyser-MCP.exe`

   If the dialog does not expand `%LOCALAPPDATA%`, browse to the file under
   your Windows user profile's `AppData\Local\Programs` directory.
6. Save, restart ChatGPT Desktop, and type `/mcp` to verify the connection.

The MCP executable must be configured in the **local Windows desktop host**,
not a cloud-hosted or web ChatGPT session.

## Available MCP tools

| Name | Behaviour |
| ---- | --------- |
| `network_report` | Reads the local database, redacting IP/MAC/hostnames by default |
| `scan_private_network` | Scans up to 1,024 private LAN hosts and records results |
| `router_status` | Reads OpenWrt status using a configured, verified SSH key |
| `router_action` | Wi-Fi reload or reboot, requiring a new Windows approval dialog each time |

Only the named tools are available. Arbitrary shell commands, firewall edits,
port-forward modifications, firmware updates and factory reset are **not**
supported by this version. A router must already accept key-based SSH from
the local Windows user, and its SSH host key must have been verified.

## Security and privacy

- The background monitor is local-only and runs every 300 seconds on the first
  bounded private wired/Wi-Fi interface it can safely identify.
- No Windows service, firewall exception, port forward, VPN or tunnel is added.
- Start/stop the persistent monitor by managing the **Advanced IP Analyser
  Background Monitor** shortcut in your per-user Startup folder. Signing out
  stops the monitoring process; next sign-in restarts it.
- The MCP tools are accessible through the local ChatGPT Desktop MCP settings.
  Remove or disable that server to revoke ChatGPT access.
- Router state changes additionally require an interactive Windows confirmation
  **each time**. If the approval prompt cannot open, the router action fails.
- Reports containing private IP/MAC identifiers are exposed to ChatGPT **only
  when requested**, not as automatic background telemetry.
