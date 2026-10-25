# Local AI Control (v2.8.3)

This optional interface runs **on your PC only**. It opens a web dashboard bound
to `127.0.0.1:18796`, and never starts with Windows or contacts a cloud API.
It does not provide direct access to ChatGPT by itself; a supported browser
integration must be able to open and operate the local dashboard.

## Start

From PowerShell, after installing the Windows package:

```powershell
advanced-ip-analyser local-control --router 192.168.1.1
```

Alternatively, from a source checkout:

```powershell
python -m ip_analyser.cli local-control --router 192.168.1.1
```

Open `http://127.0.0.1:18796/` on the **same PC** and paste the session token
printed in PowerShell. Authorise the session once. The token is not stored to
disk, and is revoked when the service stops. Do not share it or paste it into
cloud chats. Anyone who has the token and local browser access can perform
scanner operations during that session.

## Access and limits

- Read: report and OpenWrt board status.
- Scanner writes: run one bounded LAN scan, start/stop periodic monitoring.
- Router writes: reload Wi-Fi or reboot, each requiring a separate Windows
  approval dialog. A browser confirmation **does not** replace local approval.
- Not yet available: firewall changes, IPv6 configuration, DHCP edits, port
  forwarding, firmware upgrades or factory reset.
- No public/network listener, generic shell commands, CORS access or unattended
  cloud data transfer.

Router read/write requires an already configured, host-key-verified **SSH key**
for `root@192.168.1.1` (or the `--router` private IP). Password authentication
and automatic host-key acceptance are deliberately disabled. On GL.iNet routers,
SSH access may need to be enabled and an authorised key installed first.

The current IP address, MAC and hostname report contains sensitive LAN data.
It is shown locally; if the browser integration shares it with a cloud AI
session, that individual report leaves the PC. No such transfer is automatic.

Stop the service using Ctrl+C in PowerShell. Keep the PowerShell window open
while using the dashboard. The router approval prompt requires a normal
interactive Windows desktop; headless use will not approve changes.
