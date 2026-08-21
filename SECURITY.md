# Security policy

## Supported release

Security fixes are provided for the latest published release of Advanced IP
Analyser on Debian 13.

## Security properties

- Network, imported-inventory, hostname, banner, username, and service values
  must never alter an executable or subprocess argument structure.
- Inventory parsers and protocol probes are bounded and reject unsupported XML
  declarations, invalid device types, and oversized inputs.
- Update packages must come from this repository's exact GitHub release URL,
  match its published SHA-256 digest, and identify as the expected Debian package
  and version before PolicyKit authorization is requested.
- Remote power is explicitly confirmed, non-interactive, and key based; no
  passwords are collected or stored.

## Reporting

Please report suspected vulnerabilities privately through GitHub's security
advisory interface for `2E0LXY/Advanced-IP-Analyser`. Include the affected
version, Debian version, reproduction steps, and impact. Do not test against
networks or systems without authorization.
