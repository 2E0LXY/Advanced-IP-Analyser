# Changelog

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
