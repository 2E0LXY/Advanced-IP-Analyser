# Advanced IP Analyser for Android

Native Android companion for Advanced IP Analyser, built with Kotlin and Jetpack Compose.

## Included in Android 1.2.3

- modern dashboard matching the desktop application's dark network-tool interface;
- current local IPv4 address, gateway, interface, Wi-Fi name and network prefix;
- bounded LAN discovery across the active subnet, capped at the phone's local `/22`;
- response-time measurement and common TCP service checks;
- neighbour-table discovery for devices that do not answer ping or common ports;
- tap-to-open access to the best web or remote service found on a LAN device;
- nearby Wi-Fi names, BSSIDs, channels, signal levels and advertised security review;
- user-approved connection to a selected nearby Wi-Fi network;
- ping/reachability, DNS, common-port and HTTP response diagnostics; and
- real UDP latency benchmarking for 36 public DNS resolvers, with five-round
  average, jitter, timeout and validated-reply results;
- device storage used and free-space reporting on the dashboard;
- custom TCP ranges, traceroute, connection inspection, TLS certificate and email-security checks;
- Wake-on-LAN, SSH command execution and SFTP directory inspection;
- local TP-Link/Kasa discovery and power control;
- favorites, retained scan history, CSV/JSON export and SVG topology export;
- persistent, revocable desktop pairing with signed two-way LAN scan requests;
- an opt-in local-VPN DNS monitor showing queries, requesting app where Android exposes it,
  resolver, returned addresses, destination region and an approximate map; and
- explicit Android permission prompts for nearby Wi-Fi results.

Android does not give ordinary applications access to other devices' MAC addresses,
saved Wi-Fi passwords, monitor-mode packet capture, raw ICMP sockets, or unrestricted
background Wi-Fi scanning. The app explains these platform limits instead of showing
invented values.

Encrypted DNS-over-HTTPS traffic is not visible to the DNS monitor. App attribution can
also be hidden by Android or by the app issuing the request. Public answer addresses are
sent to `ipwho.is` only while the user has enabled DNS monitoring so that the app can show
a country/region label.

## Build

Install JDK 17 and Android SDK 36, then run:

```powershell
cd android
.\gradlew.bat test assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.
