# Install Advanced IP Analyser on Android

## Download the APK

The main GitHub **Latest** release contains Android, Windows and Debian downloads
together. Android also retains a separate version tag for its independent build
and signing history.

**[Download Advanced IP Analyser Android 1.2.7](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/android-v1.2.7/Advanced-IP-Analyser-Android-1.2.7.apk)**

File name: `Advanced-IP-Analyser-Android-1.2.7.apk`

Main download page: [Advanced IP Analyser 3.0.0 — all platforms](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/tag/v3.0.0)

## Install it

1. Download the APK on the Android phone or tablet.
2. Open the download from the browser's downloads list or the Files app.
3. If Android says the source is not allowed to install apps, select **Settings**.
4. Enable **Allow from this source** for the browser or Files app you used.
5. Return to the installer and select **Install**.
6. Open **Advanced IP Analyser**.
7. Approve only the permissions needed for the feature you choose, such as
   nearby Wi-Fi, notifications or the local DNS-monitor VPN.

The application supports Android 8.0 and newer.

## Update an existing installation

Download the newer APK and open it. Android should show **Update** instead of
**Install**. The APK is signed with the same release key, so favorites and app
settings remain in place. Do not uninstall the old app first unless you want to
remove its stored data.

If Android reports that the package conflicts with an existing application,
check that the installed copy came from this repository and that the downloaded
file is the signed release APK rather than a debug build.

## Verify the download

The release includes the generated SHA-256 checksum in
[`SHA256SUMS-ANDROID.txt`](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/android-v1.2.7/SHA256SUMS-ANDROID.txt)
file.

## Permissions and privacy

- LAN discovery requires normal network access.
- Nearby Wi-Fi scanning requires Android's nearby-device/location permission,
  depending on the Android version.
- Wi-Fi analyser views include a network list, a horizontally scrollable signal
  history retained for up to two hours, and 2.4/5/6 GHz channel/bandwidth graphs.
  Charts label the dBm scale, time or channel axis, strongest SSIDs, centre channel
  and advertised bandwidth; the details below each graph remain scrollable.
  Refresh can be requested every 1–5 seconds; Android may throttle radio scans and
  repeat its latest result.
- Connecting to a selected Wi-Fi network always uses Android's system approval.
- The live DNS monitor uses Android's local VPN interface. It does not connect
  to a commercial VPN or send DNS history to the desktop.
- Only public destination IP addresses are sent to `ipwho.is` while destination
  mapping is active. Private and LAN addresses are never submitted.
- Android may hide the application responsible for a connection and encrypted
  DNS-over-HTTPS or DNS-over-TLS can hide domain requests.

Only scan networks and devices you own or are explicitly authorized to inspect.
