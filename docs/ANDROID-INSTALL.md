# Install Advanced IP Analyser on Android

## Download the APK

The Android app is a separate release from the Windows and Debian editions.
GitHub's green **Latest** label points to the desktop release so the Windows
in-app updater works correctly.

**[Download Advanced IP Analyser Android 1.2.1](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/android-v1.2.1/Advanced-IP-Analyser-Android-1.2.1.apk)**

File name: `Advanced-IP-Analyser-Android-1.2.1.apk`

Release page: [Android 1.2.1](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/tag/android-v1.2.1)

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

The SHA-256 checksum for Android 1.2.1 is:

```text
76005c437aac6033cbc58a7ab83668bd42bcad40be51d03c6bef6674b3ad4e2b
```

The release also includes the signed
[`SHA256SUMS-ANDROID.txt`](https://github.com/2E0LXY/Advanced-IP-Analyser/releases/download/android-v1.2.1/SHA256SUMS-ANDROID.txt)
file.

## Permissions and privacy

- LAN discovery requires normal network access.
- Nearby Wi-Fi scanning requires Android's nearby-device/location permission,
  depending on the Android version.
- Connecting to a selected Wi-Fi network always uses Android's system approval.
- The live DNS monitor uses Android's local VPN interface. It does not connect
  to a commercial VPN or send DNS history to the desktop.
- Only public destination IP addresses are sent to `ipwho.is` while destination
  mapping is active. Private and LAN addresses are never submitted.
- Android may hide the application responsible for a connection and encrypted
  DNS-over-HTTPS or DNS-over-TLS can hide domain requests.

Only scan networks and devices you own or are explicitly authorized to inspect.
