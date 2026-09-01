# Passive Wi-Fi Watch

Passive Wi-Fi Watch brings the non-disruptive discovery portion of wireless audit
tools into Advanced IP Analyser. It requires Debian's `iw` utility and a wireless
adapter/driver that supports monitor-mode virtual interfaces.

After explicit confirmation and PolicyKit authorization, the narrow helper creates
a temporary interface named from the source adapter's Linux interface index. It
does not stop NetworkManager, rename or reconfigure the managed adapter, or change
its MAC address. It hops only across validated channel numbers and removes only the
reserved monitor interface when the session ends.

The window can show:

- access-point SSID and BSSID;
- advertised channel, signal level, and Open/WEP/WPA/WPA2/WPA3 indication;
- beacon and observed data counts;
- associated client addresses and passive probe-request names;
- whether EAPOL key-exchange traffic was observed; and
- a bounded radiotap PCAP recording or JSON report.

Signal values depend on driver-provided radiotap metadata. Security labels describe
advertised information elements and are not a guarantee of configuration quality.
“EAPOL observed” is not a recovered key or password.

This implementation intentionally excludes deauthentication, denial of service,
packet injection, rogue access points, credential capture, and password/key
cracking. It transmits no audit frames. Use it only where you are authorized to
observe radio traffic; local law and organizational policy may impose additional
requirements even for passive monitoring.
