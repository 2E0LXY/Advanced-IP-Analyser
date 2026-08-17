# Advanced IP Analyser

Advanced IP Analyser is a Debian 13 network discovery and remote-access desktop
application built on the Angry IP Scanner codebase. The current development plan,
feature comparison, and architecture notes are in
[`docs/ADVANCED_IP_SCANNER_REPLICA.md`](docs/ADVANCED_IP_SCANNER_REPLICA.md).

The first Debian milestone adds native Wake-on-LAN plus HTTPS, SMB, SSH, and
FreeRDP host actions. See [`docs/DEBIAN13.md`](docs/DEBIAN13.md) for build and
runtime requirements.

## Upstream project

This fork is based on the source code of [Angry IP Scanner](https://github.com/angryip/ipscan)
and remains licensed under GPL v2 or later. Advanced IP Analyser targets Debian 13 only.

The code is written mostly in Java.
[SWT library from Eclipse project](https://eclipse.org/swt/) is used for GUI that provides native components for each supported platform.

The upstream project runs on Linux, Windows, and macOS. This fork is built,
packaged, and supported for Debian 13 on amd64.

## Helping / Contributing

As there are millions of different networks, configurations, and devices, please submit a **Pull Request** when something
doesn't work as expected on Debian 13. Reproduction details and a small test make network-specific problems much easier to fix.

For that, download [Intellij IDEA community edition](https://www.jetbrains.com/idea/download/) and open the cloned project.
Then, you can run Angry IP Scanner in Debug mode and put a breakpoint into the [desired Fetcher class](src/net/azib/ipscan/fetchers).

## Building [![Debian 13 CI](https://github.com/2E0LXY/Advanced-IP-Analyser/actions/workflows/build.yml/badge.svg)](https://github.com/2E0LXY/Advanced-IP-Analyser/actions/workflows/build.yml)

Use Gradle to test and build the Debian package:

`xvfb-run -a ./gradlew --no-daemon test linux64`

The resulting binaries will be put into the `build/libs` directory.
Install the generated package with `sudo apt install ./build/libs/*.deb`.

The supported package target is `./gradlew linux64`, run on Debian 13.

### Dependencies

On Debian 13 install the following packages:
```
sudo apt install openjdk-21-jdk fakeroot libgtk-3-0t64 xvfb xauth
```
