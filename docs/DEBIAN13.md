# Debian 13 build and runtime

Install the build dependency and create the Debian package:

```sh
sudo apt update
sudo apt install openjdk-21-jdk rpm fakeroot
./gradlew linux64
```

The package is written to `build/libs`. For a development build without creating
an OS package, run `./gradlew current` and then execute the resulting JAR.

Optional desktop integrations used by host actions:

```sh
sudo apt install iputils-ping iproute2 traceroute openssh-client freerdp3-x11 gvfs-backends
```

- RDP uses Debian 13's `xfreerdp3` executable.
- SSH uses the OpenSSH client.
- SMB, HTTP(S), and FTP URLs use the configured desktop handler.
- Wake-on-LAN is implemented directly and does not require `wakeonlan` or
  `etherwake`.

Only scan networks and operate computers you are authorized to manage.
