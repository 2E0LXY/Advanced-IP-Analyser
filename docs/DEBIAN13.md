# Debian 13 build and runtime

Install the build dependency and create the Debian package:

```sh
sudo apt update
sudo apt install openjdk-21-jdk fakeroot libgtk-3-0t64 xvfb xauth appstream desktop-file-utils lintian
xvfb-run -a ./gradlew --no-daemon test linux64
```

The package is written to `build/libs` and includes a minimized Java 21 runtime.
Install it with `sudo apt install ./build/libs/Advanced-IP-Analyser_*_amd64.deb`.
For a development build without creating an OS package, run `./gradlew current`
and execute the resulting JAR with Java 21.

Optional desktop integrations used by host actions:

```sh
sudo apt install iputils-ping iputils-tracepath openssh-client freerdp3-x11 gvfs-backends telnet whois
```

- RDP uses Debian 13's `xfreerdp3` executable.
- SSH uses the OpenSSH client.
- SMB, HTTP(S), and FTP URLs use the configured desktop handler.
- Wake-on-LAN is implemented directly and does not require `wakeonlan` or
  `etherwake`.
- Shutdown, reboot, and cancellation use non-interactive SSH with an existing
  key or agent and passwordless authorization for the narrowly scoped remote
  command. Passwords are never stored by the application.
- The application checks optional clients on first run and disables unavailable
  opener actions.

Only scan networks and operate computers you are authorized to manage.
