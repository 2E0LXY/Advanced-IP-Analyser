package net.azib.ipscan.gui.actions;

import net.azib.ipscan.config.OpenersConfig.Opener;
import net.azib.ipscan.config.Platform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Checks whether an opener's external client is available before launch. */
public class ClientAvailability {
    public boolean isAvailable(Opener opener) {
        var command = opener.execString.strip();
        if (command.startsWith("http:") || command.startsWith("https:") || command.startsWith("ftp:") || command.startsWith("mailto:")) return true;
        if (command.startsWith("smb:")) return !Platform.LINUX || commandAvailable("gio") || commandAvailable("xdg-open");
        if (command.startsWith("\\\\")) return !Platform.LINUX;
        var arguments = OpenerLauncher.splitCommand(command);
        return arguments.length == 0 || arguments[0].contains("${") || commandAvailable(arguments[0]);
    }

    public boolean commandAvailable(String command) {
        var candidate = Path.of(command);
        if (candidate.isAbsolute()) return Files.isExecutable(candidate);
        var path = System.getenv("PATH");
        if (path == null) return false;
        for (var directory : path.split(java.io.File.pathSeparator))
            if (!directory.isBlank() && Files.isExecutable(Path.of(directory, command))) return true;
        return false;
    }

    public List<String> missingRecommendedPackages() {
        var missing = new ArrayList<String>();
        require(missing, "ping", "iputils-ping");
        require(missing, "tracepath", "iputils-tracepath");
        require(missing, "ssh", "openssh-client");
        require(missing, "xfreerdp3", "freerdp3-x11");
        if (!commandAvailable("gio") && !commandAvailable("xdg-open")) missing.add("gvfs-backends");
        return List.copyOf(missing);
    }

    private void require(List<String> missing, String command, String packageName) {
        if (!commandAvailable(command)) missing.add(packageName);
    }
}
