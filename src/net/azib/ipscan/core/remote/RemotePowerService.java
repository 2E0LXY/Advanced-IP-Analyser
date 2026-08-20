package net.azib.ipscan.core.remote;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Executes non-interactive, key/agent-based SSH power commands. */
public class RemotePowerService {
    public enum Action { SHUTDOWN, REBOOT, CANCEL_SHUTDOWN }
    public record Outcome(String host, boolean successful, String message) {}

    public List<Outcome> execute(List<String> hosts, Action action) {
        var outcomes = new ArrayList<Outcome>();
        for (var host : hosts) outcomes.add(execute(host, action));
        return List.copyOf(outcomes);
    }

    Outcome execute(String host, Action action) {
        try {
            var process = new ProcessBuilder(commandFor(host, action)).redirectErrorStream(true).start();
            if (!process.waitFor(Duration.ofSeconds(20).toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                return new Outcome(host, false, "Timed out");
            }
            var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
            return new Outcome(host, process.exitValue() == 0, output.isEmpty() ? "Exit status " + process.exitValue() : output);
        }
        catch (Exception e) {
            return new Outcome(host, false, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    public static List<String> commandFor(String host, Action action) {
        if (host == null || !host.matches("[0-9A-Fa-f:.]+")) throw new IllegalArgumentException("Unsafe host: " + host);
        var remoteCommand = switch (action) {
            case SHUTDOWN -> "sudo -n systemctl poweroff";
            case REBOOT -> "sudo -n systemctl reboot";
            case CANCEL_SHUTDOWN -> "sudo -n shutdown -c";
        };
        return List.of("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "--", host, remoteCommand);
    }
}
