package net.azib.ipscan.fetchers;

import net.azib.ipscan.config.ScannerConfig;
import net.azib.ipscan.core.ScanningSubject;
import net.azib.ipscan.util.ThreadResourceBinder;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/** Detects the conservative set of services supported by built-in actions. */
public class ServicesFetcher extends AbstractFetcher {
    public static final String ID = "fetcher.services";
    private static final Map<Integer, String> SERVICES = new LinkedHashMap<>();
    static {
        SERVICES.put(21, "ftp");
        SERVICES.put(22, "ssh");
        SERVICES.put(80, "http");
        SERVICES.put(443, "https");
        SERVICES.put(445, "smb");
        SERVICES.put(3389, "rdp");
    }

    private final ScannerConfig config;
    private final ThreadResourceBinder<Socket> sockets = new ThreadResourceBinder<>();

    public ServicesFetcher(ScannerConfig config) {
        this.config = config;
    }

    @Override public String getId() {
        return ID;
    }

    @Override public Object scan(ScanningSubject subject) {
        var detected = new ArrayList<String>();
        for (var service : SERVICES.entrySet()) {
            if (Thread.currentThread().isInterrupted()) break;
            var socket = sockets.bind(new Socket());
            try {
                socket.connect(new InetSocketAddress(subject.getAddress(), service.getKey()), Math.min(subject.getAdaptedPortTimeout(), config.portTimeout));
                detected.add(service.getValue());
            }
            catch (Exception ignored) {
                // A closed, filtered, or unreachable port is simply not advertised.
            }
            finally {
                sockets.closeAndUnbind(socket);
            }
        }
        return detected.isEmpty() ? null : String.join(", ", detected);
    }

    @Override public void cleanup() {
        sockets.close();
    }
}
