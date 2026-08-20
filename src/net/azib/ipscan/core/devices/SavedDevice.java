package net.azib.ipscan.core.devices;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/** Immutable device saved from a scan result. */
public record SavedDevice(String name, String ipAddress, String macAddress, String comment,
                          long lastSeenEpochMillis, List<String> services) {
    public SavedDevice {
        name = clean(name);
        ipAddress = clean(ipAddress);
        macAddress = normalizeMac(macAddress);
        comment = clean(comment);
        services = normalizeServices(services);
        if (ipAddress.isEmpty()) throw new IllegalArgumentException("IP address is required");
        if (lastSeenEpochMillis < 0) throw new IllegalArgumentException("Last-seen time cannot be negative");
    }

    public String identity() {
        return macAddress.isEmpty() ? "ip:" + ipAddress.toLowerCase(Locale.ROOT) : "mac:" + macAddress;
    }

    public SavedDevice merge(SavedDevice newer) {
        if (!identity().equals(newer.identity())) throw new IllegalArgumentException("Cannot merge different devices");
        var mergedServices = new TreeSet<>(services);
        mergedServices.addAll(newer.services);
        return new SavedDevice(
            newer.name.isEmpty() ? name : newer.name,
            newer.ipAddress,
            newer.macAddress.isEmpty() ? macAddress : newer.macAddress,
            newer.comment.isEmpty() ? comment : newer.comment,
            Math.max(lastSeenEpochMillis, newer.lastSeenEpochMillis),
            List.copyOf(mergedServices));
    }

    public SavedDevice adoptMacIdentity(SavedDevice newer) {
        if (!macAddress.isEmpty() || newer.macAddress.isEmpty() || !ipAddress.equalsIgnoreCase(newer.ipAddress))
            throw new IllegalArgumentException("Cannot adopt MAC identity for different devices");
        var mergedServices = new TreeSet<>(services);
        mergedServices.addAll(newer.services);
        return new SavedDevice(
            newer.name.isEmpty() ? name : newer.name,
            newer.ipAddress,
            newer.macAddress,
            newer.comment.isEmpty() ? comment : newer.comment,
            Math.max(lastSeenEpochMillis, newer.lastSeenEpochMillis),
            List.copyOf(mergedServices));
    }

    public static String normalizeMac(String value) {
        var compact = clean(value).replace(":", "").replace("-", "").toUpperCase(Locale.ROOT);
        if (compact.isEmpty()) return "";
        if (!compact.matches("[0-9A-F]{12}")) throw new IllegalArgumentException("Invalid MAC address: " + value);
        return compact.replaceAll("(..)(?!$)", "$1:");
    }

    private static List<String> normalizeServices(Collection<String> values) {
        var normalized = new TreeSet<String>();
        if (values != null) for (var value : values) if (!clean(value).isEmpty()) normalized.add(clean(value).toLowerCase(Locale.ROOT));
        return List.copyOf(normalized);
    }

    private static String clean(String value) {
        return value == null ? "" : value.strip();
    }
}
