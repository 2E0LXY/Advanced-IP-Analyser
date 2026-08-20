package net.azib.ipscan.core.devices;

import net.azib.ipscan.core.ScanningResult;
import net.azib.ipscan.fetchers.CommentFetcher;
import net.azib.ipscan.fetchers.Fetcher;
import net.azib.ipscan.fetchers.HostnameFetcher;
import net.azib.ipscan.fetchers.ServicesFetcher;

import java.util.ArrayList;
import java.util.List;

/** Converts a completed scanner row into a durable device record. */
public final class SavedDeviceFactory {
    private SavedDeviceFactory() {}

    public static SavedDevice from(ScanningResult result, List<Fetcher> fetchers) {
        var name = "";
        var comment = "";
        var services = new ArrayList<String>();
        var values = result.getValues();
        for (var i = 0; i < Math.min(fetchers.size(), values.size()); i++) {
            var value = values.get(i);
            if (value == null) continue;
            var text = value.toString().strip();
            var id = fetchers.get(i).getId();
            if (HostnameFetcher.ID.equals(id)) name = text;
            else if (CommentFetcher.ID.equals(id)) comment = text;
            else if (ServicesFetcher.ID.equals(id)) {
                for (var service : text.split(",")) if (!service.isBlank()) services.add(service.strip());
            }
        }
        var ip = result.getAddress().getHostAddress();
        if (name.isBlank()) name = ip;
        var lastSeen = result.getType().ordinal() > ScanningResult.ResultType.DEAD.ordinal() ? System.currentTimeMillis() : 0;
        return new SavedDevice(name, ip, result.getMac(), comment, lastSeen, services);
    }
}
