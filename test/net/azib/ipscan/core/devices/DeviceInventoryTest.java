package net.azib.ipscan.core.devices;

import net.azib.ipscan.core.UserErrorException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Files;
import java.util.List;

import static org.junit.Assert.*;

public class DeviceInventoryTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void persistsMergesAndTracksChangedIpByMac() throws Exception {
        var file = temporaryFolder.newFolder("inventory").toPath().resolve("devices.xml");
        var inventory = new DeviceInventory(file);
        inventory.save(new SavedDevice("printer", "192.0.2.10", "", "upstairs", 10, List.of("http")));
        inventory.save(new SavedDevice("printer", "192.0.2.10", "00-11-22-33-44-55", "", 20, List.of("https")));
        inventory.save(new SavedDevice("printer-new", "192.0.2.20", "00:11:22:33:44:55", "", 30, List.of("ssh")));

        var reloaded = new DeviceInventory(file);
        assertEquals(1, reloaded.all().size());
        var device = reloaded.all().getFirst();
        assertEquals("printer-new", device.name());
        assertEquals("192.0.2.20", device.ipAddress());
        assertEquals("00:11:22:33:44:55", device.macAddress());
        assertEquals("upstairs", device.comment());
        assertEquals(List.of("http", "https", "ssh"), device.services());
        assertEquals(30, device.lastSeenEpochMillis());
    }

    @Test
    public void exportsEscapedCsvAndHtml() throws Exception {
        var root = temporaryFolder.newFolder("exports").toPath();
        var inventory = new DeviceInventory(root.resolve("devices.xml"));
        var device = new SavedDevice("<router>", "192.0.2.1", "", "a,\"b\"", 0, List.of("http"));
        inventory.exportCsv(root.resolve("devices.csv"), List.of(device));
        inventory.exportHtml(root.resolve("devices.html"), List.of(device));

        assertTrue(Files.readString(root.resolve("devices.csv")).contains("\"a,\"\"b\"\"\""));
        var html = Files.readString(root.resolve("devices.html"));
        assertTrue(html.contains("&lt;router&gt;"));
        assertFalse(html.contains("<router>"));
    }

    @Test
    public void rejectsDoctypeAndExternalEntities() throws Exception {
        var root = temporaryFolder.newFolder("xxe").toPath();
        var source = root.resolve("malicious.xml");
        Files.writeString(source, "<!DOCTYPE x [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]><advanced-ip-analyser-devices version='1'><device ip='192.0.2.1'><comment>&leak;</comment></device></advanced-ip-analyser-devices>");
        var inventory = new DeviceInventory(root.resolve("devices.xml"));

        try {
            inventory.importXml(source);
            fail("DOCTYPE input must be rejected");
        }
        catch (UserErrorException expected) {
            assertTrue(inventory.all().isEmpty());
        }
    }
}
