package net.azib.ipscan.gui.actions;

import net.azib.ipscan.core.devices.SavedDevice;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class SavedDeviceLauncherTest {
    @Test
    public void selectsBestDetectedServiceWithoutUsingShellCommands() {
        var device = new SavedDevice("host", "192.0.2.4", "", "", 0, List.of("ssh", "http", "https"));
        assertEquals("https://192.0.2.4/", SavedDeviceLauncher.preferredAction(device));
        assertEquals("rdp", SavedDeviceLauncher.preferredAction(new SavedDevice("host", "192.0.2.4", "", "", 0, List.of("rdp"))));
    }
}
