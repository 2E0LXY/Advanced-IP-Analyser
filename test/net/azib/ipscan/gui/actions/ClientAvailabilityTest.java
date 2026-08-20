package net.azib.ipscan.gui.actions;

import net.azib.ipscan.config.OpenersConfig;
import org.junit.Test;

import java.nio.file.Path;

import static org.junit.Assert.*;

public class ClientAvailabilityTest {
    @Test
    public void validatesAbsoluteExecutablesWithoutInvokingThem() {
        var availability = new ClientAvailability();
        var java = Path.of(System.getProperty("java.home"), "bin", System.getProperty("os.name").contains("Windows") ? "java.exe" : "java").toString();
        assertTrue(availability.isAvailable(new OpenersConfig.Opener(java + " --version", false, null)));
        assertFalse(availability.isAvailable(new OpenersConfig.Opener(Path.of(System.getProperty("java.io.tmpdir"), "definitely-not-a-client").toString(), false, null)));
    }
}
