package net.azib.ipscan.gui.actions;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

public class DebianUpdaterTest {
    private final DebianUpdater updater = new DebianUpdater();

    @Test public void comparesSemanticReleaseVersions() {
        assertTrue(updater.isNewer("1.2.0", "1.1.9"));
        assertFalse(updater.isNewer("1.0.0", "1.0.0"));
        assertFalse(updater.isNewer("0.9.9", "1.0.0"));
    }

    @Test public void acceptsOnlyChecksumForExactAsset() throws Exception {
        var digest = "a".repeat(64);
        assertEquals(digest, DebianUpdater.expectedDigest(digest + "  Advanced-IP-Analyser_1.0.0_amd64.deb\n", "Advanced-IP-Analyser_1.0.0_amd64.deb"));
    }

    @Test(expected = IOException.class) public void rejectsMissingChecksum() throws Exception {
        DebianUpdater.expectedDigest("a".repeat(64) + "  another.deb\n", "Advanced-IP-Analyser_1.0.0_amd64.deb");
    }
}
