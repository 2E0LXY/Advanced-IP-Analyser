package net.azib.ipscan.core.remote;

import org.junit.Test;

import static org.junit.Assert.*;

public class RemotePowerServiceTest {
    @Test
    public void createsNonInteractiveArgumentVector() {
        assertEquals(java.util.List.of("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "--", "192.0.2.1", "sudo -n systemctl reboot"),
            RemotePowerService.commandFor("192.0.2.1", RemotePowerService.Action.REBOOT));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsHostsThatCouldChangeCommandStructure() {
        RemotePowerService.commandFor("host; touch /tmp/bad", RemotePowerService.Action.SHUTDOWN);
    }
}
