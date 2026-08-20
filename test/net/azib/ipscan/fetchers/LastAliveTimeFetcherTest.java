package net.azib.ipscan.fetchers;

import net.azib.ipscan.core.ScanningResult;
import net.azib.ipscan.core.ScanningSubject;
import org.junit.Test;

import java.net.InetAddress;
import java.time.Instant;

import static org.junit.Assert.*;

public class LastAliveTimeFetcherTest {
    @Test
    public void recordsOnlyConfirmedAliveDevices() throws Exception {
        var fetcher = new LastAliveTimeFetcher();
        var subject = new ScanningSubject(InetAddress.getLoopbackAddress(), null, null);
        subject.setResultType(ScanningResult.ResultType.DEAD);
        assertNull(fetcher.scan(subject));

        subject.setResultType(ScanningResult.ResultType.ALIVE);
        assertNotNull(Instant.parse(fetcher.scan(subject).toString()));
    }
}
