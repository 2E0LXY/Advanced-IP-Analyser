package uk.co.twoe0lxy.ipanalyser.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScannerUtilsTest {
  @Test
  fun local24ExcludesNetworkAndBroadcastAddresses() {
    val targets = ScannerUtils.scanTargets("192.168.1.42", 24)
    assertEquals(254, targets.size)
    assertEquals("192.168.1.1", targets.first())
    assertEquals("192.168.1.254", targets.last())
  }

  @Test
  fun widerNetworksAreBoundedToPhonesLocal24() {
    val targets = ScannerUtils.scanTargets("10.20.30.40", 16)
    assertEquals("10.20.30.1", targets.first())
    assertEquals("10.20.30.254", targets.last())
  }

  @Test
  fun invalidAddressProducesNoTargets() {
    assertTrue(ScannerUtils.scanTargets("not-an-ip", 24).isEmpty())
  }

  @Test
  fun wifiSecurityUsesCautiousConfigurationLabels() {
    assertEquals("High · WEP is obsolete", ScannerUtils.wifiSecurity("[WEP]").second)
    assertEquals("WPA3", ScannerUtils.wifiSecurity("[RSN-SAE-CCMP]").first)
    assertEquals("No obvious issue", ScannerUtils.wifiSecurity("[WPA2-PSK-CCMP]").second)
    assertTrue(ScannerUtils.wifiSecurity("").second.startsWith("High"))
  }

  @Test
  fun wifiChannelsCoverCommonBands() {
    assertEquals(1, ScannerUtils.channelFor(2412))
    assertEquals(36, ScannerUtils.channelFor(5180))
    assertEquals(5, ScannerUtils.channelFor(5975))
  }
}
