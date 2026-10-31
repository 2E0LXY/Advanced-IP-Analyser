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
  fun widerNetworksAreBoundedToPhonesLocal22() {
    val targets = ScannerUtils.scanTargets("10.20.30.40", 16)
    assertEquals(1022, targets.size)
    assertEquals("10.20.28.1", targets.first())
    assertEquals("10.20.31.254", targets.last())
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

  @Test
  fun arpTableIncludesOnlyCompletedNeighbours() {
    val table = """
      IP address       HW type     Flags       HW address            Mask     Device
      192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
      192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        wlan0
      192.168.1.30     0x1         0x2         11:22:33:44:55:66     *        wlan0
    """.trimIndent()
    assertEquals(setOf("192.168.1.1", "192.168.1.30"), ScannerUtils.arpAddresses(table))
  }

  @Test
  fun ipNeighbourTableExcludesFailedEntries() {
    val table = """
      192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
      192.168.1.20 dev wlan0 INCOMPLETE
      192.168.1.30 dev wlan0 lladdr 11:22:33:44:55:66 STALE
      fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    """.trimIndent()
    assertEquals(setOf("192.168.1.1", "192.168.1.30"), ScannerUtils.ipNeighbourAddresses(table))
  }

  @Test
  fun deviceTapPrefersSecureWebService() {
    assertEquals(
      "https://192.168.1.50",
      ScannerUtils.preferredServiceUrl("192.168.1.50", listOf(22, 80, 443)),
    )
    assertEquals(
      "http://192.168.1.60:8080",
      ScannerUtils.preferredServiceUrl("192.168.1.60", listOf(53, 8080)),
    )
    assertEquals(null, ScannerUtils.preferredServiceUrl("192.168.1.70", listOf(53, 445)))
  }
}
