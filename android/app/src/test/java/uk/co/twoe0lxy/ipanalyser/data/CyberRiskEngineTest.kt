package uk.co.twoe0lxy.ipanalyser.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CyberRiskEngineTest {
  private fun host(address: String, vararg ports: Int) =
    HostResult(address = address, latencyMs = 10, openPorts = ports.toList())

  @Test fun emptyScanIsUnknownWithoutBaseline() {
    val result = CyberRiskEngine.assess(emptyList())
    assertEquals(0, result.devices.size)
    assertEquals(0, result.observedPorts)
    assertEquals(0, result.priorityDevices)
    assertNull(result.changes)
  }

  @Test fun recordsHighRiskLanPortsWithoutClaimingCve() {
    val result = CyberRiskEngine.assess(listOf(host("192.168.1.50", 21, 23, 445)))
    assertEquals("High", result.devices.single().level)
    assertEquals(52, result.devices.single().score)
    assertEquals(3, result.observedPorts)
    assertTrue(result.devices.single().evidence.any { "Telnet" in it })
  }

  @Test fun riskCountsAreEvidenceBased() {
    val result = CyberRiskEngine.assess(
      listOf(host("192.168.1.2", 80), host("192.168.1.3", 21, 23, 445))
    )
    assertEquals(2, result.devices.size)
    assertEquals(1, result.priorityDevices)
    assertEquals(1, result.severityCounts["High"])
    assertEquals(1, result.severityCounts["Low"])
  }

  @Test fun onlyChangesInObservationsAreCounted() {
    val latest = listOf(host("192.168.1.2", 80, 443), host("192.168.1.7", 22))
    val previous = listOf(host("192.168.1.2", 80), host("192.168.1.8", 22))
    val changes = CyberRiskEngine.assess(latest, previous).changes
    assertNotNull(changes)
    assertEquals(1, changes?.newDevices)
    assertEquals(1, changes?.missingDevices)
    assertEquals(1, changes?.changedServices)
  }

  @Test fun duplicateAddressesAndPortsDoNotInflateMetrics() {
    val result = CyberRiskEngine.assess(
      listOf(host("192.168.1.2", 80, 80, 443), host("192.168.1.2", 80))
    )
    assertEquals(1, result.devices.size)
    assertEquals(2, result.observedPorts)
  }

  @Test fun unknownOrUnscannedPortsDoNotBecomeCves() {
    val result = CyberRiskEngine.assess(listOf(host("192.168.1.5", 12345)))
    assertEquals("Low", result.devices.single().level)
    assertTrue(result.devices.single().evidence.first().contains("No elevated"))
  }
}
