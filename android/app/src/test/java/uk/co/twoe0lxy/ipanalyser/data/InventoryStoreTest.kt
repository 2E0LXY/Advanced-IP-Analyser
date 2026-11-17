package uk.co.twoe0lxy.ipanalyser.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InventoryStoreTest {
  @Test
  fun csvExportNeutralisesSpreadsheetFormulas() {
    val hosts = listOf(HostResult("10.0.0.2", 3, listOf(80), hostname = "=HYPERLINK(\"http://x\")", macAddress = "@x"))
    val csv = InventoryStore.csv(hosts)
    assertTrue(csv.contains("\"'=HYPERLINK("))
    assertTrue(csv.contains("\"'@x\""))
    assertFalse(csv.contains(",\"=HYPERLINK"))
  }

  @Test
  fun csvExportKeepsOrdinaryValuesUnchanged() {
    val csv = InventoryStore.csv(listOf(HostResult("10.0.0.3", 1, listOf(22, 443), hostname = "printer", macAddress = "AA:BB")))
    assertTrue(csv.contains("\"printer\""))
    assertTrue(csv.contains("\"22|443\""))
  }
}
