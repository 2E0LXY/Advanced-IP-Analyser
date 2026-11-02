package uk.co.twoe0lxy.ipanalyser.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsBenchmarkTest {
  @Test
  fun buildsARecordQueryWithTransactionId() {
    val query = DnsBenchmark.buildQuery(0x1234, "example.com")
    assertEquals(0x12, query[0].toInt() and 0xff)
    assertEquals(0x34, query[1].toInt() and 0xff)
    assertEquals(1, query[5].toInt() and 0xff)
    assertTrue(query.size > 20)
  }

  @Test
  fun validatesTransactionAndDnsResponseFlag() {
    val response = ByteArray(12)
    response[0] = 0x12
    response[1] = 0x34
    response[2] = 0x80.toByte()
    assertTrue(DnsBenchmark.isValidResponse(response, response.size, 0x1234))
    assertFalse(DnsBenchmark.isValidResponse(response, response.size, 0x9999))
    response[3] = 0x03
    assertFalse(DnsBenchmark.isValidResponse(response, response.size, 0x1234))
  }

  @Test
  fun benchmarkRowIgnoresTimeoutsWhenAveraging() {
    val row = DnsBenchmarkRow(DnsResolver("Test", "192.0.2.1"), listOf(10, null, 30))
    assertEquals(20.0, row.averageMs!!, 0.01)
    assertEquals(10.0, row.jitterMs!!, 0.01)
    assertEquals(2, row.successfulRounds)
  }
}
