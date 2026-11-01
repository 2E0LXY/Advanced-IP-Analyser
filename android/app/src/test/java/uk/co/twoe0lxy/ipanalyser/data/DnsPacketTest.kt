package uk.co.twoe0lxy.ipanalyser.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class DnsPacketTest {
  @Test
  fun parsesDnsQueryFromIpv4UdpPacket() {
    val dns = byteArrayOf(
      0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
      0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00, 0x00, 0x01, 0x00, 0x01,
    )
    val packet = ByteArray(28 + dns.size)
    packet[0] = 0x45; packet[9] = 17
    packet[12] = 10; packet[15] = 1; packet[16] = 1; packet[17] = 1; packet[18] = 1; packet[19] = 1
    packet[20] = 0x30; packet[21] = 0x39; packet[23] = 53
    val udpLength = 8 + dns.size
    packet[24] = (udpLength ushr 8).toByte(); packet[25] = udpLength.toByte()
    dns.copyInto(packet, 28)

    val parsed = DnsPacket.parseIpv4Udp(packet, packet.size)
    assertNotNull(parsed)
    assertEquals("example.com", DnsPacket.queryName(parsed!!.payload))
    assertEquals(53, parsed.destinationPort)
  }

  @Test
  fun extractsReturnedIpv4Address() {
    val response = byteArrayOf(
      0x12, 0x34, (0x81).toByte(), (0x80).toByte(), 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x01, 'a'.code.toByte(), 0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00, 0x00, 0x01, 0x00, 0x01,
      (0xC0).toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184.toByte(), 216.toByte(), 34,
    )
    assertEquals(listOf("93.184.216.34"), DnsPacket.answerAddresses(response))
  }
}
