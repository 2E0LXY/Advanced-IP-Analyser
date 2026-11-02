package uk.co.twoe0lxy.ipanalyser.data

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.math.sqrt

data class DnsResolver(val name: String, val address: String)

data class DnsBenchmarkRow(
  val resolver: DnsResolver,
  val rounds: List<Long?>,
) {
  val averageMs: Double?
    get() = rounds.filterNotNull().takeIf { it.isNotEmpty() }?.average()
  val jitterMs: Double?
    get() {
      val values = rounds.filterNotNull().map(Long::toDouble)
      if (values.isEmpty()) return null
      val mean = values.average()
      return sqrt(values.sumOf { sample -> (sample - mean) * (sample - mean) } / values.size)
    }
  val successfulRounds: Int get() = rounds.count { it != null }
}

class DnsBenchmark(private val timeoutMs: Int = 2_500) {
  suspend fun run(
    rounds: Int = 5,
    queryName: String = "example.com",
    onRound: (Int, List<DnsBenchmarkRow>) -> Unit = { _, _ -> },
  ): List<DnsBenchmarkRow> = coroutineScope {
    require(rounds in 1..10) { "DNS benchmark rounds must be between 1 and 10." }
    val results = RESOLVERS.associateWith { mutableListOf<Long?>() }
    repeat(rounds) { roundIndex ->
      val latencies = RESOLVERS.map { resolver ->
        async(Dispatchers.IO) { resolver to queryLatency(resolver.address, queryName) }
      }.awaitAll()
      latencies.forEach { (resolver, latency) -> results.getValue(resolver) += latency }
      val rows = rows(results)
      onRound(roundIndex + 1, rows)
      if (roundIndex + 1 < rounds) delay(750)
    }
    rows(results)
  }

  private fun queryLatency(server: String, queryName: String): Long? {
    val transactionId = (System.nanoTime() and 0xffff).toInt()
    val request = buildQuery(transactionId, queryName)
    val response = ByteArray(2_048)
    return try {
      DatagramSocket().use { socket ->
        socket.soTimeout = timeoutMs
        socket.connect(InetAddress.getByName(server), 53)
        val started = SystemClock.elapsedRealtimeNanos()
        socket.send(DatagramPacket(request, request.size))
        val packet = DatagramPacket(response, response.size)
        socket.receive(packet)
        if (!isValidResponse(response, packet.length, transactionId)) return null
        (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000
      }
    } catch (_: Exception) {
      null
    }
  }

  private fun rows(values: Map<DnsResolver, List<Long?>>): List<DnsBenchmarkRow> =
    values.map { (resolver, samples) -> DnsBenchmarkRow(resolver, samples.toList()) }
      .sortedWith(compareBy<DnsBenchmarkRow> { it.averageMs == null }.thenBy { it.averageMs })

  companion object {
    val RESOLVERS = listOf(
      DnsResolver("Cloudflare", "1.1.1.1"),
      DnsResolver("Google", "8.8.8.8"),
      DnsResolver("Quad9", "9.9.9.9"),
      DnsResolver("OpenDNS", "208.67.222.222"),
      DnsResolver("AdGuard", "94.140.14.14"),
      DnsResolver("CleanBrowsing", "185.228.168.9"),
      DnsResolver("Control D", "76.76.2.0"),
      DnsResolver("DNS.SB", "185.222.222.222"),
      DnsResolver("Mullvad", "194.242.2.2"),
      DnsResolver("Hurricane Electric", "74.82.42.42"),
      DnsResolver("DNS4EU", "86.54.11.1"),
      DnsResolver("Cloudflare Secondary", "1.0.0.1"),
      DnsResolver("Cloudflare Security", "1.1.1.2"),
      DnsResolver("Google Secondary", "8.8.4.4"),
      DnsResolver("Quad9 Secondary", "149.112.112.112"),
      DnsResolver("Quad9 Unsecured", "9.9.9.10"),
      DnsResolver("OpenDNS Secondary", "208.67.220.220"),
      DnsResolver("NextDNS Primary", "45.90.28.0"),
      DnsResolver("NextDNS Secondary", "45.90.30.0"),
      DnsResolver("AdGuard Non-Filtering", "94.140.14.140"),
      DnsResolver("Control D Malware", "76.76.2.1"),
      DnsResolver("GCore", "95.85.95.85"),
      DnsResolver("Lumen / Level3", "4.2.2.1"),
      DnsResolver("Verisign", "64.6.64.6"),
      DnsResolver("DNS4EU Unfiltered", "86.54.11.100"),
      DnsResolver("CZ.NIC", "193.17.47.1"),
      DnsResolver("FDN", "80.67.169.12"),
      DnsResolver("DNS.Watch", "84.200.69.80"),
      DnsResolver("CIRA Canadian Shield", "149.112.121.20"),
      DnsResolver("FlashStart", "185.236.104.104"),
      DnsResolver("Alternate DNS", "76.76.19.19"),
      DnsResolver("Comodo Secure", "8.26.56.26"),
      DnsResolver("Yandex", "77.88.8.8"),
      DnsResolver("AliDNS", "223.5.5.5"),
      DnsResolver("DNSPod", "119.29.29.29"),
      DnsResolver("DNS.SB Secondary", "45.11.45.11"),
    )

    internal fun buildQuery(transactionId: Int, name: String): ByteArray {
      val labels = name.trim().trim('.').split('.').filter { it.isNotBlank() }
      require(labels.isNotEmpty() && labels.all { it.length in 1..63 }) { "Invalid DNS test name." }
      val output = ByteArrayOutputStream()
      output.write((transactionId ushr 8) and 0xff)
      output.write(transactionId and 0xff)
      output.write(byteArrayOf(0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
      labels.forEach { label ->
        val bytes = label.toByteArray(Charsets.UTF_8)
        output.write(bytes.size)
        output.write(bytes)
      }
      output.write(byteArrayOf(0x00, 0x00, 0x01, 0x00, 0x01))
      return output.toByteArray()
    }

    internal fun isValidResponse(data: ByteArray, length: Int, transactionId: Int): Boolean {
      if (length < 12) return false
      val returnedId = ((data[0].toInt() and 0xff) shl 8) or (data[1].toInt() and 0xff)
      val isResponse = data[2].toInt() and 0x80 != 0
      val responseCode = data[3].toInt() and 0x0f
      return returnedId == transactionId && isResponse && responseCode == 0
    }
  }
}
