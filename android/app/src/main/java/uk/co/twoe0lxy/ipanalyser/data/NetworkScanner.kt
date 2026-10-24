package uk.co.twoe0lxy.ipanalyser.data

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger

data class NetworkInfo(
  val localIp: String = "Unavailable",
  val gateway: String = "Unavailable",
  val prefixLength: Int = 24,
  val interfaceName: String = "No active network",
  val wifiName: String = "",
) {
  val range: String get() = if (localIp == "Unavailable") "Unavailable" else "$localIp/$prefixLength"
}

data class HostResult(val address: String, val latencyMs: Long, val openPorts: List<Int>) {
  val services: String get() = openPorts.joinToString { portName(it) }

  companion object {
    fun portName(port: Int): String = when (port) {
      22 -> "SSH · 22"
      53 -> "DNS · 53"
      80 -> "HTTP · 80"
      443 -> "HTTPS · 443"
      445 -> "SMB · 445"
      554 -> "RTSP · 554"
      8080 -> "HTTP · 8080"
      8443 -> "HTTPS · 8443"
      9000 -> "Web · 9000"
      else -> port.toString()
    }
  }
}

data class WifiNetwork(
  val name: String,
  val bssid: String,
  val signalPercent: Int,
  val frequencyMhz: Int,
  val channel: Int,
  val security: String,
  val review: String,
)

object ScannerUtils {
  fun scanTargets(localIp: String, prefixLength: Int): List<String> {
    val octets = localIp.split('.').mapNotNull(String::toIntOrNull)
    if (octets.size != 4 || octets.any { it !in 0..255 } || prefixLength !in 1..32) return emptyList()
    val address = octets.fold(0) { value, octet -> (value shl 8) or octet }
    // Keep phone scans bounded: a network wider than /24 is scanned as the phone's local /24.
    val effectivePrefix = maxOf(prefixLength, 24)
    val mask = if (effectivePrefix == 32) -1 else -1 shl (32 - effectivePrefix)
    val network = address and mask
    val count = (1L shl (32 - effectivePrefix)).toInt()
    if (count <= 2) return listOf(intToIp(address))
    return (1 until count - 1).map { intToIp(network + it) }
  }

  fun wifiSecurity(capabilities: String): Pair<String, String> {
    val value = capabilities.uppercase()
    return when {
      "WEP" in value -> "WEP" to "High · WEP is obsolete"
      "WPA3" in value || "SAE" in value -> "WPA3" to "No obvious issue"
      "WPA2" in value || "RSN" in value -> "WPA2" to "No obvious issue"
      "WPA" in value -> "WPA" to "Medium · Legacy WPA advertised"
      else -> "Open" to "High · No encryption advertised"
    }
  }

  fun channelFor(frequencyMhz: Int): Int = when {
    frequencyMhz == 2484 -> 14
    frequencyMhz in 2412..2472 -> (frequencyMhz - 2407) / 5
    frequencyMhz in 5000..5895 -> (frequencyMhz - 5000) / 5
    frequencyMhz in 5955..7115 -> (frequencyMhz - 5950) / 5
    else -> 0
  }

  private fun intToIp(value: Int): String = listOf(
    value ushr 24 and 255, value ushr 16 and 255, value ushr 8 and 255, value and 255,
  ).joinToString(".")
}

class NetworkScanner(context: Context) {
  private val appContext = context.applicationContext
  private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
  private val wifi = appContext.getSystemService(WifiManager::class.java)
  private val commonPorts = listOf(22, 53, 80, 443, 445, 554, 8080, 8443, 9000)

  @SuppressLint("MissingPermission")
  fun networkInfo(): NetworkInfo {
    val active = connectivity.activeNetwork ?: return NetworkInfo()
    val properties = connectivity.getLinkProperties(active) ?: return NetworkInfo()
    val address = properties.linkAddresses.firstOrNull { it.address is Inet4Address }
      ?: return NetworkInfo(interfaceName = properties.interfaceName ?: "Active network")
    val gateway = properties.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
      ?.gateway?.hostAddress ?: "Unavailable"
    val ssid = try {
      wifi.connectionInfo?.ssid?.trim('"')?.takeUnless { it == "<unknown ssid>" }.orEmpty()
    } catch (_: SecurityException) { "" }
    return NetworkInfo(
      localIp = address.address.hostAddress ?: "Unavailable",
      gateway = gateway,
      prefixLength = address.prefixLength,
      interfaceName = properties.interfaceName ?: "Active network",
      wifiName = ssid,
    )
  }

  suspend fun scanLan(info: NetworkInfo, progress: (Int, Int) -> Unit): List<HostResult> = coroutineScope {
    val targets = ScannerUtils.scanTargets(info.localIp, info.prefixLength)
    val semaphore = Semaphore(48)
    val finished = AtomicInteger(0)
    progress(0, targets.size)
    targets.map { address ->
      async(Dispatchers.IO) {
        semaphore.withPermit {
          val result = inspectHost(address)
          progress(finished.incrementAndGet(), targets.size)
          result
        }
      }
    }.awaitAll().filterNotNull().sortedBy { ipSortKey(it.address) }
  }

  private fun inspectHost(address: String): HostResult? {
    var reachable = false
    var latency = Long.MAX_VALUE
    try {
      val started = SystemClock.elapsedRealtime()
      reachable = InetAddress.getByName(address).isReachable(180)
      if (reachable) latency = SystemClock.elapsedRealtime() - started
    } catch (_: Exception) {
      // TCP checks can still identify a host when ICMP echo is blocked.
    }
    val open = mutableListOf<Int>()
    commonPorts.forEach { port ->
      val started = SystemClock.elapsedRealtime()
      try {
        Socket().use { socket -> socket.connect(InetSocketAddress(address, port), 110) }
        open += port
        latency = minOf(latency, SystemClock.elapsedRealtime() - started)
      } catch (_: Exception) {
        // Closed or filtered is expected during discovery.
      }
    }
    if (!reachable && open.isEmpty()) return null
    return HostResult(address, if (latency == Long.MAX_VALUE) 0 else latency, open)
  }

  @SuppressLint("MissingPermission")
  suspend fun scanWifi(): List<WifiNetwork> = withContext(Dispatchers.IO) {
    try {
      wifi.startScan()
      delay(1_800)
      wifi.scanResults.map { result ->
        val (security, review) = ScannerUtils.wifiSecurity(result.capabilities.orEmpty())
        WifiNetwork(
          name = result.SSID.takeIf { it.isNotBlank() } ?: "Hidden network",
          bssid = result.BSSID ?: "Unavailable",
          signalPercent = WifiManager.calculateSignalLevel(result.level, 101),
          frequencyMhz = result.frequency,
          channel = ScannerUtils.channelFor(result.frequency),
          security = security,
          review = review,
        )
      }.distinctBy { it.bssid }.sortedByDescending { it.signalPercent }
    } catch (error: SecurityException) {
      throw IllegalStateException("Wi-Fi permission is required to list nearby networks.", error)
    }
  }

  suspend fun ping(target: String): String = withContext(Dispatchers.IO) {
    val host = target.trim().ifEmpty { throw IllegalArgumentException("Enter a host or IP address.") }
    buildString {
      repeat(4) { attempt ->
        val started = SystemClock.elapsedRealtime()
        val reachable = try { InetAddress.getByName(host).isReachable(1_200) } catch (_: Exception) { false }
        val elapsed = SystemClock.elapsedRealtime() - started
        append("Reply ${attempt + 1}: ")
        append(if (reachable) "${elapsed} ms" else "no response")
        append('\n')
      }
    }.trimEnd()
  }

  suspend fun dns(target: String): String = withContext(Dispatchers.IO) {
    val host = target.trim().ifEmpty { throw IllegalArgumentException("Enter a hostname.") }
    InetAddress.getAllByName(host).mapNotNull { it.hostAddress }.distinct().joinToString("\n")
      .ifEmpty { "No addresses returned" }
  }

  suspend fun portCheck(target: String): String = withContext(Dispatchers.IO) {
    val host = target.trim().ifEmpty { throw IllegalArgumentException("Enter a host or IP address.") }
    val open = commonPorts.filter { port ->
      try {
        Socket().use { it.connect(InetSocketAddress(host, port), 350) }
        true
      } catch (_: Exception) { false }
    }
    if (open.isEmpty()) "No common TCP ports responded." else open.joinToString("\n") { HostResult.portName(it) }
  }

  suspend fun httpCheck(target: String): String = withContext(Dispatchers.IO) {
    var value = target.trim().ifEmpty { throw IllegalArgumentException("Enter a URL or host.") }
    if (!value.startsWith("http://") && !value.startsWith("https://")) value = "https://$value"
    val connection = URL(value).openConnection() as HttpURLConnection
    connection.requestMethod = "HEAD"
    connection.connectTimeout = 4_000
    connection.readTimeout = 4_000
    connection.instanceFollowRedirects = false
    try {
      "${connection.responseCode} ${connection.responseMessage}\nServer: ${connection.getHeaderField("Server") ?: "Not disclosed"}\nContent type: ${connection.contentType ?: "Unknown"}"
    } finally { connection.disconnect() }
  }

  private fun ipSortKey(address: String): Long = address.split('.').fold(0L) { total, part ->
    total * 256 + (part.toLongOrNull() ?: 0)
  }
}
