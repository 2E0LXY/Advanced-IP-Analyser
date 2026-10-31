package uk.co.twoe0lxy.ipanalyser.data

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.MacAddress
import android.net.Network
import android.net.NetworkRequest
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSpecifier
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.TimeUnit

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
    // Honour normal LAN subnet sizes while keeping very large enterprise ranges bounded.
    // A /22 is 1,022 usable addresses and is the maximum suitable for an on-device scan.
    val effectivePrefix = maxOf(prefixLength, 22)
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

  fun arpAddresses(table: String): Set<String> = table.lineSequence().drop(1).mapNotNull { line ->
    val fields = line.trim().split(Regex("\\s+"))
    val address = fields.getOrNull(0) ?: return@mapNotNull null
    val flags = fields.getOrNull(2) ?: return@mapNotNull null
    val mac = fields.getOrNull(3) ?: return@mapNotNull null
    address.takeIf {
      flags != "0x0" && mac != "00:00:00:00:00:00" &&
        it.split('.').size == 4 && it.split('.').all { part -> part.toIntOrNull() in 0..255 }
    }
  }.toSet()

  fun ipNeighbourAddresses(table: String): Set<String> = table.lineSequence().mapNotNull { line ->
    val fields = line.trim().split(Regex("\\s+"))
    val address = fields.firstOrNull() ?: return@mapNotNull null
    val state = fields.lastOrNull()?.uppercase().orEmpty()
    address.takeIf {
      state !in setOf("FAILED", "INCOMPLETE") && isIpv4Address(it)
    }
  }.toSet()

  fun preferredServiceUrl(address: String, ports: List<Int>): String? {
    val port = listOf(443, 80, 8443, 8080, 8000, 8888, 9000, 5000, 21, 22, 23, 554)
      .firstOrNull(ports::contains) ?: return null
    return when (port) {
      443 -> "https://$address"
      80 -> "http://$address"
      8443 -> "https://$address:8443"
      8080, 8000, 8888, 9000, 5000 -> "http://$address:$port"
      21 -> "ftp://$address"
      22 -> "ssh://$address"
      23 -> "telnet://$address"
      554 -> "rtsp://$address"
      else -> null
    }
  }

  private fun isIpv4Address(value: String): Boolean = value.split('.').let { parts ->
    parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
  }

  private fun intToIp(value: Int): String = listOf(
    value ushr 24 and 255, value ushr 16 and 255, value ushr 8 and 255, value and 255,
  ).joinToString(".")
}

class NetworkScanner(context: Context) {
  private val appContext = context.applicationContext
  private val connectivity = appContext.getSystemService(ConnectivityManager::class.java)
  private val wifi = appContext.getSystemService(WifiManager::class.java)
  private val commonPorts = listOf(
    21, 22, 23, 53, 80, 139, 443, 445, 554, 1883, 5000, 8000, 8080, 8443, 8883, 9000, 9100,
  )
  private var wifiRequestCallback: ConnectivityManager.NetworkCallback? = null

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
    stimulateNeighbours(targets)
    delay(350)
    val neighbours = neighbourAddresses()
    val alwaysInclude = neighbours + setOf(info.gateway, info.localIp)
    val semaphore = Semaphore(64)
    val finished = AtomicInteger(0)
    progress(0, targets.size)
    targets.map { address ->
      async(Dispatchers.IO) {
        semaphore.withPermit {
          val result = inspectHost(address, address in alwaysInclude)
          progress(finished.incrementAndGet(), targets.size)
          result
        }
      }
    }.awaitAll().filterNotNull().sortedBy { ipSortKey(it.address) }
  }

  private suspend fun stimulateNeighbours(targets: List<String>) = coroutineScope {
    val semaphore = Semaphore(64)
    targets.map { address ->
      async(Dispatchers.IO) {
        semaphore.withPermit {
          try {
            DatagramSocket().use { socket ->
              val packet = DatagramPacket(byteArrayOf(0), 1, InetAddress.getByName(address), 9)
              socket.send(packet)
            }
          } catch (_: Exception) {
            // A failed UDP send does not prevent the normal host probes below.
          }
        }
      }
    }.awaitAll()
  }

  private fun neighbourAddresses(): Set<String> {
    val arp = try {
      ScannerUtils.arpAddresses(java.io.File("/proc/net/arp").readText())
    } catch (_: Exception) {
      emptySet()
    }
    val ipNeighbours = try {
      val process = ProcessBuilder("/system/bin/ip", "neigh", "show")
        .redirectErrorStream(true)
        .start()
      if (!process.waitFor(2, TimeUnit.SECONDS)) {
        process.destroyForcibly()
        emptySet()
      } else {
        ScannerUtils.ipNeighbourAddresses(process.inputStream.bufferedReader().use { it.readText() })
      }
    } catch (_: Exception) {
      emptySet()
    }
    return arp + ipNeighbours
  }

  private fun inspectHost(address: String, knownNeighbour: Boolean = false): HostResult? {
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
        Socket().use { socket -> socket.connect(InetSocketAddress(address, port), 140) }
        open += port
        latency = minOf(latency, SystemClock.elapsedRealtime() - started)
      } catch (_: Exception) {
        // Closed or filtered is expected during discovery.
      }
    }
    if (!knownNeighbour && !reachable && open.isEmpty()) return null
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

  @SuppressLint("MissingPermission")
  fun connectWifi(network: WifiNetwork, password: String, status: (String) -> Unit) {
    if (network.name == "Hidden network") {
      openWifiSettings()
      status("Choose the hidden network in Android Wi-Fi settings.")
      return
    }
    if (network.security == "WEP") {
      openWifiSettings()
      status("Choose ${network.name} in Android Wi-Fi settings; apps cannot join WEP directly.")
      return
    }
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
      openWifiSettings()
      status("Choose ${network.name} in Android Wi-Fi settings.")
      return
    }
    if (network.security != "Open" && password.length < 8) {
      status("Enter the Wi-Fi password (at least 8 characters).")
      return
    }
    try {
      wifiRequestCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
      val specifier = WifiNetworkSpecifier.Builder().setSsid(network.name).apply {
        if (network.bssid != "Unavailable") {
          runCatching { setBssid(MacAddress.fromString(network.bssid)) }
        }
        when (network.security) {
          "WPA3" -> setWpa3Passphrase(password)
          "WPA2", "WPA" -> setWpa2Passphrase(password)
        }
      }.build()
      val request = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .setNetworkSpecifier(specifier)
        .build()
      val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(available: Network) {
          status("Connected to ${network.name}")
        }

        override fun onUnavailable() {
          status("Could not connect to ${network.name}. Check the password and try again.")
        }

        override fun onLost(lost: Network) {
          status("Disconnected from ${network.name}")
        }
      }
      wifiRequestCallback = callback
      status("Approve the Android connection request for ${network.name}.")
      connectivity.requestNetwork(request, callback, 30_000)
    } catch (error: SecurityException) {
      status("Wi-Fi permission is required before connecting.")
    } catch (error: IllegalArgumentException) {
      status(error.message ?: "This Wi-Fi configuration is not supported.")
    }
  }

  private fun openWifiSettings() {
    appContext.startActivity(Intent(Settings.ACTION_WIFI_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
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
