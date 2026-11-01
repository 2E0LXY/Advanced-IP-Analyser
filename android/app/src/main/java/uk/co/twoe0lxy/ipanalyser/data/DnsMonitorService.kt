package uk.co.twoe0lxy.ipanalyser.data

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import uk.co.twoe0lxy.ipanalyser.MainActivity
import uk.co.twoe0lxy.ipanalyser.R
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

data class DnsEvent(
  val id: Long,
  val time: String,
  val query: String,
  val appName: String,
  val resolver: String,
  val answers: List<String>,
  val location: String,
  val latitude: Double? = null,
  val longitude: Double? = null,
  val organisation: String = "",
)

private data class DnsGeo(
  val label: String,
  val latitude: Double?,
  val longitude: Double?,
  val organisation: String,
)

object DnsMonitorRepository {
  private val mutableEvents = MutableStateFlow<List<DnsEvent>>(emptyList())
  val events: StateFlow<List<DnsEvent>> = mutableEvents.asStateFlow()
  val running = MutableStateFlow(false)

  fun add(event: DnsEvent) { mutableEvents.value = (listOf(event) + mutableEvents.value).take(300) }
  fun locate(id: Long, location: String, latitude: Double? = null,
             longitude: Double? = null, organisation: String = "") {
    mutableEvents.value = mutableEvents.value.map {
      if (it.id == id) it.copy(location = location, latitude = latitude,
        longitude = longitude, organisation = organisation) else it
    }
  }
  fun clear() { mutableEvents.value = emptyList() }
}

class DnsMonitorService : VpnService() {
  private var descriptor: ParcelFileDescriptor? = null
  @Volatile private var active = false
  private val geoCache = ConcurrentHashMap<String, DnsGeo>()
  private lateinit var connectivity: ConnectivityManager

  override fun onCreate() {
    super.onCreate()
    connectivity = getSystemService(ConnectivityManager::class.java)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent?.action == ACTION_STOP) {
      stopMonitor(); return Service.START_NOT_STICKY
    }
    if (!active) startMonitor()
    return Service.START_STICKY
  }

  override fun onDestroy() { stopMonitor(); super.onDestroy() }

  private fun startMonitor() {
    val resolver = connectivity.getLinkProperties(connectivity.activeNetwork)?.dnsServers
      ?.firstOrNull { it is Inet4Address } ?: InetAddress.getByName("1.1.1.1")
    createNotificationChannel()
    startForeground(NOTIFICATION_ID, notification())
    descriptor = Builder()
      .setSession("Advanced IP Analyser DNS monitor")
      .setMtu(1500)
      .addAddress("10.111.0.1", 32)
      .addRoute(resolver.hostAddress ?: "1.1.1.1", 32)
      .addDnsServer(resolver)
      .setBlocking(true)
      .establish()
    if (descriptor == null) { stopSelf(); return }
    active = true
    DnsMonitorRepository.running.value = true
    Thread({ packetLoop(resolver) }, "dns-vpn-monitor").apply { isDaemon = true }.start()
  }

  private fun stopMonitor() {
    active = false
    DnsMonitorRepository.running.value = false
    runCatching { descriptor?.close() }
    descriptor = null
    stopForeground(STOP_FOREGROUND_REMOVE)
    stopSelf()
  }

  private fun packetLoop(defaultResolver: InetAddress) {
    val current = descriptor ?: return
    FileInputStream(current.fileDescriptor).use { input ->
      FileOutputStream(current.fileDescriptor).use { output ->
        val buffer = ByteArray(32767)
        while (active) {
          val count = try { input.read(buffer) } catch (_: Exception) { break }
          if (count <= 28) continue
          val parsed = DnsPacket.parseIpv4Udp(buffer, count) ?: continue
          if (parsed.destinationPort != 53) continue
          val resolver = runCatching { InetAddress.getByAddress(parsed.destinationAddress) }.getOrDefault(defaultResolver)
          val app = ownerApp(parsed, resolver)
          try {
            DatagramSocket().use { socket ->
              protect(socket)
              socket.soTimeout = 4_000
              socket.send(DatagramPacket(parsed.payload, parsed.payload.size, resolver, 53))
              val responseBuffer = ByteArray(8192)
              val response = DatagramPacket(responseBuffer, responseBuffer.size)
              socket.receive(response)
              val dnsResponse = response.data.copyOf(response.length)
              val answers = DnsPacket.answerAddresses(dnsResponse)
              output.write(DnsPacket.ipv4UdpResponse(parsed, dnsResponse))
              val query = DnsPacket.queryName(parsed.payload).ifBlank { "Unknown query" }
              val event = DnsEvent(
                id = System.nanoTime(),
                time = SimpleDateFormat("HH:mm:ss", Locale.UK).format(Date()),
                query = query,
                appName = app,
                resolver = resolver.hostAddress ?: "Unknown resolver",
                answers = answers,
                location = when {
                  answers.isEmpty() -> "No address returned"
                  query.endsWith("ipwho.is") -> "Geolocation service"
                  else -> "Locating…"
                },
              )
              DnsMonitorRepository.add(event)
              if (answers.isNotEmpty() && !query.endsWith("ipwho.is")) locateAsync(event.id, answers.first())
            }
          } catch (_: Exception) {
            // A timeout appears in the calling app normally; the monitor continues.
          }
        }
      }
    }
  }

  private fun ownerApp(packet: ParsedDnsPacket, resolver: InetAddress): String {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return "App attribution unavailable"
    return runCatching {
      val local = InetSocketAddress(InetAddress.getByAddress(packet.sourceAddress), packet.sourcePort)
      val remote = InetSocketAddress(resolver, 53)
      val uid = connectivity.getConnectionOwnerUid(OsConstants.IPPROTO_UDP, local, remote)
      val packageName = packageManager.getPackagesForUid(uid)?.firstOrNull()
        ?: packageManager.getNameForUid(uid)
        ?: return@runCatching "UID $uid"
      runCatching {
        val info = packageManager.getApplicationInfo(packageName, 0)
        packageManager.getApplicationLabel(info).toString()
      }.getOrDefault(packageName)
    }.getOrDefault("Unknown app (Android restricted attribution)")
  }

  private fun locateAsync(eventId: Long, address: String) {
    geoCache[address]?.let {
      DnsMonitorRepository.locate(eventId, it.label, it.latitude, it.longitude, it.organisation)
      return
    }
    Thread({
      var latitude: Double? = null
      var longitude: Double? = null
      var organisation = ""
      val location = runCatching {
        val ip = InetAddress.getByName(address)
        if (ip.isSiteLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress) return@runCatching "Private/local destination"
        val connection = URL(DnsGeoLookup.url(address)).openConnection() as HttpURLConnection
        connection.connectTimeout = 3_000; connection.readTimeout = 3_000
        val json = connection.inputStream.bufferedReader().use { JSONObject(it.readText()) }
        connection.disconnect()
        if (!json.optBoolean("success")) "Location unavailable" else buildList {
          latitude = json.optDouble("latitude").takeUnless(Double::isNaN)
          longitude = json.optDouble("longitude").takeUnless(Double::isNaN)
          organisation = json.optJSONObject("connection")?.optString("isp").orEmpty()
          json.optString("city").takeIf(String::isNotBlank)?.let(::add)
          json.optString("region").takeIf(String::isNotBlank)?.let(::add)
          json.optString("country").takeIf(String::isNotBlank)?.let(::add)
          json.optJSONObject("connection")?.optString("isp")?.takeIf(String::isNotBlank)?.let(::add)
        }.joinToString(", ").ifBlank { "Location unavailable" }
      }.getOrDefault("Location unavailable")
      geoCache[address] = DnsGeo(location, latitude, longitude, organisation)
      DnsMonitorRepository.locate(eventId, location, latitude, longitude, organisation)
    }, "dns-geo").apply { isDaemon = true }.start()
  }

  private fun notification() = NotificationCompat.Builder(this, CHANNEL_ID)
    .setSmallIcon(R.mipmap.ic_launcher)
    .setContentTitle("DNS monitor active")
    .setContentText("Inspecting and forwarding DNS requests locally")
    .setOngoing(true)
    .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
    .addAction(0, "Stop", PendingIntent.getService(this, 1, Intent(this, DnsMonitorService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE))
    .build()

  private fun createNotificationChannel() {
    getSystemService(NotificationManager::class.java).createNotificationChannel(
      NotificationChannel(CHANNEL_ID, "DNS monitoring", NotificationManager.IMPORTANCE_LOW))
  }

  companion object {
    const val ACTION_START = "uk.co.twoe0lxy.ipanalyser.DNS_START"
    const val ACTION_STOP = "uk.co.twoe0lxy.ipanalyser.DNS_STOP"
    private const val CHANNEL_ID = "dns-monitor"
    private const val NOTIFICATION_ID = 18798
  }
}

internal object DnsGeoLookup {
  fun url(address: String): String =
    "https://ipwho.is/$address?fields=success,country,region,city,latitude,longitude,connection"
}

data class ParsedDnsPacket(
  val sourceAddress: ByteArray,
  val destinationAddress: ByteArray,
  val sourcePort: Int,
  val destinationPort: Int,
  val payload: ByteArray,
)

object DnsPacket {
  fun parseIpv4Udp(data: ByteArray, size: Int): ParsedDnsPacket? {
    if (size < 28 || (data[0].toInt() ushr 4) != 4 || (data[9].toInt() and 0xff) != 17) return null
    val header = (data[0].toInt() and 0x0f) * 4
    if (header < 20 || size < header + 8) return null
    val sourcePort = u16(data, header)
    val destinationPort = u16(data, header + 2)
    val length = u16(data, header + 4).coerceAtMost(size - header)
    if (length < 8) return null
    return ParsedDnsPacket(data.copyOfRange(12, 16), data.copyOfRange(16, 20), sourcePort, destinationPort, data.copyOfRange(header + 8, header + length))
  }

  fun queryName(dns: ByteArray): String {
    if (dns.size < 13) return ""
    return readName(dns, 12).first
  }

  fun answerAddresses(dns: ByteArray): List<String> {
    if (dns.size < 12) return emptyList()
    var offset = 12
    repeat(u16(dns, 4)) { offset = skipName(dns, offset) + 4; if (offset > dns.size) return emptyList() }
    val answers = mutableListOf<String>()
    repeat(u16(dns, 6)) {
      offset = skipName(dns, offset)
      if (offset + 10 > dns.size) return@repeat
      val type = u16(dns, offset); offset += 8
      val length = u16(dns, offset); offset += 2
      if (offset + length > dns.size) return@repeat
      if (type == 1 && length == 4) answers += InetAddress.getByAddress(dns.copyOfRange(offset, offset + 4)).hostAddress.orEmpty()
      if (type == 28 && length == 16) answers += InetAddress.getByAddress(dns.copyOfRange(offset, offset + 16)).hostAddress.orEmpty()
      offset += length
    }
    return answers.distinct()
  }

  fun ipv4UdpResponse(request: ParsedDnsPacket, dns: ByteArray): ByteArray {
    val total = 20 + 8 + dns.size
    val packet = ByteArray(total)
    packet[0] = 0x45
    packet[2] = (total ushr 8).toByte(); packet[3] = total.toByte()
    packet[6] = 0x40; packet[8] = 64; packet[9] = 17
    request.destinationAddress.copyInto(packet, 12); request.sourceAddress.copyInto(packet, 16)
    packet[20] = (request.destinationPort ushr 8).toByte(); packet[21] = request.destinationPort.toByte()
    packet[22] = (request.sourcePort ushr 8).toByte(); packet[23] = request.sourcePort.toByte()
    val udpLength = 8 + dns.size
    packet[24] = (udpLength ushr 8).toByte(); packet[25] = udpLength.toByte()
    dns.copyInto(packet, 28)
    putChecksum(packet, 10, checksum(packet, 0, 20))
    putChecksum(packet, 26, udpChecksum(packet))
    return packet
  }

  private fun udpChecksum(packet: ByteArray): Int {
    var sum = 0L
    fun add(offset: Int) { sum += u16(packet, offset).toLong() }
    for (offset in 12 until 20 step 2) add(offset)
    sum += 17; sum += packet.size - 20
    for (offset in 20 until packet.size - 1 step 2) add(offset)
    if ((packet.size - 20) % 2 == 1) sum += (packet.last().toInt() and 0xff) shl 8
    while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
    val value = sum.inv().toInt() and 0xffff
    return if (value == 0) 0xffff else value
  }

  private fun checksum(data: ByteArray, start: Int, length: Int): Int {
    var sum = 0L
    var index = start
    while (index + 1 < start + length) { sum += u16(data, index); index += 2 }
    if (index < start + length) sum += (data[index].toInt() and 0xff) shl 8
    while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
    return sum.inv().toInt() and 0xffff
  }

  private fun putChecksum(data: ByteArray, offset: Int, value: Int) { data[offset] = (value ushr 8).toByte(); data[offset + 1] = value.toByte() }
  private fun u16(data: ByteArray, offset: Int) = if (offset + 1 >= data.size) 0 else ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)
  private fun skipName(data: ByteArray, start: Int) = readName(data, start).second
  private fun readName(data: ByteArray, start: Int): Pair<String, Int> {
    val labels = mutableListOf<String>(); var cursor = start; var next = -1; var guard = 0
    while (cursor in data.indices && guard++ < 64) {
      val length = data[cursor].toInt() and 0xff
      if (length == 0) { cursor++; break }
      if (length and 0xC0 == 0xC0) {
        if (cursor + 1 >= data.size) break
        if (next < 0) next = cursor + 2
        cursor = ((length and 0x3f) shl 8) or (data[cursor + 1].toInt() and 0xff)
      } else {
        cursor++
        if (cursor + length > data.size) break
        labels += String(data, cursor, length, Charsets.UTF_8); cursor += length
      }
    }
    return labels.joinToString(".") to if (next >= 0) next else cursor
  }
}
