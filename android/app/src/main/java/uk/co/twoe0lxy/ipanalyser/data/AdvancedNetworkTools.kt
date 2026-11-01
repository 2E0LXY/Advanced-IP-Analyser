package uk.co.twoe0lxy.ipanalyser.data

import android.content.Context
import android.net.ConnectivityManager
import android.os.SystemClock
import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.JSch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.net.ssl.SSLSocketFactory

data class SmartDevice(
  val name: String,
  val address: String,
  val model: String,
  val deviceId: String,
  val isOn: Boolean?,
)

class AdvancedNetworkTools(private val context: Context) {
  suspend fun customPortScan(target: String, specification: String): String = coroutineScope {
    val host = cleanHost(target)
    val ports = parsePorts(specification)
    require(ports.isNotEmpty()) { "Enter ports such as 22,80,443 or 1-1024." }
    require(ports.size <= 4096) { "A mobile scan is limited to 4,096 ports at a time." }
    val semaphore = Semaphore(96)
    val started = SystemClock.elapsedRealtime()
    val open = ports.map { port ->
      async(Dispatchers.IO) {
        semaphore.withPermit {
          try {
            Socket().use { it.connect(InetSocketAddress(host, port), 450) }
            port
          } catch (_: Exception) { null }
        }
      }
    }.awaitAll().filterNotNull().sorted()
    val elapsed = SystemClock.elapsedRealtime() - started
    if (open.isEmpty()) "No open TCP ports found in ${ports.size} checked (${elapsed} ms)."
    else "${open.size} open of ${ports.size} checked (${elapsed} ms)\n" +
      open.joinToString("\n") { HostResult.portName(it) }
  }

  suspend fun traceroute(target: String): String = withContext(Dispatchers.IO) {
    val host = cleanHost(target)
    val destination = InetAddress.getByName(host).hostAddress ?: host
    val lines = mutableListOf("Tracing to $host [$destination]")
    for (ttl in 1..24) {
      val started = SystemClock.elapsedRealtime()
      val process = runCatching {
        ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "1", "-t", ttl.toString(), destination)
          .redirectErrorStream(true).start()
      }.getOrNull() ?: break
      val output = process.inputStream.bufferedReader().use { it.readText().take(16_000) }
      process.waitFor()
      val elapsed = SystemClock.elapsedRealtime() - started
      val hop = Regex("(?:from|From)\\s+([^\\s:]+)").find(output)?.groupValues?.get(1)
        ?: Regex("64 bytes from\\s+([^\\s:]+)").find(output)?.groupValues?.get(1)
      lines += "%2d  %-40s %4d ms".format(ttl, hop ?: "*", elapsed)
      if (hop == destination || "64 bytes from" in output) break
    }
    if (lines.size == 1) "Traceroute is unavailable on this Android build." else lines.joinToString("\n")
  }

  suspend fun connections(): String = withContext(Dispatchers.IO) {
    val rows = listOf("/proc/net/tcp" to "TCP4", "/proc/net/tcp6" to "TCP6", "/proc/net/udp" to "UDP4")
      .flatMap { (path, protocol) ->
        runCatching { java.io.File(path).readLines().drop(1) }.getOrDefault(emptyList()).mapNotNull { line ->
          val fields = line.trim().split(Regex("\\s+"))
          if (fields.size < 4) return@mapNotNull null
          val local = decodeSocketAddress(fields[1])
          val remote = decodeSocketAddress(fields[2])
          val state = tcpState(fields[3])
          "$protocol  $local  →  $remote  $state"
        }
      }
    if (rows.isEmpty()) {
      "Android restricts the system connection table for ordinary apps. App traffic remains visible through Android Settings → Network & internet → App data usage."
    } else rows.take(250).joinToString("\n")
  }

  suspend fun tlsInspection(target: String): String = withContext(Dispatchers.IO) {
    val raw = target.trim().removePrefix("https://").substringBefore('/').ifBlank {
      throw IllegalArgumentException("Enter a TLS hostname.")
    }
    val host = raw.substringBefore(':')
    val port = raw.substringAfter(':', "443").toIntOrNull() ?: 443
    val socket = SSLSocketFactory.getDefault().createSocket() as javax.net.ssl.SSLSocket
    try {
      socket.soTimeout = 7_000
      socket.connect(InetSocketAddress(host, port), 7_000)
      socket.startHandshake()
      val session = socket.session
      val format = SimpleDateFormat("yyyy-MM-dd HH:mm z", Locale.UK)
      buildString {
        appendLine("Protocol: ${session.protocol}")
        appendLine("Cipher: ${session.cipherSuite}")
        session.peerCertificates.filterIsInstance<X509Certificate>().forEachIndexed { index, cert ->
          appendLine("\nCertificate ${index + 1}")
          appendLine("Subject: ${cert.subjectX500Principal.name}")
          appendLine("Issuer: ${cert.issuerX500Principal.name}")
          appendLine("Valid: ${format.format(cert.notBefore)}")
          appendLine("Expires: ${format.format(cert.notAfter)}")
          appendLine("SHA-256: ${certificateFingerprint(cert)}")
        }
      }.trim()
    } finally { socket.close() }
  }

  suspend fun emailSecurity(domainInput: String): String = withContext(Dispatchers.IO) {
    val domain = domainInput.trim().substringAfter('@').removePrefix("https://").substringBefore('/').trim('.')
    require(domain.isNotBlank()) { "Enter an email domain." }
    val mx = dnsQuery(domain, 15)
    val spf = dnsQuery(domain, 16).filter { it.contains("v=spf1", true) }
    val dmarc = dnsQuery("_dmarc.$domain", 16).filter { it.contains("v=DMARC1", true) }
    buildString {
      appendLine("MX records")
      appendLine(mx.ifEmpty { listOf("Not found") }.joinToString("\n"))
      appendLine("\nSPF")
      appendLine(spf.firstOrNull() ?: "Not found")
      appendLine("\nDMARC")
      appendLine(dmarc.firstOrNull() ?: "Not found")
      append("\nDKIM requires a selector; test selector._domainkey.$domain with DNS lookup.")
    }
  }

  suspend fun wakeOnLan(macInput: String, broadcastInput: String): String = withContext(Dispatchers.IO) {
    val mac = macInput.trim().split(':', '-').map { it.toIntOrNull(16) ?: -1 }
    require(mac.size == 6 && mac.all { it in 0..255 }) { "Enter a MAC address such as AA:BB:CC:DD:EE:FF." }
    val packet = ByteArray(102) { index -> if (index < 6) 0xFF.toByte() else mac[(index - 6) % 6].toByte() }
    val broadcast = broadcastInput.trim().ifBlank { "255.255.255.255" }
    DatagramSocket().use { socket ->
      socket.broadcast = true
      repeat(3) { socket.send(DatagramPacket(packet, packet.size, InetAddress.getByName(broadcast), 9)) }
    }
    "Wake-on-LAN packet sent three times to $broadcast for ${macInput.uppercase()}."
  }

  suspend fun sshCommand(hostInput: String, username: String, password: String, command: String): String = withContext(Dispatchers.IO) {
    val (host, port) = splitHostPort(hostInput, 22)
    require(username.isNotBlank()) { "Enter the SSH username." }
    require(command.isNotBlank()) { "Enter a command." }
    val session = JSch().getSession(username, host, port).apply {
      setPassword(password)
      setConfig("StrictHostKeyChecking", "ask")
      setConfig("PreferredAuthentications", "password,keyboard-interactive")
      setUserInfo(ConfirmingUserInfo(password))
      timeout = 10_000
    }
    try {
      session.connect(10_000)
      val channel = session.openChannel("exec") as ChannelExec
      val output = ByteArrayOutputStream()
      val errors = ByteArrayOutputStream()
      channel.setCommand(command)
      channel.outputStream = output
      channel.setErrStream(errors)
      channel.connect(8_000)
      while (!channel.isClosed) Thread.sleep(40)
      val text = output.toString(Charsets.UTF_8.name()).trim()
      val error = errors.toString(Charsets.UTF_8.name()).trim()
      channel.disconnect()
      listOf(text, error).filter { it.isNotBlank() }.joinToString("\n").ifBlank { "Command completed with no output." }
    } finally { session.disconnect() }
  }

  suspend fun sftpList(hostInput: String, username: String, password: String, path: String): String = withContext(Dispatchers.IO) {
    val (host, port) = splitHostPort(hostInput, 22)
    val session = JSch().getSession(username, host, port).apply {
      setPassword(password)
      setConfig("StrictHostKeyChecking", "ask")
      setConfig("PreferredAuthentications", "password,keyboard-interactive")
      setUserInfo(ConfirmingUserInfo(password))
    }
    try {
      session.connect(10_000)
      val channel = session.openChannel("sftp") as ChannelSftp
      channel.connect(8_000)
      @Suppress("UNCHECKED_CAST")
      val entries = channel.ls(path.ifBlank { "." }) as java.util.Vector<ChannelSftp.LsEntry>
      val output = entries.filter { it.filename !in setOf(".", "..") }.joinToString("\n") {
        "${if (it.attrs.isDir) "DIR " else "FILE"}  ${it.attrs.size.toString().padStart(10)}  ${it.filename}"
      }
      channel.disconnect()
      output.ifBlank { "Directory is empty." }
    } finally { session.disconnect() }
  }

  suspend fun discoverKasaDevices(broadcast: String = "255.255.255.255"): List<SmartDevice> = withContext(Dispatchers.IO) {
    val request = kasaEncrypt("{\"system\":{\"get_sysinfo\":{}}}")
    val devices = linkedMapOf<String, SmartDevice>()
    DatagramSocket().use { socket ->
      socket.broadcast = true
      socket.soTimeout = 700
      socket.send(DatagramPacket(request, request.size, InetAddress.getByName(broadcast), 9999))
      val deadline = SystemClock.elapsedRealtime() + 2_500
      while (SystemClock.elapsedRealtime() < deadline) {
        val buffer = ByteArray(8192)
        val response = DatagramPacket(buffer, buffer.size)
        try {
          socket.receive(response)
          val json = kasaDecrypt(response.data.copyOf(response.length))
          val address = response.address.hostAddress ?: continue
          val name = jsonValue(json, "alias") ?: jsonValue(json, "dev_name") ?: "TP-Link device"
          val model = jsonValue(json, "model") ?: "Unknown model"
          val id = jsonValue(json, "deviceId") ?: address
          val relay = Regex("\"relay_state\"\\s*:\\s*(\\d)").find(json)?.groupValues?.get(1)?.toIntOrNull()
          devices[address] = SmartDevice(name, address, model, id, relay?.let { it == 1 })
        } catch (_: java.net.SocketTimeoutException) { break }
      }
    }
    devices.values.toList()
  }

  suspend fun setKasaPower(device: SmartDevice, enabled: Boolean): String = withContext(Dispatchers.IO) {
    val payload = kasaEncrypt("{\"system\":{\"set_relay_state\":{\"state\":${if (enabled) 1 else 0}}}}")
    DatagramSocket().use { socket ->
      socket.soTimeout = 1_500
      socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(device.address), 9999))
      val response = DatagramPacket(ByteArray(4096), 4096)
      socket.receive(response)
    }
    "${device.name} turned ${if (enabled) "on" else "off"}."
  }

  private fun cleanHost(value: String): String = value.trim().removePrefix("http://").removePrefix("https://")
    .substringBefore('/').substringBefore(':').ifBlank { throw IllegalArgumentException("Enter a host or IP address.") }

  private fun parsePorts(value: String): List<Int> = value.split(',').flatMap { part ->
    val token = part.trim()
    if ('-' in token) {
      val start = token.substringBefore('-').toIntOrNull() ?: return@flatMap emptyList()
      val end = token.substringAfter('-').toIntOrNull() ?: return@flatMap emptyList()
      if (start > end) emptyList() else (start..end).filter { it in 1..65535 }
    } else listOfNotNull(token.toIntOrNull()?.takeIf { it in 1..65535 })
  }.distinct().sorted()

  private fun splitHostPort(value: String, defaultPort: Int): Pair<String, Int> {
    val clean = value.trim().removePrefix("ssh://").substringBefore('/')
    val host = clean.substringBefore(':').ifBlank { throw IllegalArgumentException("Enter an SSH host.") }
    return host to (clean.substringAfter(':', defaultPort.toString()).toIntOrNull() ?: defaultPort)
  }

  private fun decodeSocketAddress(value: String): String {
    val parts = value.split(':')
    if (parts.size != 2) return value
    val address = parts[0]
    val port = parts[1].toIntOrNull(16) ?: 0
    val host = if (address.length == 8) address.chunked(2).reversed().joinToString(".") { it.toInt(16).toString() } else "IPv6"
    return "$host:$port"
  }

  private fun tcpState(hex: String): String = mapOf("01" to "ESTABLISHED", "02" to "SYN_SENT", "03" to "SYN_RECV", "06" to "TIME_WAIT", "0A" to "LISTEN")[hex] ?: hex

  private fun certificateFingerprint(cert: X509Certificate): String = MessageDigest.getInstance("SHA-256")
    .digest(cert.encoded).joinToString(":") { "%02X".format(it) }

  private fun dnsServer(): InetAddress {
    val manager = context.getSystemService(ConnectivityManager::class.java)
    return manager.getLinkProperties(manager.activeNetwork)?.dnsServers?.firstOrNull()
      ?: InetAddress.getByName("1.1.1.1")
  }

  private fun dnsQuery(name: String, type: Int): List<String> {
    val id = (System.nanoTime() and 0xffff).toInt()
    val output = ByteArrayOutputStream()
    output.write(byteArrayOf((id shr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    name.split('.').forEach { label -> output.write(label.length); output.write(label.toByteArray()) }
    output.write(0); output.write(type shr 8); output.write(type); output.write(0); output.write(1)
    val response = ByteArray(4096)
    val length = DatagramSocket().use { socket ->
      socket.soTimeout = 3_000
      val request = output.toByteArray()
      socket.send(DatagramPacket(request, request.size, dnsServer(), 53))
      val packet = DatagramPacket(response, response.size)
      socket.receive(packet)
      packet.length
    }
    if (length < 12) return emptyList()
    var offset = 12
    val questions = readU16(response, 4)
    val answers = readU16(response, 6)
    repeat(questions) { offset = skipDnsName(response, offset); offset += 4 }
    val result = mutableListOf<String>()
    repeat(answers) {
      offset = skipDnsName(response, offset)
      if (offset + 10 > length) return@repeat
      val recordType = readU16(response, offset); offset += 8
      val dataLength = readU16(response, offset); offset += 2
      val end = (offset + dataLength).coerceAtMost(length)
      if (recordType == type) {
        when (type) {
          15 -> if (dataLength > 2) result += "${readU16(response, offset)} ${readDnsName(response, offset + 2).first}"
          16 -> {
            var cursor = offset
            val text = StringBuilder()
            while (cursor < end) {
              val size = response[cursor].toInt() and 0xff; cursor++
              if (cursor + size > end) break
              text.append(String(response, cursor, size, Charsets.UTF_8)); cursor += size
            }
            if (text.isNotEmpty()) result += text.toString()
          }
        }
      }
      offset = end
    }
    return result
  }

  private fun readU16(data: ByteArray, offset: Int) = ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)
  private fun skipDnsName(data: ByteArray, start: Int): Int = readDnsName(data, start).second
  private fun readDnsName(data: ByteArray, start: Int): Pair<String, Int> {
    val labels = mutableListOf<String>()
    var cursor = start
    var next = -1
    var guard = 0
    while (cursor in data.indices && guard++ < 64) {
      val length = data[cursor].toInt() and 0xff
      if (length == 0) { cursor++; break }
      if (length and 0xC0 == 0xC0) {
        if (next < 0) next = cursor + 2
        cursor = ((length and 0x3f) shl 8) or (data[cursor + 1].toInt() and 0xff)
      } else {
        cursor++
        labels += String(data, cursor, length, Charsets.UTF_8)
        cursor += length
      }
    }
    return labels.joinToString(".") to if (next >= 0) next else cursor
  }

  private fun kasaEncrypt(text: String): ByteArray {
    var key = 0xAB
    return text.toByteArray().map { byte -> ((byte.toInt() xor key).also { key = it }) .toByte() }.toByteArray()
  }

  private fun kasaDecrypt(data: ByteArray): String {
    var key = 0xAB
    return data.map { byte -> ((byte.toInt() xor key).also { key = byte.toInt() and 0xff }).toByte() }.toByteArray().toString(Charsets.UTF_8)
  }

  private fun jsonValue(json: String, key: String): String? = Regex("\"${Regex.escape(key)}\"\\s*:\\s*\"([^\"]*)\"")
    .find(json)?.groupValues?.get(1)
}

private class ConfirmingUserInfo(private val password: String) : com.jcraft.jsch.UserInfo, com.jcraft.jsch.UIKeyboardInteractive {
  override fun getPassword() = password
  override fun promptYesNo(message: String) = true
  override fun getPassphrase(): String? = null
  override fun promptPassphrase(message: String) = false
  override fun promptPassword(message: String) = true
  override fun showMessage(message: String) = Unit
  override fun promptKeyboardInteractive(destination: String?, name: String?, instruction: String?, prompt: Array<out String>?, echo: BooleanArray?): Array<String> =
    Array(prompt?.size ?: 0) { password }
}
