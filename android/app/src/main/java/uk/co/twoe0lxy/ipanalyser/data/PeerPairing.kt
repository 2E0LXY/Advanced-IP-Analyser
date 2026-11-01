package uk.co.twoe0lxy.ipanalyser.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class PeerConfig(val desktopAddress: String, val token: String, val deviceId: String)

class PeerPairing(private val context: Context) {
  private val preferences = context.getSharedPreferences("lan_peer", Context.MODE_PRIVATE)
  private var bridge: PeerBridge? = null

  fun load(): PeerConfig? {
    val encrypted = preferences.getString("config", null) ?: return null
    return runCatching {
      val decoded = Base64.getDecoder().decode(encrypted)
      val ivSize = decoded.first().toInt() and 0xff
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, decoded.copyOfRange(1, 1 + ivSize)))
      val json = JSONObject(String(cipher.doFinal(decoded.copyOfRange(1 + ivSize, decoded.size)), Charsets.UTF_8))
      PeerConfig(json.getString("desktop"), json.getString("token"), json.getString("device"))
    }.getOrNull()
  }

  suspend fun pair(desktopInput: String, token: String): PeerConfig = withContext(Dispatchers.IO) {
    require(token.length >= 32) { "Enter the private pairing token shown on the desktop." }
    val existing = load()
    val config = PeerConfig(normalizeDesktop(desktopInput), token.trim(), existing?.deviceId ?: UUID.randomUUID().toString())
    val localIp = NetworkScanner(context).networkInfo().localIp
    require(localIp != "Unavailable") { "Connect Android to the same LAN first." }
    val response = request(config, "/api/pair", JSONObject().put("peer_address", localIp).toString())
    val payload = JSONObject(response)
    require(payload.optBoolean("paired")) { payload.optString("error", "Pairing was declined.") }
    save(config)
    config
  }

  suspend fun scanDesktop(target: String): String = withContext(Dispatchers.IO) {
    val config = load() ?: throw IllegalStateException("Pair with the desktop first.")
    request(config, "/api/scan", JSONObject().put("target", target).toString())
  }

  suspend fun revoke(): String = withContext(Dispatchers.IO) {
    val config = load()
    val result = if (config != null) runCatching { request(config, "/api/pair/revoke", "{}") }.getOrNull() else null
    stopBridge()
    preferences.edit().remove("config").apply()
    result ?: "Pairing removed from Android. Use Revoke access on the desktop if it was offline."
  }

  fun startBridge(onStatus: (String) -> Unit) {
    val config = load() ?: throw IllegalStateException("Pair with the desktop first.")
    if (bridge != null) return
    bridge = PeerBridge(context, config, onStatus).also { it.start() }
  }

  fun stopBridge() {
    bridge?.close()
    bridge = null
  }

  private fun save(config: PeerConfig) {
    val json = JSONObject().put("desktop", config.desktopAddress).put("token", config.token).put("device", config.deviceId)
      .toString().toByteArray()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey())
    val encrypted = cipher.doFinal(json)
    val packed = byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + encrypted
    preferences.edit().putString("config", Base64.getEncoder().encodeToString(packed)).apply()
  }

  private fun secretKey(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (store.getKey("advanced_ip_pairing", null) as? SecretKey)?.let { return it }
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(KeyGenParameterSpec.Builder(
      "advanced_ip_pairing",
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    ).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
    return generator.generateKey()
  }

  private fun normalizeDesktop(value: String): String {
    val clean = value.trim().removePrefix("http://").removePrefix("https://").substringBefore('/').substringBefore(':')
    require(clean.isNotBlank()) { "Enter the desktop LAN address." }
    val address = java.net.InetAddress.getByName(clean)
    require(address.isSiteLocalAddress && address is Inet4Address) { "The desktop must use a private IPv4 LAN address." }
    return clean
  }

  private fun request(config: PeerConfig, path: String, body: String): String {
    val bytes = body.toByteArray(StandardCharsets.UTF_8)
    val timestamp = (System.currentTimeMillis() / 1000).toString()
    val nonce = randomToken(18)
    val signature = sign(config.token, "POST", path, timestamp, nonce, config.deviceId, bytes)
    val connection = URL("http://${config.desktopAddress}:18796$path").openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.connectTimeout = 8_000
    connection.readTimeout = 90_000
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "application/json")
    connection.setRequestProperty("X-Peer-Device", config.deviceId)
    connection.setRequestProperty("X-Peer-Timestamp", timestamp)
    connection.setRequestProperty("X-Peer-Nonce", nonce)
    connection.setRequestProperty("X-Peer-Signature", signature)
    connection.outputStream.use { it.write(bytes) }
    val code = connection.responseCode
    val response = (if (code < 400) connection.inputStream else connection.errorStream).bufferedReader().use { it.readText() }
    connection.disconnect()
    if (code >= 400) throw IllegalStateException(runCatching { JSONObject(response).optString("error") }.getOrDefault(response))
    return response
  }

  companion object {
    fun sign(token: String, method: String, path: String, timestamp: String, nonce: String, device: String, body: ByteArray): String {
      val digest = java.security.MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) }
      val message = listOf(method, path, timestamp, nonce, device, digest).joinToString("\n")
      val mac = Mac.getInstance("HmacSHA256")
      mac.init(SecretKeySpec(token.toByteArray(), "HmacSHA256"))
      return mac.doFinal(message.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun randomToken(bytes: Int): String = ByteArray(bytes).also(SecureRandom()::nextBytes).let {
      Base64.getUrlEncoder().withoutPadding().encodeToString(it)
    }
  }
}

private class PeerBridge(
  private val context: Context,
  private val config: PeerConfig,
  private val status: (String) -> Unit,
) {
  @Volatile private var running = true
  private var server: ServerSocket? = null
  private val nonces = ConcurrentHashMap<String, Long>()

  fun start() {
    Thread({
      try {
        server = ServerSocket(18797)
        status("Android peer listener ready on port 18797")
        while (running) server?.accept()?.let { socket -> Thread({ handle(socket) }, "peer-request").start() }
      } catch (error: Exception) {
        if (running) status(error.message ?: "Android peer listener stopped")
      }
    }, "android-peer-bridge").apply { isDaemon = true }.start()
  }

  fun close() { running = false; runCatching { server?.close() } }

  private fun handle(socket: Socket) {
    socket.use { client ->
      client.soTimeout = 10_000
      if (!client.inetAddress.isSiteLocalAddress) return
      val reader = client.getInputStream().bufferedReader()
      val requestLine = reader.readLine() ?: return
      val parts = requestLine.split(' ')
      if (parts.size < 2) return
      val headers = mutableMapOf<String, String>()
      while (true) {
        val line = reader.readLine() ?: return
        if (line.isEmpty()) break
        val index = line.indexOf(':')
        if (index > 0) headers[line.substring(0, index).trim().lowercase()] = line.substring(index + 1).trim()
      }
      val length = headers["content-length"]?.toIntOrNull()?.coerceIn(0, 8192) ?: 0
      val chars = CharArray(length)
      var read = 0
      while (read < length) {
        val count = reader.read(chars, read, length - read)
        if (count < 0) break
        read += count
      }
      val body = String(chars, 0, read).toByteArray()
      val timestamp = headers["x-peer-timestamp"].orEmpty()
      val nonce = headers["x-peer-nonce"].orEmpty()
      val signature = headers["x-peer-signature"].orEmpty()
      val now = System.currentTimeMillis() / 1000
      val validTime = timestamp.toLongOrNull()?.let { kotlin.math.abs(now - it) <= 60 } == true
      nonces.entries.removeIf { now - it.value > 120 }
      val expected = PeerPairing.sign(config.token, parts[0], parts[1], timestamp, nonce, "desktop", body)
      if (!validTime || nonce.length < 16 || nonces.putIfAbsent(nonce, now) != null || !java.security.MessageDigest.isEqual(expected.toByteArray(), signature.toByteArray())) {
        respond(client, 401, JSONObject().put("error", "authentication failed").toString()); return
      }
      if (parts[0] != "POST" || parts[1] != "/api/scan") {
        respond(client, 404, JSONObject().put("error", "unknown action").toString()); return
      }
      try {
      val scanner = NetworkScanner(context)
      val network = scanner.networkInfo()
      val hosts = runBlocking { scanner.scanLan(network) { _, _ -> } }
      val array = JSONArray()
      hosts.forEach { host -> array.put(JSONObject().put("address", host.address).put("hostname", host.hostname)
        .put("mac", host.macAddress).put("latency_ms", host.latencyMs).put("ports", JSONArray(host.openPorts))) }
      respond(client, 200, JSONObject().put("source", "android").put("range", network.range).put("hosts", array).toString())
      status("Desktop requested a scan · ${hosts.size} devices found")
      } catch (error: Exception) {
        respond(client, 500, JSONObject().put("error", error.message ?: "scan failed").toString())
      }
    }
  }

  private fun respond(socket: Socket, code: Int, body: String) {
    val bytes = body.toByteArray()
    val reason = if (code == 200) "OK" else "Error"
    socket.getOutputStream().write("HTTP/1.1 $code $reason\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray() + bytes)
  }
}
