package uk.co.twoe0lxy.ipanalyser.data

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class InventoryStore(context: Context) {
  private val preferences = context.getSharedPreferences("network_inventory", Context.MODE_PRIVATE)

  fun favorites(): Set<String> = preferences.getStringSet("favorites", emptySet())?.toSet().orEmpty()

  fun toggleFavorite(address: String): Set<String> {
    val values = favorites().toMutableSet()
    if (!values.add(address)) values.remove(address)
    preferences.edit().putStringSet("favorites", values).apply()
    return values
  }

  fun saveScan(hosts: List<HostResult>) {
    val history = JSONArray(preferences.getString("history", "[]"))
    val record = JSONObject().put("time", System.currentTimeMillis()).put("hosts", JSONArray().apply {
      hosts.forEach { host -> put(hostJson(host)) }
    })
    val updated = JSONArray().put(record)
    for (index in 0 until minOf(history.length(), 19)) updated.put(history.get(index))
    preferences.edit().putString("history", updated.toString()).apply()
  }

  fun historyCount(): Int = runCatching { JSONArray(preferences.getString("history", "[]")).length() }.getOrDefault(0)

  /**
   * Read at most twenty previously saved LAN inventories. This never performs a
   * scan or transmits data; invalid legacy entries are safely skipped.
   */
  fun recentScans(limit: Int = 20): List<SavedNetworkScan> {
    val history = runCatching { JSONArray(preferences.getString("history", "[]")) }
      .getOrDefault(JSONArray())
    return (0 until minOf(history.length(), limit.coerceIn(0, 20))).mapNotNull { index ->
      val saved = history.optJSONObject(index) ?: return@mapNotNull null
      val timestamp = saved.optLong("time", 0L)
      val rows = saved.optJSONArray("hosts") ?: return@mapNotNull null
      val hosts = (0 until minOf(rows.length(), 1024)).mapNotNull { hostIndex ->
        val obj = rows.optJSONObject(hostIndex) ?: return@mapNotNull null
        val address = obj.optString("address").take(128)
        val octets = address.split('.').mapNotNull { it.toIntOrNull() }
        if (octets.size != 4 || octets.any { it !in 0..255 }) return@mapNotNull null
        val rawPorts = obj.optJSONArray("open_ports") ?: JSONArray()
        val ports = (0 until minOf(rawPorts.length(), 64)).mapNotNull { portIndex ->
          val port = rawPorts.optInt(portIndex, -1)
          port.takeIf { it in 1..65535 }
        }
        HostResult(
          address = address,
          hostname = obj.optString("hostname").take(255),
          macAddress = obj.optString("mac").take(32),
          latencyMs = obj.optLong("latency_ms", 0L).coerceAtLeast(0L),
          openPorts = ports,
        )
      }
      SavedNetworkScan(timestamp, hosts)
    }
  }

  companion object {
    fun json(hosts: List<HostResult>): String = JSONArray().apply { hosts.forEach { put(hostJson(it)) } }.toString(2)

    fun csv(hosts: List<HostResult>): String = buildString {
      appendLine("Address,Hostname,MAC,LatencyMs,OpenPorts")
      hosts.forEach { host -> appendLine(listOf(host.address, host.hostname, host.macAddress, host.latencyMs.toString(), host.openPorts.joinToString("|")).joinToString(",") { csvCell(it) }) }
    }

    fun topologySvg(hosts: List<HostResult>, gateway: String): String {
      val height = maxOf(220, 100 + hosts.size * 52)
      return buildString {
        append("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"900\" height=\"$height\" viewBox=\"0 0 900 $height\"><rect width=\"100%\" height=\"100%\" fill=\"#081724\"/><style>text{font-family:system-ui;fill:#ddecff}.node{fill:#102b42;stroke:#199cff;stroke-width:2}.link{stroke:#44627b}</style>")
        append("<rect class=\"node\" x=\"35\" y=\"${height / 2 - 30}\" width=\"180\" height=\"60\" rx=\"10\"/><text x=\"55\" y=\"${height / 2}\">Gateway $gateway</text>")
        hosts.forEachIndexed { index, host ->
          val y = 35 + index * 52
          append("<line class=\"link\" x1=\"215\" y1=\"${height / 2}\" x2=\"300\" y2=\"${y + 18}\"/><rect class=\"node\" x=\"300\" y=\"$y\" width=\"540\" height=\"38\" rx=\"8\"/>")
          append("<text x=\"315\" y=\"${y + 24}\">${xml(host.hostname.ifBlank { host.address })} · ${xml(host.address)} · ports ${host.openPorts.joinToString("/")}</text>")
        }
        append("</svg>")
      }
    }

    private fun hostJson(host: HostResult) = JSONObject().put("address", host.address).put("hostname", host.hostname)
      .put("mac", host.macAddress).put("latency_ms", host.latencyMs).put("open_ports", JSONArray(host.openPorts))

    private fun csvCell(value: String): String {
      // Hostnames and MACs come from the network; stop spreadsheets treating them as formulas.
      val safe = if (value.isNotEmpty() && value.trimStart().firstOrNull() in setOf('=', '+', '-', '@')) "'" + value else value
      return "\"${safe.replace("\"", "\"\"")}\""
    }
    private fun xml(value: String) = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
  }
}
