package uk.co.twoe0lxy.ipanalyser.data

/**
 * LAN exposure prioritisation, not vulnerability detection.
 * No Internet request, privileged operation or router change is performed here.
 */
data class DeviceExposure(
  val host: HostResult,
  val score: Int,
  val level: String,
  val evidence: List<String>,
)

data class SavedNetworkScan(
  val timestampMillis: Long,
  val hosts: List<HostResult>,
)

data class NetworkChanges(
  val newDevices: Int,
  val missingDevices: Int,
  val changedServices: Int,
)

data class CyberOverview(
  val devices: List<DeviceExposure>,
  val observedPorts: Int,
  val severityCounts: Map<String, Int>,
  val changes: NetworkChanges?,
) {
  val priorityDevices: Int get() = (severityCounts["Critical"] ?: 0) + (severityCounts["High"] ?: 0)
}

object CyberRiskEngine {
  // Align heuristics with the desktop's network_intelligence.py where Android has the evidence.
  private val priorityPorts = mapOf(
    21 to (14 to "Unencrypted FTP service"),
    23 to (24 to "Unencrypted Telnet service"),
    25 to (8 to "Mail service"),
    111 to (8 to "RPC service"),
    135 to (8 to "Windows RPC service"),
    139 to (10 to "Legacy NetBIOS service"),
    445 to (14 to "SMB file sharing"),
    1433 to (12 to "Database service"),
    3306 to (12 to "Database service"),
    3389 to (14 to "Remote desktop service"),
    5432 to (12 to "Database service"),
    5900 to (14 to "Remote display service"),
  )

  fun assess(hosts: List<HostResult>, previous: List<HostResult>? = null): CyberOverview {
    val current = hosts.distinctBy { it.address }
    val devices = current.map { host ->
      val ports = host.openPorts.filter { it in 1..65535 }.distinct().sorted()
      val reasons = mutableListOf<String>()
      var score = 0
      for (port in ports) {
        val weight = priorityPorts[port] ?: continue
        score += weight.first
        reasons += "TCP $port: ${weight.second} (+${weight.first})"
      }
      if (ports.size >= 12) {
        score += 12
        reasons += "Large local service surface (+12)"
      } else if (ports.size >= 6) {
        score += 6
        reasons += "Multiple local services (+6)"
      }
      if (reasons.isEmpty()) reasons += "No elevated LAN port indicators detected"
      val bounded = score.coerceIn(0, 100)
      val level = when {
        bounded >= 70 -> "Critical"
        bounded >= 45 -> "High"
        bounded >= 20 -> "Medium"
        else -> "Low"
      }
      DeviceExposure(host, bounded, level, reasons)
    }.sortedWith(compareByDescending<DeviceExposure> { it.score }.thenBy { it.host.address })

    val levelCounts = listOf("Critical", "High", "Medium", "Low")
      .associateWith { level -> devices.count { it.level == level } }
    val changes = previous?.let { older ->
      val before = older.associateBy { it.address }
      val now = current.associateBy { it.address }
      NetworkChanges(
        newDevices = now.keys.minus(before.keys).size,
        missingDevices = before.keys.minus(now.keys).size,
        changedServices = now.keys.intersect(before.keys).count { address ->
          now.getValue(address).openPorts.toSet() != before.getValue(address).openPorts.toSet()
        },
      )
    }
    return CyberOverview(
      devices = devices,
      observedPorts = current.sumOf { it.openPorts.filter { port -> port in 1..65535 }.distinct().size },
      severityCounts = levelCounts,
      changes = changes,
    )
  }
}
