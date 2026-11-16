package uk.co.twoe0lxy.ipanalyser.ui.main

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import uk.co.twoe0lxy.ipanalyser.data.CyberOverview
import uk.co.twoe0lxy.ipanalyser.data.CyberRiskEngine
import uk.co.twoe0lxy.ipanalyser.data.DeviceExposure
import java.text.DateFormat
import java.util.Date

private val RiskRed = Color(0xFFF47E87)
private val RiskOrange = Color(0xFFFFA271)
private val RiskAmber = Color(0xFFFFC46A)
private val RiskGreen = Color(0xFF62D9AC)
private val PanelBg = Color(0xFF171F2B)
private val PanelBorder = Color(0xFF304054)

private fun riskColour(level: String) = when (level) {
  "Critical" -> RiskRed
  "High" -> RiskOrange
  "Medium" -> RiskAmber
  else -> RiskGreen
}

/**
 * Offline Android cyber overview. All data comes from current local scans or
 * history already saved on this phone. No cloud queries or privileged actions.
 */
@Composable
fun CyberPlatformPage(state: MainScreenUiState, onScan: () -> Unit, onOpenLan: () -> Unit) {
  val currentSession = state.hosts.isNotEmpty()
  val history = state.scanHistory
  val hosts = if (currentSession) state.hosts else history.firstOrNull()?.hosts.orEmpty()
  val previous = if (currentSession) history.firstOrNull()?.hosts else history.getOrNull(1)?.hosts
  val overview = CyberRiskEngine.assess(hosts, previous)
  val sourceLabel = when {
    currentSession -> "CURRENT SESSION"
    history.isNotEmpty() -> "SAVED SNAPSHOT"
    else -> "NO SCAN DATA"
  }
  val stamp = if (currentSession) "Scan results in this session" else history.firstOrNull()?.timestampMillis
    ?.takeIf { it > 0 }?.let { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(it)) }
    ?: "No previous scan"

  LazyColumn(
    modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 12.dp),
    verticalArrangement = Arrangement.spacedBy(13.dp),
  ) {
    item {
      Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Column(modifier = Modifier.weight(1f)) {
          Text("CYBER PLATFORM", fontSize = 22.sp, fontWeight = FontWeight.Bold)
          Text("Local network security overview", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
        }
        Text(sourceLabel, color = MaterialTheme.colorScheme.primary,
          fontWeight = FontWeight.Bold, fontSize = 10.sp,
          modifier = Modifier.padding(top = 6.dp))
      }
      Text(stamp, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    item {
      CyberPanel {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
          Icon(Icons.Outlined.Security, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(27.dp))
          Column {
            Text("Your network at a glance", fontWeight = FontWeight.Bold, fontSize = 17.sp)
            Text("Evidence-based local observations, not an Internet vulnerability test",
              fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        }
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          Button(onClick = onScan, enabled = !state.scanningLan, modifier = Modifier.weight(1f)) {
            Icon(Icons.Outlined.Search, null, modifier = Modifier.size(16.dp))
            Text(if (state.scanningLan) "Scanning…" else "Scan now", modifier = Modifier.padding(start = 5.dp), fontSize = 12.sp)
          }
          OutlinedButton(onClick = onOpenLan, modifier = Modifier.weight(1f)) {
            Text("LAN devices", fontSize = 12.sp)
          }
        }
      }
    }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(9.dp)) {
        CyberMetric("ASSETS", hosts.size.toString(), "discovered", MaterialTheme.colorScheme.primary, Modifier.weight(1f))
        CyberMetric("LAN PORTS", overview.observedPorts.toString(), "observed TCP", RiskAmber, Modifier.weight(1f))
      }
    }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(9.dp)) {
        CyberMetric("PRIORITY", overview.priorityDevices.toString(), "high / critical", RiskRed, Modifier.weight(1f))
        val changed = overview.changes?.let { it.newDevices + it.missingDevices + it.changedServices }
        CyberMetric("CHANGES", changed?.toString() ?: "—", if (changed == null) "no baseline" else "since prior scan",
          RiskGreen, Modifier.weight(1f))
      }
    }
    item {
      CyberPanel {
        Text("EXPOSURE PRIORITY", fontSize = 14.sp, fontWeight = FontWeight.Bold)
        Text("Heuristic LAN service indicators — not confirmed CVEs",
          fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(8.dp))
        listOf("Critical", "High", "Medium", "Low").forEach { level ->
          SeverityRow(level, overview)
        }
      }
    }
    item {
      CyberPanel {
        Text("DISCOVERY HISTORY", fontWeight = FontWeight.Bold, fontSize = 14.sp)
        Text("Devices recorded in your saved local scans", fontSize = 11.sp,
          color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(7.dp))
        val values = history.take(16).asReversed().map { it.hosts.size }
        if (values.isEmpty()) {
          Text("No historical scans saved yet", color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 12.sp, modifier = Modifier.padding(vertical = 20.dp))
        } else {
          DiscoveryTrend(values)
          Text("${values.size} scans · most recent: ${values.last()} devices",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        val changes = overview.changes
        if (changes != null) {
          Spacer(Modifier.height(8.dp))
          Text("${changes.newDevices} new · ${changes.missingDevices} missing · ${changes.changedServices} service changes",
            fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    }
    item {
      Text("DEVICES TO REVIEW", fontSize = 15.sp, fontWeight = FontWeight.Bold)
      Text("Ranked by observed LAN service exposure", fontSize = 11.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    if (overview.devices.isEmpty()) {
      item {
        CyberPanel {
          Icon(Icons.Outlined.Devices, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
          Text("No device observations yet. Scan your LAN to generate a security overview.",
            fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    } else {
      items(count = minOf(overview.devices.size, 25), key = { overview.devices[it].host.address }) { index ->
        DeviceExposureCard(overview.devices[index])
      }
      if (overview.devices.size > 25) {
        item {
          Text("Showing the highest-priority 25 of ${overview.devices.size} devices. Open LAN devices for the full list.",
            fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    }
    item {
      CyberPanel {
        Row(horizontalArrangement = Arrangement.spacedBy(9.dp)) {
          Icon(Icons.Outlined.WarningAmber, null, tint = RiskAmber, modifier = Modifier.size(21.dp))
          Column {
            Text("Assessment limits", fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text("CVE matching: Not assessed. Public IPv4/IPv6 exposure: Not verified. " +
              "A low LAN score does not mean a device is secure. " +
              "No router configuration changes or cloud uploads are made.",
              fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        }
      }
    }
  }
}

@Composable
private fun CyberPanel(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
  Card(
    modifier = Modifier.fillMaxWidth(),
    shape = RoundedCornerShape(13.dp),
    border = BorderStroke(1.dp, PanelBorder),
    colors = CardDefaults.cardColors(containerColor = PanelBg),
  ) {
    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp), content = content)
  }
}

@Composable
private fun CyberMetric(label: String, number: String, detail: String, accent: Color, modifier: Modifier) {
  Card(modifier = modifier, shape = RoundedCornerShape(12.dp),
    colors = CardDefaults.cardColors(containerColor = PanelBg), border = BorderStroke(1.dp, PanelBorder)) {
    Column(modifier = Modifier.fillMaxWidth().padding(13.dp)) {
      Text(label, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.Bold)
      Text(number, color = accent, fontSize = 27.sp, fontWeight = FontWeight.Bold)
      Text(detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
    }
  }
}

@Composable
private fun SeverityRow(level: String, overview: CyberOverview) {
  val count = overview.severityCounts[level] ?: 0
  Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
      horizontalArrangement = Arrangement.spacedBy(10.dp)) {
    Text(level, fontSize = 12.sp, modifier = Modifier.weight(0.7f))
    LinearProgressIndicator(
      progress = { if (overview.devices.isEmpty()) 0f else count.toFloat() / overview.devices.size },
      modifier = Modifier.weight(2f).height(10.dp),
      color = riskColour(level), trackColor = Color(0xFF2E3B49),
    )
    Text(count.toString(), fontSize = 12.sp, color = riskColour(level),
      modifier = Modifier.weight(0.3f))
  }
}

@Composable
private fun DiscoveryTrend(values: List<Int>) {
  Canvas(modifier = Modifier.fillMaxWidth().height(118.dp)) {
    val bottom = size.height - 18.dp.toPx()
    val top = 12.dp.toPx()
    val left = 10.dp.toPx()
    val width = (size.width - 2 * left).coerceAtLeast(1f)
    val height = (bottom - top).coerceAtLeast(1f)
    val maxValue = (values.maxOrNull() ?: 1).coerceAtLeast(1)
    val points = values.mapIndexed { index, count ->
      val x = left + width * index / (values.size - 1).coerceAtLeast(1)
      val y = bottom - (count.toFloat() / maxValue) * height
      Offset(x, y)
    }
    drawLine(Color(0xFF344656), Offset(left, bottom), Offset(size.width - left, bottom), 1.dp.toPx())
    points.zipWithNext().forEach { (a, b) ->
      drawLine(Color(0xFF55ABF7), a, b, strokeWidth = 2.5.dp.toPx())
    }
    points.forEach { drawCircle(Color(0xFF6FC6FA), radius = 3.dp.toPx(), center = it) }
  }
}

@Composable
private fun DeviceExposureCard(item: DeviceExposure) {
  CyberPanel {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
      Column(modifier = Modifier.weight(1f)) {
        Text(item.host.hostname.ifBlank { item.host.address },
          fontWeight = FontWeight.SemiBold, fontSize = 14.sp,
          maxLines = 1, overflow = TextOverflow.Ellipsis)
        if (item.host.hostname.isNotBlank()) {
          Text(item.host.address, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
      Text("${item.level} · ${item.score}/100", color = riskColour(item.level),
        fontWeight = FontWeight.Bold, fontSize = 11.sp)
    }
    Text("LAN TCP: " + item.host.openPorts.distinct().sorted().take(16).joinToString(", ")
      .ifBlank { "No common ports detected" }, fontSize = 11.sp,
      color = MaterialTheme.colorScheme.onSurfaceVariant)
    Text(item.evidence.take(3).joinToString(" · "), fontSize = 11.sp,
      color = MaterialTheme.colorScheme.onSurfaceVariant)
  }
}
