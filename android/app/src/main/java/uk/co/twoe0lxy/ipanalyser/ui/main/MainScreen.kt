package uk.co.twoe0lxy.ipanalyser.ui.main

import android.Manifest
import android.app.Activity
import android.graphics.Paint as AndroidPaint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.net.VpnService
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Analytics
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.NetworkCheck
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.SettingsEthernet
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.outlined.PowerSettingsNew
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import uk.co.twoe0lxy.ipanalyser.data.HostResult
import uk.co.twoe0lxy.ipanalyser.data.ScannerUtils
import uk.co.twoe0lxy.ipanalyser.data.SmartDevice
import uk.co.twoe0lxy.ipanalyser.data.DnsEvent
import uk.co.twoe0lxy.ipanalyser.data.DnsMonitorRepository
import uk.co.twoe0lxy.ipanalyser.data.DnsMonitorService
import uk.co.twoe0lxy.ipanalyser.data.InventoryStore
import uk.co.twoe0lxy.ipanalyser.data.WifiNetwork
import uk.co.twoe0lxy.ipanalyser.theme.Green400
import uk.co.twoe0lxy.ipanalyser.theme.Navy700
import uk.co.twoe0lxy.ipanalyser.theme.Orange400
import uk.co.twoe0lxy.ipanalyser.theme.Purple400

private enum class AppPage(val label: String, val icon: ImageVector) {
  Dashboard("Dashboard", Icons.Outlined.Dashboard),
  Lan("LAN scan", Icons.Outlined.Search),
  Wifi("Wi-Fi", Icons.Outlined.Wifi),
  DnsBench("DNS test", Icons.Outlined.Speed),
  Tools("Tools", Icons.Outlined.Analytics),
}

@Composable
fun MainScreen(
  modifier: Modifier = Modifier,
  viewModel: MainScreenViewModel = viewModel(),
) {
  val state by viewModel.uiState.collectAsStateWithLifecycle()
  val dnsEvents by DnsMonitorRepository.events.collectAsStateWithLifecycle()
  val dnsRunning by DnsMonitorRepository.running.collectAsStateWithLifecycle()
  var selectedPage by rememberSaveable { mutableIntStateOf(0) }
  val pages = AppPage.entries

  Scaffold(
    modifier = modifier.fillMaxSize(),
    containerColor = MaterialTheme.colorScheme.background,
    topBar = { AppHeader(state) },
    bottomBar = {
      Column {
        Row(
          modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Text("●", color = Green400, fontSize = 10.sp)
          Text(
            state.status,
            modifier = Modifier.padding(start = 7.dp).weight(1f),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 11.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
        NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
          pages.forEachIndexed { index, page ->
            NavigationBarItem(
              selected = selectedPage == index,
              onClick = { selectedPage = index },
              icon = { Icon(page.icon, contentDescription = null) },
              label = { Text(page.label, fontSize = 10.sp) },
              colors = NavigationBarItemDefaults.colors(
                selectedIconColor = MaterialTheme.colorScheme.primary,
                selectedTextColor = MaterialTheme.colorScheme.primary,
                indicatorColor = Navy700,
              ),
            )
          }
        }
      }
    },
  ) { padding ->
    Box(Modifier.padding(padding).fillMaxSize()) {
      when (pages[selectedPage]) {
        AppPage.Dashboard -> DashboardPage(state)
        AppPage.Lan -> LanPage(state, viewModel::scanLan, viewModel::refreshNetwork, viewModel::toggleFavorite)
        AppPage.Wifi -> WifiPage(state, viewModel::scanWifi, viewModel::toggleWifiMonitor,
          viewModel::clearWifiHistory, viewModel::connectWifi)
        AppPage.DnsBench -> DnsBenchmarkPage(state, viewModel::toggleDnsBenchmark)
        AppPage.Tools -> ToolsPage(
          state,
          viewModel::runDiagnostic,
          viewModel::runSsh,
          viewModel::listSftp,
          viewModel::discoverSmartHome,
          viewModel::setSmartPower,
          viewModel::pairDesktop,
          viewModel::scanFromDesktop,
          viewModel::setPeerListener,
          viewModel::revokeDesktop,
          dnsEvents,
          dnsRunning,
        )
      }
    }
  }
}

@Composable
private fun AppHeader(state: MainScreenUiState) {
  Column {
    Row(
      modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Card(
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.cardColors(containerColor = Navy700),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary),
      ) {
        Icon(
          Icons.Outlined.Hub,
          contentDescription = null,
          tint = MaterialTheme.colorScheme.primary,
          modifier = Modifier.padding(9.dp).size(25.dp),
        )
      }
      Column(Modifier.padding(start = 11.dp).weight(1f)) {
        Text("Advanced IP Analyser", fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Text("Network diagnostics & toolkit", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
      Column(horizontalAlignment = Alignment.End) {
        Text("LOCAL IP", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(compactAddress(state.network.localIp), color = MaterialTheme.colorScheme.primary, fontSize = 12.sp)
      }
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
  }
}

@Composable
private fun DashboardPage(state: MainScreenUiState) {
  LazyColumn(
    modifier = Modifier.fillMaxSize().padding(16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp),
  ) {
    item {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
          Text("Network Dashboard", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
          Text("Overview and quick actions", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
        }
      }
    }
    item { VisibilityCard(state) }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        MetricCard("Hosts", state.hosts.size.toString(), "discovered", Icons.Outlined.Devices, Modifier.weight(1f))
        MetricCard("Open ports", state.hosts.sumOf { it.openPorts.size }.toString(), "common services", Icons.Outlined.SettingsEthernet, Modifier.weight(1f), Orange400)
      }
    }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        MetricCard("Avg response", averageLatency(state.hosts), "LAN scan", Icons.Outlined.Speed, Modifier.weight(1f), Green400)
        MetricCard("Gateway", compactAddress(state.network.gateway), "active route", Icons.Outlined.Router, Modifier.weight(1f))
      }
    }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        val used = (state.storageTotalBytes - state.storageFreeBytes).coerceAtLeast(0)
        MetricCard("Storage used", formatStorage(used), "device storage", Icons.Outlined.Storage, Modifier.weight(1f), Orange400)
        MetricCard("Storage free", formatStorage(state.storageFreeBytes), "available", Icons.Outlined.Storage, Modifier.weight(1f), Green400)
      }
    }
    item {
      SectionCard("Recent activity", Icons.Outlined.Analytics) {
        InfoLine("Current status", state.status)
        InfoLine("Scan progress", if (state.total > 0) "${state.completed} / ${state.total}" else "Not started")
        InfoLine("Nearby Wi-Fi", "${state.wifiNetworks.size} networks")
        InfoLine("Favorites", state.favorites.size.toString())
        InfoLine("Saved scans", state.savedScans.toString())
        state.activity.take(4).forEach { Text(it, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 5.dp)) }
      }
    }
    item {
      SectionCard("System information", Icons.Outlined.Devices) {
        InfoLine("Local IP", state.network.localIp)
        InfoLine("Network range", state.network.range)
        InfoLine("Interface", state.network.interfaceName)
        InfoLine("Wi-Fi", state.network.wifiName.ifBlank { "Permission required" })
      }
    }
  }
}

@Composable
private fun VisibilityCard(state: MainScreenUiState) {
  val openPorts = state.hosts.sumOf { it.openPorts.size }
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, Purple400),
    shape = RoundedCornerShape(12.dp),
  ) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Card(
          colors = CardDefaults.cardColors(containerColor = Navy700),
          shape = RoundedCornerShape(10.dp),
        ) {
          Icon(
            Icons.Outlined.Security,
            contentDescription = null,
            tint = Purple400,
            modifier = Modifier.padding(10.dp).size(26.dp),
          )
        }
        Column(Modifier.padding(start = 12.dp).weight(1f)) {
          Text("Complete visibility", fontSize = 18.sp, fontWeight = FontWeight.Bold)
          Text("Your local network in one dashboard", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
        }
        Text("LIVE", color = Green400, fontSize = 10.sp, fontWeight = FontWeight.Bold)
      }
      HorizontalDivider(modifier = Modifier.padding(vertical = 14.dp), color = MaterialTheme.colorScheme.surfaceVariant)
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        VisibilityValue("DEVICES", state.hosts.size.toString(), Modifier.weight(1f), MaterialTheme.colorScheme.primary)
        VisibilityValue("OPEN PORTS", openPorts.toString(), Modifier.weight(1f), Orange400)
        VisibilityValue("WI-FI", state.wifiNetworks.size.toString(), Modifier.weight(1f), Purple400)
      }
    }
  }
}

@Composable
private fun VisibilityValue(label: String, value: String, modifier: Modifier, accent: Color) {
  Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
    Text(value, color = accent, fontSize = 23.sp, fontWeight = FontWeight.Bold)
    Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 9.sp, fontWeight = FontWeight.Bold)
  }
}

@Composable
private fun LanPage(state: MainScreenUiState, onScan: () -> Unit, onRefresh: () -> Unit, onFavorite: (String) -> Unit) {
  val context = LocalContext.current
  fun share(label: String, content: String, mime: String) {
    val intent = Intent(Intent.ACTION_SEND).apply { type = mime; putExtra(Intent.EXTRA_SUBJECT, label); putExtra(Intent.EXTRA_TEXT, content) }
    context.startActivity(Intent.createChooser(intent, label))
  }
  Column(Modifier.fillMaxSize().padding(16.dp)) {
    PageHeading("LAN discovery", "Find active devices and common services", Icons.Outlined.Search)
    Spacer(Modifier.height(12.dp))
    SectionCard(state.network.range, Icons.Outlined.Hub) {
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onScan, modifier = Modifier.weight(1f)) { Text(if (state.scanningLan) "Stop scan" else "Scan network") }
        OutlinedButton(onClick = onRefresh) { Text("Refresh") }
      }
      if (state.hosts.isNotEmpty()) {
        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), modifier = Modifier.padding(top = 8.dp)) {
          OutlinedButton(onClick = { share("LAN scan CSV", InventoryStore.csv(state.hosts), "text/csv") }, modifier = Modifier.weight(1f)) { Text("CSV") }
          OutlinedButton(onClick = { share("LAN scan JSON", InventoryStore.json(state.hosts), "application/json") }, modifier = Modifier.weight(1f)) { Text("JSON") }
          OutlinedButton(onClick = { share("Network topology SVG", InventoryStore.topologySvg(state.hosts, state.network.gateway), "image/svg+xml") }, modifier = Modifier.weight(1f)) { Text("Topology") }
        }
      }
      if (state.scanningLan && state.total > 0) {
        Spacer(Modifier.height(10.dp))
        LinearProgressIndicator(
          progress = { state.completed.toFloat() / state.total.toFloat() },
          modifier = Modifier.fillMaxWidth(),
        )
        Text("${state.completed} of ${state.total} addresses", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
    }
    Spacer(Modifier.height(12.dp))
    if (state.hosts.isEmpty()) {
      EmptyPanel(if (state.scanningLan) "Looking for devices…" else "Press Scan network to discover devices on this LAN.")
    } else {
      LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(state.hosts, key = HostResult::address) { HostRow(it, it.address in state.favorites, onFavorite) }
      }
    }
  }
}

@Composable
private fun HostRow(host: HostResult, favorite: Boolean, onFavorite: (String) -> Unit) {
  val context = LocalContext.current
  val serviceUrl = ScannerUtils.preferredServiceUrl(host.address, host.openPorts)
  var showPorts by remember { mutableStateOf(false) }
  Card(
    modifier = Modifier.clickable(enabled = host.openPorts.isNotEmpty()) {
      if (serviceUrl == null) {
        showPorts = true
      } else {
        try {
          context.startActivity(Intent(Intent.ACTION_VIEW, serviceUrl.toUri()))
        } catch (_: ActivityNotFoundException) {
          Toast.makeText(context, "No app can open $serviceUrl", Toast.LENGTH_LONG).show()
        }
      }
    },
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = panelBorder(),
    shape = RoundedCornerShape(9.dp),
  ) {
    Row(Modifier.fillMaxWidth().padding(13.dp), verticalAlignment = Alignment.CenterVertically) {
      IconButton(onClick = { onFavorite(host.address) }, modifier = Modifier.size(30.dp)) {
        Icon(if (favorite) Icons.Outlined.Star else Icons.Outlined.StarBorder, "Favorite", tint = if (favorite) Color(0xFFFFD54F) else MaterialTheme.colorScheme.onSurfaceVariant)
      }
      Icon(Icons.Outlined.Devices, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(22.dp))
      Column(Modifier.padding(start = 11.dp).weight(1f)) {
        Text(host.hostname.ifBlank { host.address }, fontWeight = FontWeight.Bold)
        if (host.hostname.isNotBlank()) Text(host.address, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
          if (host.openPorts.isEmpty()) "Online · no common ports responded" else host.services,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          fontSize = 12.sp,
        )
        if (host.macAddress.isNotBlank()) Text(host.macAddress.uppercase(), fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
      }
      Column(horizontalAlignment = Alignment.End) {
        Text(if (host.latencyMs > 0) "${host.latencyMs} ms" else "Online", color = Green400, fontSize = 12.sp)
        if (host.openPorts.isNotEmpty()) {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (serviceUrl == null) "View ports" else "Open service", color = MaterialTheme.colorScheme.primary, fontSize = 11.sp)
            Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(start = 4.dp).size(14.dp))
          }
        }
      }
    }
  }
  if (showPorts) {
    AlertDialog(
      onDismissRequest = { showPorts = false },
      title = { Text(host.address) },
      text = {
        Column {
          Text("Open ports found", fontWeight = FontWeight.Bold)
          Spacer(Modifier.height(8.dp))
          host.openPorts.forEach { Text(HostResult.portName(it), color = MaterialTheme.colorScheme.onSurfaceVariant) }
          Spacer(Modifier.height(10.dp))
          Text("These services do not open directly in a browser.", fontSize = 12.sp)
        }
      },
      confirmButton = { TextButton(onClick = { showPorts = false }) { Text("Close") } },
    )
  }
}

@Composable
private fun WifiPage(
  state: MainScreenUiState,
  onScan: () -> Unit,
  onToggleMonitor: (Int) -> Unit,
  onClearHistory: () -> Unit,
  onConnect: (WifiNetwork, String) -> Unit,
) {
  val context = LocalContext.current
  val permissions = remember {
    buildList {
      add(Manifest.permission.ACCESS_COARSE_LOCATION)
      add(Manifest.permission.ACCESS_FINE_LOCATION)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) add(Manifest.permission.NEARBY_WIFI_DEVICES)
    }.toTypedArray()
  }
  var permissionDenied by rememberSaveable { mutableStateOf(false) }
  var pendingMonitor by remember { mutableStateOf(false) }
  var viewMode by rememberSaveable { mutableIntStateOf(0) }
  var refreshSeconds by rememberSaveable { mutableIntStateOf(state.wifiRefreshSeconds) }
  var band by rememberSaveable { mutableIntStateOf(0) }
  val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
    permissionDenied = grants.values.any { !it }
    if (!permissionDenied) {
      if (pendingMonitor) onToggleMonitor(refreshSeconds) else onScan()
    }
    pendingMonitor = false
  }
  fun requestWifi(monitor: Boolean) {
    val missing = permissions.any { ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }
    if (missing) {
      pendingMonitor = monitor
      permissionLauncher.launch(permissions)
    } else if (monitor) onToggleMonitor(refreshSeconds) else onScan()
  }

  Column(Modifier.fillMaxSize().padding(16.dp)) {
    PageHeading("Wi-Fi analyzer", "Nearby channels, bandwidth and two-hour signal history", Icons.Outlined.Wifi)
    Spacer(Modifier.height(12.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
      listOf("Networks", "History", "Channels").forEachIndexed { index, label ->
        if (viewMode == index) Button(onClick = { viewMode = index }, modifier = Modifier.weight(1f)) { Text(label, fontSize = 11.sp) }
        else OutlinedButton(onClick = { viewMode = index }, modifier = Modifier.weight(1f)) { Text(label, fontSize = 11.sp) }
      }
    }
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
      Button(onClick = { requestWifi(false) }, enabled = !state.scanningWifi,
        modifier = Modifier.weight(1f)) { Text(if (state.scanningWifi && !state.wifiMonitoring) "Scanning…" else "Scan now") }
      Button(onClick = { if (state.wifiMonitoring) onToggleMonitor(refreshSeconds) else requestWifi(true) }, modifier = Modifier.weight(1f)) {
        Text(if (state.wifiMonitoring) "Stop monitor" else "Start monitor")
      }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
      Text("Refresh", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
      (1..5).forEach { seconds ->
        TextButton(onClick = { refreshSeconds = seconds }, enabled = !state.wifiMonitoring) {
          Text("${seconds}s", color = if (refreshSeconds == seconds) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    }
    Text(
      if (permissionDenied) "Wi-Fi scan permission was denied. Allow it in Android settings to scan nearby networks."
      else if (state.wifiMonitoring) "Recording every ${state.wifiRefreshSeconds}s for up to 2 hours. Android may throttle scans and repeat its latest sample."
      else "Nearby-device and precise-location permission are required by Android.",
      fontSize = 11.sp,
      color = if (permissionDenied) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
      modifier = Modifier.padding(vertical = 9.dp),
    )
    when (viewMode) {
      0 -> if (state.wifiNetworks.isEmpty()) EmptyPanel("No nearby Wi-Fi results yet.") else {
        LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          items(state.wifiNetworks, key = WifiNetwork::bssid) { WifiRow(it, onConnect) }
        }
      }
      1 -> {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text("${state.wifiHistory.size} samples · swipe sideways for history", fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
          TextButton(onClick = onClearHistory) { Text("Clear") }
        }
        WifiHistoryChart(state.wifiHistory, state.wifiRefreshSeconds, Modifier.weight(1f))
      }
      else -> {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          listOf("2.4 GHz", "5 GHz", "6 GHz").forEachIndexed { index, label ->
            if (band == index) Button(onClick = { band = index }, modifier = Modifier.weight(1f)) { Text(label, fontSize = 11.sp) }
            else OutlinedButton(onClick = { band = index }, modifier = Modifier.weight(1f)) { Text(label, fontSize = 11.sp) }
          }
        }
        WifiChannelChart(state.wifiNetworks, band, Modifier.weight(1f))
      }
    }
  }
}

private val WifiChartColors = listOf(
  Color(0xFF22B8FF), Green400, Color(0xFFFFCC3D), Color(0xFFFF6B6B),
  Purple400, Color(0xFF31D6C4), Orange400, Color(0xFF8DC5FF),
)

@Composable
private fun WifiHistoryChart(history: List<WifiSignalSnapshot>, refreshSeconds: Int, modifier: Modifier = Modifier) {
  if (history.isEmpty()) {
    Box(modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { Text("Start monitoring to collect signal history") }
    return
  }
  val strongest = history.last().networks.sortedByDescending { it.signalDbm }.take(8)
  val keys = strongest.map(WifiNetwork::bssid)
  val scroll = rememberScrollState()
  val chartWidth = maxOf(620, history.size * 7)
  val timeFormatter = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }
  LaunchedEffect(history.size) { scroll.animateScrollTo(scroll.maxValue) }
  Column(modifier) {
    strongest.chunked(2).forEach { row ->
      Row(Modifier.fillMaxWidth()) {
        row.forEach { network ->
          val color = WifiChartColors[keys.indexOf(network.bssid) % WifiChartColors.size]
          Text("● ${network.name}", color = color, fontSize = 10.sp, maxLines = 1,
            modifier = Modifier.weight(1f).padding(end = 6.dp))
        }
        if (row.size == 1) Spacer(Modifier.weight(1f))
      }
    }
    Row(Modifier.fillMaxWidth().height(330.dp)) {
      WifiDbmAxis(Modifier.width(48.dp).fillMaxHeight())
      Box(Modifier.weight(1f).fillMaxHeight().horizontalScroll(scroll)) {
        Canvas(Modifier.width(chartWidth.dp).fillMaxHeight()) {
        val left = 4.dp.toPx()
        val right = size.width - 8.dp.toPx()
        val top = 18.dp.toPx()
        val bottom = size.height - 30.dp.toPx()
        val labelPaint = AndroidPaint(AndroidPaint.ANTI_ALIAS_FLAG).apply {
          color = Color(0xFF9FB0C7).toArgb()
          textSize = 10.sp.toPx()
          textAlign = AndroidPaint.Align.CENTER
        }
        for (dbm in -100..-30 step 10) {
          val y = top + (-30 - dbm) / 70f * (bottom - top)
          drawLine(Color(0xFF284157), Offset(left, y), Offset(right, y), 1f)
        }
        drawLine(Color(0xFF60758B), Offset(left, bottom), Offset(right, bottom), 1.5f)
        val tickStep = maxOf(1, history.lastIndex / 5)
        history.indices.filter { it % tickStep == 0 || it == history.lastIndex }.forEach { index ->
          val x = if (history.size == 1) left else left + index.toFloat() / history.lastIndex * (right - left)
          drawLine(Color(0xFF20384E), Offset(x, top), Offset(x, bottom), 1f)
          drawContext.canvas.nativeCanvas.drawText(
            timeFormatter.format(Date(history[index].timestampMillis)), x, size.height - 8.dp.toPx(), labelPaint,
          )
        }
        keys.forEachIndexed { colorIndex, bssid ->
          val path = Path()
          var started = false
          history.forEachIndexed { index, snapshot ->
            snapshot.networks.firstOrNull { it.bssid == bssid }?.let { network ->
              val x = if (history.size == 1) left else left + index.toFloat() / history.lastIndex * (right - left)
              val y = top + (-30 - network.signalDbm.coerceIn(-100, -30)) / 70f * (bottom - top)
              if (!started) { path.moveTo(x, y); started = true } else path.lineTo(x, y)
            }
          }
          if (started) drawPath(path, WifiChartColors[colorIndex % WifiChartColors.size], style = androidx.compose.ui.graphics.drawscope.Stroke(3f))
        }
        }
      }
    }
    Text("Signal history · ${refreshSeconds}s requested interval · drag sideways for up to 2 hours",
      fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
  }
}

@Composable
private fun WifiDbmAxis(modifier: Modifier = Modifier) {
  Canvas(modifier) {
    val top = 18.dp.toPx()
    val bottom = size.height - 30.dp.toPx()
    val labelPaint = AndroidPaint(AndroidPaint.ANTI_ALIAS_FLAG).apply {
      color = Color(0xFF9FB0C7).toArgb()
      textSize = 10.sp.toPx()
      textAlign = AndroidPaint.Align.RIGHT
    }
    drawContext.canvas.nativeCanvas.drawText("dBm", size.width - 5.dp.toPx(), 11.dp.toPx(), labelPaint)
    for (dbm in -100..-30 step 10) {
      val y = top + (-30 - dbm) / 70f * (bottom - top)
      drawContext.canvas.nativeCanvas.drawText(dbm.toString(), size.width - 5.dp.toPx(), y + 3.dp.toPx(), labelPaint)
    }
  }
}

@Composable
private fun WifiChannelChart(networks: List<WifiNetwork>, band: Int, modifier: Modifier = Modifier) {
  val low = if (band == 0) 2402f else if (band == 1) 5150f else 5925f
  val high = if (band == 0) 2494f else if (band == 1) 5900f else 7125f
  val visible = networks.filter { it.frequencyMhz.toFloat() in low..high }
    .sortedByDescending(WifiNetwork::signalDbm).take(16)
  val channelTicks = when (band) {
    0 -> (1..13).map { it to (2407 + it * 5).toFloat() } + (14 to 2484f)
    1 -> listOf(36, 48, 64, 100, 116, 132, 149, 165).map { it to (5000 + it * 5).toFloat() }
    else -> listOf(1, 33, 65, 97, 129, 161, 193, 225).map { it to (5950 + it * 5).toFloat() }
  }
  val detailScroll = rememberScrollState()
  Column(modifier.padding(top = 8.dp).verticalScroll(detailScroll)) {
    Canvas(Modifier.fillMaxWidth().height(330.dp)) {
      val left = 45.dp.toPx()
      val right = size.width - 7.dp.toPx()
      val top = 26.dp.toPx()
      val bottom = size.height - 31.dp.toPx()
      val axisPaint = AndroidPaint(AndroidPaint.ANTI_ALIAS_FLAG).apply {
        color = Color(0xFF9FB0C7).toArgb()
        textSize = 9.sp.toPx()
      }
      val networkPaint = AndroidPaint(AndroidPaint.ANTI_ALIAS_FLAG).apply {
        textSize = 9.sp.toPx()
        textAlign = AndroidPaint.Align.CENTER
      }
      fun x(frequency: Float) = left + (frequency - low) / (high - low) * (right - left)
      fun y(dbm: Int) = top + (-30 - dbm.coerceIn(-100, -30)) / 70f * (bottom - top)
      for (dbm in -100..-30 step 10) {
        val lineY = y(dbm)
        drawLine(Color(0xFF284157), Offset(left, lineY), Offset(right, lineY), 1f)
        axisPaint.textAlign = AndroidPaint.Align.RIGHT
        drawContext.canvas.nativeCanvas.drawText("$dbm", left - 6.dp.toPx(), lineY + 3.dp.toPx(), axisPaint)
      }
      axisPaint.textAlign = AndroidPaint.Align.LEFT
      drawContext.canvas.nativeCanvas.drawText("dBm", 2.dp.toPx(), 14.dp.toPx(), axisPaint)
      drawLine(Color(0xFF60758B), Offset(left, bottom), Offset(right, bottom), 1.5f)
      channelTicks.filter { it.second in low..high }.forEach { (channel, frequency) ->
        val tickX = x(frequency)
        drawLine(Color(0xFF20384E), Offset(tickX, top), Offset(tickX, bottom), 1f)
        axisPaint.textAlign = AndroidPaint.Align.CENTER
        drawContext.canvas.nativeCanvas.drawText(channel.toString(), tickX, size.height - 9.dp.toPx(), axisPaint)
      }
      val colorByBssid = visible.mapIndexed { index, network -> network.bssid to WifiChartColors[index % WifiChartColors.size] }.toMap()
      visible.sortedBy(WifiNetwork::signalDbm).forEach { network ->
        val color = colorByBssid.getValue(network.bssid)
        val halfWidth = network.channelWidthMhz.coerceAtLeast(1) / 2f
        val startX = x(network.frequencyMhz - halfWidth).coerceAtLeast(left)
        val peakX = x(network.frequencyMhz.toFloat())
        val endX = x(network.frequencyMhz + halfWidth).coerceAtMost(right)
        val peakY = y(network.signalDbm)
        val path = Path().apply {
          moveTo(startX, bottom)
          cubicTo(startX, (bottom + peakY) / 2, peakX - (peakX - startX) / 2, peakY, peakX, peakY)
          cubicTo(peakX + (endX - peakX) / 2, peakY, endX, (bottom + peakY) / 2, endX, bottom)
          close()
        }
        drawPath(path, color.copy(alpha = .18f))
        drawPath(path, color, style = androidx.compose.ui.graphics.drawscope.Stroke(2.5f))
      }
      visible.take(6).forEach { network ->
        val color = colorByBssid.getValue(network.bssid)
        val peakX = x(network.frequencyMhz.toFloat()).coerceIn(left + 28.dp.toPx(), right - 28.dp.toPx())
        val peakY = y(network.signalDbm)
        networkPaint.color = color.toArgb()
        val shortName = if (network.name.length > 12) network.name.take(11) + "…" else network.name
        drawContext.canvas.nativeCanvas.drawText(shortName, peakX, (peakY - 13.dp.toPx()).coerceAtLeast(13.dp.toPx()), networkPaint)
        drawContext.canvas.nativeCanvas.drawText(
          "ch ${network.channel} · ${network.channelWidthMhz} MHz", peakX,
          (peakY - 3.dp.toPx()).coerceAtLeast(24.dp.toPx()), networkPaint,
        )
      }
    }
    Text("Channel number →  ·  curve width = advertised bandwidth  ·  higher dBm = stronger",
      fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 5.dp))
    if (visible.isEmpty()) Text("No access points in this band in the latest scan.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    else Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
      visible.forEachIndexed { index, network ->
        val color = WifiChartColors[index % WifiChartColors.size]
        Text("● ${network.name} · channel ${network.channel} · ${network.channelWidthMhz} MHz · ${network.signalDbm} dBm",
          color = color, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
      }
    }
  }
}

@Composable
private fun WifiRow(network: WifiNetwork, onConnect: (WifiNetwork, String) -> Unit) {
  var showPassword by remember { mutableStateOf(false) }
  var password by remember { mutableStateOf("") }
  val reviewColor = if (network.review.startsWith("High")) Color(0xFFFF6767)
  else if (network.review.startsWith("Medium")) Orange400 else Green400
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = panelBorder(),
    shape = RoundedCornerShape(9.dp),
  ) {
    Row(Modifier.fillMaxWidth().padding(13.dp), verticalAlignment = Alignment.CenterVertically) {
      Icon(Icons.Outlined.Wifi, null, tint = MaterialTheme.colorScheme.primary)
      Column(Modifier.padding(start = 11.dp).weight(1f)) {
        Text(network.name, fontWeight = FontWeight.Bold)
        Text("Channel ${network.channel} · ${network.channelWidthMhz} MHz wide · ${network.frequencyMhz} MHz · ${network.security}", fontSize = 12.sp)
        Text(network.review, color = reviewColor, fontSize = 12.sp)
      }
      Column(horizontalAlignment = Alignment.End) {
        val signalColor = when {
          network.signalPercent < 25 -> Color(0xFFFF5252)
          network.signalPercent < 50 -> Orange400
          network.signalPercent < 75 -> Color(0xFFFFD54F)
          else -> Green400
        }
        val bars = when {
          network.signalPercent < 25 -> "▂"
          network.signalPercent < 50 -> "▂▃"
          network.signalPercent < 75 -> "▂▃▅"
          else -> "▂▃▅▇"
        }
        Text(bars, color = signalColor, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        Text("${network.signalPercent}%", color = signalColor, fontWeight = FontWeight.Bold, fontSize = 11.sp)
        Text("${network.signalDbm} dBm", color = signalColor, fontSize = 10.sp)
        TextButton(onClick = {
          if (network.security !in setOf("WPA", "WPA2", "WPA3")) onConnect(network, "")
          else showPassword = true
        }) { Text("Connect") }
      }
    }
  }
  if (showPassword) {
    AlertDialog(
      onDismissRequest = {
        password = ""
        showPassword = false
      },
      title = { Text("Connect to ${network.name}") },
      text = {
        OutlinedTextField(
          value = password,
          onValueChange = { password = it },
          label = { Text("Wi-Fi password") },
          singleLine = true,
          visualTransformation = PasswordVisualTransformation(),
        )
      },
      confirmButton = {
        TextButton(onClick = {
          onConnect(network, password)
          password = ""
          showPassword = false
        }) { Text("Connect") }
      },
      dismissButton = {
        TextButton(onClick = {
          password = ""
          showPassword = false
        }) { Text("Cancel") }
      },
    )
  }
}

@Composable
private fun DnsBenchmarkPage(state: MainScreenUiState, onToggle: () -> Unit) {
  var showHelp by rememberSaveable { mutableStateOf(false) }
  LazyColumn(
    modifier = Modifier.fillMaxSize().padding(16.dp),
    verticalArrangement = Arrangement.spacedBy(10.dp),
  ) {
    item { PageHeading("DNS latency benchmark", "Real UDP DNS queries from this device", Icons.Outlined.Speed) }
    item {
      SectionCard("Five-round comparison", Icons.Outlined.Dns) {
        Text(
          "Each of 36 resolvers receives the same A-record query. Results measure a validated DNS reply, not a web request.",
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          fontSize = 12.sp,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          Button(onClick = onToggle, modifier = Modifier.weight(1f)) {
            Text(if (state.dnsBenchmarkRunning) "Stop benchmark" else "Start 5-round benchmark")
          }
          OutlinedButton(onClick = { showHelp = true }) { Text("?") }
        }
        if (state.dnsBenchmarkRunning) {
          Spacer(Modifier.height(10.dp))
          LinearProgressIndicator(progress = { state.dnsBenchmarkRound / 5f }, modifier = Modifier.fillMaxWidth())
          Text("Round ${state.dnsBenchmarkRound.coerceAtLeast(1)} of 5", fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      }
    }
    if (state.dnsBenchmark.isEmpty()) {
      item { EmptyPanel("Start the benchmark to compare public DNS resolvers from your current connection.") }
    } else {
      items(state.dnsBenchmark, key = { it.resolver.address }) { row ->
        val average = row.averageMs
        val accent = when {
          average == null -> MaterialTheme.colorScheme.onSurfaceVariant
          average < 50 -> Green400
          average < 150 -> Orange400
          else -> MaterialTheme.colorScheme.error
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          border = panelBorder(), shape = RoundedCornerShape(10.dp)) {
          Column(Modifier.fillMaxWidth().padding(13.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Column(Modifier.weight(1f)) {
                Text(row.resolver.name, fontWeight = FontWeight.Bold)
                Text(row.resolver.address, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
              }
              Column(horizontalAlignment = Alignment.End) {
                Text(average?.let { "%.1f ms".format(it) } ?: "No reply",
                  color = accent, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(row.jitterMs?.let { "jitter %.1f ms".format(it) } ?: "jitter —",
                  color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 10.sp)
              }
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
              repeat(5) { index ->
                val sample = row.rounds.getOrNull(index)
                Card(modifier = Modifier.weight(1f), colors = CardDefaults.cardColors(containerColor = Navy700),
                  shape = RoundedCornerShape(6.dp)) {
                  Column(Modifier.fillMaxWidth().padding(vertical = 6.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("R${index + 1}", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(sample?.let { "${it}ms" } ?: if (index < row.rounds.size) "T/O" else "—",
                      fontSize = 10.sp, fontWeight = FontWeight.Bold)
                  }
                }
              }
            }
            Text("${row.successfulRounds}/${row.rounds.size} validated replies", modifier = Modifier.padding(top = 7.dp),
              fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        }
      }
    }
  }
  if (showHelp) {
    AlertDialog(
      onDismissRequest = { showHelp = false },
      title = { Text("DNS benchmark help") },
      text = { Text(
        "What it does: sends real UDP A-record queries to 36 public DNS resolvers and ranks valid replies by average latency and jitter.\n\n" +
          "How to use it: select Start and keep the app open for five rounds. Stop keeps completed results.\n\n" +
          "How it works: each request has a transaction ID and only a matching DNS response counts. Timeouts reduce the reply total.\n\n" +
          "Why: DNS speed depends on this device, Wi-Fi, ISP, route and current resolver load.\n\n" +
          "Limits: this measures unencrypted UDP port 53, not privacy, filtering, encrypted DNS or cache quality. Fastest does not automatically mean best."
      ) },
      confirmButton = { TextButton(onClick = { showHelp = false }) { Text("Close") } },
    )
  }
}

@Composable
private fun ToolsPage(
  state: MainScreenUiState,
  onRun: (DiagnosticKind, String, String) -> Unit,
  onSsh: (String, String, String, String) -> Unit,
  onSftp: (String, String, String, String) -> Unit,
  onDiscoverSmart: () -> Unit,
  onSmartPower: (SmartDevice, Boolean) -> Unit,
  onPairDesktop: (String, String) -> Unit,
  onScanDesktop: (String) -> Unit,
  onPeerListener: (Boolean) -> Unit,
  onRevokeDesktop: () -> Unit,
  dnsEvents: List<DnsEvent>,
  dnsRunning: Boolean,
) {
  val context = LocalContext.current
  var target by rememberSaveable { mutableStateOf("8.8.8.8") }
  var options by rememberSaveable { mutableStateOf("22,53,80,443,8080-8090") }
  var sshHost by rememberSaveable { mutableStateOf("") }
  var sshUser by rememberSaveable { mutableStateOf("") }
  var sshPassword by rememberSaveable { mutableStateOf("") }
  var sshCommand by rememberSaveable { mutableStateOf("uname -a") }
  var sftpPath by rememberSaveable { mutableStateOf(".") }
  var desktopAddress by rememberSaveable { mutableStateOf(state.pairedDesktop) }
  var pairingToken by rememberSaveable { mutableStateOf("") }
  fun startDnsService() {
    ContextCompat.startForegroundService(context, Intent(context, DnsMonitorService::class.java).setAction(DnsMonitorService.ACTION_START))
  }
  val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
    if (result.resultCode == Activity.RESULT_OK) startDnsService()
  }
  fun toggleDnsMonitor() {
    if (dnsRunning) {
      context.startService(Intent(context, DnsMonitorService::class.java).setAction(DnsMonitorService.ACTION_STOP))
    } else {
      val approval = VpnService.prepare(context)
      if (approval == null) startDnsService() else vpnPermission.launch(approval)
    }
  }
  Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
    PageHeading("Network toolkit", "Diagnostics, security, SSH and Smart Home", Icons.Outlined.Analytics)
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(
      value = target,
      onValueChange = { target = it },
      label = { Text("Target host, IP address or URL") },
      singleLine = true,
      modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
      value = options,
      onValueChange = { options = it },
      label = { Text("Ports, broadcast address or tool option") },
      supportingText = { Text("Custom ports: 1-1024 · Wake-on-LAN: target is MAC, option is broadcast") },
      singleLine = true,
      modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(10.dp))
    DiagnosticKind.entries.chunked(2).forEach { row ->
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(bottom = 8.dp)) {
        row.forEach { kind -> Button(onClick = { onRun(kind, target, options) }, enabled = !state.working, modifier = Modifier.weight(1f)) { Text(kind.label) } }
      }
    }
    SectionCard("Result", Icons.Outlined.NetworkCheck) {
      if (state.working) LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp))
      Text(state.diagnosticResult)
      Spacer(Modifier.height(8.dp))
      OutlinedButton(onClick = {
        val share = Intent(Intent.ACTION_SEND).apply {
          type = "text/plain"
          putExtra(Intent.EXTRA_SUBJECT, "Advanced IP Analyser result")
          putExtra(Intent.EXTRA_TEXT, state.diagnosticResult)
        }
        context.startActivity(Intent.createChooser(share, "Export result"))
      }, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Outlined.Share, null, modifier = Modifier.size(17.dp))
        Text("  Export / share result")
      }
    }
    Spacer(Modifier.height(12.dp))
    SectionCard("Desktop ↔ Android private LAN pairing", Icons.Outlined.Hub) {
      Text(
        if (state.pairedDesktop.isBlank()) "Not paired" else "Paired with ${state.pairedDesktop}",
        color = if (state.pairedDesktop.isBlank()) Orange400 else Green400,
        fontWeight = FontWeight.Bold,
      )
      OutlinedTextField(
        desktopAddress,
        { desktopAddress = it },
        label = { Text("Desktop private LAN address") },
        placeholder = { Text("192.168.1.201") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
      )
      OutlinedTextField(
        pairingToken,
        { pairingToken = it },
        label = { Text("Private pairing token") },
        visualTransformation = PasswordVisualTransformation(),
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
      )
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
          onClick = { onPairDesktop(desktopAddress, pairingToken); pairingToken = "" },
          enabled = !state.working,
          modifier = Modifier.weight(1f),
        ) { Text("Pair securely") }
        OutlinedButton(
          onClick = { onScanDesktop(target) },
          enabled = state.pairedDesktop.isNotBlank() && !state.working,
          modifier = Modifier.weight(1f),
        ) { Text("Scan on desktop") }
      }
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
          onClick = { onPeerListener(!state.peerListening) },
          enabled = state.pairedDesktop.isNotBlank(),
          modifier = Modifier.weight(1f),
        ) { Text(if (state.peerListening) "Stop peer scans" else "Allow desktop scans") }
        OutlinedButton(
          onClick = onRevokeDesktop,
          enabled = state.pairedDesktop.isNotBlank() && !state.working,
          modifier = Modifier.weight(1f),
        ) { Text("Revoke") }
      }
      Text(
        "The secret is encrypted with Android Keystore and never sent in an API request. Requests are signed, expire after 60 seconds and cannot be replayed. The listener runs only while this app process is active.",
        fontSize = 11.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
    Spacer(Modifier.height(12.dp))
    SectionCard("Live DNS connections & map", Icons.Outlined.Dns) {
      Text(
        if (dnsRunning) "Monitoring and forwarding DNS requests" else "Stopped",
        color = if (dnsRunning) Green400 else MaterialTheme.colorScheme.onSurfaceVariant,
        fontWeight = FontWeight.Bold,
      )
      Button(onClick = ::toggleDnsMonitor, modifier = Modifier.fillMaxWidth()) {
        Text(if (dnsRunning) "Stop DNS monitor" else "Start DNS monitor")
      }
      if (dnsEvents.isNotEmpty()) {
        OutlinedButton(onClick = DnsMonitorRepository::clear, modifier = Modifier.fillMaxWidth()) { Text("Clear DNS history") }
        DnsDestinationMap(dnsEvents)
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth()) {
          Text("Time / request", modifier = Modifier.weight(1.2f), fontWeight = FontWeight.Bold, fontSize = 10.sp)
          Text("Application", modifier = Modifier.weight(1f), fontWeight = FontWeight.Bold, fontSize = 10.sp)
          Text("Destination", modifier = Modifier.weight(1.2f), fontWeight = FontWeight.Bold, fontSize = 10.sp)
        }
        dnsEvents.take(40).forEach { event ->
          HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.surfaceVariant)
          Row(Modifier.fillMaxWidth()) {
            Column(Modifier.weight(1.2f)) {
              Text(event.time, fontWeight = FontWeight.Bold, fontSize = 10.sp)
              Text(event.query, fontSize = 10.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Text(event.appName, modifier = Modifier.weight(1f), fontSize = 10.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Column(Modifier.weight(1.2f)) {
              Text(event.answers.firstOrNull() ?: "No address", color = MaterialTheme.colorScheme.primary, fontSize = 10.sp)
              Text(event.location, fontSize = 9.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
          }
          Text("DNS resolver: ${event.resolver} · ${event.answers.joinToString().ifBlank { "No answer" }}", fontSize = 9.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      } else {
        Text("Start monitoring to see the requested domain, requesting app where Android permits attribution, DNS resolver, returned addresses and destination country/region.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
      }
      Text("Android shows a system VPN approval because DNS is captured locally. No traffic is sent to the desktop or cloud; only returned public IPs are submitted to ipwho.is for the location label.", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
    }
    Spacer(Modifier.height(12.dp))
    SectionCard("SSH terminal & SFTP", Icons.Outlined.Terminal) {
      OutlinedTextField(sshHost, { sshHost = it }, label = { Text("Host or host:port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(sshUser, { sshUser = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.weight(1f))
        OutlinedTextField(
          sshPassword,
          { sshPassword = it },
          label = { Text("Password") },
          singleLine = true,
          visualTransformation = PasswordVisualTransformation(),
          modifier = Modifier.weight(1f),
        )
      }
      OutlinedTextField(sshCommand, { sshCommand = it }, label = { Text("SSH command") }, modifier = Modifier.fillMaxWidth())
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { onSsh(sshHost, sshUser, sshPassword, sshCommand) }, enabled = !state.working, modifier = Modifier.weight(1f)) { Text("Run command") }
        OutlinedButton(onClick = { onSftp(sshHost, sshUser, sshPassword, sftpPath) }, enabled = !state.working, modifier = Modifier.weight(1f)) { Text("List SFTP") }
      }
      OutlinedTextField(sftpPath, { sftpPath = it }, label = { Text("Remote SFTP path") }, singleLine = true, modifier = Modifier.fillMaxWidth())
      Text("The first connection asks Android to approve the server host key. Credentials remain in this screen only.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Spacer(Modifier.height(12.dp))
    SectionCard("Smart Home", Icons.Outlined.PowerSettingsNew) {
      Button(onClick = onDiscoverSmart, enabled = !state.working, modifier = Modifier.fillMaxWidth()) { Text("Discover local TP-Link / Kasa devices") }
      if (state.smartDevices.isEmpty()) {
        Text("Supports local Kasa protocol devices. Home Assistant remains the bridge for encrypted Tapo, Tuya and other vendors.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
      } else {
        state.smartDevices.forEach { device ->
          HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.surfaceVariant)
          Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
              Text(device.name, fontWeight = FontWeight.Bold)
              Text("${device.address} · ${device.model}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            OutlinedButton(onClick = { onSmartPower(device, device.isOn != true) }) { Text(if (device.isOn == true) "Turn off" else "Turn on") }
          }
        }
      }
    }
    Spacer(Modifier.height(12.dp))
    SectionCard("Packet and Wi-Fi access", Icons.Outlined.Security) {
      Text("Android protects other devices' MAC addresses and saved Wi-Fi passwords. Full packet capture requires a user-approved local VPN session; this build provides the live connection table without intercepting or decrypting traffic.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
    }
  }
}

@Composable
private fun DnsDestinationMap(events: List<DnsEvent>) {
  val mapped = events.filter { it.latitude != null && it.longitude != null }
    .distinctBy { it.answers.firstOrNull().orEmpty() }
  Canvas(
    Modifier.fillMaxWidth().height(210.dp)
      .padding(top = 8.dp),
  ) {
    drawRect(Color(0xFF081827))
    val land = Color(0xFF193A4D)
    fun continent(points: List<Pair<Float, Float>>) {
      if (points.isEmpty()) return
      val path = Path().apply {
        moveTo(points.first().first * size.width, points.first().second * size.height)
        points.drop(1).forEach { (x, y) -> lineTo(x * size.width, y * size.height) }
        close()
      }
      drawPath(path, land)
      drawPath(path, Color(0xFF315A6F), style = androidx.compose.ui.graphics.drawscope.Stroke(1.5f))
    }
    continent(listOf(.05f to .23f, .11f to .10f, .22f to .13f, .30f to .25f, .25f to .38f, .17f to .40f, .10f to .32f))
    continent(listOf(.25f to .42f, .35f to .47f, .36f to .61f, .30f to .88f, .25f to .69f))
    continent(listOf(.41f to .10f, .47f to .08f, .49f to .18f, .44f to .24f))
    continent(listOf(.45f to .24f, .56f to .20f, .61f to .31f, .55f to .38f, .47f to .34f))
    continent(listOf(.47f to .36f, .58f to .37f, .61f to .55f, .54f to .78f, .47f to .61f, .43f to .46f))
    continent(listOf(.57f to .18f, .75f to .10f, .92f to .24f, .91f to .38f, .79f to .49f, .65f to .42f, .58f to .31f))
    continent(listOf(.78f to .64f, .90f to .60f, .95f to .73f, .87f to .83f, .77f to .75f))
    val grid = Color(0xFF244158)
    for (step in 0..6) {
      val x = size.width * step / 6f
      drawLine(grid, Offset(x, 0f), Offset(x, size.height), 1f)
    }
    for (step in 0..4) {
      val y = size.height * step / 4f
      drawLine(grid, Offset(0f, y), Offset(size.width, y), 1f)
    }
    mapped.forEach { event ->
      val x = ((event.longitude!! + 180.0) / 360.0 * size.width).toFloat()
      val y = ((90.0 - event.latitude!!) / 180.0 * size.height).toFloat()
      drawCircle(Color(0x5531B8FF), 14f, Offset(x, y))
      drawCircle(Color(0xFF31B8FF), 7f, Offset(x, y))
      drawCircle(Color.White, 7f, Offset(x, y), style = androidx.compose.ui.graphics.drawscope.Stroke(2f))
    }
  }
  val mapStatus = when {
    mapped.isNotEmpty() -> "${mapped.size} public destination${if (mapped.size == 1) "" else "s"} mapped"
    events.any { it.location == "Locating…" } -> "Locating public destinations…"
    events.isNotEmpty() -> "No public destination coordinates available yet"
    else -> "DNS destinations will appear here"
  }
  Text("$mapStatus · approximate IP location",
    fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun PageHeading(title: String, subtitle: String, icon: ImageVector) {
  Row(verticalAlignment = Alignment.CenterVertically) {
    Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
    Column(Modifier.padding(start = 10.dp)) {
      Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
      Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
    }
  }
}

@Composable
private fun MetricCard(
  title: String,
  value: String,
  detail: String,
  icon: ImageVector,
  modifier: Modifier = Modifier,
  accent: Color = MaterialTheme.colorScheme.primary,
) {
  Card(
    modifier,
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = panelBorder(),
    shape = RoundedCornerShape(10.dp),
  ) {
    Column(Modifier.padding(14.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = accent, modifier = Modifier.size(21.dp))
        Text(title, modifier = Modifier.padding(start = 7.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
      }
      Text(value, color = accent, fontWeight = FontWeight.Bold, fontSize = if (value.length > 10) 15.sp else 26.sp, maxLines = 1)
      Text(detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp, maxLines = 1)
    }
  }
}

@Composable
private fun SectionCard(title: String, icon: ImageVector, content: @Composable ColumnScope.() -> Unit) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = panelBorder(),
    shape = RoundedCornerShape(10.dp),
  ) {
    Column(Modifier.fillMaxWidth().padding(14.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
        Text(title, modifier = Modifier.padding(start = 8.dp), fontWeight = FontWeight.Bold)
      }
      HorizontalDivider(modifier = Modifier.padding(vertical = 10.dp), color = MaterialTheme.colorScheme.surfaceVariant)
      content()
    }
  }
}

@Composable
private fun InfoLine(label: String, value: String) {
  Row(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
    Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.4f), fontSize = 12.sp)
    Text(value, modifier = Modifier.weight(0.6f), fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
  }
}

@Composable
private fun EmptyPanel(message: String) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = panelBorder(),
    shape = RoundedCornerShape(10.dp),
  ) {
    Text(message, modifier = Modifier.fillMaxWidth().padding(24.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
  }
}

@Composable
private fun panelBorder() = BorderStroke(1.dp, MaterialTheme.colorScheme.surfaceVariant)

private fun averageLatency(hosts: List<HostResult>): String =
  hosts.map { it.latencyMs }.filter { it > 0 }.let { samples ->
    if (samples.isEmpty()) "—" else "${samples.average().toInt()} ms"
  }

private fun formatStorage(bytes: Long): String {
  var value = bytes.coerceAtLeast(0).toDouble()
  val units = listOf("B", "KB", "MB", "GB", "TB")
  var index = 0
  while (value >= 1024 && index < units.lastIndex) {
    value /= 1024
    index++
  }
  return if (index == 0) "${value.toLong()} ${units[index]}" else "%.1f %s".format(value, units[index])
}

private fun compactAddress(value: String): String = if (value.length > 15) value.take(15) else value
