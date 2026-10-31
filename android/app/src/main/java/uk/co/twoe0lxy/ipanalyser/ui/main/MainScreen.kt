package uk.co.twoe0lxy.ipanalyser.ui.main

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
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
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
import uk.co.twoe0lxy.ipanalyser.data.HostResult
import uk.co.twoe0lxy.ipanalyser.data.ScannerUtils
import uk.co.twoe0lxy.ipanalyser.data.WifiNetwork
import uk.co.twoe0lxy.ipanalyser.theme.Green400
import uk.co.twoe0lxy.ipanalyser.theme.Navy700
import uk.co.twoe0lxy.ipanalyser.theme.Orange400
import uk.co.twoe0lxy.ipanalyser.theme.Purple400

private enum class AppPage(val label: String, val icon: ImageVector) {
  Dashboard("Dashboard", Icons.Outlined.Dashboard),
  Lan("LAN scan", Icons.Outlined.Search),
  Wifi("Wi-Fi", Icons.Outlined.Wifi),
  Tools("Tools", Icons.Outlined.Analytics),
}

@Composable
fun MainScreen(
  modifier: Modifier = Modifier,
  viewModel: MainScreenViewModel = viewModel(),
) {
  val state by viewModel.uiState.collectAsStateWithLifecycle()
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
        AppPage.Dashboard -> DashboardPage(state, { selectedPage = it.ordinal }, viewModel::scanLan)
        AppPage.Lan -> LanPage(state, viewModel::scanLan, viewModel::refreshNetwork)
        AppPage.Wifi -> WifiPage(state, viewModel::scanWifi, viewModel::connectWifi)
        AppPage.Tools -> ToolsPage(state, viewModel::runDiagnostic)
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
private fun DashboardPage(state: MainScreenUiState, onPage: (AppPage) -> Unit, onScan: () -> Unit) {
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
        Button(onClick = onScan) {
          Icon(Icons.Outlined.Search, contentDescription = null, modifier = Modifier.size(18.dp))
          Spacer(Modifier.width(6.dp))
          Text(if (state.scanningLan) "Stop" else "Scan")
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
      SectionCard("Quick actions", Icons.Outlined.NetworkCheck) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          QuickAction("Scan network", Icons.Outlined.Search, Modifier.weight(1f), onScan)
          QuickAction("Wi-Fi scan", Icons.Outlined.Wifi, Modifier.weight(1f)) { onPage(AppPage.Wifi) }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          QuickAction("Ping & DNS", Icons.Outlined.Dns, Modifier.weight(1f)) { onPage(AppPage.Tools) }
          QuickAction("View devices", Icons.Outlined.Devices, Modifier.weight(1f)) { onPage(AppPage.Lan) }
        }
      }
    }
    item {
      SectionCard("Recent activity", Icons.Outlined.Analytics) {
        InfoLine("Current status", state.status)
        InfoLine("Scan progress", if (state.total > 0) "${state.completed} / ${state.total}" else "Not started")
        InfoLine("Nearby Wi-Fi", "${state.wifiNetworks.size} networks")
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
private fun LanPage(state: MainScreenUiState, onScan: () -> Unit, onRefresh: () -> Unit) {
  Column(Modifier.fillMaxSize().padding(16.dp)) {
    PageHeading("LAN discovery", "Find active devices and common services", Icons.Outlined.Search)
    Spacer(Modifier.height(12.dp))
    SectionCard(state.network.range, Icons.Outlined.Hub) {
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onScan, modifier = Modifier.weight(1f)) { Text(if (state.scanningLan) "Stop scan" else "Scan network") }
        OutlinedButton(onClick = onRefresh) { Text("Refresh") }
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
        items(state.hosts, key = HostResult::address) { HostRow(it) }
      }
    }
  }
}

@Composable
private fun HostRow(host: HostResult) {
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
      Icon(Icons.Outlined.Devices, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(22.dp))
      Column(Modifier.padding(start = 11.dp).weight(1f)) {
        Text(host.address, fontWeight = FontWeight.Bold)
        Text(
          if (host.openPorts.isEmpty()) "Online · no common ports responded" else host.services,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          fontSize = 12.sp,
        )
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
  val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
    permissionDenied = grants.values.any { !it }
    if (!permissionDenied) onScan()
  }
  fun requestOrScan() {
    val missing = permissions.any { ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }
    if (missing) permissionLauncher.launch(permissions) else onScan()
  }

  Column(Modifier.fillMaxSize().padding(16.dp)) {
    PageHeading("Wi-Fi analyzer", "Nearby channels, signal and security", Icons.Outlined.Wifi)
    Spacer(Modifier.height(12.dp))
    Button(onClick = ::requestOrScan, enabled = !state.scanningWifi, modifier = Modifier.fillMaxWidth()) {
      Icon(Icons.Outlined.Wifi, null, modifier = Modifier.size(18.dp))
      Text(if (state.scanningWifi) "  Scanning…" else "  Scan nearby Wi-Fi")
    }
    Text(
      if (permissionDenied) "Wi-Fi scan permission was denied. Allow it in Android settings to scan nearby networks."
      else "Nearby-device and precise-location permission are required by Android.",
      fontSize = 11.sp,
      color = if (permissionDenied) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
      modifier = Modifier.padding(vertical = 9.dp),
    )
    if (state.wifiNetworks.isEmpty()) {
      EmptyPanel("No nearby Wi-Fi results yet.")
    } else {
      LazyColumn(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(state.wifiNetworks, key = WifiNetwork::bssid) { WifiRow(it, onConnect) }
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
        Text("Channel ${network.channel} · ${network.frequencyMhz} MHz · ${network.security}", fontSize = 12.sp)
        Text(network.review, color = reviewColor, fontSize = 12.sp)
      }
      Column(horizontalAlignment = Alignment.End) {
        Text("${network.signalPercent}%", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
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
private fun ToolsPage(state: MainScreenUiState, onRun: (DiagnosticKind, String) -> Unit) {
  var target by rememberSaveable { mutableStateOf("8.8.8.8") }
  Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
    PageHeading("Diagnostics", "Test a host, address or URL", Icons.Outlined.Analytics)
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(
      value = target,
      onValueChange = { target = it },
      label = { Text("Target host, IP address or URL") },
      singleLine = true,
      modifier = Modifier.fillMaxWidth(),
    )
    Spacer(Modifier.height(10.dp))
    DiagnosticKind.entries.chunked(2).forEach { row ->
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(bottom = 8.dp)) {
        row.forEach { kind -> Button(onClick = { onRun(kind, target) }, modifier = Modifier.weight(1f)) { Text(kind.label) } }
      }
    }
    SectionCard("Result", Icons.Outlined.NetworkCheck) { Text(state.diagnosticResult) }
    Spacer(Modifier.height(12.dp))
    SectionCard("Android network access", Icons.Outlined.Security) {
      Text(
        "Device MAC addresses and saved Wi-Fi passwords are protected by Android.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        fontSize = 12.sp,
      )
    }
  }
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
private fun QuickAction(label: String, icon: ImageVector, modifier: Modifier = Modifier, onClick: () -> Unit) {
  OutlinedButton(onClick = onClick, modifier = modifier.height(54.dp), shape = RoundedCornerShape(8.dp)) {
    Icon(icon, null, modifier = Modifier.size(18.dp))
    Text("  $label", fontSize = 12.sp)
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

private fun compactAddress(value: String): String = if (value.length > 15) value.take(15) else value
