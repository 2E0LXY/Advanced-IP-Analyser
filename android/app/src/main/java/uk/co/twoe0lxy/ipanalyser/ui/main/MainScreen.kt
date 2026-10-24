package uk.co.twoe0lxy.ipanalyser.ui.main

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import uk.co.twoe0lxy.ipanalyser.data.HostResult
import uk.co.twoe0lxy.ipanalyser.data.WifiNetwork
import uk.co.twoe0lxy.ipanalyser.theme.Green400
import uk.co.twoe0lxy.ipanalyser.theme.Orange400

private enum class AppPage(val label: String, val mark: String) {
  Dashboard("Dashboard", "⌂"), Lan("LAN scan", "⌕"), Wifi("Wi-Fi", "◉"), Tools("Tools", "⚙")
}

@OptIn(ExperimentalMaterial3Api::class)
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
    topBar = {
      TopAppBar(
        title = {
          Column {
            Text("Advanced IP Analyser", fontWeight = FontWeight.Bold)
            Text("Network diagnostics for Android", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
          }
        },
        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
      )
    },
    bottomBar = {
      Column {
        Text(
          state.status,
          modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          fontSize = 12.sp,
        )
        NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
          pages.forEachIndexed { index, page ->
            NavigationBarItem(
              selected = selectedPage == index,
              onClick = { selectedPage = index },
              icon = { Text(page.mark, fontSize = 20.sp) },
              label = { Text(page.label) },
            )
          }
        }
      }
    },
  ) { padding ->
    Box(Modifier.padding(padding).fillMaxSize()) {
      when (pages[selectedPage]) {
        AppPage.Dashboard -> DashboardPage(state, onPage = { selectedPage = it.ordinal }, onScan = viewModel::scanLan)
        AppPage.Lan -> LanPage(state, onScan = viewModel::scanLan, onRefresh = viewModel::refreshNetwork)
        AppPage.Wifi -> WifiPage(state, onScan = viewModel::scanWifi)
        AppPage.Tools -> ToolsPage(state, onRun = viewModel::runDiagnostic)
      }
    }
  }
}

@Composable
private fun DashboardPage(state: MainScreenUiState, onPage: (AppPage) -> Unit, onScan: () -> Unit) {
  LazyColumn(
    modifier = Modifier.fillMaxSize().padding(16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp),
  ) {
    item {
      Text("Network Dashboard", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
      Text("Your current connection and quick diagnostic tools.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        MetricCard("Devices", state.hosts.size.toString(), "found in last scan", Modifier.weight(1f))
        MetricCard("Open ports", state.hosts.sumOf { it.openPorts.size }.toString(), "common services", Modifier.weight(1f), Orange400)
      }
    }
    item {
      Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        MetricCard("Local IP", state.network.localIp, state.network.interfaceName, Modifier.weight(1f))
        MetricCard("Gateway", state.network.gateway, state.network.wifiName.ifBlank { "active route" }, Modifier.weight(1f), Green400)
      }
    }
    item {
      SectionCard("Quick actions") {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          Button(onClick = onScan, modifier = Modifier.weight(1f)) { Text(if (state.scanningLan) "Stop scan" else "Scan network") }
          OutlinedButton(onClick = { onPage(AppPage.Wifi) }, modifier = Modifier.weight(1f)) { Text("Wi-Fi") }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          OutlinedButton(onClick = { onPage(AppPage.Tools) }, modifier = Modifier.weight(1f)) { Text("Ping & DNS") }
          OutlinedButton(onClick = { onPage(AppPage.Lan) }, modifier = Modifier.weight(1f)) { Text("View devices") }
        }
      }
    }
    item {
      SectionCard("Network information") {
        InfoLine("Network range", state.network.range)
        InfoLine("Interface", state.network.interfaceName)
        InfoLine("Wi-Fi", state.network.wifiName.ifBlank { "Unavailable or permission required" })
        InfoLine("Platform limits", "Android protects device MACs and saved Wi-Fi passwords")
      }
    }
  }
}

@Composable
private fun LanPage(state: MainScreenUiState, onScan: () -> Unit, onRefresh: () -> Unit) {
  Column(Modifier.fillMaxSize().padding(16.dp)) {
    Text("LAN discovery", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
    Text("Bounded to the phone's local /24 for responsive scanning.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(12.dp))
    SectionCard("${state.network.range} · ${state.network.interfaceName}") {
      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onScan, modifier = Modifier.weight(1f)) { Text(if (state.scanningLan) "Stop" else "Scan") }
        OutlinedButton(onClick = onRefresh) { Text("Refresh") }
      }
      if (state.scanningLan && state.total > 0) {
        Spacer(Modifier.height(10.dp))
        LinearProgressIndicator(
          progress = { state.completed.toFloat() / state.total.toFloat() },
          modifier = Modifier.fillMaxWidth(),
        )
        Text("${state.completed} of ${state.total} addresses", fontSize = 12.sp)
      }
    }
    Spacer(Modifier.height(12.dp))
    if (state.hosts.isEmpty()) {
      EmptyPanel(if (state.scanningLan) "Looking for devices…" else "Press Scan to discover devices and common services.")
    } else {
      LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(state.hosts, key = HostResult::address) { HostRow(it) }
      }
    }
  }
}

@Composable
private fun HostRow(host: HostResult) {
  Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
    Column(Modifier.fillMaxWidth().padding(14.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Text(host.address, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
        Text("${host.latencyMs} ms", color = Green400)
      }
      Text(if (host.openPorts.isEmpty()) "Online · no common TCP ports responded" else host.services,
        color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
    }
  }
}

@Composable
private fun WifiPage(state: MainScreenUiState, onScan: () -> Unit) {
  val context = LocalContext.current
  val permissions = remember {
    buildList {
      add(Manifest.permission.ACCESS_COARSE_LOCATION)
      add(Manifest.permission.ACCESS_FINE_LOCATION)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) add(Manifest.permission.NEARBY_WIFI_DEVICES)
    }.toTypedArray()
  }
  val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
    onScan()
  }
  fun requestOrScan() {
    val missing = permissions.any { ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }
    if (missing) permissionLauncher.launch(permissions) else onScan()
  }

  Column(Modifier.fillMaxSize().padding(16.dp)) {
    Text("Wi-Fi analyzer", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
    Text("Nearby network names, channels, signal and advertised security.", color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(10.dp))
    Button(onClick = ::requestOrScan, enabled = !state.scanningWifi) {
      Text(if (state.scanningWifi) "Scanning…" else "Scan nearby Wi-Fi")
    }
    Text("Android requires nearby-device and precise-location permission for Wi-Fi scan results.",
      fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 8.dp))
    if (state.wifiNetworks.isEmpty()) {
      EmptyPanel("No nearby Wi-Fi results yet.")
    } else {
      LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(state.wifiNetworks, key = WifiNetwork::bssid) { WifiRow(it) }
      }
    }
  }
}

@Composable
private fun WifiRow(network: WifiNetwork) {
  val reviewColor = if (network.review.startsWith("High")) Color(0xFFFF6767)
  else if (network.review.startsWith("Medium")) Orange400 else Green400
  Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
    Column(Modifier.fillMaxWidth().padding(14.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Text(network.name, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
        Text("${network.signalPercent}%", color = MaterialTheme.colorScheme.primary)
      }
      Text(network.bssid, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
      Text("Channel ${network.channel} · ${network.frequencyMhz} MHz · ${network.security}", fontSize = 13.sp)
      Text(network.review, color = reviewColor, fontSize = 13.sp, fontWeight = FontWeight.Medium)
    }
  }
}

@Composable
private fun ToolsPage(state: MainScreenUiState, onRun: (DiagnosticKind, String) -> Unit) {
  var target by rememberSaveable { mutableStateOf("8.8.8.8") }
  Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
    Text("Diagnostics", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
    Text("Test a host, address or URL from this phone.", color = MaterialTheme.colorScheme.onSurfaceVariant)
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
        row.forEach { kind ->
          Button(onClick = { onRun(kind, target) }, modifier = Modifier.weight(1f)) { Text(kind.label) }
        }
        if (row.size == 1) Spacer(Modifier.weight(1f))
      }
    }
    SectionCard("Result") {
      Text(state.diagnosticResult)
    }
    Spacer(Modifier.height(12.dp))
    Text("Ping uses Android's reachability API, so some hosts that block echo requests can still be online.",
      color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
  }
}

@Composable
private fun MetricCard(title: String, value: String, detail: String, modifier: Modifier = Modifier, accent: Color = MaterialTheme.colorScheme.primary) {
  Card(modifier, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
    Column(Modifier.padding(14.dp)) {
      Text(title, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
      Text(value, color = accent, fontWeight = FontWeight.Bold, fontSize = if (value.length > 10) 16.sp else 28.sp, maxLines = 1)
      Text(detail, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp, maxLines = 1)
    }
  }
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
  Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
    Column(Modifier.fillMaxWidth().padding(14.dp)) {
      Text(title, fontWeight = FontWeight.Bold)
      Spacer(Modifier.height(10.dp))
      content()
    }
  }
}

@Composable
private fun InfoLine(label: String, value: String) {
  Row(Modifier.fillMaxWidth().padding(vertical = 5.dp)) {
    Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.42f))
    Text(value, modifier = Modifier.weight(0.58f))
  }
  HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
}

@Composable
private fun EmptyPanel(message: String) {
  Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
    Text(message, modifier = Modifier.fillMaxWidth().padding(24.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
  }
}
