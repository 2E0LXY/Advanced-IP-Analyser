package uk.co.twoe0lxy.ipanalyser.ui.main

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import uk.co.twoe0lxy.ipanalyser.data.HostResult
import uk.co.twoe0lxy.ipanalyser.data.AdvancedNetworkTools
import uk.co.twoe0lxy.ipanalyser.data.NetworkInfo
import uk.co.twoe0lxy.ipanalyser.data.NetworkScanner
import uk.co.twoe0lxy.ipanalyser.data.SmartDevice
import uk.co.twoe0lxy.ipanalyser.data.PeerPairing
import uk.co.twoe0lxy.ipanalyser.data.InventoryStore
import uk.co.twoe0lxy.ipanalyser.data.WifiNetwork

data class MainScreenUiState(
  val network: NetworkInfo = NetworkInfo(),
  val hosts: List<HostResult> = emptyList(),
  val wifiNetworks: List<WifiNetwork> = emptyList(),
  val scanningLan: Boolean = false,
  val scanningWifi: Boolean = false,
  val completed: Int = 0,
  val total: Int = 0,
  val status: String = "Ready",
  val diagnosticResult: String = "Choose a diagnostic tool.",
  val smartDevices: List<SmartDevice> = emptyList(),
  val working: Boolean = false,
  val activity: List<String> = emptyList(),
  val pairedDesktop: String = "",
  val peerListening: Boolean = false,
  val favorites: Set<String> = emptySet(),
  val savedScans: Int = 0,
)

class MainScreenViewModel(application: Application) : AndroidViewModel(application) {
  private val scanner = NetworkScanner(application)
  private val advanced = AdvancedNetworkTools(application)
  private val pairing = PeerPairing(application)
  private val inventory = InventoryStore(application)
  private val mutableState = MutableStateFlow(MainScreenUiState(
    network = scanner.networkInfo(),
    pairedDesktop = pairing.load()?.desktopAddress.orEmpty(),
    favorites = inventory.favorites(),
    savedScans = inventory.historyCount(),
  ))
  val uiState: StateFlow<MainScreenUiState> = mutableState.asStateFlow()
  private var scanJob: Job? = null

  fun refreshNetwork() {
    mutableState.update { it.copy(network = scanner.networkInfo()) }
  }

  fun scanLan() {
    if (mutableState.value.scanningLan) {
      scanJob?.cancel()
      return
    }
    val network = scanner.networkInfo()
    if (network.localIp == "Unavailable") {
      mutableState.update { it.copy(status = "Connect to a local network first.") }
      return
    }
    scanJob = viewModelScope.launch {
      mutableState.update { it.copy(network = network, hosts = emptyList(), scanningLan = true, status = "Scanning local network…") }
      try {
        val hosts = scanner.scanLan(network) { completed, total ->
          mutableState.update { it.copy(completed = completed, total = total) }
        }
        inventory.saveScan(hosts)
        mutableState.update { it.copy(hosts = hosts, scanningLan = false, status = "Scan complete · ${hosts.size} devices responded") }
        mutableState.update { it.copy(savedScans = inventory.historyCount()) }
        record("LAN scan · ${hosts.size} devices")
      } catch (_: CancellationException) {
        mutableState.update { it.copy(scanningLan = false, status = "Scan stopped") }
      } catch (error: Exception) {
        mutableState.update { it.copy(scanningLan = false, status = error.message ?: "Scan failed") }
      }
    }
  }

  fun scanWifi() {
    if (mutableState.value.scanningWifi) return
    viewModelScope.launch {
      mutableState.update { it.copy(scanningWifi = true, status = "Requesting nearby Wi-Fi scan…") }
      try {
        val networks = scanner.scanWifi()
        mutableState.update { it.copy(wifiNetworks = networks, scanningWifi = false, status = "${networks.size} nearby networks") }
        record("Wi-Fi scan · ${networks.size} networks")
      } catch (error: Exception) {
        mutableState.update { it.copy(scanningWifi = false, status = error.message ?: "Wi-Fi scan failed") }
      }
    }
  }

  fun connectWifi(network: WifiNetwork, password: String) {
    scanner.connectWifi(network, password) { message ->
      mutableState.update {
        it.copy(
          status = message,
          network = if (message.startsWith("Connected to ")) scanner.networkInfo() else it.network,
        )
      }
    }
  }

  fun runDiagnostic(kind: DiagnosticKind, target: String, options: String = "") {
    viewModelScope.launch {
      mutableState.update { it.copy(diagnosticResult = "Running ${kind.label.lowercase()}…", working = true) }
      try {
        val result = when (kind) {
          DiagnosticKind.Ping -> scanner.ping(target)
          DiagnosticKind.Dns -> scanner.dns(target)
          DiagnosticKind.Ports -> scanner.portCheck(target)
          DiagnosticKind.Http -> scanner.httpCheck(target)
          DiagnosticKind.CustomPorts -> advanced.customPortScan(target, options)
          DiagnosticKind.Traceroute -> advanced.traceroute(target)
          DiagnosticKind.Connections -> advanced.connections()
          DiagnosticKind.Tls -> advanced.tlsInspection(target)
          DiagnosticKind.EmailSecurity -> advanced.emailSecurity(target)
          DiagnosticKind.WakeOnLan -> advanced.wakeOnLan(target, options)
        }
        mutableState.update { it.copy(diagnosticResult = result, working = false) }
        record("${kind.label} · ${target.ifBlank { "local device" }}")
      } catch (error: Exception) {
        mutableState.update { it.copy(diagnosticResult = error.message ?: "Diagnostic failed", working = false) }
      }
    }
  }

  fun runSsh(host: String, username: String, password: String, command: String) {
    runAdvanced("SSH command") { advanced.sshCommand(host, username, password, command) }
  }

  fun listSftp(host: String, username: String, password: String, path: String) {
    runAdvanced("SFTP listing") { advanced.sftpList(host, username, password, path) }
  }

  fun discoverSmartHome() {
    viewModelScope.launch {
      mutableState.update { it.copy(working = true, diagnosticResult = "Discovering compatible TP-Link/Kasa devices…") }
      try {
        val devices = advanced.discoverKasaDevices()
        mutableState.update {
          it.copy(
            smartDevices = devices,
            working = false,
            diagnosticResult = if (devices.isEmpty()) "No compatible local Kasa devices replied. Modern Tapo devices can be controlled through their own app or Home Assistant." else "${devices.size} compatible smart devices found.",
          )
        }
        record("Smart Home · ${devices.size} devices")
      } catch (error: Exception) {
        mutableState.update { it.copy(working = false, diagnosticResult = error.message ?: "Smart Home discovery failed") }
      }
    }
  }

  fun setSmartPower(device: SmartDevice, enabled: Boolean) {
    runAdvanced("Smart Home") { advanced.setKasaPower(device, enabled) }
  }

  fun toggleFavorite(address: String) {
    mutableState.update { it.copy(favorites = inventory.toggleFavorite(address)) }
  }

  private fun runAdvanced(label: String, operation: suspend () -> String) {
    viewModelScope.launch {
      mutableState.update { it.copy(working = true, diagnosticResult = "Running ${label.lowercase()}…") }
      try {
        val result = operation()
        mutableState.update { it.copy(working = false, diagnosticResult = result) }
        record(label)
      } catch (error: Exception) {
        mutableState.update { it.copy(working = false, diagnosticResult = error.message ?: "$label failed") }
      }
    }
  }

  private fun record(message: String) {
    val stamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.UK).format(java.util.Date())
    mutableState.update { it.copy(activity = (listOf("$stamp  $message") + it.activity).take(30)) }
  }

  fun pairDesktop(address: String, token: String) {
    runAdvanced("Desktop pairing") {
      val config = pairing.pair(address, token)
      mutableState.update { it.copy(pairedDesktop = config.desktopAddress) }
      "Paired securely with desktop ${config.desktopAddress}. The token is encrypted by Android Keystore."
    }
  }

  fun scanFromDesktop(target: String) {
    runAdvanced("Desktop scan") { pairing.scanDesktop(target) }
  }

  fun setPeerListener(enabled: Boolean) {
    try {
      if (enabled) pairing.startBridge { message ->
        mutableState.update { it.copy(status = message) }
        record(message)
      } else pairing.stopBridge()
      mutableState.update { it.copy(peerListening = enabled, status = if (enabled) "Desktop can request Android LAN scans" else "Android peer listener stopped") }
    } catch (error: Exception) {
      mutableState.update { it.copy(peerListening = false, status = error.message ?: "Could not start peer listener") }
    }
  }

  fun revokeDesktop() {
    runAdvanced("Pairing revocation") {
      val result = pairing.revoke()
      mutableState.update { it.copy(pairedDesktop = "", peerListening = false) }
      result
    }
  }

  override fun onCleared() {
    pairing.stopBridge()
    super.onCleared()
  }
}

enum class DiagnosticKind(val label: String) {
  Ping("Ping"),
  Dns("DNS lookup"),
  Ports("Common ports"),
  Http("HTTP inspect"),
  CustomPorts("Custom ports"),
  Traceroute("Traceroute"),
  Connections("Connections"),
  Tls("TLS certificate"),
  EmailSecurity("Email security"),
  WakeOnLan("Wake-on-LAN"),
}
