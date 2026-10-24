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
import uk.co.twoe0lxy.ipanalyser.data.NetworkInfo
import uk.co.twoe0lxy.ipanalyser.data.NetworkScanner
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
)

class MainScreenViewModel(application: Application) : AndroidViewModel(application) {
  private val scanner = NetworkScanner(application)
  private val mutableState = MutableStateFlow(MainScreenUiState(network = scanner.networkInfo()))
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
        mutableState.update { it.copy(hosts = hosts, scanningLan = false, status = "Scan complete · ${hosts.size} devices responded") }
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
      } catch (error: Exception) {
        mutableState.update { it.copy(scanningWifi = false, status = error.message ?: "Wi-Fi scan failed") }
      }
    }
  }

  fun runDiagnostic(kind: DiagnosticKind, target: String) {
    viewModelScope.launch {
      mutableState.update { it.copy(diagnosticResult = "Running ${kind.label.lowercase()}…") }
      try {
        val result = when (kind) {
          DiagnosticKind.Ping -> scanner.ping(target)
          DiagnosticKind.Dns -> scanner.dns(target)
          DiagnosticKind.Ports -> scanner.portCheck(target)
          DiagnosticKind.Http -> scanner.httpCheck(target)
        }
        mutableState.update { it.copy(diagnosticResult = result) }
      } catch (error: Exception) {
        mutableState.update { it.copy(diagnosticResult = error.message ?: "Diagnostic failed") }
      }
    }
  }
}

enum class DiagnosticKind(val label: String) {
  Ping("Ping"), Dns("DNS lookup"), Ports("Port check"), Http("HTTP check")
}
