from __future__ import annotations

import ctypes
import os
from contextlib import contextmanager
from dataclasses import dataclass
from ctypes import wintypes

from defusedxml import ElementTree

from .wifi_tools import wifi_security_assessment


WLAN_MAX_NAME_LENGTH = 256
DOT11_SSID_MAX_LENGTH = 32
WLAN_AVAILABLE_NETWORK_CONNECTED = 0x00000001
WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000004
ERROR_SUCCESS = 0


@dataclass(frozen=True, slots=True)
class WifiInterface:
    name: str
    guid: str
    state: str


@dataclass(frozen=True, slots=True)
class NearbyWifiNetwork:
    ssid: str
    signal_percent: int
    signal_dbm: int
    security: str
    profile_name: str
    interface: str
    connected: bool
    risk_level: str = "No obvious issue"
    risk_reason: str = ""
    bssid: str = ""
    frequency_mhz: int = 0
    channel: int = 0
    channel_width_mhz: int | None = None


@dataclass(frozen=True, slots=True)
class SavedWifiProfile:
    name: str
    interface: str
    interface_guid: str
    security: str = "Unknown"


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    def text(self) -> str:
        tail = bytes(self.Data4)
        return (f"{self.Data1:08x}-{self.Data2:04x}-{self.Data3:04x}-"
                f"{tail[0]:02x}{tail[1]:02x}-" + "".join(f"{value:02x}" for value in tail[2:]))


class _DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", wintypes.ULONG),
                ("ucSSID", ctypes.c_ubyte * DOT11_SSID_MAX_LENGTH)]

    def text(self) -> str:
        length = min(int(self.uSSIDLength), DOT11_SSID_MAX_LENGTH)
        return bytes(self.ucSSID[:length]).decode("utf-8", errors="replace")


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", _GUID),
                ("strInterfaceDescription", wintypes.WCHAR * WLAN_MAX_NAME_LENGTH),
                ("isState", wintypes.DWORD)]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1)]


class _WLAN_AVAILABLE_NETWORK(ctypes.Structure):
    _fields_ = [("strProfileName", wintypes.WCHAR * WLAN_MAX_NAME_LENGTH),
                ("dot11Ssid", _DOT11_SSID),
                ("dot11BssType", wintypes.DWORD),
                ("uNumberOfBssids", wintypes.ULONG),
                ("bNetworkConnectable", wintypes.BOOL),
                ("wlanNotConnectableReason", wintypes.DWORD),
                ("uNumberOfPhyTypes", wintypes.ULONG),
                ("dot11PhyTypes", wintypes.DWORD * 8),
                ("bMorePhyTypes", wintypes.BOOL),
                ("wlanSignalQuality", wintypes.ULONG),
                ("bSecurityEnabled", wintypes.BOOL),
                ("dot11DefaultAuthAlgorithm", wintypes.DWORD),
                ("dot11DefaultCipherAlgorithm", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("dwReserved", wintypes.DWORD)]


class _WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("Network", _WLAN_AVAILABLE_NETWORK * 1)]


class _WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", wintypes.ULONG),
                ("usRateSet", wintypes.USHORT * 126)]


class _WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", _DOT11_SSID),
                ("uPhyId", wintypes.ULONG),
                ("dot11Bssid", ctypes.c_ubyte * 6),
                ("dot11BssType", wintypes.DWORD),
                ("dot11BssPhyType", wintypes.DWORD),
                ("lRssi", wintypes.LONG),
                ("uLinkQuality", wintypes.ULONG),
                ("bInRegDomain", wintypes.BOOL),
                ("usBeaconPeriod", wintypes.USHORT),
                ("ullTimestamp", ctypes.c_ulonglong),
                ("ullHostTimestamp", ctypes.c_ulonglong),
                ("usCapabilityInformation", wintypes.USHORT),
                ("ulChCenterFrequency", wintypes.ULONG),
                ("wlanRateSet", _WLAN_RATE_SET),
                ("ulIeOffset", wintypes.ULONG),
                ("ulIeSize", wintypes.ULONG)]


class _WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", wintypes.DWORD),
                ("dwNumberOfItems", wintypes.DWORD),
                ("wlanBssEntries", _WLAN_BSS_ENTRY * 1)]


class _WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [("strProfileName", wintypes.WCHAR * WLAN_MAX_NAME_LENGTH),
                ("dwFlags", wintypes.DWORD)]


class _WLAN_PROFILE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("ProfileInfo", _WLAN_PROFILE_INFO * 1)]


_INTERFACE_STATES = {
    0: "Not ready", 1: "Connected", 2: "Ad hoc network formed",
    3: "Disconnecting", 4: "Disconnected", 5: "Associating",
    6: "Discovering", 7: "Authenticating",
}
_AUTH = {
    1: "Open", 2: "Shared key", 3: "WPA Enterprise", 4: "WPA Personal",
    5: "WPA None", 6: "WPA2 Enterprise", 7: "WPA2 Personal",
    8: "WPA3 Enterprise", 9: "WPA3 Personal", 10: "WPA3 Enterprise 192-bit",
    11: "OWE",
}
_CIPHER = {
    0x00: "None", 0x01: "WEP-40", 0x02: "TKIP", 0x04: "AES",
    0x05: "WEP-104", 0x100: "Use group", 0x101: "WEP",
}


def _wlan_api():
    if os.name != "nt":
        raise RuntimeError("Windows Wi-Fi Analyzer is available on Windows 10 and 11.")
    api = ctypes.WinDLL("wlanapi.dll", use_last_error=True)
    api.WlanOpenHandle.argtypes = [wintypes.DWORD, wintypes.LPVOID,
                                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE)]
    api.WlanOpenHandle.restype = wintypes.DWORD
    api.WlanCloseHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    api.WlanCloseHandle.restype = wintypes.DWORD
    api.WlanEnumInterfaces.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                       ctypes.POINTER(ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST))]
    api.WlanEnumInterfaces.restype = wintypes.DWORD
    api.WlanGetAvailableNetworkList.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID),
                                                wintypes.DWORD, wintypes.LPVOID,
                                                ctypes.POINTER(ctypes.POINTER(_WLAN_AVAILABLE_NETWORK_LIST))]
    api.WlanGetAvailableNetworkList.restype = wintypes.DWORD
    api.WlanGetNetworkBssList.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID),
                                          ctypes.POINTER(_DOT11_SSID), wintypes.DWORD,
                                          wintypes.BOOL, wintypes.LPVOID,
                                          ctypes.POINTER(ctypes.POINTER(_WLAN_BSS_LIST))]
    api.WlanGetNetworkBssList.restype = wintypes.DWORD
    api.WlanGetProfileList.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID), wintypes.LPVOID,
                                       ctypes.POINTER(ctypes.POINTER(_WLAN_PROFILE_INFO_LIST))]
    api.WlanGetProfileList.restype = wintypes.DWORD
    api.WlanGetProfile.argtypes = [wintypes.HANDLE, ctypes.POINTER(_GUID), wintypes.LPCWSTR,
                                   wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR),
                                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    api.WlanGetProfile.restype = wintypes.DWORD
    api.WlanFreeMemory.argtypes = [wintypes.LPVOID]
    api.WlanFreeMemory.restype = None
    return api


def _raise_windows_error(code: int, action: str) -> None:
    if code != ERROR_SUCCESS:
        detail = ctypes.FormatError(code).strip() or f"Windows error {code}"
        raise OSError(code, f"{action}: {detail}")


@contextmanager
def _client():
    api = _wlan_api()
    negotiated = wintypes.DWORD()
    handle = wintypes.HANDLE()
    _raise_windows_error(api.WlanOpenHandle(2, None, ctypes.byref(negotiated),
                                            ctypes.byref(handle)), "Open Windows Wi-Fi service")
    try:
        yield api, handle
    finally:
        api.WlanCloseHandle(handle, None)


def _variable_array(pointer, list_type, item_type, field_name: str):
    count = int(pointer.contents.dwNumberOfItems)
    if count <= 0:
        return []
    offset = getattr(list_type, field_name).offset
    array_type = item_type * count
    return list(array_type.from_address(ctypes.addressof(pointer.contents) + offset))


def _interfaces(api, handle) -> list[tuple[WifiInterface, _GUID]]:
    pointer = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
    _raise_windows_error(api.WlanEnumInterfaces(handle, None, ctypes.byref(pointer)),
                         "List Wi-Fi adapters")
    try:
        records = _variable_array(pointer, _WLAN_INTERFACE_INFO_LIST,
                                  _WLAN_INTERFACE_INFO, "InterfaceInfo")
        return [(WifiInterface(record.strInterfaceDescription, record.InterfaceGuid.text(),
                               _INTERFACE_STATES.get(int(record.isState), "Unknown")),
                 record.InterfaceGuid) for record in records]
    finally:
        if pointer:
            api.WlanFreeMemory(pointer)


def list_wifi_interfaces() -> list[WifiInterface]:
    with _client() as (api, handle):
        return [interface for interface, _guid in _interfaces(api, handle)]


def _security(auth: int, cipher: int, enabled: bool) -> str:
    if not enabled:
        return "Open"
    auth_name = _AUTH.get(auth, f"Authentication {auth}")
    cipher_name = _CIPHER.get(cipher, f"Cipher {cipher}")
    return auth_name if cipher_name in {"None", "Use group"} else f"{auth_name} · {cipher_name}"


def channel_for_frequency(frequency_mhz: int) -> int:
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz <= 5895:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    return 0


def channel_width_from_information_elements(data: bytes) -> int | None:
    """Read advertised HT/VHT channel width without inventing unavailable data."""
    width: int | None = None
    position = 0
    while position + 2 <= len(data):
        element_id = data[position]
        length = data[position + 1]
        body = data[position + 2:position + 2 + length]
        if len(body) != length:
            break
        if element_id == 61 and len(body) >= 2:  # HT Operation
            width = 40 if body[1] & 0x03 in {1, 3} else 20
        elif element_id == 192 and body:  # VHT Operation
            if body[0] == 1:
                width = 80
            elif body[0] in {2, 3}:
                width = 160
        position += length + 2
    return width


def _bss_details(api, handle, guid: _GUID) -> dict[str, tuple[int, int, str, int | None]]:
    pointer = ctypes.POINTER(_WLAN_BSS_LIST)()
    result = api.WlanGetNetworkBssList(handle, ctypes.byref(guid), None, 3, False,
                                       None, ctypes.byref(pointer))
    if result != ERROR_SUCCESS:
        return {}
    details: dict[str, tuple[int, int, str, int | None]] = {}
    try:
        records = _variable_array(pointer, _WLAN_BSS_LIST, _WLAN_BSS_ENTRY,
                                  "wlanBssEntries")
        for record in records:
            ssid = record.dot11Ssid.text() or "<hidden>"
            frequency = int(record.ulChCenterFrequency) // 1000
            bssid = ":".join(f"{value:02X}" for value in record.dot11Bssid)
            ie_data = b""
            if record.ulIeSize:
                ie_data = ctypes.string_at(ctypes.addressof(record) + int(record.ulIeOffset),
                                           int(record.ulIeSize))
            candidate = (int(record.lRssi), frequency, bssid,
                         channel_width_from_information_elements(ie_data))
            previous = details.get(ssid.casefold())
            if previous is None or candidate[0] > previous[0]:
                details[ssid.casefold()] = candidate
        return details
    finally:
        if pointer:
            api.WlanFreeMemory(pointer)


def list_nearby_wifi_networks() -> list[NearbyWifiNetwork]:
    networks: dict[tuple[str, str], NearbyWifiNetwork] = {}
    with _client() as (api, handle):
        for interface, guid in _interfaces(api, handle):
            bss_by_ssid = _bss_details(api, handle, guid)
            pointer = ctypes.POINTER(_WLAN_AVAILABLE_NETWORK_LIST)()
            result = api.WlanGetAvailableNetworkList(handle, ctypes.byref(guid), 0, None,
                                                     ctypes.byref(pointer))
            if result != ERROR_SUCCESS:
                continue
            try:
                records = _variable_array(pointer, _WLAN_AVAILABLE_NETWORK_LIST,
                                          _WLAN_AVAILABLE_NETWORK, "Network")
                for record in records:
                    ssid = record.dot11Ssid.text() or "<hidden>"
                    quality = max(0, min(100, int(record.wlanSignalQuality)))
                    security = _security(int(record.dot11DefaultAuthAlgorithm),
                                         int(record.dot11DefaultCipherAlgorithm),
                                         bool(record.bSecurityEnabled))
                    risk_level, risk_reasons = wifi_security_assessment(security)
                    detail = bss_by_ssid.get(ssid.casefold())
                    dbm = detail[0] if detail else (-100 if quality == 0 else -50 if quality == 100 else -100 + quality // 2)
                    frequency = detail[1] if detail else 0
                    network = NearbyWifiNetwork(
                        ssid=ssid, signal_percent=quality,
                        signal_dbm=dbm,
                        security=security,
                        profile_name=record.strProfileName,
                        interface=interface.name,
                        connected=bool(int(record.dwFlags) & WLAN_AVAILABLE_NETWORK_CONNECTED),
                        risk_level=risk_level, risk_reason="; ".join(risk_reasons),
                        bssid=detail[2] if detail else "", frequency_mhz=frequency,
                        channel=channel_for_frequency(frequency),
                        channel_width_mhz=detail[3] if detail else None)
                    key = (ssid.casefold(), interface.guid)
                    previous = networks.get(key)
                    if previous is None or network.signal_percent > previous.signal_percent:
                        networks[key] = network
            finally:
                if pointer:
                    api.WlanFreeMemory(pointer)
    return sorted(networks.values(), key=lambda item: (not item.connected, -item.signal_percent,
                                                       item.ssid.casefold()))


def _profile_xml(api, handle, guid: _GUID, name: str, plaintext: bool) -> str:
    xml_pointer = wintypes.LPWSTR()
    flags = wintypes.DWORD(WLAN_PROFILE_GET_PLAINTEXT_KEY if plaintext else 0)
    access = wintypes.DWORD()
    result = api.WlanGetProfile(handle, ctypes.byref(guid), name, None,
                                ctypes.byref(xml_pointer), ctypes.byref(flags), ctypes.byref(access))
    _raise_windows_error(result, f"Read Wi-Fi profile {name}")
    try:
        return xml_pointer.value or ""
    finally:
        if xml_pointer:
            api.WlanFreeMemory(xml_pointer)


def _xml_text(xml: str, local_name: str) -> str:
    root = ElementTree.fromstring(xml)
    node = root.find(f".//{{*}}{local_name}")
    return (node.text or "").strip() if node is not None else ""


def list_saved_wifi_profiles() -> list[SavedWifiProfile]:
    profiles: list[SavedWifiProfile] = []
    with _client() as (api, handle):
        for interface, guid in _interfaces(api, handle):
            pointer = ctypes.POINTER(_WLAN_PROFILE_INFO_LIST)()
            result = api.WlanGetProfileList(handle, ctypes.byref(guid), None, ctypes.byref(pointer))
            if result != ERROR_SUCCESS:
                continue
            try:
                records = _variable_array(pointer, _WLAN_PROFILE_INFO_LIST,
                                          _WLAN_PROFILE_INFO, "ProfileInfo")
                for record in records:
                    security = "Unknown"
                    try:
                        xml = _profile_xml(api, handle, guid, record.strProfileName, False)
                        authentication = _xml_text(xml, "authentication")
                        encryption = _xml_text(xml, "encryption")
                        security = " · ".join(value for value in (authentication, encryption) if value) or "Open"
                    except (OSError, ValueError, ElementTree.ParseError):
                        pass
                    profiles.append(SavedWifiProfile(record.strProfileName, interface.name,
                                                     interface.guid, security))
            finally:
                if pointer:
                    api.WlanFreeMemory(pointer)
    return sorted(profiles, key=lambda item: (item.name.casefold(), item.interface.casefold()))


def reveal_saved_wifi_password(profile: SavedWifiProfile) -> str:
    """Return one locally saved key after the caller has obtained explicit user confirmation."""
    with _client() as (api, handle):
        for _interface, guid in _interfaces(api, handle):
            if guid.text().casefold() != profile.interface_guid.casefold():
                continue
            xml = _profile_xml(api, handle, guid, profile.name, True)
            protected = _xml_text(xml, "protected").casefold()
            key = _xml_text(xml, "keyMaterial")
            if not key:
                raise PermissionError("This profile has no saved Wi-Fi password.")
            if protected in {"true", "1", "yes"}:
                raise PermissionError(
                    "Windows kept this key encrypted. Sign in with an administrator account "
                    "and reopen the application if you are authorized to view it.")
            return key
    raise ValueError("The selected Wi-Fi adapter or profile is no longer available.")
