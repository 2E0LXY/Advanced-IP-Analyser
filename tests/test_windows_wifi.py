import ctypes
import unittest

from ip_analyser.windows_wifi import (
    _WLAN_PROFILE_INFO,
    _WLAN_PROFILE_INFO_LIST,
    _security,
    _variable_array,
    _xml_text,
)


class WindowsWifiTests(unittest.TestCase):
    def test_security_names_modern_and_open_networks(self):
        self.assertEqual(_security(7, 4, True), "WPA2 Personal · AES")
        self.assertEqual(_security(9, 4, True), "WPA3 Personal · AES")
        self.assertEqual(_security(1, 0, False), "Open")

    def test_profile_xml_extracts_namespaced_values(self):
        xml = """<?xml version="1.0"?>
        <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
          <MSM><security><authEncryption>
            <authentication>WPA2PSK</authentication><encryption>AES</encryption>
          </authEncryption><sharedKey><protected>false</protected>
            <keyMaterial>example-value</keyMaterial>
          </sharedKey></security></MSM>
        </WLANProfile>"""
        self.assertEqual(_xml_text(xml, "authentication"), "WPA2PSK")
        self.assertEqual(_xml_text(xml, "protected"), "false")
        self.assertEqual(_xml_text(xml, "keyMaterial"), "example-value")

    def test_variable_native_list_uses_declared_array_offset(self):
        class TwoProfiles(ctypes.Structure):
            _fields_ = [("dwNumberOfItems", ctypes.c_ulong),
                        ("dwIndex", ctypes.c_ulong),
                        ("ProfileInfo", _WLAN_PROFILE_INFO * 2)]

        native = TwoProfiles()
        native.dwNumberOfItems = 2
        native.ProfileInfo[0].strProfileName = "First"
        native.ProfileInfo[1].strProfileName = "Second"
        pointer = ctypes.cast(ctypes.pointer(native), ctypes.POINTER(_WLAN_PROFILE_INFO_LIST))
        records = _variable_array(pointer, _WLAN_PROFILE_INFO_LIST,
                                  _WLAN_PROFILE_INFO, "ProfileInfo")
        self.assertEqual([record.strProfileName for record in records], ["First", "Second"])


if __name__ == "__main__":
    unittest.main()
