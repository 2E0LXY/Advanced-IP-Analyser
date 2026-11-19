import os
import tempfile
import unittest
from pathlib import Path

from ip_analyser.usb_audit import read_usb_devices, usb_audit_report


def device(root: Path, name: str, vendor: str, product: str, interfaces, manufacturer="", title=""):
    folder = root / name
    folder.mkdir()
    (folder / "idVendor").write_text(vendor + "\n")
    (folder / "idProduct").write_text(product + "\n")
    if manufacturer:
        (folder / "manufacturer").write_text(manufacturer + "\n")
    if title:
        (folder / "product").write_text(title + "\n")
    for index, (klass, subclass, protocol) in enumerate(interfaces):
        iface = root / f"{name}:1.{index}"
        iface.mkdir()
        (iface / "bInterfaceClass").write_text(f"{klass:02x}\n")
        (iface / "bInterfaceSubClass").write_text(f"{subclass:02x}\n")
        (iface / "bInterfaceProtocol").write_text(f"{protocol:02x}\n")


class UsbAuditTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "sysfs interface names contain ':', invalid on Windows")
    def test_plain_keyboard_is_not_flagged_but_composite_gadget_is(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            device(root, "1-1", "046d", "c31c", [(3, 1, 1)], "Logitech", "Keyboard")
            device(root, "1-2", "1234", "abcd", [(3, 1, 1), (8, 6, 80)], "Acme", "Flash")
            device(root, "1-3", "1d6b", "0104", [(3, 1, 1), (2, 6, 0)])
            devices = {item.path: item for item in read_usb_devices(root)}
        self.assertEqual(devices["1-1"].indicators, [])
        self.assertTrue(any("mass storage" in reason for reason in devices["1-2"].indicators))
        reasons = " ".join(devices["1-3"].indicators)
        self.assertIn("network adapter", reasons)
        self.assertIn("gadget vendor", reasons)
        self.assertIn("Indicators for review: 2", usb_audit_report(list(devices.values())))

    def test_unreadable_sysfs_raises_instead_of_reporting_clean(self):
        with self.assertRaises(OSError):
            read_usb_devices(Path("/nonexistent/usb"))


if __name__ == "__main__":
    unittest.main()
