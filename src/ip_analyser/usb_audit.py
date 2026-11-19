"""Read-only audit of attached USB devices for keystroke-injection and gadget indicators.

Linux only: reads sysfs and never opens, binds or modifies a device. A match is an
indicator for review, never proof of an attack.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

SYSFS_USB = Path("/sys/bus/usb/devices")
MAX_USB_DEVICES = 512
_CLASS_NAMES = {
    0x01: "audio", 0x02: "communications", 0x03: "HID", 0x08: "mass storage",
    0x0A: "CDC data", 0xE0: "wireless controller", 0xEF: "miscellaneous",
}
_NETWORK_CLASSES = {0x02, 0x0A, 0xE0}


@dataclass(slots=True)
class UsbDevice:
    path: str
    vendor_id: str = ""
    product_id: str = ""
    manufacturer: str = ""
    product: str = ""
    classes: set[int] = field(default_factory=set)
    hid_protocols: set[int] = field(default_factory=set)
    authorized: bool = True
    indicators: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        name = " ".join(part for part in (self.manufacturer, self.product) if part) or "Unnamed device"
        return f"{name} ({self.vendor_id}:{self.product_id})"


def _read(path: Path, limit: int = 128) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit].strip()
    except OSError:
        return ""


def _hex(value: str) -> int | None:
    try:
        return int(value, 16)
    except ValueError:
        return None


def assess_usb_device(device: UsbDevice) -> list[str]:
    reasons: list[str] = []
    is_keyboard = 1 in device.hid_protocols
    if is_keyboard and (device.classes & {0x08}):
        reasons.append("Presents as a keyboard and mass storage together, the layout "
                       "used by keystroke-injection (BadUSB) devices.")
    if is_keyboard and (device.classes & _NETWORK_CLASSES):
        reasons.append("Presents as a keyboard and a network adapter together; a "
                       "malicious gadget can inject keystrokes and redirect traffic.")
    if device.hid_protocols and not device.product and not device.manufacturer:
        reasons.append("HID device with no manufacturer or product string; verify it is expected.")
    if device.vendor_id == "1d6b" and device.hid_protocols:
        reasons.append("Linux Foundation gadget vendor ID on a HID device: a computer or "
                       "microcontroller in gadget mode is emulating an input device.")
    return reasons


def read_usb_devices(root: Path = SYSFS_USB) -> list[UsbDevice]:
    devices: list[UsbDevice] = []
    try:
        entries = sorted(root.iterdir())[:MAX_USB_DEVICES * 8]
    except OSError:
        return []
    by_name: dict[str, UsbDevice] = {}
    for entry in entries:
        if ":" in entry.name:
            continue
        vendor = _read(entry / "idVendor")
        if not vendor or len(devices) >= MAX_USB_DEVICES:
            continue
        device = UsbDevice(entry.name, vendor.casefold(), _read(entry / "idProduct").casefold(),
                           _read(entry / "manufacturer"), _read(entry / "product"),
                           authorized=_read(entry / "authorized") != "0")
        devices.append(device)
        by_name[entry.name] = device
    for entry in entries:
        if ":" not in entry.name:
            continue
        owner = by_name.get(entry.name.split(":", 1)[0])
        if owner is None:
            continue
        interface_class = _hex(_read(entry / "bInterfaceClass"))
        if interface_class is None:
            continue
        owner.classes.add(interface_class)
        if interface_class == 0x03 and _hex(_read(entry / "bInterfaceSubClass")) == 1:
            protocol = _hex(_read(entry / "bInterfaceProtocol"))
            if protocol:
                owner.hid_protocols.add(protocol)
    for device in devices:
        device.indicators = assess_usb_device(device)
    return devices


def usb_audit_report(devices: list[UsbDevice]) -> str:
    lines = [f"USB devices: {len(devices)}"]
    flagged = [device for device in devices if device.indicators]
    for device in devices:
        names = ", ".join(sorted(_CLASS_NAMES.get(item, f"class {item:#04x}") for item in device.classes))
        lines.append(f"- {device.path}: {device.label}; {names or 'no interfaces'}")
        lines.extend(f"    ! {reason}" for reason in device.indicators)
    lines.append(f"Indicators for review: {len(flagged)}" if flagged else "No USB indicators found.")
    return "\n".join(lines)
