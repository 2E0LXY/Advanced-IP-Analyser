from __future__ import annotations

import gzip
import ipaddress
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

MAX_CAPTURE_HOSTS = 64
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_CAPTURE_PACKETS = 100_000
MAX_PCAPNG_BLOCKS = 200_000
MAX_PCAPNG_INTERFACES = 4_096
MAX_PCAPNG_SECTIONS = 1_024
_INTERFACE = re.compile(r"[A-Za-z0-9_.:@-]{1,64}")


@dataclass(frozen=True, slots=True)
class PacketRecord:
    number: int
    timestamp: float
    source: str
    destination: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    length: int
    info: str
    preview: bytes

    @property
    def time_text(self) -> str:
        try:
            return datetime.fromtimestamp(self.timestamp, UTC).astimezone().strftime("%H:%M:%S.%f")[:-3]
        except (OSError, OverflowError, ValueError):
            return "invalid time"


def _addresses(hosts: list[str] | None) -> list[str]:
    hosts = hosts or []
    if len(hosts) > MAX_CAPTURE_HOSTS:
        raise ValueError(f"packet filters are limited to {MAX_CAPTURE_HOSTS} selected hosts")
    addresses: list[str] = []
    for host in hosts:
        address = str(ipaddress.ip_address(host))
        if address not in addresses:
            addresses.append(address)
    return addresses


def _port(port: int | None) -> int | None:
    if port is not None and (isinstance(port, bool) or not 1 <= port <= 65_535):
        raise ValueError("packet filter port must be from 1 to 65535")
    return port


def validate_interface(interface: str) -> str:
    interface = interface.strip()
    if not _INTERFACE.fullmatch(interface):
        raise ValueError("capture interface name is invalid")
    return interface


def list_capture_interfaces() -> list[tuple[str, str]]:
    """List Linux interfaces without depending on Wireshark or another program."""
    interfaces = [("any", "All Linux interfaces")]
    try:
        for _index, name in socket.if_nameindex():
            if _INTERFACE.fullmatch(name) and name != "any":
                interfaces.append((name, "Loopback" if name == "lo" else "Network interface"))
    except OSError as error:
        raise RuntimeError(f"could not list Linux capture interfaces: {error}") from error
    return interfaces


def _helper_path() -> Path:
    return Path(__file__).with_name("capture_helper.py").resolve()


def _capture_command(output: Path, interface: str, hosts: list[str], port: int | None,
                     duration: int, max_packets: int, isolated: bool = False,
                     snaplen: int = 65_535, linktype: int = 1) -> list[str]:
    executable = "/usr/bin/python3" if isolated else sys.executable
    command = [executable]
    if isolated:
        command.append("-I")
    command.extend([str(_helper_path()), "--output", str(output), "--interface", interface,
                    "--duration", str(duration), "--max-packets", str(max_packets),
                    "--snaplen", str(snaplen), "--linktype", str(linktype)])
    for host in hosts:
        command.extend(["--host", host])
    if port is not None:
        command.extend(["--port", str(port)])
    return command


def capture_live(hosts: list[str], interface: str = "any", port: int | None = None,
                 duration: int = 10, max_packets: int = 5_000,
                 cache_dir: Path | None = None) -> Path:
    """Capture bounded Linux traffic, requesting PolicyKit only when required."""
    addresses = _addresses(hosts)
    if not addresses:
        raise ValueError("select at least one host for live capture")
    interface = validate_interface(interface)
    port = _port(port)
    if not 1 <= duration <= 300:
        raise ValueError("capture duration must be from 1 to 300 seconds")
    if not 1 <= max_packets <= 100_000:
        raise ValueError("capture packet limit must be from 1 to 100,000")
    directory = cache_dir or Path.home() / ".cache" / "advanced-ip-analyser" / "captures"
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix="capture-", suffix=".pcap", dir=directory)
    os.close(descriptor)
    output = Path(name)
    try:
        direct = subprocess.run(
            _capture_command(output, interface, addresses, port, duration, max_packets),
            capture_output=True, text=True, timeout=duration + 15, check=False)
        if direct.returncode == 13:
            helper = _helper_path()
            helper_stat = helper.stat()
            if (os.name != "posix" or helper_stat.st_uid != 0 or
                    helper_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError(
                    "live capture needs the installed Debian package before authorization can be requested")
            pkexec = shutil.which("pkexec")
            if not pkexec:
                raise RuntimeError("PolicyKit is unavailable; install the pkexec package")
            elevated = subprocess.run(
                [pkexec, *_capture_command(output, interface, addresses, port, duration,
                                            max_packets, isolated=True)],
                capture_output=True, text=True, timeout=duration + 30, check=False)
            if elevated.returncode:
                detail = (elevated.stderr or elevated.stdout).strip()
                raise RuntimeError(detail or "capture authorization was cancelled or failed")
        elif direct.returncode:
            detail = (direct.stderr or direct.stdout).strip()
            raise RuntimeError(detail or f"native capture exited {direct.returncode}")
        if output.stat().st_size < 24:
            raise RuntimeError("native capture did not produce a valid capture file")
        return output
    except Exception:
        output.unlink(missing_ok=True)
        raise


@dataclass(slots=True)
class CaptureSession:
    path: Path
    process: subprocess.Popen

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    def stop(self, timeout: float = 5.0) -> None:
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)

    def error(self) -> str:
        if self.running or self.process.returncode == 0:
            return ""
        output = self.process.communicate(timeout=1)
        return (output[1] or output[0] or "native monitor capture failed").strip()


def start_monitor_capture(interface: str = "any", duration: int = 3_600,
                          max_packets: int = 100_000, snaplen: int = 128,
                          hosts: list[str] | None = None,
                          cache_dir: Path | None = None,
                          linktype: int = 1) -> CaptureSession:
    """Start a bounded header-focused capture that can be inspected while running."""
    addresses = _addresses(hosts)
    interface = validate_interface(interface)
    if not 1 <= duration <= 86_400:
        raise ValueError("monitor duration must be from 1 second to 24 hours")
    if not 1 <= max_packets <= MAX_CAPTURE_PACKETS:
        raise ValueError("monitor packet limit must be from 1 to 100,000")
    if not 96 <= snaplen <= 65_535:
        raise ValueError("monitor snapshot length must be from 96 to 65,535 bytes")
    if linktype not in {1, 127} or (linktype == 127 and addresses):
        raise ValueError("monitor capture link type is invalid")
    directory = cache_dir or Path.home() / ".local" / "share" / "advanced-ip-analyser" / "captures"
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix="watch-", suffix=".pcap", dir=directory)
    os.close(descriptor)
    output = Path(name).resolve()
    command = _capture_command(output, interface, addresses, None, duration,
                               max_packets, snaplen=snaplen, linktype=linktype)
    try:
        probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        probe.close()
    except (AttributeError, PermissionError, OSError):
        helper_stat = _helper_path().stat()
        if (os.name != "posix" or helper_stat.st_uid != 0 or
                helper_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            output.unlink(missing_ok=True)
            raise RuntimeError(
                "Network Watch authorization requires the installed Debian package")
        pkexec = shutil.which("pkexec")
        if not pkexec:
            output.unlink(missing_ok=True)
            raise RuntimeError("PolicyKit is unavailable; install the pkexec package")
        command = [pkexec, *_capture_command(
            output, interface, addresses, None, duration, max_packets,
            isolated=True, snaplen=snaplen, linktype=linktype)]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return CaptureSession(output, process)


def _parse_packet(data: bytes, number: int, timestamp: float, original_length: int,
                  link_type: int = 1) -> PacketRecord:
    source = destination = ""
    protocol = "Other"
    source_port = destination_port = None
    info = ""
    offset = 0
    ether_type = 0
    if link_type == 1 and len(data) >= 14:
        destination_mac = ":".join(f"{byte:02X}" for byte in data[0:6])
        source_mac = ":".join(f"{byte:02X}" for byte in data[6:12])
        source, destination = source_mac, destination_mac
        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14
        for _ in range(2):
            if ether_type not in {0x8100, 0x88A8} or len(data) < offset + 4:
                break
            ether_type = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
    if ether_type == 0x0800 and len(data) >= offset + 20:
        header_length = (data[offset] & 0x0F) * 4
        if header_length >= 20 and len(data) >= offset + header_length:
            source = str(ipaddress.ip_address(data[offset + 12:offset + 16]))
            destination = str(ipaddress.ip_address(data[offset + 16:offset + 20]))
            protocol_number = data[offset + 9]
            fragment_offset = struct.unpack("!H", data[offset + 6:offset + 8])[0] & 0x1FFF
            offset += header_length
            if fragment_offset:
                protocol, info = "IPv4 fragment", f"fragment offset {fragment_offset * 8}"
            else:
                protocol, source_port, destination_port, info = _transport_details(
                    data, offset, protocol_number)
    elif ether_type == 0x86DD and len(data) >= offset + 40:
        source = str(ipaddress.ip_address(data[offset + 8:offset + 24]))
        destination = str(ipaddress.ip_address(data[offset + 24:offset + 40]))
        protocol_number = data[offset + 6]
        offset += 40
        fragment_offset = 0
        for _ in range(8):
            if protocol_number in {0, 43, 60} and len(data) >= offset + 2:
                protocol_number, units = data[offset], data[offset + 1]
                offset += (units + 1) * 8
            elif protocol_number == 44 and len(data) >= offset + 8:
                protocol_number = data[offset]
                fragment_offset = (struct.unpack("!H", data[offset + 2:offset + 4])[0] >> 3) * 8
                offset += 8
            elif protocol_number == 51 and len(data) >= offset + 2:
                protocol_number, units = data[offset], data[offset + 1]
                offset += (units + 2) * 4
            else:
                break
        if fragment_offset:
            protocol, info = "IPv6 fragment", f"fragment offset {fragment_offset}"
        else:
            protocol, source_port, destination_port, info = _transport_details(
                data, offset, protocol_number)
    elif ether_type == 0x0806 and len(data) >= offset + 28:
        protocol = "ARP"
        operation = struct.unpack("!H", data[offset + 6:offset + 8])[0]
        source = str(ipaddress.ip_address(data[offset + 14:offset + 18]))
        destination = str(ipaddress.ip_address(data[offset + 24:offset + 28]))
        info = "request" if operation == 1 else "reply" if operation == 2 else f"operation {operation}"
    return PacketRecord(number, timestamp, source, destination, protocol, source_port,
                        destination_port, original_length, info, data[:512])


def _transport_details(data: bytes, offset: int, protocol_number: int) -> tuple[str, int | None, int | None, str]:
    if protocol_number == 6 and len(data) >= offset + 20:
        source_port, destination_port = struct.unpack("!HH", data[offset:offset + 4])
        flags = data[offset + 13]
        names = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"),
                 (0x08, "PSH"), (0x20, "URG")]
        return "TCP", source_port, destination_port, ",".join(name for bit, name in names if flags & bit)
    if protocol_number == 17 and len(data) >= offset + 8:
        source_port, destination_port = struct.unpack("!HH", data[offset:offset + 4])
        ports = {source_port, destination_port}
        name = ("DNS" if 53 in ports else "mDNS" if 5353 in ports else
                "DHCP" if ports & {67, 68, 546, 547} else
                "SSDP" if 1900 in ports else "NTP" if 123 in ports else
                "NBNS" if 137 in ports else "UDP")
        return name, source_port, destination_port, ""
    if protocol_number in {1, 58} and len(data) >= offset + 2:
        return ("ICMPv6" if protocol_number == 58 else "ICMP", None, None,
                f"type {data[offset]}, code {data[offset + 1]}")
    names = {47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF"}
    return names.get(protocol_number, f"IP protocol {protocol_number}"), None, None, ""


def _matches(record: PacketRecord, hosts: set[str], port: int | None) -> bool:
    return ((not hosts or record.source in hosts or record.destination in hosts) and
            (port is None or record.source_port == port or record.destination_port == port))


def read_capture(path: Path, hosts: list[str] | None = None, port: int | None = None,
                 limit: int = MAX_CAPTURE_PACKETS,
                 allow_incomplete: bool = False) -> list[PacketRecord]:
    """Read bounded Ethernet PCAP or PCAPNG data with optional host/service filtering."""
    capture = path.expanduser().resolve()
    if not capture.is_file():
        raise ValueError("capture file does not exist or is not a regular file")
    if capture.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError("capture file exceeds the 512 MiB analysis limit")
    addresses = set(_addresses(hosts))
    port = _port(port)
    if port is not None and not addresses:
        raise ValueError("a port filter requires at least one host")
    if not 1 <= limit <= MAX_CAPTURE_PACKETS:
        raise ValueError(f"packet analysis limit must be from 1 to {MAX_CAPTURE_PACKETS:,}")
    opener = gzip.open if capture.suffix.lower() == ".gz" else open
    with opener(capture, "rb") as stream:
        content = stream.read(MAX_CAPTURE_BYTES + 1)
    if len(content) > MAX_CAPTURE_BYTES:
        raise ValueError("expanded capture data exceeds the 512 MiB analysis limit")
    records = (_read_pcapng(content, MAX_CAPTURE_PACKETS)
               if content.startswith(b"\x0a\x0d\x0d\x0a")
               else _read_pcap(content, MAX_CAPTURE_PACKETS, allow_incomplete))
    return [record for record in records if _matches(record, addresses, port)][:limit]


def _read_pcap(content: bytes, limit: int, allow_incomplete: bool = False) -> list[PacketRecord]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if len(content) < 24 or content[:4] not in formats:
        raise ValueError("file is not a supported PCAP or PCAPNG capture")
    endian, precision = formats[content[:4]]
    link_type = struct.unpack(f"{endian}I", content[20:24])[0]
    if link_type != 1:
        raise ValueError(f"unsupported PCAP link type {link_type}; Ethernet captures are required")
    records: list[PacketRecord] = []
    offset = 24
    while offset + 16 <= len(content) and len(records) < limit:
        seconds, fraction, captured_length, original_length = struct.unpack(
            f"{endian}IIII", content[offset:offset + 16])
        offset += 16
        if captured_length > 262_144:
            raise ValueError("capture contains a malformed packet record")
        if offset + captured_length > len(content):
            if allow_incomplete:
                break
            raise ValueError("capture contains a malformed packet record")
        data = content[offset:offset + captured_length]
        offset += captured_length
        records.append(_parse_packet(data, len(records) + 1,
                                     seconds + fraction / precision, original_length, link_type))
    if offset != len(content) and len(records) < limit and not allow_incomplete:
        raise ValueError("capture contains a truncated PCAP packet header")
    return records


def _read_pcapng(content: bytes, limit: int) -> list[PacketRecord]:
    records: list[PacketRecord] = []
    interfaces: list[tuple[int, int]] = []
    saw_interface = False
    offset = 0
    endian = "<"
    block_count = 0
    section_count = 0
    while offset + 12 <= len(content) and len(records) < limit:
        block_count += 1
        if block_count > MAX_PCAPNG_BLOCKS:
            raise ValueError("PCAPNG capture contains too many blocks")
        if content[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            section_count += 1
            if section_count > MAX_PCAPNG_SECTIONS:
                raise ValueError("PCAPNG capture contains too many sections")
            byte_order = content[offset + 8:offset + 12]
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("PCAPNG section has an invalid byte-order marker")
            interfaces = []
        block_type, block_length = struct.unpack(f"{endian}II", content[offset:offset + 8])
        if (block_length < 12 or block_length % 4 or offset + block_length > len(content) or
                struct.unpack(f"{endian}I", content[offset + block_length - 4:offset + block_length])[0] != block_length):
            raise ValueError("capture contains a malformed PCAPNG block")
        body = content[offset + 8:offset + block_length - 4]
        if block_type == 1 and len(body) >= 8:
            link_type = struct.unpack(f"{endian}H", body[:2])[0]
            timestamp_divisor = 1_000_000
            option_offset = 8
            while option_offset + 4 <= len(body):
                option_code, option_length = struct.unpack(
                    f"{endian}HH", body[option_offset:option_offset + 4])
                option_offset += 4
                if option_code == 0:
                    break
                if option_offset + option_length > len(body):
                    raise ValueError("capture contains a malformed PCAPNG interface option")
                option_value = body[option_offset:option_offset + option_length]
                if option_code == 9 and option_length == 1:
                    resolution = option_value[0]
                    timestamp_divisor = (2 ** (resolution & 0x7F)
                                         if resolution & 0x80 else 10 ** resolution)
                option_offset += (option_length + 3) & ~3
            if len(interfaces) >= MAX_PCAPNG_INTERFACES:
                raise ValueError("PCAPNG capture contains too many interfaces")
            interfaces.append((link_type, timestamp_divisor))
            saw_interface = True
        elif block_type == 6 and len(body) >= 20:
            interface_id, timestamp_high, timestamp_low, captured_length, original_length = struct.unpack(
                f"{endian}IIIII", body[:20])
            if captured_length > 262_144 or 20 + captured_length > len(body):
                raise ValueError("capture contains a malformed PCAPNG packet")
            link_type, timestamp_divisor = (interfaces[interface_id]
                                             if interface_id < len(interfaces) else (-1, 1))
            if link_type == 1:
                data = body[20:20 + captured_length]
                timestamp = ((timestamp_high << 32) | timestamp_low) / timestamp_divisor
                records.append(_parse_packet(data, len(records) + 1, timestamp,
                                             original_length, link_type))
        offset += block_length
    if offset != len(content) and len(records) < limit:
        raise ValueError("capture contains a truncated PCAPNG block")
    if not saw_interface:
        raise ValueError("PCAPNG capture contains no interface description")
    return records


def packet_hex_preview(record: PacketRecord) -> str:
    lines = []
    for offset in range(0, len(record.preview), 16):
        chunk = record.preview[offset:offset + 16]
        hexadecimal = " ".join(f"{byte:02x}" for byte in chunk)
        printable = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hexadecimal:<47}  {printable}")
    return "\n".join(lines)
