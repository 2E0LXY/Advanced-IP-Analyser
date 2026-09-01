from __future__ import annotations

import ipaddress
import json
import os
import re
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .packet_tools import PacketRecord


MAX_FILTER_LENGTH = 2_048
MAX_FILTER_TOKENS = 256
MAX_SAVED_FILTERS = 100
_COMPARISONS = {"==", "!=", ">", "<", ">=", "<=", "contains", "matches"}
_PROTOCOLS = {
    "ip", "ipv6", "tcp", "udp", "dns", "http", "http.request", "http.response",
    "https", "tls", "ssl", "icmp", "icmpv6", "arp", "mdns", "ssdp", "dhcp",
    "ntp", "nbns",
}
_FIELDS = {
    "ip.addr", "ip.src", "ip.dst", "tcp.port", "tcp.srcport", "tcp.dstport",
    "udp.port", "udp.srcport", "udp.dstport", "tcp.flags.syn", "tcp.flags.ack",
    "tcp.flags.fin", "tcp.flags.rst", "tcp.flags.psh", "tcp.flags.urg", "tcp.len",
    "dns.flags.response", "dns.qry.name", "http.request.method", "http.response.code",
    "http.host", "http.request.uri", "tls.handshake.type", "ssl.handshake.type",
    "frame.len", "frame.number", "protocol",
}

QUICK_FILTERS: tuple[tuple[str, str], ...] = (
    ("My IP…", "ip.addr == 192.168.1.10"),
    ("HTTP", "tcp.port == 80"),
    ("HTTPS", "tcp.port == 443"),
    ("SSH", "tcp.port == 22"),
    ("DNS", "dns"),
    ("DNS queries", "dns.flags.response == 0"),
    ("DNS responses", "dns.flags.response == 1"),
    ("HTTP requests", "http.request"),
    ("HTTP responses", "http.response"),
    ("ICMP", "icmp || icmpv6"),
    ("ARP", "arp"),
    ("TCP SYN", "tcp.flags.syn == 1"),
    ("TCP ACK", "tcp.flags.ack == 1"),
    ("SYN attempts", "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
    ("TCP FIN", "tcp.flags.fin == 1"),
    ("TCP resets", "tcp.flags.rst == 1"),
    ("HTTP GET", 'http.request.method == "GET"'),
    ("HTTP 404", "http.response.code == 404"),
    ("TLS Client Hello", "tls.handshake.type == 1"),
    ("Large packets", "frame.len > 1000"),
)


class FilterSyntaxError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PacketFields:
    values: dict[str, tuple[object, ...]]
    protocols: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    text: str
    position: int


_TOKEN = re.compile(
    r'\s*(?:(?P<op>&&|\|\||==|!=|>=|<=|>|<|!)|(?P<lpar>\()|(?P<rpar>\))|'
    r'(?P<string>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')|'
    r'(?P<word>[^\s()!<>=&|]+))')


def _tokenize(expression: str) -> list[_Token]:
    if len(expression) > MAX_FILTER_LENGTH:
        raise FilterSyntaxError(f"filter is limited to {MAX_FILTER_LENGTH} characters")
    tokens: list[_Token] = []
    position = 0
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if not match:
            raise FilterSyntaxError(f"unexpected character at position {position + 1}")
        if match.end() == position:
            raise FilterSyntaxError("invalid filter")
        position = match.end()
        kind = match.lastgroup or ""
        text = match.group(kind)
        if kind == "word" and text.casefold() in {"contains", "matches"}:
            kind, text = "op", text.casefold()
        tokens.append(_Token(kind, text, match.start() + 1))
        if len(tokens) > MAX_FILTER_TOKENS:
            raise FilterSyntaxError(f"filter is limited to {MAX_FILTER_TOKENS} tokens")
    return tokens


def _decode_string(text: str) -> str:
    quote = text[0]
    body = text[1:-1]
    result: list[str] = []
    index = 0
    while index < len(body):
        if body[index] != "\\" or index + 1 >= len(body):
            result.append(body[index])
            index += 1
            continue
        escaped = body[index + 1]
        if escaped == "n":
            result.append("\n")
        elif escaped == "t":
            result.append("\t")
        elif escaped in {quote, "\\"}:
            result.append(escaped)
        else:
            result.extend(("\\", escaped))
        index += 2
    return "".join(result)


class _Parser:
    def __init__(self, tokens: list[_Token]):
        self.tokens = tokens
        self.index = 0

    def parse(self) -> Callable[[PacketFields], bool]:
        if not self.tokens:
            return lambda _fields: True
        predicate = self._or(0)
        if self.index != len(self.tokens):
            token = self.tokens[self.index]
            raise FilterSyntaxError(f"unexpected {token.text!r} at position {token.position}")
        return predicate

    def _peek(self, text: str | None = None) -> _Token | None:
        if self.index >= len(self.tokens):
            return None
        token = self.tokens[self.index]
        return token if text is None or token.text == text else None

    def _take(self) -> _Token:
        token = self._peek()
        if token is None:
            raise FilterSyntaxError("filter ends before the condition is complete")
        self.index += 1
        return token

    def _or(self, depth: int) -> Callable[[PacketFields], bool]:
        left = self._and(depth)
        while self._peek("||"):
            self._take()
            right = self._and(depth)
            previous = left
            left = lambda fields, a=previous, b=right: a(fields) or b(fields)
        return left

    def _and(self, depth: int) -> Callable[[PacketFields], bool]:
        left = self._unary(depth)
        while self._peek("&&"):
            self._take()
            right = self._unary(depth)
            previous = left
            left = lambda fields, a=previous, b=right: a(fields) and b(fields)
        return left

    def _unary(self, depth: int) -> Callable[[PacketFields], bool]:
        if depth > 32:
            raise FilterSyntaxError("filter parentheses are nested too deeply")
        if self._peek("!"):
            self._take()
            inner = self._unary(depth + 1)
            return lambda fields: not inner(fields)
        if self._peek("("):
            self._take()
            inner = self._or(depth + 1)
            if not self._peek(")"):
                raise FilterSyntaxError("missing closing parenthesis")
            self._take()
            return inner
        return self._condition()

    def _condition(self) -> Callable[[PacketFields], bool]:
        name_token = self._take()
        if name_token.kind != "word":
            raise FilterSyntaxError(f"expected a protocol or field at position {name_token.position}")
        name = name_token.text.casefold()
        operator = self._peek()
        if operator is None or operator.kind != "op" or operator.text in {"&&", "||", "!"}:
            if name not in _PROTOCOLS:
                raise FilterSyntaxError(f"unknown protocol {name_token.text!r}")
            return lambda fields, protocol=name: protocol in fields.protocols
        operator = self._take().text
        if operator not in _COMPARISONS:
            raise FilterSyntaxError(f"invalid comparison {operator!r}")
        if name not in _FIELDS:
            raise FilterSyntaxError(f"unknown field {name_token.text!r}")
        value_token = self._take()
        if value_token.kind not in {"word", "string"}:
            raise FilterSyntaxError(f"expected a value at position {value_token.position}")
        value: object = (_decode_string(value_token.text) if value_token.kind == "string"
                         else _literal(value_token.text))
        matcher = _comparison(name, operator, value)
        return lambda fields: matcher(fields.values.get(name, ()))


def _literal(text: str) -> object:
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_address(text)
    except ValueError:
        return text


def _safe_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > 128:
        raise FilterSyntaxError("regular expression is limited to 128 characters")
    if (re.search(r"\\[1-9]", pattern) or any(character in pattern for character in "(){}") or
            len(re.findall(r"(?<!\\)[*+?]", pattern)) > 8 or
            re.search(r"(?<!\\)[*+?]{2}", pattern)):
        raise FilterSyntaxError("grouped, counted, or heavily repeating regular expressions are not supported")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as error:
        raise FilterSyntaxError(f"invalid regular expression: {error}") from error


def _comparison(field: str, operator: str, expected: object) -> Callable[[tuple[object, ...]], bool]:
    regex = _safe_regex(str(expected)) if operator == "matches" else None

    def equal(actual: object) -> bool:
        if isinstance(expected, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            try:
                return ipaddress.ip_address(str(actual)) in expected
            except ValueError:
                return False
        if isinstance(expected, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(actual) == str(expected)
        if isinstance(expected, int):
            try:
                return int(actual) == expected
            except (TypeError, ValueError):
                return False
        return str(actual).casefold() == str(expected).casefold()

    def compare_one(actual: object) -> bool:
        if operator == "==":
            return equal(actual)
        if operator == "!=":
            return not equal(actual)
        if operator == "contains":
            return str(expected).casefold() in str(actual)[:4_096].casefold()
        if operator == "matches":
            return bool(regex and regex.search(str(actual)[:4_096]))
        try:
            left, right = float(actual), float(expected)
        except (TypeError, ValueError):
            left, right = str(actual).casefold(), str(expected).casefold()
        return {">": left > right, "<": left < right,
                ">=": left >= right, "<=": left <= right}[operator]

    if operator == "!=":
        return lambda values: bool(values) and all(compare_one(value) for value in values)
    return lambda values: any(compare_one(value) for value in values)


def _dns_name(data: bytes, offset: int, limit: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    steps = 0
    while cursor < limit and steps < 64:
        size = data[cursor]
        cursor += 1
        steps += 1
        if size == 0:
            return ".".join(labels), cursor
        if size & 0xC0 or size > 63 or cursor + size > limit:
            return "", cursor
        labels.append(data[cursor:cursor + size].decode("ascii", "replace"))
        cursor += size
    return "", cursor


def packet_fields(record: PacketRecord) -> PacketFields:
    values: dict[str, list[object]] = {
        "frame.len": [record.length], "frame.number": [record.number],
        "protocol": [record.protocol.casefold()],
    }
    protocols: set[str] = set()
    data = record.preview
    offset = 0
    ether_type = 0
    if len(data) >= 14:
        ether_type = struct.unpack("!H", data[12:14])[0]
        offset = 14
        for _ in range(2):
            if ether_type not in {0x8100, 0x88A8} or len(data) < offset + 4:
                break
            ether_type = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
    if ether_type == 0x0806:
        protocols.add("arp")
    transport = -1
    transport_size: int | None = None
    payload = offset
    source = destination = ""
    if ether_type == 0x0800 and len(data) >= offset + 20:
        ihl = (data[offset] & 0x0F) * 4
        if ihl >= 20 and len(data) >= offset + ihl:
            total_length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            source = str(ipaddress.ip_address(data[offset + 12:offset + 16]))
            destination = str(ipaddress.ip_address(data[offset + 16:offset + 20]))
            transport = data[offset + 9]
            fragment_offset = struct.unpack("!H", data[offset + 6:offset + 8])[0] & 0x1FFF
            payload = offset + ihl
            transport_size = max(0, total_length - ihl)
            if fragment_offset:
                transport = -1
            protocols.add("ip")
    elif ether_type == 0x86DD and len(data) >= offset + 40:
        ipv6_start = offset
        ipv6_payload_length = struct.unpack("!H", data[offset + 4:offset + 6])[0]
        source = str(ipaddress.ip_address(data[offset + 8:offset + 24]))
        destination = str(ipaddress.ip_address(data[offset + 24:offset + 40]))
        transport = data[offset + 6]
        payload = offset + 40
        protocols.update(("ip", "ipv6"))
        for _ in range(8):
            if transport in {0, 43, 60} and len(data) >= payload + 2:
                transport, size = data[payload], (data[payload + 1] + 1) * 8
                payload += size
            elif transport == 44 and len(data) >= payload + 8:
                fragment_transport = data[payload]
                fragment_offset = struct.unpack("!H", data[payload + 2:payload + 4])[0] >> 3
                transport, payload = (-1 if fragment_offset else fragment_transport), payload + 8
            elif transport == 51 and len(data) >= payload + 2:
                transport, size = data[payload], (data[payload + 1] + 2) * 4
                payload += size
            else:
                break
        transport_size = max(0, ipv6_payload_length - (payload - ipv6_start - 40))
    if source:
        values.update({"ip.src": [source], "ip.dst": [destination],
                       "ip.addr": [source, destination]})
    app_offset = payload
    source_port = destination_port = None
    if transport == 6 and len(data) >= payload + 20:
        protocols.add("tcp")
        source_port, destination_port = struct.unpack("!HH", data[payload:payload + 4])
        header_size = ((data[payload + 12] >> 4) & 0xF) * 4
        flags = data[payload + 13]
        values.update({
            "tcp.srcport": [source_port], "tcp.dstport": [destination_port],
            "tcp.port": [source_port, destination_port], "tcp.flags.fin": [flags & 1 and 1 or 0],
            "tcp.flags.syn": [(flags >> 1) & 1], "tcp.flags.rst": [(flags >> 2) & 1],
            "tcp.flags.psh": [(flags >> 3) & 1], "tcp.flags.ack": [(flags >> 4) & 1],
            "tcp.flags.urg": [(flags >> 5) & 1],
            "tcp.len": [max(0, (transport_size if transport_size is not None
                                else len(data) - payload) - header_size)],
        })
        app_offset = payload + header_size if header_size >= 20 else payload + 20
    elif transport == 17 and len(data) >= payload + 8:
        protocols.add("udp")
        source_port, destination_port = struct.unpack("!HH", data[payload:payload + 4])
        values.update({"udp.srcport": [source_port], "udp.dstport": [destination_port],
                       "udp.port": [source_port, destination_port]})
        app_offset = payload + 8
    elif transport == 1:
        protocols.add("icmp")
    elif transport == 58:
        protocols.add("icmpv6")
    ports = {source_port, destination_port}
    service_ports = {53: "dns", 5353: "mdns", 1900: "ssdp", 123: "ntp", 137: "nbns"}
    for port, protocol in service_ports.items():
        if port in ports:
            protocols.add(protocol)
    if ports & {67, 68, 546, 547}:
        protocols.add("dhcp")
    payload_data = data[app_offset:]
    if "dns" in protocols or "mdns" in protocols:
        if len(payload_data) >= 12:
            flags = struct.unpack("!H", payload_data[2:4])[0]
            values["dns.flags.response"] = [(flags >> 15) & 1]
            questions = struct.unpack("!H", payload_data[4:6])[0]
            if questions:
                name, _cursor = _dns_name(payload_data, 12, len(payload_data))
                if name:
                    values["dns.qry.name"] = [name]
    http_match = re.match(rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) ([^ ]+) HTTP/1\.[01]\r?\n", payload_data)
    response_match = re.match(rb"HTTP/1\.[01] (\d{3})", payload_data)
    if http_match:
        protocols.update(("http", "http.request"))
        values["http.request.method"] = [http_match.group(1).decode("ascii")]
        values["http.request.uri"] = [http_match.group(2).decode("utf-8", "replace")[:2_048]]
        host = re.search(rb"(?im)^Host:\s*([^\r\n]+)", payload_data[:8_192])
        if host:
            values["http.host"] = [host.group(1).decode("utf-8", "replace").strip()[:1_024]]
    elif response_match:
        protocols.update(("http", "http.response"))
        values["http.response.code"] = [int(response_match.group(1))]
    if 443 in ports:
        protocols.add("https")
    if len(payload_data) >= 6 and payload_data[0] in {20, 21, 22, 23} and payload_data[1] == 3:
        protocols.update(("tls", "ssl", "https"))
        if payload_data[0] == 22:
            handshake_type = payload_data[5]
            values["tls.handshake.type"] = [handshake_type]
            values["ssl.handshake.type"] = [handshake_type]
    return PacketFields({name: tuple(items) for name, items in values.items()}, frozenset(protocols))


def compile_filter(expression: str) -> Callable[[PacketRecord], bool]:
    parsed = _Parser(_tokenize(expression.strip())).parse()
    return lambda record: parsed(packet_fields(record))


def default_filter_path() -> Path:
    return Path.home() / ".config" / "advanced-ip-analyser" / "packet-filters.json"


def load_saved_filters(path: Path | None = None) -> dict[str, str]:
    path = path or default_filter_path()
    if not path.exists():
        return {}
    if path.stat().st_size > 1_048_576:
        raise ValueError("saved filter file is too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or len(data) > MAX_SAVED_FILTERS:
        raise ValueError("saved filters must be a bounded object")
    result: dict[str, str] = {}
    for name, expression in data.items():
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64 or not isinstance(expression, str):
            raise ValueError("saved filter entry is invalid")
        compile_filter(expression)
        result[name.strip()] = expression
    return result


def save_saved_filters(filters: dict[str, str], path: Path | None = None) -> None:
    if len(filters) > MAX_SAVED_FILTERS:
        raise ValueError(f"no more than {MAX_SAVED_FILTERS} filters can be saved")
    clean: dict[str, str] = {}
    for name, expression in filters.items():
        if not isinstance(name, str) or not isinstance(expression, str):
            raise ValueError("saved filters must use text names and expressions")
        name = name.strip()
        if not 1 <= len(name) <= 64:
            raise ValueError("filter name must be from 1 to 64 characters")
        compile_filter(expression)
        clean[name] = expression
    path = path or default_filter_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".packet-filters-", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(clean, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            path.chmod(0o600)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise
