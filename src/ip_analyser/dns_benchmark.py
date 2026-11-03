"""Accurate, bounded DNS resolver latency benchmarking."""

from __future__ import annotations

import math
import queue
import secrets
import socket
import statistics
import struct
import threading
import time
import tkinter as tk
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from tkinter import ttk


@dataclass(frozen=True)
class DNSResolver:
    name: str
    address: str
    category: str = "Public resolver"


@dataclass
class DNSBenchmarkResult:
    resolver: DNSResolver
    latencies: list[float | None] = field(default_factory=list)

    @property
    def samples(self) -> tuple[float | None, ...]:
        return tuple(self.latencies)

    @property
    def successful(self) -> list[float]:
        return [sample for sample in self.latencies if sample is not None]

    @property
    def replies(self) -> int:
        return len(self.successful)

    @property
    def average_ms(self) -> float | None:
        return statistics.mean(self.successful) if self.successful else None

    @property
    def jitter_ms(self) -> float | None:
        return statistics.pstdev(self.successful) if len(self.successful) > 1 else (0.0 if self.successful else None)

    @property
    def average(self) -> float | None:
        return self.average_ms

    @property
    def jitter(self) -> float | None:
        return self.jitter_ms


DNS_RESOLVERS = (
    DNSResolver("Cloudflare", "1.1.1.1", "Privacy / anycast"),
    DNSResolver("Google", "8.8.8.8", "Global anycast"),
    DNSResolver("Quad9", "9.9.9.9", "Threat blocking"),
    DNSResolver("OpenDNS", "208.67.222.222", "Cisco / filtering"),
    DNSResolver("AdGuard", "94.140.14.14", "Ad blocking"),
    DNSResolver("CleanBrowsing", "185.228.168.9", "Family filtering"),
    DNSResolver("Control D", "76.76.2.0", "Privacy / filtering"),
    DNSResolver("DNS.SB", "185.222.222.222", "Privacy"),
    DNSResolver("Mullvad", "194.242.2.2", "Privacy"),
    DNSResolver("Hurricane Electric", "74.82.42.42", "Open recursive"),
    DNSResolver("DNS4EU", "86.54.11.1", "European Union"),
    DNSResolver("Yandex Basic", "77.88.8.8", "Global resolver"),
    DNSResolver("AliDNS", "223.5.5.5", "Asia anycast"),
    DNSResolver("DNSPod", "119.29.29.29", "Asia anycast"),
    DNSResolver("CZ.NIC", "193.17.47.1", "European resolver"),
    DNSResolver("CIRA Shield", "149.112.121.20", "Threat blocking"),
    DNSResolver("FDN", "80.67.169.12", "Non-profit"),
    DNSResolver("Alternate DNS", "76.76.19.19", "Ad blocking"),
    DNSResolver("Comodo Secure", "8.26.56.26", "Security filtering"),
    DNSResolver("NextDNS", "45.90.28.0", "Configurable privacy"),
    DNSResolver("Cloudflare Secondary", "1.0.0.1", "Privacy / anycast"),
    DNSResolver("Cloudflare Security", "1.1.1.2", "Security filtering"),
    DNSResolver("Google Secondary", "8.8.4.4", "Global anycast"),
    DNSResolver("Quad9 Secondary", "149.112.112.112", "Threat blocking"),
    DNSResolver("Quad9 Unsecured", "9.9.9.10", "Unfiltered"),
    DNSResolver("OpenDNS Secondary", "208.67.220.220", "Cisco / filtering"),
    DNSResolver("NextDNS Secondary", "45.90.30.0", "Configurable privacy"),
    DNSResolver("AdGuard Non-Filtering", "94.140.14.140", "Unfiltered"),
    DNSResolver("Control D Malware", "76.76.2.1", "Security filtering"),
    DNSResolver("GCore", "95.85.95.85", "Public resolver"),
    DNSResolver("Lumen / Level3", "4.2.2.1", "Public resolver"),
    DNSResolver("Verisign", "64.6.64.6", "Public resolver"),
    DNSResolver("DNS4EU Unfiltered", "86.54.11.100", "Unfiltered"),
    DNSResolver("DNS.Watch", "84.200.69.80", "Public resolver"),
    DNSResolver("FlashStart", "185.236.104.104", "Public resolver"),
    DNSResolver("DNS.SB Secondary", "45.11.45.11", "Privacy"),
)

RESOLVERS = DNS_RESOLVERS
Resolver = DNSResolver
ResolverResult = DNSBenchmarkResult


def build_query(name: str, transaction_id: int) -> bytes:
    labels = [label.encode("idna") for label in name.strip().strip(".").split(".") if label]
    if not labels or any(len(label) > 63 for label in labels):
        raise ValueError("invalid DNS test name")
    question = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", transaction_id & 0xFFFF, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)


def valid_response(data: bytes, transaction_id: int) -> bool:
    if len(data) < 12:
        return False
    returned_id, flags = struct.unpack("!HH", data[:4])
    return returned_id == transaction_id and bool(flags & 0x8000) and flags & 0x000F == 0


def validate_query_name(name: str) -> str:
    clean = name.strip().strip(".")
    labels = clean.split(".")
    if (not clean or len(clean) > 253 or any(not label or len(label.encode("idna")) > 63
                                             for label in labels)):
        raise ValueError("Enter a valid DNS name such as example.com.")
    build_query(clean, 0)
    return clean


def probe_resolver(resolver: DNSResolver, query_name: str = "example.com",
                   timeout: float = 2.5) -> tuple[float | None, int | None]:
    transaction_id = secrets.randbelow(65_536)
    request = build_query(validate_query_name(query_name), transaction_id)
    family = socket.AF_INET6 if ":" in resolver.address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            started = time.perf_counter()
            client.sendto(request, (resolver.address, 53))
            response, _address = client.recvfrom(4_096)
            elapsed = (time.perf_counter() - started) * 1_000
        if len(response) < 12:
            return None, None
        returned_id, flags = struct.unpack("!HH", response[:4])
        if returned_id != transaction_id or not flags & 0x8000:
            return None, None
        response_code = flags & 0x000F
        return (elapsed if response_code == 0 else None), response_code
    except (OSError, ValueError):
        return None, None


def query_resolver(resolver: Resolver, *, name: str = "example.com", timeout: float = 2.5) -> float | None:
    latency, _response_code = probe_resolver(resolver, name, timeout)
    return latency


def result_sort_key(result: DNSBenchmarkResult) -> tuple[bool, float, float, float, str]:
    """Rank by displayed average, then stability, then exact average.

    Average and jitter are shown to one decimal place in the interface. Using
    those displayed values first prevents two apparently equal rows being
    ordered alphabetically while the less stable resolver ranks higher.
    """
    average = result.average if result.average is not None else math.inf
    jitter = result.jitter if result.jitter is not None else math.inf
    return (result.average is None, round(average, 1), round(jitter, 1), average,
            result.resolver.name.casefold())


def benchmark_resolvers(*, rounds: int = 5, timeout: float = 2.5, delay: float = 0.5,
                        cancelled: threading.Event | None = None,
                        on_round: Callable[[int, list[ResolverResult]], None] | None = None) -> list[ResolverResult]:
    if rounds not in range(1, 6):
        raise ValueError("rounds must be between 1 and 5")
    if not math.isfinite(timeout) or not 0.1 <= timeout <= 10:
        raise ValueError("timeout must be between 0.1 and 10 seconds")
    if not math.isfinite(delay) or not 0 <= delay <= 60:
        raise ValueError("delay must be between 0 and 60 seconds")
    samples: dict[Resolver, list[float | None]] = {resolver: [] for resolver in RESOLVERS}
    for round_index in range(rounds):
        if cancelled is not None and cancelled.is_set():
            break
        with ThreadPoolExecutor(max_workers=min(20, len(RESOLVERS))) as executor:
            futures = {executor.submit(query_resolver, resolver, timeout=timeout): resolver
                       for resolver in RESOLVERS}
            for future in as_completed(futures):
                resolver = futures[future]
                samples[resolver].append(future.result())
        results = _sort_results(samples)
        if on_round is not None:
            on_round(round_index + 1, results)
        if round_index + 1 < rounds and (cancelled is None or not cancelled.wait(delay)):
            continue
        if cancelled is not None and cancelled.is_set():
            break
    return _sort_results(samples)


def _sort_results(samples: dict[Resolver, list[float | None]]) -> list[ResolverResult]:
    return sorted((ResolverResult(resolver, list(values)) for resolver, values in samples.items()),
                  key=result_sort_key)


class DnsBenchmarkView(tk.Frame):
    BACKGROUND = "#0d1b29"
    TEXT = "#e8f1fc"
    MUTED = "#9fb4ca"

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, bg=self.BACKGROUND)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.results: list[ResolverResult] = []
        self._build()

    def _build(self) -> None:
        header = tk.Frame(self, bg=self.BACKGROUND, padx=10, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="DNS Latency Benchmark", bg=self.BACKGROUND, fg=self.TEXT,
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(header, text="Compare public resolvers with validated UDP DNS replies.",
                 bg=self.BACKGROUND, fg=self.MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 10))
        controls = tk.Frame(header, bg=self.BACKGROUND)
        controls.pack(fill="x")
        ttk.Label(controls, text="Rounds").pack(side="left")
        self.rounds = ttk.Spinbox(controls, from_=1, to=5, width=4)
        self.rounds.set("5")
        self.rounds.pack(side="left", padx=(6, 14))
        ttk.Label(controls, text="Timeout (s)").pack(side="left")
        self.timeout = ttk.Spinbox(controls, from_=0.1, to=10, increment=0.1, width=6)
        self.timeout.set("2.5")
        self.timeout.pack(side="left", padx=(6, 14))
        ttk.Label(controls, text="Delay (s)").pack(side="left")
        self.delay = ttk.Spinbox(controls, from_=0, to=60, increment=0.5, width=6)
        self.delay.set("0.5")
        self.delay.pack(side="left", padx=(6, 14))
        self.start_button = ttk.Button(controls, text="Start benchmark", style="Accent.TButton", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(controls, text="Stop", state="disabled", command=self.stop)
        self.stop_button.pack(side="left", padx=(8, 0))
        self.copy_button = ttk.Button(controls, text="Copy report", state="disabled", command=self.copy_report)
        self.copy_button.pack(side="left", padx=(8, 0))
        self.status = tk.Label(header, text="Ready · no web requests or browser timing used.",
                               bg=self.BACKGROUND, fg=self.MUTED, font=("Segoe UI", 9), anchor="w")
        self.status.pack(fill="x", pady=(8, 0))
        filter_row = ttk.Frame(self, padding=(10, 0, 10, 6))
        filter_row.pack(fill="x")
        ttk.Label(filter_row, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_args: self._render())
        ttk.Entry(filter_row, textvariable=self.filter_var).pack(side="left", fill="x", expand=True, padx=(7, 0))
        columns = ("provider", "address", "average", "jitter", "replies", "r1", "r2", "r3", "r4", "r5")
        self.table = ttk.Treeview(self, columns=columns, show="headings")
        widths = (190, 135, 85, 85, 75, 65, 65, 65, 65, 65)
        labels = ("Provider", "Address", "Average", "Jitter", "Replies", "R1", "R2", "R3", "R4", "R5")
        for column, label, width in zip(columns, labels, widths):
            self.table.heading(column, text=label)
            self.table.column(column, width=width, anchor="w" if column in {"provider", "address"} else "center")
        self.table.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def start(self) -> None:
        try:
            rounds = int(self.rounds.get())
            timeout = float(self.timeout.get())
            delay = float(self.delay.get())
            if rounds not in range(1, 6) or not 0.1 <= timeout <= 10 or not 0 <= delay <= 60:
                raise ValueError
        except ValueError:
            self.status.configure(text="Enter 1–5 rounds, a 0.1–10 second timeout and a 0–60 second delay.")
            return
        self.cancel_event = threading.Event()
        self.results = []
        self._render()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.copy_button.configure(state="disabled")
        self.status.configure(text=f"Starting round 1 of {rounds}…")
        threading.Thread(target=self._worker, args=(rounds, timeout, delay), daemon=True).start()
        self.after(60, self._drain)

    def _worker(self, rounds: int, timeout: float, delay: float) -> None:
        try:
            results = benchmark_resolvers(
                rounds=rounds, timeout=timeout, delay=delay, cancelled=self.cancel_event,
                on_round=lambda current, rows: self.events.put(("round", (current, rounds, rows))),
            )
            self.events.put(("done", results))
        except (OSError, ValueError) as error:
            self.events.put(("error", error))

    def _drain(self) -> None:
        finished = False
        while True:
            try:
                event, value = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "round":
                current, total, rows = value
                self.results = rows
                self.status.configure(text=f"Completed round {current} of {total} · results sorted by valid average")
                self._render()
            elif event == "done":
                self.results = value
                self._render()
                replies = sum(result.replies > 0 for result in self.results)
                suffix = " · stopped" if self.cancel_event.is_set() else ""
                self.status.configure(text=f"Complete · {replies} of {len(self.results)} resolvers replied{suffix}")
                finished = True
            else:
                self.status.configure(text=f"Benchmark failed: {value}")
                finished = True
        if finished:
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.copy_button.configure(state="normal" if self.results else "disabled")
        else:
            self.after(60, self._drain)

    def stop(self) -> None:
        self.cancel_event.set()
        self.stop_button.configure(state="disabled")
        self.status.configure(text="Stopping after the active DNS requests finish…")

    def _render(self) -> None:
        self.table.delete(*self.table.get_children())
        query = self.filter_var.get().strip().casefold()
        for result in self.results:
            if query and query not in f"{result.resolver.name} {result.resolver.address}".casefold():
                continue
            average = result.average_ms
            jitter = result.jitter_ms
            rounds = [(f"{sample:.1f}" if sample is not None else "T/O") for sample in result.samples]
            rounds.extend("—" for _ in range(5 - len(rounds)))
            self.table.insert("", "end", values=(
                result.resolver.name, result.resolver.address,
                f"{average:.1f} ms" if average is not None else "No reply",
                f"{jitter:.1f} ms" if jitter is not None else "—",
                f"{result.replies}/{len(result.samples)}", *rounds[:5],
            ))

    def copy_report(self) -> None:
        lines = ["DNS resolver\tAddress\tAverage ms\tJitter ms\tReplies"]
        for result in self.results:
            lines.append("\t".join((result.resolver.name, result.resolver.address,
                                     f"{result.average_ms:.1f}" if result.average_ms is not None else "",
                                     f"{result.jitter_ms:.1f}" if result.jitter_ms is not None else "",
                                     f"{result.replies}/{len(result.samples)}")))
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.status.configure(text="Report copied to the clipboard.")
