"""Native DNS resolver benchmark tab."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import messagebox, ttk

from .dns_benchmark import (
    DNS_RESOLVERS,
    DNSBenchmarkResult,
    probe_resolver,
    result_sort_key,
    validate_query_name,
)
from .windows_settings import open_windows_dns_settings


class DNSBenchmarkView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.results = [DNSBenchmarkResult(resolver) for resolver in DNS_RESOLVERS]
        self.events: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.skip_wait_event = threading.Event()
        self.running = False
        self.waiting = False
        self.completed_probes = 0
        self.total_probes = 0
        self.filter_text = tk.StringVar()
        self._build()
        self.after(100, self._drain_events)
        self._render()

    def _build(self) -> None:
        header = ttk.Frame(self, padding=(12, 12, 12, 8))
        header.pack(fill="x")
        title = ttk.Frame(header)
        title.pack(side="left", fill="x", expand=True)
        ttk.Label(title, text="DNS Latency Benchmark", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        ttk.Label(title, text="Compare real UDP DNS query latency, reliability and stability across public resolvers.",
                  foreground="#90abc4").pack(anchor="w")
        ttk.Button(header, text="?", width=3, command=self._show_help).pack(side="right", padx=(8, 0))
        self.copy_button = ttk.Button(header, text="Copy report", command=self.copy_report)
        self.copy_button.pack(side="right", padx=(8, 0))
        self.dns_settings_button = ttk.Button(
            header, text="Windows DNS settings", command=self._open_dns_settings,
            state="disabled",
        )
        if os.name == "nt":
            self.dns_settings_button.pack(side="right", padx=(8, 0))
        self.stop_button = ttk.Button(header, text="Stop", command=self.stop, state="disabled",
                                      style="Danger.TButton")
        self.stop_button.pack(side="right", padx=(8, 0))
        self.skip_button = ttk.Button(header, text="Skip wait", command=self.skip_wait, state="disabled")
        self.skip_button.pack(side="right", padx=(8, 0))
        self.start_button = ttk.Button(header, text="Start benchmark", command=self.start,
                                       style="Accent.TButton")
        self.start_button.pack(side="right")

        controls = ttk.Frame(self, padding=(12, 0, 12, 8))
        controls.pack(fill="x")
        ttk.Label(controls, text="Query name").pack(side="left")
        self.query_entry = ttk.Entry(controls, width=24)
        self.query_entry.insert(0, "example.com")
        self.query_entry.pack(side="left", padx=(6, 12))
        ttk.Label(controls, text="Rounds").pack(side="left")
        self.rounds = ttk.Spinbox(controls, from_=1, to=5, width=4)
        self.rounds.set("5")
        self.rounds.pack(side="left", padx=(6, 12))
        ttk.Label(controls, text="Delay (s)").pack(side="left")
        self.delay = ttk.Spinbox(controls, from_=0, to=300, width=5)
        self.delay.set("60")
        self.delay.pack(side="left", padx=(6, 12))
        ttk.Label(controls, text="Timeout (s)").pack(side="left")
        self.timeout = ttk.Spinbox(controls, from_=0.2, to=10, increment=0.1, width=5)
        self.timeout.set("2.2")
        self.timeout.pack(side="left", padx=(6, 18))
        ttk.Label(controls, text="Filter").pack(side="left")
        entry = ttk.Entry(controls, textvariable=self.filter_text)
        entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.filter_text.trace_add("write", lambda *_args: self._render())

        summary = ttk.Frame(self, padding=(12, 0, 12, 8))
        summary.pack(fill="x")
        self.winner = ttk.Label(summary, text="Fastest resolver will appear after the first successful reply.",
                                font=("Segoe UI", 11, "bold"), foreground="#31b8ff")
        self.winner.pack(side="left", fill="x", expand=True)
        self.status = ttk.Label(summary, text=f"Ready to test {len(DNS_RESOLVERS)} resolvers")
        self.status.pack(side="right")

        self.progress = ttk.Progressbar(self, style="Green.Horizontal.TProgressbar", maximum=100)
        self.progress.pack(fill="x", padx=12, pady=(0, 8))

        table_frame = ttk.Frame(self, padding=(12, 0, 12, 8))
        table_frame.pack(fill="both", expand=True)
        columns = ("rank", "provider", "address", "category", "average", "jitter", "success",
                   "round1", "round2", "round3", "round4", "round5")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = ("#", "Provider", "IP address", "Category", "Average", "Jitter", "Replies",
                    "R1", "R2", "R3", "R4", "R5")
        widths = (45, 175, 125, 135, 80, 80, 70, 65, 65, 65, 65, 65)
        for column, heading, width in zip(columns, headings, widths):
            self.table.heading(column, text=heading)
            self.table.column(column, width=width, anchor="center" if column not in {
                "provider", "address", "category"} else "w", stretch=column in {"provider", "category"})
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.table.bind("<Double-1>", self._copy_selected_address)
        for tag, colour in (("fast", "#55e6a5"), ("ok", "#e9c46a"),
                            ("slow", "#ff8f70"), ("timeout", "#a9bfd4")):
            self.table.tag_configure(tag, foreground=colour)

        ttk.Label(self,
                  text="Ranking uses the displayed average first, then lower jitter for equal averages. Timeouts reduce reply count.",
                  foreground="#90abc4", padding=(12, 0, 12, 10)).pack(fill="x")

    def start(self) -> None:
        if self.running:
            return
        try:
            query_name = validate_query_name(self.query_entry.get())
            rounds = int(self.rounds.get())
            delay = int(self.delay.get())
            timeout = float(self.timeout.get())
            if not 1 <= rounds <= 5 or not 0 <= delay <= 300 or not 0.2 <= timeout <= 10:
                raise ValueError("Use 1–5 rounds, a 0–300 second delay and a 0.2–10 second timeout.")
        except (ValueError, tk.TclError) as error:
            messagebox.showerror("Invalid benchmark settings", str(error), parent=self)
            return
        self.results = [DNSBenchmarkResult(resolver) for resolver in DNS_RESOLVERS]
        self.stop_event.clear()
        self.skip_wait_event.clear()
        self.running = True
        self.waiting = False
        self.completed_probes = 0
        self.total_probes = rounds * len(DNS_RESOLVERS)
        self.progress.configure(value=0)
        self.start_button.configure(state="disabled")
        self.dns_settings_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.skip_button.configure(state="disabled")
        self.query_entry.configure(state="disabled")
        self.rounds.configure(state="disabled")
        self.delay.configure(state="disabled")
        self.timeout.configure(state="disabled")
        self.winner.configure(text="Waiting for the first successful DNS reply…")
        self._render()
        threading.Thread(target=self._run, args=(query_name, rounds, delay, timeout),
                         name="dns-benchmark", daemon=True).start()

    def stop(self) -> None:
        if self.running:
            self.stop_event.set()
            self.skip_wait_event.set()
            self.status.configure(text="Stopping after active DNS queries finish…")

    def skip_wait(self) -> None:
        if self.waiting:
            self.skip_wait_event.set()

    def _run(self, query_name: str, rounds: int, delay: int, timeout: float) -> None:
        try:
            for round_index in range(rounds):
                if self.stop_event.is_set():
                    break
                self.events.put(("status", f"Round {round_index + 1}/{rounds} · querying {len(DNS_RESOLVERS)} resolvers"))
                with ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns-probe") as executor:
                    futures = {executor.submit(probe_resolver, resolver, query_name, timeout): index
                               for index, resolver in enumerate(DNS_RESOLVERS)}
                    for future in as_completed(futures):
                        index = futures[future]
                        latency, rcode = future.result()
                        self.events.put(("result", (round_index, index, latency, rcode)))
                if self.stop_event.is_set() or round_index + 1 >= rounds:
                    break
                self.skip_wait_event.clear()
                self.events.put(("waiting", True))
                for remaining in range(delay, 0, -1):
                    self.events.put(("status", f"Round {round_index + 1}/{rounds} complete · next round in {remaining}s"))
                    if self.skip_wait_event.wait(1) or self.stop_event.is_set():
                        break
                self.events.put(("waiting", False))
            self.events.put(("complete", "Benchmark stopped — partial results retained" if self.stop_event.is_set()
                             else "Benchmark complete — ranked fastest to slowest"))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("error", str(error)))

    def _drain_events(self) -> None:
        try:
            while True:
                event, value = self.events.get_nowait()
                if event == "result":
                    round_index, index, latency, _rcode = value
                    while len(self.results[index].latencies) < round_index:
                        self.results[index].latencies.append(None)
                    self.results[index].latencies.append(latency)
                    self.completed_probes += 1
                    self.progress.configure(value=self.completed_probes / max(1, self.total_probes) * 100)
                    self._render()
                elif event == "status":
                    self.status.configure(text=value)
                elif event == "waiting":
                    self.waiting = bool(value)
                    self.skip_button.configure(state="normal" if self.waiting else "disabled")
                elif event == "complete":
                    self.status.configure(text=value)
                    self._finish()
                elif event == "error":
                    self.status.configure(text=f"Benchmark failed: {value}")
                    self._finish()
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _finish(self) -> None:
        self.running = False
        self.waiting = False
        self.start_button.configure(state="normal", text="Run again")
        self.stop_button.configure(state="disabled")
        self.skip_button.configure(state="disabled")
        self.query_entry.configure(state="normal")
        self.rounds.configure(state="normal")
        self.delay.configure(state="normal")
        self.timeout.configure(state="normal")
        has_reply = any(result.average is not None for result in self.results)
        if os.name == "nt":
            self.dns_settings_button.configure(state="normal" if has_reply else "disabled")
        self._render()

    def _open_dns_settings(self) -> None:
        try:
            open_windows_dns_settings()
            self.status.configure(text="Opened Windows network settings · select Edit beside DNS server assignment")
        except (OSError, RuntimeError) as error:
            messagebox.showerror("Cannot open Windows DNS settings", str(error), parent=self)

    def _filtered_results(self) -> list[DNSBenchmarkResult]:
        needle = self.filter_text.get().strip().casefold()
        ordered = sorted(self.results, key=result_sort_key)
        if not needle:
            return ordered
        return [result for result in ordered if needle in
                f"{result.resolver.name} {result.resolver.address} {result.resolver.category}".casefold()]

    def _render(self) -> None:
        self.table.delete(*self.table.get_children())
        all_ranked = sorted(self.results, key=result_sort_key)
        rank_by_address = {result.resolver.address: rank for rank, result in enumerate(all_ranked, 1)}
        for result in self._filtered_results():
            average = result.average
            jitter = result.jitter
            rounds = ["T/O" if value is None else f"{value:.1f}" for value in result.latencies]
            rounds.extend(["—"] * (5 - len(rounds)))
            tag = "timeout" if average is None else "fast" if average < 35 else "ok" if average <= 100 else "slow"
            self.table.insert("", "end", iid=result.resolver.address, values=(
                rank_by_address[result.resolver.address], result.resolver.name, result.resolver.address,
                result.resolver.category, "T/O" if average is None else f"{average:.1f} ms",
                "—" if jitter is None else f"±{jitter:.1f} ms",
                f"{len(result.successful)}/{len(result.latencies)}" if result.latencies else "—",
                *rounds[:5]), tags=(tag,))
        winner = next((result for result in all_ranked if result.average is not None), None)
        if winner:
            self.winner.configure(text=(f"Fastest: {winner.resolver.name} · {winner.resolver.address} · "
                                        f"{winner.average:.1f} ms average · ±{winner.jitter:.1f} ms jitter"))

    def copy_report(self) -> None:
        lines = ["Advanced IP Analyser DNS Benchmark", "===================================",
                 f"Query: {self.query_entry.get().strip() or 'example.com'}", ""]
        for rank, result in enumerate(sorted(self.results, key=result_sort_key), 1):
            average = "Timeout" if result.average is None else f"{result.average:.1f} ms"
            jitter = "—" if result.jitter is None else f"±{result.jitter:.1f} ms"
            samples = ", ".join("T/O" if value is None else f"{value:.1f} ms" for value in result.latencies) or "Not tested"
            lines.append(f"{rank}. {result.resolver.name} [{result.resolver.address}] · avg {average} · jitter {jitter} · {samples}")
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.status.configure(text="Benchmark report copied to clipboard")

    def _copy_selected_address(self, _event=None) -> None:
        selected = self.table.selection()
        if selected:
            self.clipboard_clear()
            self.clipboard_append(selected[0])
            self.status.configure(text=f"Copied resolver address: {selected[0]}")

    def _show_help(self) -> None:
        messagebox.showinfo(
            "DNS Benchmark help",
            "WHAT IT DOES\n"
            "Sends real UDP DNS A-record queries directly to each listed resolver and ranks successful replies by average latency, then jitter.\n\n"
            "HOW TO USE IT\n"
            "Choose a query name, 1–5 rounds, the delay between rounds and a timeout. Select Start benchmark. Stop retains partial results; Skip wait starts the next round early. Filter narrows the table and double-clicking a row copies its IP. After a successful Windows test, Windows DNS settings opens the active Ethernet or Wi-Fi page; select Edit beside DNS server assignment.\n\n"
            "HOW IT WORKS\n"
            "Every query has a random transaction ID. Replies must match that ID and be marked as DNS responses. Up to eight resolvers are tested concurrently so an unreachable server cannot stall the complete list. Jitter is the population standard deviation of successful samples.\n\n"
            "WHY IT DOES IT\n"
            "Resolver performance depends on your ISP, routing, location, filtering and current load. Measuring from this computer is more useful than relying on another person's ranking.\n\n"
            "LIMITATIONS\n"
            "This measures UDP port 53 from this device; it does not benchmark encrypted DNS, cache quality, privacy policy, filtering correctness or security. A fast resolver is not automatically the best resolver. Firewalls may block third-party DNS.",
            parent=self,
        )
