"""Live, local-only system performance diagnostics for the desktop application."""

from __future__ import annotations

import json
import os
import platform
import socket
import time
import tkinter as tk
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk

try:
    import psutil
except ImportError:  # The view explains the unavailable provider instead of inventing data.
    psutil = None


BACKGROUND = "#0d1b29"
PANEL = "#152535"
BORDER = "#294155"
TEXT = "#e8f1fc"
MUTED = "#9fb4ca"
BLUE = "#3c9eff"
CYAN = "#37bffc"
GREEN = "#5adb55"
ORANGE = "#ff9b36"
RED = "#ff6868"
PURPLE = "#b58cff"


@dataclass(frozen=True)
class SystemSample:
    """One explicitly-available-or-missing measurement set."""

    timestamp: float
    cpu_percent: float | None
    memory_percent: float | None
    memory_used: int | None
    memory_total: int | None
    disk_busy_percent: float | None
    disk_read_bps: float | None
    disk_write_bps: float | None
    net_down_bps: float | None
    net_up_bps: float | None


def format_bytes(value: float | None) -> str:
    if value is None:
        return "Unavailable"
    amount = float(value)
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return "Unavailable"


def format_rate(value: float | None) -> str:
    return "Unavailable" if value is None else f"{format_bytes(value)}/s"


def diagnose_sample(sample: SystemSample, top_process: tuple[str, float] | None = None) -> tuple[str, str, str]:
    """Return a cautious diagnosis without turning missing data into zeroes."""
    candidates: list[tuple[float, str, str, str]] = []
    if sample.cpu_percent is not None:
        detail = f"CPU is {sample.cpu_percent:.0f}% utilised"
        if top_process and top_process[1] >= 1:
            detail += f"; {top_process[0]} is currently highest at {top_process[1]:.1f}%"
        candidates.append((sample.cpu_percent, "CPU pressure", detail + ".", RED if sample.cpu_percent >= 85 else ORANGE))
    if sample.memory_percent is not None:
        candidates.append((sample.memory_percent, "Memory pressure",
                           f"Memory use is {sample.memory_percent:.0f}%; sustained pressure can cause paging.",
                           RED if sample.memory_percent >= 90 else ORANGE))
    if sample.disk_busy_percent is not None:
        throughput = (sample.disk_read_bps or 0) + (sample.disk_write_bps or 0)
        candidates.append((sample.disk_busy_percent, "Storage pressure",
                           f"Storage is {sample.disk_busy_percent:.0f}% busy at {format_rate(throughput)} combined.",
                           RED if sample.disk_busy_percent >= 90 else ORANGE))
    elif sample.disk_read_bps is not None or sample.disk_write_bps is not None:
        throughput = (sample.disk_read_bps or 0) + (sample.disk_write_bps or 0)
        activity_score = min(100.0, throughput / (1024 * 1024))
        candidates.append((activity_score, "Storage activity",
                           f"Storage busy time is unavailable, but measured throughput is {format_rate(throughput)}.",
                           ORANGE))
    if not candidates:
        return "Measurements unavailable", "No supported system provider returned a usable sample.", MUTED
    score, title, detail, color = max(candidates, key=lambda item: item[0])
    if score < 70:
        network = (sample.net_down_bps or 0) + (sample.net_up_bps or 0)
        if network >= 10 * 1024 * 1024:
            return "Network activity", f"The machine is moving {format_rate(network)}; CPU, memory and storage pressure are moderate.", CYAN
        return "No dominant bottleneck", "CPU, memory and storage are below sustained pressure thresholds in this sample.", GREEN
    return title, detail, color


def trace_payload(samples: list[SystemSample]) -> dict:
    return {
        "format": 1,
        "created": datetime.now().astimezone().isoformat(),
        "host": socket.gethostname(),
        "samples": [asdict(sample) for sample in samples],
    }


class HistoryChart(tk.Canvas):
    """Small honest chart: None values create visible gaps."""

    def __init__(self, parent: tk.Misc, *, title: str, value_getters: tuple[tuple[str, str], ...],
                 ceiling: float = 100.0):
        super().__init__(parent, bg=PANEL, highlightthickness=0, height=155)
        self.title = title
        self.value_getters = value_getters
        self.ceiling = ceiling
        self.samples: list[SystemSample] = []
        self.bind("<Configure>", lambda _event: self.redraw())

    def set_samples(self, samples: list[SystemSample]) -> None:
        self.samples = samples
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        width, height = self.winfo_width(), self.winfo_height()
        if width < 120 or height < 90:
            return
        left, right, top, bottom = 42, width - 12, 29, height - 26
        self.create_text(12, 12, text=self.title, anchor="nw", fill=TEXT,
                         font=("Segoe UI", 10, "bold"))
        legend_x = right
        for label, color in reversed(self.value_getters):
            self.create_text(legend_x, 13, text=label, anchor="e", fill=color,
                             font=("Segoe UI", 8, "bold"))
            legend_x -= max(60, len(label) * 7 + 12)
        for row in range(5):
            y = top + (bottom - top) * row / 4
            value = self.ceiling * (4 - row) / 4
            self.create_line(left, y, right, y, fill="#294051")
            self.create_text(left - 5, y, text=f"{value:g}", anchor="e", fill=MUTED,
                             font=("Segoe UI", 8))
        self.create_text(left, height - 9, text="Earlier", anchor="w", fill=MUTED,
                         font=("Segoe UI", 8))
        self.create_text(right, height - 9, text="Now", anchor="e", fill=MUTED,
                         font=("Segoe UI", 8))
        if len(self.samples) < 2:
            self.create_text((left + right) / 2, (top + bottom) / 2,
                             text="Collecting live samples…", fill=MUTED,
                             font=("Segoe UI", 9))
            return
        span = max(1, len(self.samples) - 1)
        attributes = ("cpu_percent", "memory_percent")
        for attribute, (_label, color) in zip(attributes, self.value_getters):
            segment: list[float] = []
            for index, sample in enumerate(self.samples):
                value = getattr(sample, attribute)
                if value is None:
                    if len(segment) >= 4:
                        self.create_line(*segment, fill=color, width=2, smooth=True)
                    segment = []
                    continue
                x = left + (right - left) * index / span
                y = bottom - (bottom - top) * min(self.ceiling, max(0.0, value)) / self.ceiling
                segment.extend((x, y))
            if len(segment) >= 4:
                self.create_line(*segment, fill=color, width=2, smooth=True)


class SystemMonitorView(tk.Frame):
    """Explain current machine pressure and attribute it to real processes."""

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, bg=BACKGROUND)
        self.samples: deque[SystemSample] = deque(maxlen=600)
        self.process_rows: list[dict] = []
        self.previous_time: float | None = None
        self.previous_disk = None
        self.previous_net = None
        self.paused = False
        self.after_id: str | None = None
        self.values: dict[str, tk.Label] = {}
        self.details: dict[str, tk.Label] = {}
        self.search_text = tk.StringVar()
        self.search_text.trace_add("write", lambda *_args: self._render_processes())
        self.sort_mode = tk.StringVar(value="CPU")
        self._build()
        if psutil is not None:
            psutil.cpu_percent(interval=None)
            for process in psutil.process_iter():
                try:
                    process.cpu_percent(interval=None)
                except (psutil.Error, OSError):
                    pass
        self.after_id = self.after(250, self._sample)

    @staticmethod
    def _panel(parent: tk.Misc) -> tk.Frame:
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)

    @staticmethod
    def _label(parent: tk.Misc, text: str, *, size: int = 10, color: str = TEXT,
               bold: bool = False, background: str = PANEL) -> tk.Label:
        return tk.Label(parent, text=text, bg=background, fg=color, anchor="w",
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        header = tk.Frame(self, bg=BACKGROUND)
        header.grid(row=0, column=0, sticky="ew", pady=(8, 14))
        titles = tk.Frame(header, bg=BACKGROUND)
        titles.pack(side="left", fill="x", expand=True)
        self._label(titles, "System Monitor", size=23, bold=True,
                    background=BACKGROUND).pack(anchor="w")
        self._label(titles, "Know which subsystem and process is slowing this computer down—measured locally.",
                    size=10, color=MUTED, background=BACKGROUND).pack(anchor="w", pady=(2, 0))
        controls = tk.Frame(header, bg=BACKGROUND)
        controls.pack(side="right")
        self.live_label = self._label(controls, "● Live", color=GREEN, bold=True,
                                      background=BACKGROUND)
        self.live_label.pack(side="left", padx=(0, 12))
        self.pause_button = tk.Button(controls, text="Pause", command=self.toggle_pause,
                                      relief="flat", bd=0, bg=PANEL, fg=TEXT,
                                      activebackground="#26435d", activeforeground="#ffffff",
                                      padx=13, pady=8, cursor="hand2")
        self.pause_button.pack(side="left")
        tk.Button(controls, text="Export flight recorder…", command=self.export_trace,
                  relief="flat", bd=0, bg="#1887e7", fg="#ffffff",
                  activebackground="#43a7fa", activeforeground="#ffffff",
                  padx=13, pady=8, cursor="hand2").pack(side="left", padx=(8, 0))

        metrics = tk.Frame(self, bg=BACKGROUND)
        metrics.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for index, (key, label, color) in enumerate((
                ("cpu", "CPU", BLUE), ("memory", "Memory", PURPLE),
                ("disk", "Storage", ORANGE), ("network", "Network", CYAN),
                ("diagnosis", "Current diagnosis", GREEN))):
            metrics.columnconfigure(index, weight=1, uniform="system-metric")
            card = self._panel(metrics)
            card.grid(row=0, column=index, sticky="nsew", padx=(0, 10 if index < 4 else 0))
            inside = tk.Frame(card, bg=PANEL, padx=14, pady=12)
            inside.pack(fill="both", expand=True)
            self._label(inside, label, color=MUTED, size=9).pack(anchor="w")
            value = self._label(inside, "Unavailable", color=color, size=18, bold=True)
            value.pack(anchor="w", pady=(5, 1))
            detail = self._label(inside, "Waiting for a sample", color=MUTED, size=8)
            detail.pack(anchor="w")
            self.values[key], self.details[key] = value, detail

        middle = tk.Frame(self, bg=BACKGROUND)
        middle.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        middle.columnconfigure(0, weight=7)
        middle.columnconfigure(1, weight=4)
        chart_panel = self._panel(middle)
        chart_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.chart = HistoryChart(chart_panel, title="Resource pressure history",
                                  value_getters=(("CPU", BLUE), ("Memory", PURPLE)))
        self.chart.pack(fill="both", expand=True, padx=8, pady=6)
        diagnosis = self._panel(middle)
        diagnosis.grid(row=0, column=1, sticky="nsew")
        self._label(diagnosis, "Why did the machine flinch?", size=11, bold=True).pack(
            anchor="w", padx=15, pady=(13, 5))
        self.diagnosis_title = self._label(diagnosis, "Collecting evidence…", size=15,
                                           bold=True, color=CYAN)
        self.diagnosis_title.pack(anchor="w", padx=15, pady=(10, 4))
        self.diagnosis_detail = self._label(diagnosis,
                                            "A zero means measured zero. Missing sensors stay unavailable.",
                                            color=MUTED, size=9)
        self.diagnosis_detail.configure(wraplength=340, justify="left")
        self.diagnosis_detail.pack(anchor="w", fill="x", padx=15, pady=(0, 12))
        self.diagnosis_process = self._label(diagnosis, "", color=TEXT, size=9)
        self.diagnosis_process.configure(wraplength=340, justify="left")
        self.diagnosis_process.pack(anchor="w", fill="x", padx=15, pady=(0, 12))

        lower = self._panel(self)
        lower.grid(row=3, column=0, sticky="nsew", pady=(0, 6))
        head = tk.Frame(lower, bg=PANEL)
        head.pack(fill="x", padx=12, pady=(10, 7))
        self._label(head, "Top processes", size=11, bold=True).pack(side="left")
        self._label(head, "Search", color=MUTED, size=9).pack(side="left", padx=(22, 5))
        ttk.Entry(head, textvariable=self.search_text, width=24).pack(side="left")
        self._label(head, "Sort", color=MUTED, size=9).pack(side="left", padx=(16, 5))
        chooser = ttk.Combobox(head, textvariable=self.sort_mode,
                               values=("CPU", "Memory", "Disk read", "Disk write"),
                               state="readonly", width=12)
        chooser.pack(side="left")
        chooser.bind("<<ComboboxSelected>>", lambda _event: self._render_processes())
        self.process_status = self._label(head, "", color=MUTED, size=8)
        self.process_status.pack(side="right")

        columns = ("name", "pid", "cpu", "memory", "rss", "read", "write", "status")
        self.process_table = ttk.Treeview(lower, columns=columns, show="headings", height=10)
        headings = (("name", "Process", 250), ("pid", "PID", 70), ("cpu", "CPU %", 80),
                    ("memory", "Memory %", 90), ("rss", "Working set", 110),
                    ("read", "Read total", 110), ("write", "Write total", 110),
                    ("status", "State", 100))
        for column, title, width in headings:
            self.process_table.heading(column, text=title)
            self.process_table.column(column, width=width, anchor="w",
                                      stretch=(column == "name"))
        scroll = ttk.Scrollbar(lower, orient="vertical", command=self.process_table.yview)
        self.process_table.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y", padx=(0, 8), pady=(0, 9))
        self.process_table.pack(fill="both", expand=True, padx=(12, 0), pady=(0, 9))

    def toggle_pause(self) -> None:
        self.paused = not self.paused
        self.pause_button.configure(text="Resume" if self.paused else "Pause")
        self.live_label.configure(text="● Paused" if self.paused else "● Live",
                                  fg=ORANGE if self.paused else GREEN)

    def _sample(self) -> None:
        try:
            if not self.paused:
                sample = self._read_sample()
                self.samples.append(sample)
                self._read_processes()
                self._render(sample)
        finally:
            if self.winfo_exists():
                self.after_id = self.after(1000, self._sample)

    def _read_sample(self) -> SystemSample:
        now = time.monotonic()
        if psutil is None:
            return SystemSample(time.time(), None, None, None, None, None, None, None, None, None)
        interval = None if self.previous_time is None else max(0.1, now - self.previous_time)
        self.previous_time = now
        try:
            cpu = float(psutil.cpu_percent(interval=None))
        except (psutil.Error, OSError):
            cpu = None
        try:
            memory = psutil.virtual_memory()
            memory_percent, memory_used, memory_total = float(memory.percent), int(memory.used), int(memory.total)
        except (psutil.Error, OSError):
            memory_percent = memory_used = memory_total = None
        disk_busy = disk_read = disk_write = None
        try:
            disk = psutil.disk_io_counters()
            if disk is not None and self.previous_disk is not None and interval is not None:
                disk_read = max(0.0, (disk.read_bytes - self.previous_disk.read_bytes) / interval)
                disk_write = max(0.0, (disk.write_bytes - self.previous_disk.write_bytes) / interval)
                if hasattr(disk, "busy_time") and hasattr(self.previous_disk, "busy_time"):
                    disk_busy = min(100.0, max(0.0, (disk.busy_time - self.previous_disk.busy_time) / (interval * 10)))
            self.previous_disk = disk
        except (psutil.Error, OSError, AttributeError):
            pass
        net_down = net_up = None
        try:
            net = psutil.net_io_counters()
            if net is not None and self.previous_net is not None and interval is not None:
                net_down = max(0.0, (net.bytes_recv - self.previous_net.bytes_recv) / interval)
                net_up = max(0.0, (net.bytes_sent - self.previous_net.bytes_sent) / interval)
            self.previous_net = net
        except (psutil.Error, OSError, AttributeError):
            pass
        return SystemSample(time.time(), cpu, memory_percent, memory_used, memory_total,
                            disk_busy, disk_read, disk_write, net_down, net_up)

    def _read_processes(self) -> None:
        if psutil is None:
            self.process_rows = []
            return
        rows = []
        logical_cpus = max(1, psutil.cpu_count(logical=True) or 1)
        for process in psutil.process_iter(("pid", "name", "create_time", "memory_percent",
                                            "memory_info", "io_counters", "status")):
            try:
                info = process.info
                process_name = info.get("name") or "Unknown"
                if info["pid"] == 0 or process_name.casefold() == "system idle process":
                    continue
                io = info.get("io_counters")
                rows.append({
                    "identity": (info["pid"], info.get("create_time")),
                    "name": process_name,
                    "pid": info["pid"],
                    "cpu": min(100.0, max(0.0, float(process.cpu_percent(interval=None)) / logical_cpus)),
                    "memory": max(0.0, float(info.get("memory_percent") or 0)),
                    "rss": int(getattr(info.get("memory_info"), "rss", 0) or 0),
                    "read": int(getattr(io, "read_bytes", 0) or 0),
                    "write": int(getattr(io, "write_bytes", 0) or 0),
                    "status": info.get("status") or "unknown",
                })
            except (psutil.Error, OSError, ValueError, TypeError):
                continue
        self.process_rows = rows

    def _render(self, sample: SystemSample) -> None:
        self.values["cpu"].configure(text="Unavailable" if sample.cpu_percent is None else f"{sample.cpu_percent:.0f}%")
        self.details["cpu"].configure(text=f"{psutil.cpu_count(logical=True)} logical processors" if psutil else "Provider unavailable")
        self.values["memory"].configure(text="Unavailable" if sample.memory_percent is None else f"{sample.memory_percent:.0f}%")
        self.details["memory"].configure(text=(f"{format_bytes(sample.memory_used)} of {format_bytes(sample.memory_total)}"
                                                 if sample.memory_used is not None else "Provider unavailable"))
        disk_total = None if sample.disk_read_bps is None and sample.disk_write_bps is None else (sample.disk_read_bps or 0) + (sample.disk_write_bps or 0)
        disk_text = (f"{sample.disk_busy_percent:.0f}% busy" if sample.disk_busy_percent is not None
                     else format_rate(disk_total))
        self.values["disk"].configure(text=disk_text)
        self.details["disk"].configure(text=f"↓ {format_rate(sample.disk_read_bps)}  ↑ {format_rate(sample.disk_write_bps)}")
        network_total = None if sample.net_down_bps is None and sample.net_up_bps is None else (sample.net_down_bps or 0) + (sample.net_up_bps or 0)
        self.values["network"].configure(text=format_rate(network_total))
        self.details["network"].configure(text=f"↓ {format_rate(sample.net_down_bps)}  ↑ {format_rate(sample.net_up_bps)}")
        top = max(self.process_rows, key=lambda row: row["cpu"], default=None)
        diagnosis = diagnose_sample(sample, (top["name"], top["cpu"]) if top else None)
        self.values["diagnosis"].configure(text=diagnosis[0], fg=diagnosis[2],
                                            font=("Segoe UI", 12, "bold"))
        self.details["diagnosis"].configure(text="Based on this measured sample")
        self.diagnosis_title.configure(text=diagnosis[0], fg=diagnosis[2])
        self.diagnosis_detail.configure(text=diagnosis[1])
        if top:
            self.diagnosis_process.configure(
                text=f"Highest current CPU: {top['name']} (PID {top['pid']}, {top['cpu']:.1f}% CPU, {top['memory']:.1f}% memory)")
        else:
            self.diagnosis_process.configure(text="Process attribution is unavailable on this system.")
        self.chart.set_samples(list(self.samples)[-120:])
        self._render_processes()

    def _render_processes(self) -> None:
        if not hasattr(self, "process_table"):
            return
        self.process_table.delete(*self.process_table.get_children())
        search = self.search_text.get().casefold().strip()
        rows = [row for row in self.process_rows if not search or search in row["name"].casefold()
                or search == str(row["pid"])]
        key = {"CPU": "cpu", "Memory": "memory", "Disk read": "read", "Disk write": "write"}[self.sort_mode.get()]
        rows.sort(key=lambda row: row[key], reverse=True)
        for row in rows[:100]:
            self.process_table.insert("", "end", iid=f"{row['pid']}:{row['identity'][1]}", values=(
                row["name"], row["pid"], f"{row['cpu']:.1f}", f"{row['memory']:.1f}",
                format_bytes(row["rss"]), format_bytes(row["read"]), format_bytes(row["write"]),
                row["status"]))
        self.process_status.configure(text=f"Showing {min(100, len(rows))} of {len(rows)} matching processes")

    def export_trace(self) -> None:
        if not self.samples:
            return
        destination = filedialog.asksaveasfilename(
            parent=self, title="Export system flight recorder", defaultextension=".json",
            initialfile=f"system-trace-{datetime.now().astimezone():%Y%m%d-%H%M%S}.json",
            filetypes=[("System trace", "*.json")])
        if not destination:
            return
        path = Path(destination).expanduser()
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(trace_payload(list(self.samples)), indent=2), encoding="utf-8")
        os.replace(temporary, path)
        self.live_label.configure(text=f"● Saved {path.name}", fg=CYAN)

    def system_summary(self) -> str:
        return f"{platform.system()} {platform.release()} · {platform.machine()} · {socket.gethostname()}"

