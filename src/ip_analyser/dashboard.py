"""The network overview shown on the desktop application's first page."""

from __future__ import annotations

import ipaddress
import socket
import time
import tkinter as tk
from collections import deque
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from tkinter import ttk

from .models import Host

try:
    import psutil
except ImportError:  # The rest of the application remains usable without counters.
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


class DashboardView(tk.Frame):
    """A live overview; every count comes from the current scan or saved hosts."""

    def __init__(self, parent: tk.Misc, *, favorites: Callable[[], None],
                 interface: Callable[[], str]):
        super().__init__(parent, bg=BACKGROUND)
        self.interface = interface
        self.samples: deque[tuple[float, float]] = deque(maxlen=45)
        self.previous_counters: tuple[str, int, int, float] | None = None
        self.activities: deque[tuple[str, str, str]] = deque(maxlen=7)
        self.values: dict[str, tk.Label] = {}
        self.details: dict[str, tk.Label] = {}
        self.system_values: dict[str, tk.Label] = {}
        self.health_values: dict[str, float] = {"reachability": 0.0, "inventory": 0.0}
        self.health_canvases: dict[str, tk.Canvas] = {}
        self._gateway_cache: tuple[str, str] | None = None
        self._build(favorites)
        self.after(1800, self._sample_traffic)

    @staticmethod
    def _panel(parent: tk.Misc) -> tk.Frame:
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)

    @staticmethod
    def _label(parent: tk.Misc, text: str, *, size: int = 10, color: str = TEXT,
               bold: bool = False, background: str = PANEL) -> tk.Label:
        return tk.Label(parent, text=text, bg=background, fg=color, anchor="w",
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    def _build(self, favorites: Callable[[], None]) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.rowconfigure(3, weight=1)

        header = tk.Frame(self, bg=BACKGROUND)
        header.grid(row=0, column=0, sticky="ew", pady=(7, 15))
        title = tk.Frame(header, bg=BACKGROUND)
        title.pack(side="left", fill="x", expand=True)
        self._label(title, "Network Dashboard", size=23, bold=True,
                    background=BACKGROUND).pack(anchor="w")
        self._label(title, "Live overview of your network and recent tool activity.",
                    size=10, color=MUTED, background=BACKGROUND).pack(anchor="w", pady=(2, 0))

        metrics = tk.Frame(self, bg=BACKGROUND)
        metrics.grid(row=1, column=0, sticky="ew", pady=(0, 13))
        for index, (key, label, color, symbol) in enumerate((
                ("total", "Total Hosts", BLUE, "▣"),
                ("online", "Online Hosts", GREEN, "●"),
                ("ports", "Open Ports", ORANGE, "▤"),
                ("services", "Active Services", BLUE, "⚙"),
                ("range", "Network Range", CYAN, "⌘"))):
            metrics.columnconfigure(index, weight=1, uniform="dashboard-metric")
            card = self._panel(metrics)
            card.grid(row=0, column=index, sticky="nsew", padx=(0, 10 if index < 4 else 0))
            interior = tk.Frame(card, bg=PANEL, padx=15, pady=13)
            interior.pack(fill="both", expand=True)
            top = tk.Frame(interior, bg=PANEL)
            top.pack(fill="x")
            self._label(top, label, color=MUTED, size=9).pack(side="left")
            self._label(top, symbol, color=color, size=15).pack(side="right")
            value = self._label(interior, "—", color=color, size=20, bold=True)
            value.pack(anchor="w", pady=(7, 0))
            detail = self._label(interior, "", color=MUTED, size=9)
            detail.pack(anchor="w")
            self.values[key] = value
            self.details[key] = detail

        middle = tk.Frame(self, bg=BACKGROUND)
        middle.grid(row=2, column=0, sticky="nsew", pady=(0, 13))
        middle.columnconfigure(0, weight=7)
        middle.columnconfigure(1, weight=5)
        middle.columnconfigure(2, weight=3)
        middle.rowconfigure(0, weight=1)
        traffic = self._panel(middle)
        traffic.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self._build_traffic(traffic)
        activity = self._panel(middle)
        activity.grid(row=0, column=1, sticky="nsew", padx=(0, 12))
        self._build_activity(activity)
        health = self._panel(middle)
        health.grid(row=0, column=2, sticky="nsew")
        self._build_health(health)

        lower = tk.Frame(self, bg=BACKGROUND)
        lower.grid(row=3, column=0, sticky="nsew", pady=(0, 5))
        lower.columnconfigure(0, weight=6)
        lower.columnconfigure(1, weight=5)
        lower.rowconfigure(0, weight=1)
        favorite_panel = self._panel(lower)
        favorite_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self._build_favorites(favorite_panel, favorites)
        system = self._panel(lower)
        system.grid(row=0, column=1, sticky="nsew")
        self._build_system(system)

    def _panel_header(self, panel: tk.Frame, title: str, action: str = "",
                      command: Callable[[], None] | None = None) -> tk.Frame:
        header = tk.Frame(panel, bg=PANEL)
        header.pack(fill="x", padx=15, pady=(12, 7))
        self._label(header, title, size=11, bold=True).pack(side="left")
        if action and command:
            tk.Button(header, text=action, command=command, relief="flat", bd=0,
                      bg=PANEL, fg=BLUE, activebackground=PANEL,
                      activeforeground="#92cbff", cursor="hand2").pack(side="right")
        tk.Frame(panel, bg=BORDER, height=1).pack(fill="x", padx=15)
        return header

    def _build_traffic(self, panel: tk.Frame) -> None:
        header = self._panel_header(panel, "Network Traffic (Live)")
        self.rate_label = self._label(header, "Waiting for traffic counters", color=MUTED, size=8)
        self.rate_label.pack(side="right")
        charts = tk.Frame(panel, bg=PANEL)
        charts.pack(fill="both", expand=True, padx=9, pady=(4, 9))
        charts.rowconfigure(0, weight=1)
        charts.rowconfigure(1, weight=1)
        charts.columnconfigure(0, weight=1)
        self.download_chart = tk.Canvas(charts, bg="#101f31", highlightthickness=1,
                                        highlightbackground=BORDER, height=75)
        self.download_chart.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        self.upload_chart = tk.Canvas(charts, bg="#101f31", highlightthickness=1,
                                      highlightbackground=BORDER, height=75)
        self.upload_chart.grid(row=1, column=0, sticky="nsew")
        self.download_chart.bind("<Configure>", lambda _event: self._draw_traffic())
        self.upload_chart.bind("<Configure>", lambda _event: self._draw_traffic())

    def _build_health(self, panel: tk.Frame) -> None:
        self._panel_header(panel, "Coverage")
        holder = tk.Frame(panel, bg=PANEL)
        holder.pack(fill="both", expand=True, padx=10, pady=(5, 9))
        for key, title, color in (("reachability", "Hosts found", GREEN),
                                  ("inventory", "Identified", BLUE)):
            card = tk.Frame(holder, bg="#101f31", highlightbackground=BORDER,
                            highlightthickness=1)
            card.pack(fill="both", expand=True, pady=(0, 6))
            canvas = tk.Canvas(card, width=130, height=92, bg="#101f31", highlightthickness=0)
            canvas.pack(fill="both", expand=True)
            canvas.bind("<Configure>", lambda _event, selected=key, shade=color:
                        self._draw_health_ring(selected, shade))
            self.health_canvases[key] = canvas
            self._label(card, title, color=MUTED, size=8, background="#101f31").pack(
                anchor="center", pady=(0, 7))

    def _draw_health_ring(self, key: str, color: str) -> None:
        canvas = self.health_canvases.get(key)
        if canvas is None:
            return
        canvas.delete("all")
        width, height = max(1, canvas.winfo_width()), max(1, canvas.winfo_height())
        diameter = max(42, min(width - 28, height - 18, 74))
        left = (width - diameter) / 2
        top = max(8, (height - diameter) / 2)
        box = (left, top, left + diameter, top + diameter)
        value = max(0.0, min(1.0, self.health_values.get(key, 0.0)))
        canvas.create_arc(*box, start=90, extent=-359.9, style="arc", width=9,
                          outline="#233a50")
        if value:
            canvas.create_arc(*box, start=90, extent=-359.9 * value, style="arc", width=9,
                              outline=color)
        canvas.create_text(width / 2, top + diameter / 2, text=f"{value:.0%}", fill=TEXT,
                           font=("Segoe UI", 14, "bold"))

    def _build_activity(self, panel: tk.Frame) -> None:
        self._panel_header(panel, "Recent Tool Activity")
        self.activity_rows = tk.Frame(panel, bg=PANEL)
        self.activity_rows.pack(fill="both", expand=True, padx=15, pady=(7, 9))
        self._render_activity()

    def _build_favorites(self, panel: tk.Frame, manage: Callable[[], None]) -> None:
        self._panel_header(panel, "Favorite Hosts", "Manage", manage)
        self.favorites_table = ttk.Treeview(panel, columns=("address", "name", "note"),
                                            show="headings", height=4)
        for column, title, width in (("address", "IP Address", 135),
                                     ("name", "Name", 170), ("note", "Description", 240)):
            self.favorites_table.heading(column, text=title)
            self.favorites_table.column(column, width=width, anchor="w", stretch=True)
        self.favorites_table.pack(fill="both", expand=True, padx=12, pady=(5, 10))
        self.favorites_table.bind("<Double-1>", lambda _event: manage())

    def _build_system(self, panel: tk.Frame) -> None:
        self._panel_header(panel, "System Information")
        rows = tk.Frame(panel, bg=PANEL)
        rows.pack(fill="both", expand=True, padx=15, pady=(7, 8))
        rows.columnconfigure(1, weight=1)
        for row, title in enumerate(("Hostname", "Local IP", "MAC Address", "Network Adapter",
                                     "Subnet Mask", "Default Gateway")):
            self._label(rows, title, color=MUTED, size=9).grid(row=row, column=0, sticky="w", pady=2)
            value = self._label(rows, "—", size=9)
            value.grid(row=row, column=1, sticky="w", padx=(20, 0), pady=2)
            self.system_values[title] = value

    def refresh(self, hosts: Iterable[Host], *, scanned: int, target: str,
                favorites: Iterable[Host]) -> None:
        hosts = list(hosts)
        favorites = list(favorites)
        online = len(hosts)
        ports = sum(len(host.ports) for host in hosts)
        services = len({service for host in hosts for service in host.services})
        self.values["total"].configure(text=str(scanned) if scanned else "—")
        self.details["total"].configure(text="addresses checked" if scanned else "No scan yet")
        self.values["online"].configure(text=str(online))
        self.details["online"].configure(text=f"{online / scanned:.1%} of checked" if scanned else "Awaiting scan")
        self.values["ports"].configure(text=str(ports))
        self.details["ports"].configure(text=f"across {sum(bool(host.ports) for host in hosts)} hosts")
        self.values["services"].configure(text=str(services))
        self.details["services"].configure(text="distinct detected services")
        self.values["range"].configure(text=target or "—", font=("Segoe UI", 12, "bold"))
        self.details["range"].configure(text=("last scan target" if scanned else "selected scan target")
                                        if target else "Select a network")
        identified = sum(bool(host.hostname or host.manufacturer or host.device_type) for host in hosts)
        self.health_values["reachability"] = online / scanned if scanned else 0.0
        self.health_values["inventory"] = identified / online if online else 0.0
        self._draw_health_ring("reachability", GREEN)
        self._draw_health_ring("inventory", BLUE)
        self.favorites_table.delete(*self.favorites_table.get_children())
        for host in favorites[:6]:
            self.favorites_table.insert("", "end", values=(host.address, host.hostname or "—",
                                                           host.note or host.device_type or "—"))
        self._refresh_system()

    def record_activity(self, description: str, color: str = BLUE) -> None:
        self.activities.appendleft((datetime.now(UTC).astimezone().strftime("%H:%M:%S"),
                                    description, color))
        self._render_activity()

    def _render_activity(self) -> None:
        for child in self.activity_rows.winfo_children():
            child.destroy()
        if not self.activities:
            self._label(self.activity_rows, "No activity yet. Start a scan or run a tool.",
                        color=MUTED, size=9).pack(anchor="w", pady=9)
            return
        for stamp, description, color in self.activities:
            line = tk.Frame(self.activity_rows, bg=PANEL)
            line.pack(fill="x", pady=4)
            self._label(line, stamp, color=MUTED, size=8).pack(side="left")
            self._label(line, "●", color=color, size=9).pack(side="left", padx=(12, 8))
            self._label(line, description, size=9).pack(side="left", fill="x", expand=True)

    def _refresh_system(self) -> None:
        self.system_values["Hostname"].configure(text=socket.gethostname())
        selected = self.interface()
        self.system_values["Network Adapter"].configure(text=selected if selected != "any" else "—")
        if psutil is None:
            return
        addresses = psutil.net_if_addrs().get(selected, [])
        local_ip = ""
        for address in addresses:
            if address.family == socket.AF_INET and not local_ip:
                local_ip = address.address
                self.system_values["Local IP"].configure(text=local_ip)
                self.system_values["Subnet Mask"].configure(text=address.netmask or "—")
            elif address.family == psutil.AF_LINK:
                self.system_values["MAC Address"].configure(text=address.address)
        if local_ip and (self._gateway_cache is None or self._gateway_cache[0] != local_ip):
            try:
                from .scanner import Scanner
                gateway = next((value for network, value in Scanner._windows_local_routes()
                                if ipaddress.ip_address(local_ip) in network), "")
                self._gateway_cache = (local_ip, gateway)
                self.system_values["Default Gateway"].configure(text=gateway or "—")
            except (OSError, ValueError):
                pass

    def _sample_traffic(self) -> None:
        try:
            if psutil is None:
                self.rate_label.configure(text="Traffic counters unavailable")
                return
            counters = psutil.net_io_counters(pernic=True)
            selected = self.interface()
            if selected not in counters:
                selected = next((name for name in counters if not name.lower().startswith("loopback")), "")
            if selected not in counters:
                self.rate_label.configure(text="No active interface")
                return
            current = counters[selected]
            now = time.monotonic()
            previous = self.previous_counters
            self.previous_counters = (selected, current.bytes_recv, current.bytes_sent, now)
            if previous is not None and previous[0] == selected:
                interval = max(0.1, now - previous[3])
                down = max(0.0, (current.bytes_recv - previous[1]) * 8 / interval / 1_000_000)
                up = max(0.0, (current.bytes_sent - previous[2]) * 8 / interval / 1_000_000)
                self.samples.append((down, up))
                self.rate_label.configure(text=f"● {down:.1f} Mb/s down     ● {up:.1f} Mb/s up")
                self._draw_traffic()
        except (OSError, RuntimeError):
            self.rate_label.configure(text="Traffic counters unavailable")
        finally:
            if self.winfo_exists():
                self.after(1800, self._sample_traffic)

    def _draw_traffic(self) -> None:
        self._draw_traffic_series(self.download_chart, 0, BLUE, "DOWNLOAD")
        self._draw_traffic_series(self.upload_chart, 1, CYAN, "UPLOAD")

    def _draw_traffic_series(self, chart: tk.Canvas, series: int, color: str,
                             title: str) -> None:
        chart.delete("all")
        width, height = chart.winfo_width(), chart.winfo_height()
        if width < 100 or height < 55:
            return
        left, right, top, bottom = 44, width - 9, 18, height - 18
        peak = max((sample[series] for sample in self.samples), default=0.0)
        ceiling = max(1.0, (int(peak / 5) + 1) * 5)
        chart.create_text(9, 7, text=title, anchor="nw", fill=MUTED,
                          font=("Segoe UI", 7, "bold"))
        for row in range(4):
            y = top + (bottom - top) * row / 3
            chart.create_line(left, y, right, y, fill="#294051")
            label = f"{ceiling * (3 - row) / 3:.1f}".rstrip("0").rstrip(".")
            chart.create_text(left - 6, y, text=label,
                              anchor="e", fill=MUTED, font=("Segoe UI", 8))
        for column in range(8):
            x = left + (right - left) * column / 7
            chart.create_line(x, top, x, bottom, fill="#243b4c")
        if len(self.samples) < 2:
            chart.create_text((left + right) / 2, (top + bottom) / 2,
                              text="Collecting live interface traffic…", fill=MUTED,
                              font=("Segoe UI", 8))
            return
        points: list[float] = []
        denominator = max(1, len(self.samples) - 1)
        for index, sample in enumerate(self.samples):
            points.extend((left + (right - left) * index / denominator,
                           bottom - (bottom - top) * sample[series] / ceiling))
        area = [left, bottom, *points, points[-2], bottom]
        chart.create_polygon(*area, fill="#164d81", outline="", smooth=True)
        chart.create_line(*points, fill=color, width=2, smooth=True)
        chart.create_oval(points[-2] - 3, points[-1] - 3, points[-2] + 3, points[-1] + 3,
                          fill="#ffffff", outline=color)
