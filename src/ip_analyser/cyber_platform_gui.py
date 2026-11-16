"""Native cyber-platform overview drawing only from saved local evidence."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import ttk

from .ai_network_monitor import local_report
from .cyber_platform import build_cyber_overview

BG = "#0b1018"
PANEL = "#171e29"
BORDER = "#2b3542"
TEXT = "#ebf2fb"
MUTED = "#9dabbb"
BLUE = "#54a6ff"
GREEN = "#54d6a1"
AMBER = "#f4b65b"
RED = "#f2787c"
SEVERITY = {"Critical": RED, "High": "#ff8f68", "Medium": AMBER, "Low": GREEN}


class CyberPlatformView(tk.Frame):
    """RoboShadow-inspired layout, using our own branding and UI components."""

    def __init__(self, parent: tk.Misc, *, open_scan: Callable[[], None],
                 open_intelligence: Callable[[], None],
                 open_posture: Callable[[], None],
                 report_provider: Callable[..., dict] = local_report):
        super().__init__(parent, bg=BG)
        self.report_provider = report_provider
        self.overview: dict = {}
        self.values: dict[str, tk.Label] = {}
        self.metrics_detail: dict[str, tk.Label] = {}
        self.risk_values: dict[str, tk.Label] = {}
        self.device_rows: dict[str, dict] = {}
        self._build(open_scan, open_intelligence, open_posture)
        self.refresh()

    @staticmethod
    def _label(parent, text, *, size=10, fg=TEXT, bg=PANEL, bold=False, wraplength=0):
        return tk.Label(parent, text=text, bg=bg, fg=fg, anchor="w", justify="left",
                        wraplength=wraplength,
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    @staticmethod
    def _panel(parent):
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)

    def _build(self, open_scan, open_intelligence, open_posture):
        viewport = tk.Canvas(self, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=viewport.yview)
        viewport.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        viewport.pack(fill="both", expand=True)
        main = tk.Frame(viewport, bg=BG, padx=16, pady=12)
        window = viewport.create_window((0, 0), window=main, anchor="nw")
        main.bind("<Configure>", lambda _e: viewport.configure(scrollregion=viewport.bbox("all")))
        viewport.bind("<Configure>", lambda e: viewport.itemconfigure(window, width=e.width))

        heading = tk.Frame(main, bg=BG)
        heading.pack(fill="x", pady=(0, 14))
        title = tk.Frame(heading, bg=BG)
        title.pack(side="left", fill="x", expand=True)
        self._label(title, "CYBER PLATFORM", bg=BG, size=21, bold=True).pack(anchor="w")
        self._label(title, "Network exposure  /  device intelligence  /  change monitoring",
                    bg=BG, fg=MUTED, size=9).pack(anchor="w", pady=(2, 0))
        tk.Button(heading, text="↻ Refresh local evidence", command=self.refresh,
                  bg="#1d3752", fg=TEXT, activebackground="#2c5072", relief="flat",
                  padx=14, pady=8, bd=0, cursor="hand2").pack(side="right")

        metrics = tk.Frame(main, bg=BG)
        metrics.pack(fill="x", pady=(0, 12))
        for i, (key, label, colour, detail) in enumerate((
            ("total", "DISCOVERED ASSETS", BLUE, "From latest local scan"),
            ("open_ports", "OPEN LAN TCP PORTS", AMBER, "Not necessarily Internet-facing"),
            ("priority_review", "PRIORITY REVIEW", RED, "High or critical exposure scores"),
            ("changes", "CHANGES", GREEN, "Since previous local snapshot"),
        )):
            metrics.columnconfigure(i, weight=1, uniform="cyber-cards")
            card = self._panel(metrics)
            card.grid(row=0, column=i, sticky="nsew", padx=(0, 10 if i < 3 else 0))
            inner = tk.Frame(card, bg=PANEL, padx=14, pady=12)
            inner.pack(fill="both", expand=True)
            self._label(inner, label, size=8, fg=MUTED, bold=True).pack(anchor="w")
            value = self._label(inner, "—", size=24, fg=colour, bold=True)
            value.pack(anchor="w", pady=(4, 1))
            details = self._label(inner, detail, size=8, fg=MUTED, wraplength=210)
            details.pack(anchor="w")
            self.values[key] = value
            self.metrics_detail[key] = details

        middle = tk.Frame(main, bg=BG)
        middle.pack(fill="x", pady=(0, 12))
        middle.columnconfigure(0, weight=1, uniform="cyber-panels")
        middle.columnconfigure(1, weight=1, uniform="cyber-panels")
        risk = self._panel(middle)
        risk.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        trend = self._panel(middle)
        trend.grid(row=0, column=1, sticky="nsew")
        self._label(risk, "EXPOSURE PRIORITY", size=12, bold=True).pack(anchor="w", padx=15, pady=(12, 2))
        self._label(risk, "Explainable LAN service indicators, not confirmed CVEs",
                    size=8, fg=MUTED).pack(anchor="w", padx=15)
        for level in ("Critical", "High", "Medium", "Low"):
            row = tk.Frame(risk, bg=PANEL)
            row.pack(fill="x", padx=15, pady=5)
            self._label(row, level, size=9, fg=MUTED).pack(side="left")
            value = self._label(row, "0", size=9, fg=SEVERITY[level], bold=True)
            value.pack(side="right")
            self.risk_values[level] = value
        self._label(trend, "ASSET DISCOVERY HISTORY", size=12, bold=True).pack(
            anchor="w", padx=15, pady=(12, 2))
        self._label(trend, "Devices discovered in each saved scan", size=8, fg=MUTED).pack(
            anchor="w", padx=15)
        self.trend_canvas = tk.Canvas(trend, bg=PANEL, highlightthickness=0, height=138)
        self.trend_canvas.pack(fill="x", expand=True, padx=12, pady=(8, 8))
        self.trend_canvas.bind("<Configure>", lambda _event: self._draw_history())

        actions = tk.Frame(main, bg=BG)
        actions.pack(fill="x", pady=(0, 12))
        for label, handler in (("Network Scan", open_scan),
                               ("Device Intelligence", open_intelligence),
                               ("Windows Security Posture", open_posture)):
            tk.Button(actions, text=label, command=handler, relief="flat", bd=0,
                      bg="#1b3046", fg=TEXT, activebackground="#264e6e",
                      padx=15, pady=8, cursor="hand2").pack(side="left", padx=(0, 8))

        lower = self._panel(main)
        lower.pack(fill="both", expand=True)
        self._label(lower, "DEVICES TO REVIEW", size=12, bold=True).pack(
            anchor="w", padx=15, pady=(12, 2))
        self._label(lower, "Sorted by local exposure priority. Select a device for supporting evidence.",
                    size=8, fg=MUTED).pack(anchor="w", padx=15, pady=(0, 8))
        grid = tk.Frame(lower, bg=PANEL)
        grid.pack(fill="both", expand=True, padx=12)
        columns = ("device", "address", "zone", "priority", "ports")
        self.table = ttk.Treeview(grid, columns=columns, show="headings", height=7,
                                  selectmode="browse")
        style = ttk.Style(self)
        style.configure("Cyber.Treeview", background="#101823", fieldbackground="#101823",
                        foreground=TEXT, rowheight=27, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Cyber.Treeview.Heading", background="#263341", foreground="#d6e7f7",
                        font=("Segoe UI", 9, "bold"))
        style.map("Cyber.Treeview", background=[("selected", "#28587a")],
                  foreground=[("selected", "#ffffff")])
        self.table.configure(style="Cyber.Treeview")
        for name, width in (("device", 230), ("address", 135), ("zone", 120),
                            ("priority", 120), ("ports", 190)):
            self.table.heading(name, text=name.upper())
            self.table.column(name, width=width, stretch=name in {"device", "ports"})
        vert = ttk.Scrollbar(grid, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=vert.set)
        self.table.pack(side="left", fill="both", expand=True)
        vert.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self._select_device)
        self.explanation = self._label(lower, "No device selected.", size=9, fg=MUTED,
                                       wraplength=900)
        self.explanation.pack(fill="x", padx=15, pady=(8, 12))
        self.footer = self._label(main,
            "Local observations only · No exploitation tests · CVEs and public exposure are unverified",
            size=8, fg=MUTED, bg=BG)
        self.footer.pack(anchor="w", pady=(10, 2))

    def refresh(self):
        try:
            overview = build_cyber_overview(self.report_provider(include_identifiers=True))
        except (ValueError, OSError, RuntimeError) as error:
            self.footer.configure(text=f"Local history unavailable: {error}")
            return
        self.overview = overview
        for key in ("total", "open_ports", "priority_review"):
            self.values[key].configure(text=str(overview[key]))
        updates = overview["changes"]
        self.values["changes"].configure(text=str(sum(updates.values())))
        self.metrics_detail["changes"].configure(text=(
            f"{updates['new']} new · {updates['missing']} missing · {updates['changed']} changed"))
        for level, value in self.risk_values.items():
            value.configure(text=str(overview["risk_distribution"][level]))
        self.table.delete(*self.table.get_children())
        self.device_rows.clear()
        for item in overview["devices"]:
            ports = ", ".join(map(str, item["ports"][:12]))
            if len(item["ports"]) > 12:
                ports += "…"
            row = self.table.insert("", "end", values=(item["name"], item["address"],
                              item["zone"], f"{item['level']} · {item['score']}/100", ports))
            self.device_rows[row] = item
        self.explanation.configure(text="Select a device to inspect why its exposure score was assigned.")
        self.footer.configure(text=(
            f"Last local scan: {overview['last_scan'] or 'not available'}  ·  "
            "No CVE matching or external exposure test was performed by this view"))
        self._draw_history()

    def _select_device(self, _event=None):
        selected = self.table.selection()
        item = self.device_rows.get(selected[0]) if selected else None
        if item:
            factors = "; ".join(item["factors"][:5])
            self.explanation.configure(text=f"{item['address']} · {factors}. "
                "Scores indicate LAN service exposure, not confirmed compromise.")

    def _draw_history(self):
        if not hasattr(self, "trend_canvas"):
            return
        canvas = self.trend_canvas
        canvas.delete("all")
        history = self.overview.get("history", [])[-24:]
        width, height = max(canvas.winfo_width(), 60), max(canvas.winfo_height(), 60)
        if not history:
            canvas.create_text(width / 2, height / 2, text="No saved scan history",
                               fill=MUTED, font=("Segoe UI", 10))
            return
        points = [count for _date, count in history]
        low, high = min(points), max(points)
        span = max(1, high - low)
        pad = 24
        line = []
        for index, value in enumerate(points):
            x = pad + index * max(1, width - 2 * pad) / max(1, len(points) - 1)
            y = height - pad - (value - low) / span * (height - 2 * pad)
            line.extend((x, y))
        canvas.create_line(pad, height - pad, width - pad, height - pad, fill=BORDER)
        if len(line) >= 4:
            canvas.create_line(*line, fill=BLUE, width=3, smooth=False)
        else:
            canvas.create_oval(line[0] - 3, line[1] - 3, line[0] + 3, line[1] + 3,
                               fill=BLUE, outline="")
        canvas.create_text(pad, height - 7, text=f"{len(history)} scans", fill=MUTED,
                           anchor="w", font=("Segoe UI", 8))
        canvas.create_text(width - pad, height - 7, text=f"Latest: {points[-1]}",
                           fill=TEXT, anchor="e", font=("Segoe UI", 8))
