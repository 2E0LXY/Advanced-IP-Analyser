"""Network Intelligence workspace for inventory query, risk and graph export."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable, Iterable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .models import Host
from .network_intelligence import (
    DeviceInsight,
    analyse_hosts,
    export_graphml,
    export_intelligence_json,
    filter_insights,
)


class NetworkIntelligenceView(ttk.Frame):
    def __init__(self, master, hosts: Callable[[], Iterable[Host]]):
        super().__init__(master, padding=14)
        self.hosts = hosts
        self.items: list[DeviceInsight] = []
        self.visible: list[DeviceInsight] = []
        self.rows: dict[str, DeviceInsight] = {}
        self.query = tk.StringVar()
        self.summary = tk.StringVar(value="Run or import a network scan to build intelligence.")
        self._build()

    def _build(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 10))
        heading = ttk.Frame(header)
        heading.pack(side="left", fill="x", expand=True)
        ttk.Label(heading, text="Network Intelligence", font=("Segoe UI", 21, "bold")).pack(anchor="w")
        ttk.Label(heading, text="Local metadata analytics - no payload capture, decryption or cloud upload.",
                  foreground="#90abc4").pack(anchor="w")
        ttk.Button(header, text="Refresh", command=self.refresh, style="Accent.TButton").pack(side="right")
        ttk.Button(header, text="Export JSON...", command=self.export_json).pack(side="right", padx=(0, 8))
        ttk.Button(header, text="Export GraphML...", command=self.export_graph).pack(side="right", padx=(0, 8))

        query_bar = ttk.Frame(self)
        query_bar.pack(fill="x", pady=(0, 8))
        ttk.Label(query_bar, text="Query").pack(side="left")
        entry = ttk.Entry(query_bar, textvariable=self.query)
        entry.pack(side="left", fill="x", expand=True, padx=8)
        entry.bind("<Return>", lambda _event: self.apply_query())
        ttk.Button(query_bar, text="Apply", command=self.apply_query).pack(side="left")
        ttk.Button(query_bar, text="Clear", command=self._clear_query).pack(side="left", padx=(8, 0))
        ttk.Label(
            self,
            text=("Examples: risk:>=20  zone:iot  port:445  ip:192.168.1.0/24 "
                  "-zone:server  name:nas OR vendor:ubiquiti"),
            foreground="#7896b1",
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(self, textvariable=self.summary, foreground="#7ed6a5").pack(fill="x", pady=(0, 8))
        panes = ttk.Panedwindow(self, orient="vertical")
        panes.pack(fill="both", expand=True)
        table_frame = ttk.Frame(panes)
        detail_frame = ttk.Frame(panes, padding=(0, 9, 0, 0))
        panes.add(table_frame, weight=4)
        panes.add(detail_frame, weight=2)

        columns = ("risk", "level", "zone", "address", "name", "identity", "services", "factors")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        widths = (55, 75, 105, 125, 150, 150, 235, 350)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.title())
            self.table.column(column, width=width, minwidth=50, anchor="w")
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self.table.pack(fill="both", expand=True)
        self.table.tag_configure("critical", foreground="#ff7b7b")
        self.table.tag_configure("high", foreground="#ffb16b")
        self.table.tag_configure("medium", foreground="#f3d56b")
        self.table.tag_configure("low", foreground="#83dfa9")
        self.table.bind("<<TreeviewSelect>>", self._show_detail)

        ttk.Label(detail_frame, text="Explainable assessment", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.detail = tk.Text(detail_frame, height=8, wrap="word", bg="#0d1b29", fg="#c7d8e8",
                              insertbackground="#ffffff", relief="flat", padx=10, pady=8)
        self.detail.pack(fill="both", expand=True, pady=(5, 0))
        self.detail.configure(state="disabled")

    def _clear_query(self) -> None:
        self.query.set("")
        self.apply_query()

    def refresh(self, hosts: Iterable[Host] | None = None) -> None:
        self.items = analyse_hosts(list(self.hosts() if hosts is None else hosts))
        self.apply_query()

    def apply_query(self) -> None:
        try:
            self.visible = filter_insights(self.items, self.query.get().strip())
        except ValueError as error:
            self.summary.set(str(error))
            return
        self.rows.clear()
        self.table.delete(*self.table.get_children())
        for item in self.visible:
            services = ", ".join(f"{name or 'tcp'}:{port}" for name, port in
                                 zip(item.host.services, item.host.ports)) or "None observed"
            identity = item.host.mac or item.host.identity
            factors = "; ".join(item.factors)
            row = self.table.insert("", "end", values=(item.risk_score, item.risk_level,
                item.zone, item.host.address, item.host.hostname or "Unresolved", identity,
                services, factors), tags=(item.risk_level.casefold(),))
            self.rows[row] = item
        duplicates = sum(item.duplicate_count for item in self.items)
        elevated = sum(item.risk_score >= 20 for item in self.visible)
        self.summary.set(f"{len(self.visible)} of {len(self.items)} resolved devices - "
                         f"{elevated} elevated - {duplicates} duplicate observations merged")

    def _show_detail(self, _event=None) -> None:
        selected = self.table.selection()
        if not selected:
            return
        item = self.rows[selected[0]]
        lines = [f"{item.host.hostname or item.host.address} - {item.risk_level} ({item.risk_score}/100)",
                 f"Zone: {item.zone}", "", "Why this score:",
                 *(f"  - {factor}" for factor in item.factors), "",
                 "This is an exposure-priority score from observed metadata, not proof of compromise."]
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", "\n".join(lines))
        self.detail.configure(state="disabled")

    def export_json(self) -> None:
        if not self.visible:
            messagebox.showinfo("Nothing to export", "Run or import a scan first.", parent=self)
            return
        selected = filedialog.asksaveasfilename(parent=self, defaultextension=".json",
            filetypes=(("Intelligence JSON", "*.json"),), initialfile="network-intelligence.json")
        if selected:
            export_intelligence_json(Path(selected), self.visible, self.query.get().strip())
            messagebox.showinfo("Export complete", "The local intelligence report was saved.", parent=self)

    def export_graph(self) -> None:
        if not self.visible:
            messagebox.showinfo("Nothing to export", "Run or import a scan first.", parent=self)
            return
        selected = filedialog.asksaveasfilename(parent=self, defaultextension=".graphml",
            filetypes=(("GraphML network", "*.graphml"),), initialfile="network-dependencies.graphml")
        if selected:
            export_graphml(Path(selected), self.visible)
            messagebox.showinfo("Export complete", "The portable GraphML network was saved.", parent=self)
