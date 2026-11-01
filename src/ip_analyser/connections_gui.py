"""Live connection table and privacy-preserving destination map."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .connections import (ConnectionRecord, GeoLocation, export_connections,
                          is_public_address, locate_address, snapshot_connections)


class ConnectionMonitorView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.running = False
        self.worker_active = False
        self.records: list[ConnectionRecord] = []
        self.locations: dict[str, GeoLocation] = {}
        self.pending_locations: set[str] = set()
        self.process_cache: dict[int, tuple[str, str]] = {}
        self.events: queue.Queue = queue.Queue()
        self.search_text = tk.StringVar()
        self._build()
        self.after(100, self._drain_events)

    def _build(self) -> None:
        heading = ttk.Frame(self, padding=(10, 12, 10, 8))
        heading.pack(fill="x")
        title = ttk.Frame(heading)
        title.pack(side="left", fill="x", expand=True)
        ttk.Label(title, text="Live Connections", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        ttk.Label(title, text="See inbound, outbound and listening endpoints, the owning process and destination.",
                  foreground="#90abc4").pack(anchor="w")
        self.toggle_button = ttk.Button(heading, text="Start monitoring", style="Accent.TButton",
                                        command=self.toggle)
        self.toggle_button.pack(side="right")
        ttk.Button(heading, text="Refresh", command=self.refresh_once).pack(side="right", padx=(0, 8))
        ttk.Button(heading, text="Export…", command=self.export).pack(side="right", padx=(0, 8))

        filters = ttk.Frame(self, padding=(10, 0, 10, 8))
        filters.pack(fill="x")
        ttk.Label(filters, text="Filter").pack(side="left")
        entry = ttk.Entry(filters, textvariable=self.search_text)
        entry.pack(side="left", fill="x", expand=True, padx=(8, 12))
        entry.bind("<KeyRelease>", lambda _event: self._render())
        self.status = ttk.Label(filters, text="Stopped · location lookup starts only while monitoring")
        self.status.pack(side="right")

        pane = ttk.Panedwindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        table_frame = ttk.Frame(pane)
        map_frame = ttk.Frame(pane)
        pane.add(table_frame, weight=3)
        pane.add(map_frame, weight=2)

        columns = ("time", "direction", "application", "pid", "protocol", "local", "remote", "state", "destination")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        widths = (75, 80, 155, 65, 65, 180, 180, 95, 300)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.title())
            self.table.column(column, width=width, anchor="w", stretch=column in {"application", "destination"})
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1); table_frame.columnconfigure(0, weight=1)

        ttk.Label(map_frame, text="Destination map · public remote endpoints only",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(8, 4))
        self.map = tk.Canvas(map_frame, height=245, bg="#07131f", highlightthickness=1,
                             highlightbackground="#2c4860")
        self.map.pack(fill="both", expand=True)
        self.map.bind("<Configure>", lambda _event: self._draw_map())
        ttk.Label(map_frame,
                  text="Endpoint geolocation is approximate. Only public remote IPs are sent to ipwho.is while monitoring is active.",
                  foreground="#90abc4").pack(anchor="w", pady=(4, 0))

    def toggle(self) -> None:
        self.running = not self.running
        self.toggle_button.configure(text="Stop monitoring" if self.running else "Start monitoring")
        if self.running:
            self.status.configure(text="Starting…")
            self.refresh_once()
        else:
            self.status.configure(text="Stopped")

    def refresh_once(self) -> None:
        if self.worker_active:
            return
        self.worker_active = True
        threading.Thread(target=self._snapshot_worker, daemon=True).start()

    def _snapshot_worker(self) -> None:
        try:
            self.events.put(("snapshot", snapshot_connections(self.process_cache)))
        except Exception as error:
            self.events.put(("error", str(error)))

    def _locate_worker(self, address: str) -> None:
        try:
            location = locate_address(address)
        except Exception:
            location = GeoLocation(address)
        self.events.put(("location", location))

    def _drain_events(self) -> None:
        try:
            while True:
                event, value = self.events.get_nowait()
                if event == "snapshot":
                    self.worker_active = False
                    self.records = value
                    public = {record.remote_address for record in self.records
                              if record.remote_address and is_public_address(record.remote_address)}
                    for address in sorted(public - self.locations.keys() - self.pending_locations)[:12]:
                        self.pending_locations.add(address)
                        threading.Thread(target=self._locate_worker, args=(address,), daemon=True).start()
                    self.status.configure(text=f"Live · {len(self.records):,} current endpoints · refreshes every 2 seconds")
                    self._render()
                    if self.running:
                        self.after(2000, self.refresh_once)
                elif event == "location":
                    self.pending_locations.discard(value.address)
                    self.locations[value.address] = value
                    self._render()
                elif event == "error":
                    self.worker_active = False
                    self.running = False
                    self.toggle_button.configure(text="Start monitoring")
                    self.status.configure(text=value)
        except queue.Empty:
            pass
        self.after(150, self._drain_events)

    def _filtered_records(self) -> list[ConnectionRecord]:
        needle = self.search_text.get().strip().casefold()
        if not needle:
            return self.records
        return [record for record in self.records if needle in " ".join((
            record.direction, record.application, str(record.pid or ""), record.protocol,
            record.local_address, str(record.local_port), record.remote_address,
            str(record.remote_port), record.state,
            self.locations.get(record.remote_address, GeoLocation("")).label,
        )).casefold()]

    def _render(self) -> None:
        self.table.delete(*self.table.get_children())
        for record in self._filtered_records():
            local = f"{record.local_address}:{record.local_port}"
            remote = f"{record.remote_address}:{record.remote_port}" if record.remote_address else "—"
            location = self.locations.get(record.remote_address)
            self.table.insert("", "end", values=(
                record.observed_at, record.direction, record.application, record.pid or "—",
                record.protocol, local, remote, record.state,
                location.label if location else ("Locating…" if record.remote_address and
                                                  is_public_address(record.remote_address) else "Private / local"),
            ), tags=(record.direction.casefold(),))
        self.table.tag_configure("outbound", foreground="#66c7ff")
        self.table.tag_configure("inbound", foreground="#ffb45c")
        self.table.tag_configure("listening", foreground="#a9bfd4")
        self._draw_map()

    def _draw_map(self) -> None:
        canvas = self.map
        canvas.delete("all")
        width, height = max(canvas.winfo_width(), 400), max(canvas.winfo_height(), 180)
        for longitude in range(-180, 181, 30):
            x = (longitude + 180) / 360 * width
            canvas.create_line(x, 0, x, height, fill="#173149")
        for latitude in range(-60, 61, 30):
            y = (90 - latitude) / 180 * height
            canvas.create_line(0, y, width, y, fill="#173149")
        plotted: set[str] = set()
        for record in self._filtered_records():
            location = self.locations.get(record.remote_address)
            if (not location or location.latitude is None or location.longitude is None or
                    record.remote_address in plotted):
                continue
            plotted.add(record.remote_address)
            x = (location.longitude + 180) / 360 * width
            y = (90 - location.latitude) / 180 * height
            colour = "#ffad4f" if record.direction == "Inbound" else "#31b8ff"
            canvas.create_oval(x - 5, y - 5, x + 5, y + 5, fill=colour, outline="#ffffff")
            canvas.create_text(x + 8, y, text=location.city or location.country or record.remote_address,
                               fill="#dcecff", anchor="w", font=("Segoe UI", 8))
        canvas.create_text(10, 10, text=f"{len(plotted)} mapped public destination(s)",
                           fill="#8fb4d4", anchor="nw")

    def export(self) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self, defaultextension=".csv", initialfile="live-connections.csv",
            filetypes=[("CSV table", "*.csv"), ("JSON data", "*.json")])
        if not destination:
            return
        try:
            export_connections(Path(destination), self._filtered_records(), self.locations)
        except OSError as error:
            messagebox.showerror("Export failed", str(error), parent=self)
