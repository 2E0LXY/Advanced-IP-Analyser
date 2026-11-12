"""Live connection table and privacy-preserving destination map."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .connections import (ConnectionRecord, GeoLocation, export_connections,
                          is_public_address, locate_address, snapshot_connections)
from .slippy_map import MapMarker, SlippyMap


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

        map_heading = ttk.Frame(map_frame)
        map_heading.pack(fill="x", pady=(8, 4))
        ttk.Label(map_heading, text="Destination map · public remote endpoints only",
                  font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(map_heading, text="?", width=3, command=self._show_map_help).pack(side="left", padx=6)
        self.map_status = ttk.Label(map_heading, text="No public destinations yet", foreground="#90abc4")
        self.map_status.pack(side="left")
        ttk.Button(map_heading, text="Fit destinations", command=self._fit_map).pack(side="right")
        ttk.Button(map_heading, text="−", width=3, command=lambda: self.map.zoom_by(-1)).pack(side="right", padx=3)
        ttk.Button(map_heading, text="+", width=3, command=lambda: self.map.zoom_by(1)).pack(side="right")
        ttk.Label(map_heading, text="Drag to move · wheel to zoom", foreground="#90abc4").pack(side="right", padx=10)
        self.map = SlippyMap(map_frame, height=245, on_marker_click=self._show_marker_details)
        self.map.pack(fill="both", expand=True)
        ttk.Label(map_frame,
                  text="Map © OpenStreetMap contributors. Locations are approximate; only public remote IPs are sent to ipwho.is while monitoring is active.",
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
        markers: list[MapMarker] = []
        grouped: dict[str, list[ConnectionRecord]] = {}
        for record in self._filtered_records():
            if record.remote_address:
                grouped.setdefault(record.remote_address, []).append(record)
        for address, records in grouped.items():
            location = self.locations.get(address)
            if not location or location.latitude is None or location.longitude is None:
                continue
            markers.append(MapMarker(
                location.latitude, location.longitude,
                location.city or location.country or address,
                address,
                "#ffad4f" if any(record.direction == "Inbound" for record in records) else "#31b8ff",
                tuple(records),
            ))
        self.map.set_markers(markers)
        self.map_status.configure(
            text=f"{len(markers)} mapped public destination{'s' if len(markers) != 1 else ''}")

    def _show_marker_details(self, markers: list[MapMarker]) -> None:
        """Show every currently available process and endpoint detail for a pin/cluster."""
        records = [record for marker in markers for record in marker.payload
                   if isinstance(record, ConnectionRecord)]
        if not records:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Destination connection details")
        dialog.transient(self.winfo_toplevel())
        dialog.geometry("1180x560")
        dialog.minsize(820, 420)
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)
        addresses = list(dict.fromkeys(marker.address for marker in markers))
        ttk.Label(body, text=(addresses[0] if len(addresses) == 1 else
                             f"{len(addresses)} grouped public destinations"),
                  font=("Segoe UI", 18, "bold")).pack(anchor="w")
        location_lines = []
        for address in addresses:
            location = self.locations.get(address, GeoLocation(address))
            coordinates = (f"{location.latitude:.5f}, {location.longitude:.5f}"
                           if location.latitude is not None and location.longitude is not None else "coordinates unavailable")
            location_lines.append(f"{address} · {location.label} · {coordinates}")
        ttk.Label(body, text="\n".join(location_lines), foreground="#86bde9",
                  wraplength=1120).pack(anchor="w", fill="x", pady=(3, 10))

        frame = ttk.Frame(body)
        frame.pack(fill="both", expand=True)
        columns = ("time", "application", "pid", "executable", "direction", "protocol",
                   "local", "remote", "state", "organisation_location")
        table = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        widths = (75, 140, 65, 270, 85, 65, 175, 175, 95, 340)
        for column, width in zip(columns, widths):
            table.heading(column, text=column.replace("_", " ").title())
            table.column(column, width=width, anchor="w")
        for record in records:
            location = self.locations.get(record.remote_address, GeoLocation(record.remote_address))
            table.insert("", "end", values=(
                record.observed_at, record.application, record.pid or "—", record.executable or "Unavailable",
                record.direction, record.protocol, f"{record.local_address}:{record.local_port}",
                f"{record.remote_address}:{record.remote_port}", record.state, location.label,
            ))
        vertical = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=table.xview)
        table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        table.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        footer = ttk.Frame(body)
        footer.pack(fill="x", pady=(10, 0))
        ttk.Label(footer, text=(
            "Application and PID come from the local OS. Location normally identifies a provider/data centre, not a person."),
            foreground="#90abc4").pack(side="left")
        ttk.Button(footer, text="Close", command=dialog.destroy).pack(side="right")
        ttk.Button(footer, text="Copy all details",
                   command=lambda: self._copy_marker_details(records)).pack(side="right", padx=(0, 8))
        dialog.bind("<Escape>", lambda _event: dialog.destroy())

    def _copy_marker_details(self, records: list[ConnectionRecord]) -> None:
        lines = []
        for record in records:
            location = self.locations.get(record.remote_address, GeoLocation(record.remote_address))
            lines.append(
                f"{record.observed_at}\t{record.application}\tPID {record.pid or '—'}\t{record.executable or 'Unavailable'}\t"
                f"{record.direction}\t{record.protocol}\t{record.local_address}:{record.local_port}\t"
                f"{record.remote_address}:{record.remote_port}\t{record.state}\t{location.label}")
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def _fit_map(self) -> None:
        self.map.fit_markers()

    def _show_map_help(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Destination map help")
        dialog.transient(self.winfo_toplevel())
        dialog.resizable(True, True)
        dialog.minsize(520, 460)
        body = ttk.Frame(dialog, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Destination map", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        help_text = (
            "WHAT IT DOES\n"
            "Shows the approximate geographic destination of public remote IP addresses in the "
            "Live Connections table. Blue markers are outbound connections and orange markers are "
            "inbound connections. A numbered marker combines nearby or overlapping endpoints.\n\n"
            "HOW TO USE IT\n"
            "• Start monitoring and wait for public destinations to be located.\n"
            "• Drag the map with the left mouse button to move it.\n"
            "• Use the mouse wheel or + and − buttons to zoom.\n"
            "• Select Fit destinations to bring all current markers back into view.\n"
            "• Click a marker or numbered cluster to open all available application, executable, "
            "PID, direction, protocol, endpoint, state, organisation and location details.\n"
            "• Use the table filter to limit both the rows and the markers shown.\n\n"
            "HOW IT WORKS\n"
            "The app reads the operating system's current TCP and UDP endpoint table. Public remote "
            "IP addresses are looked up through ipwho.is for approximate latitude, longitude, city and "
            "network-provider information. Map tiles are then downloaded from OpenStreetMap. Private, "
            "loopback, link-local and listening-only addresses are never sent for geolocation.\n\n"
            "WHY IT DOES IT\n"
            "The map makes unusual destinations, unexpected international traffic and groups of "
            "connections easier to notice than in a long endpoint table. It is an investigation aid, "
            "not proof that a connection is malicious.\n\n"
            "PRIVACY AND LIMITS\n"
            "Geolocation is approximate and often identifies a provider or data centre rather than a "
            "person or device. While monitoring, public destination IPs go to ipwho.is and visible map "
            "tile coordinates go to OpenStreetMap. The app does not upload process names, PIDs, local "
            "addresses or the complete connection table to either service."
        )
        text = tk.Text(body, wrap="word", height=24, width=74, relief="flat", borderwidth=0,
                       background="#102336", foreground="#dcecff", insertbackground="#dcecff",
                       font=("Segoe UI", 10), padx=12, pady=12)
        text.insert("1.0", help_text)
        text.configure(state="disabled")
        text.pack(fill="both", expand=True, pady=(12, 12))
        ttk.Button(body, text="Close", command=dialog.destroy).pack(anchor="e")
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.grab_set()

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
