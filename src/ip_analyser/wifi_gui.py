from __future__ import annotations

import queue
import shutil
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .packet_tools import CaptureSession, start_monitor_capture
from .monitoring import enforce_capture_retention
from .wifi_tools import (AccessPoint, WifiClient, analyze_wifi_capture,
                         create_monitor_interface, list_wireless_interfaces,
                         remove_monitor_interface, save_wifi_report,
                         start_channel_hopper)


DEFAULT_CHANNELS = "1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165"


class WifiWatch(tk.Toplevel):
    def __init__(self, parent: tk.Misc):
        super().__init__(parent)
        self.title("Passive Wi-Fi Watch · Advanced IP Analyser")
        self.geometry("1180x700")
        self.minsize(820, 520)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.monitor_interface = ""
        self.capture: CaptureSession | None = None
        self.hopper = None
        self.capture_path: Path | None = None
        self.access_points: list[AccessPoint] = []
        self.unlinked_clients: list[WifiClient] = []
        self.ap_by_item: dict[str, AccessPoint] = {}
        self.events: queue.Queue = queue.Queue()
        self.worker_active = False
        self.data_dir = Path.home() / ".local" / "share" / "advanced-ip-analyser" / "wifi-captures"
        self._build()
        self._load_interfaces()
        self.after(200, self._drain_events)

    def _build(self) -> None:
        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text="Passive Wi-Fi Watch",
                  font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Label(header, text="Adapter").pack(side="left", padx=(24, 4))
        self.interface = ttk.Combobox(header, width=17, state="readonly")
        self.interface.pack(side="left")
        ttk.Label(header, text="Duration").pack(side="left", padx=(12, 4))
        self.duration = ttk.Combobox(header, width=12, state="readonly",
                                     values=("5 minutes", "15 minutes", "1 hour"))
        self.duration.set("15 minutes")
        self.duration.pack(side="left")
        self.start_button = ttk.Button(header, text="Start passive watch",
                                       command=self.start, style="Accent.TButton")
        self.start_button.pack(side="left", padx=(12, 4))
        self.stop_button = ttk.Button(header, text="Stop", command=self.stop,
                                      state="disabled", style="Danger.TButton")
        self.stop_button.pack(side="left")

        options = ttk.Frame(self, padding=(12, 0, 12, 8))
        options.pack(fill="x")
        ttk.Label(options, text="Channels").pack(side="left")
        self.channels = ttk.Entry(options)
        self.channels.insert(0, DEFAULT_CHANNELS)
        self.channels.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(options, text="Save capture…", command=self.save_capture).pack(side="left")
        ttk.Button(options, text="Save JSON report…", command=self.save_report).pack(side="left", padx=(8, 0))

        note = ttk.Label(self, padding=(12, 0, 12, 8),
                         text="Passive discovery only: this feature does not disconnect clients, inject packets, or attempt passwords.")
        note.pack(fill="x")

        panes = ttk.Panedwindow(self, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=12)
        ap_frame = ttk.Frame(panes)
        client_frame = ttk.Frame(panes)
        panes.add(ap_frame, weight=3)
        panes.add(client_frame, weight=2)

        ap_columns = ("name", "bssid", "channel", "signal", "security",
                      "beacons", "data", "clients", "handshake")
        self.ap_table = ttk.Treeview(ap_frame, columns=ap_columns, show="headings", selectmode="browse")
        ap_widths = (180, 150, 65, 65, 110, 75, 75, 65, 90)
        for column, width in zip(ap_columns, ap_widths):
            self.ap_table.heading(column, text=column.title())
            self.ap_table.column(column, width=width, anchor="w", stretch=column == "name")
        self.ap_table.pack(fill="both", expand=True)
        self.ap_table.bind("<<TreeviewSelect>>", self._show_clients)

        ttk.Label(client_frame, text="Observed clients and probe requests",
                  padding=(8, 0, 8, 6)).pack(anchor="w")
        client_columns = ("mac", "signal", "packets", "probes")
        self.client_table = ttk.Treeview(client_frame, columns=client_columns, show="headings")
        for column, width in zip(client_columns, (155, 70, 70, 300)):
            self.client_table.heading(column, text=column.title())
            self.client_table.column(column, width=width, anchor="w", stretch=column == "probes")
        self.client_table.pack(fill="both", expand=True)

        footer = ttk.Frame(self, padding=12)
        footer.pack(fill="x")
        self.status = ttk.Label(footer, text="Select a monitor-capable Wi-Fi adapter.")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=240,
                                        style="Green.Horizontal.TProgressbar")
        self.progress.pack(side="right")

    def _load_interfaces(self) -> None:
        interfaces = list_wireless_interfaces()
        self.interface.configure(values=interfaces)
        if interfaces:
            self.interface.set(interfaces[0])
        else:
            self.status.configure(text="No Linux wireless interface was detected.")
            self.start_button.configure(state="disabled")

    def _channel_plan(self) -> list[int]:
        values = []
        for part in self.channels.get().split(","):
            part = part.strip()
            if not part:
                continue
            value = int(part)
            if not 1 <= value <= 233 or value in values:
                raise ValueError("channels must be unique numbers from 1 to 233")
            values.append(value)
        if not values or len(values) > 128:
            raise ValueError("choose from 1 to 128 wireless channels")
        return values

    def start(self) -> None:
        seconds = {"5 minutes": 300, "15 minutes": 900, "1 hour": 3_600}[self.duration.get()]
        try:
            channels = self._channel_plan()
        except ValueError as error:
            messagebox.showerror("Invalid channels", str(error), parent=self)
            return
        if not messagebox.askyesno(
                "Start passive Wi-Fi Watch",
                "Create a temporary monitor interface and passively observe nearby Wi-Fi management and data headers?\n\n"
                "The adapter must support monitor mode. Debian will request administrator authorization. "
                "Only monitor wireless networks and radio traffic you are authorized to inspect.", parent=self):
            return
        try:
            self.monitor_interface = create_monitor_interface(self.interface.get())
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.capture = start_monitor_capture(self.monitor_interface, seconds, snaplen=1024,
                                                 cache_dir=self.data_dir, linktype=127)
            self.capture_path = self.capture.path
            self.hopper = start_channel_hopper(self.monitor_interface, channels, seconds)
        except (OSError, RuntimeError, ValueError) as error:
            cleanup_detail = ""
            if self.capture:
                self.capture.stop()
            if self.monitor_interface:
                try:
                    remove_monitor_interface(self.monitor_interface)
                except (OSError, RuntimeError, ValueError) as cleanup_error:
                    cleanup_detail = f"\n\nTemporary monitor cleanup also failed: {cleanup_error}"
            self.monitor_interface = ""
            messagebox.showerror("Wi-Fi Watch could not start", str(error) + cleanup_detail, parent=self)
            return
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress.start(10)
        self.status.configure(text=f"Passively watching on {self.monitor_interface}…")
        self._schedule_refresh()

    def _schedule_refresh(self) -> None:
        if self.capture_path and self.capture_path.exists() and not self.worker_active:
            self.worker_active = True
            threading.Thread(target=self._worker, args=(self.capture_path,), daemon=True).start()
        if self.capture and self.capture.running:
            self.after(3_000, self._schedule_refresh)
        else:
            self.after(200, self.stop)

    def _worker(self, path: Path) -> None:
        try:
            aps, clients = analyze_wifi_capture(path)
            self.events.put(("analysis", aps, clients))
        except (OSError, ValueError) as error:
            self.events.put(("error", str(error)))

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                self.worker_active = False
                if event[0] == "analysis":
                    self.access_points, self.unlinked_clients = event[1], event[2]
                    self._refresh_tables()
                else:
                    self.status.configure(text=f"Wireless analysis waiting: {event[1]}")
        except queue.Empty:
            if self.winfo_exists():
                self.after(200, self._drain_events)

    def _refresh_tables(self) -> None:
        selected_bssid = ""
        selected = self.ap_table.selection()
        if selected and selected[0] in self.ap_by_item:
            selected_bssid = self.ap_by_item[selected[0]].bssid
        self.ap_table.delete(*self.ap_table.get_children())
        self.ap_by_item.clear()
        selected_item = ""
        for ap in self.access_points:
            item = self.ap_table.insert("", "end", values=(
                ap.name or "<hidden>", ap.bssid, ap.channel or "", ap.signal_dbm or "",
                ap.security, ap.beacons, ap.data_packets, len(ap.clients),
                "Observed" if ap.handshake_seen else ""))
            self.ap_by_item[item] = ap
            if ap.bssid == selected_bssid:
                selected_item = item
        if selected_item:
            self.ap_table.selection_set(selected_item)
        self.status.configure(text=f"Observed {len(self.access_points)} access points and "
                                   f"{sum(len(ap.clients) for ap in self.access_points) + len(self.unlinked_clients)} clients")
        self._show_clients()

    def _show_clients(self, _event=None) -> None:
        clients = list(self.unlinked_clients)
        selected = self.ap_table.selection()
        if selected and selected[0] in self.ap_by_item:
            clients = list(self.ap_by_item[selected[0]].clients.values())
        self.client_table.delete(*self.client_table.get_children())
        for client in clients:
            self.client_table.insert("", "end", values=(
                client.mac, client.signal_dbm or "", client.packets,
                ", ".join(sorted(client.probes))))

    def stop(self) -> None:
        if self.capture and self.capture.running:
            self.capture.stop()
        if self.hopper and self.hopper.poll() is None:
            self.hopper.terminate()
            try:
                self.hopper.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.hopper.kill()
        cleanup_error = ""
        if self.monitor_interface:
            try:
                remove_monitor_interface(self.monitor_interface)
            except (OSError, RuntimeError, ValueError) as error:
                cleanup_error = str(error)
        self.monitor_interface = ""
        self.progress.stop()
        self.start_button.configure(state="normal" if self.interface.get() else "disabled")
        self.stop_button.configure(state="disabled")
        if self.capture_path and self.capture_path.exists() and not self.worker_active:
            self.worker_active = True
            threading.Thread(target=self._worker, args=(self.capture_path,), daemon=True).start()
        try:
            enforce_capture_retention(self.data_dir, days=7,
                                      protected=[self.capture_path] if self.capture_path else [])
        except OSError as error:
            cleanup_error = cleanup_error or f"recording retention failed: {error}"
        self.status.configure(text=(f"Stopped; cleanup warning: {cleanup_error}" if cleanup_error
                                    else "Passive Wi-Fi Watch stopped; recording retained locally."))

    def save_capture(self) -> None:
        if not self.capture_path or not self.capture_path.is_file():
            messagebox.showinfo("No capture", "Start Wi-Fi Watch first.", parent=self)
            return
        name = filedialog.asksaveasfilename(parent=self, defaultextension=".pcap",
                                            filetypes=[("PCAP capture", "*.pcap")])
        if name:
            try:
                shutil.copyfile(self.capture_path, name)
            except OSError as error:
                messagebox.showerror("Save failed", str(error), parent=self)

    def save_report(self) -> None:
        if not self.access_points and not self.unlinked_clients:
            messagebox.showinfo("No results", "No wireless observations are available yet.", parent=self)
            return
        name = filedialog.asksaveasfilename(parent=self, defaultextension=".json",
                                            filetypes=[("JSON report", "*.json")])
        if name:
            try:
                save_wifi_report(Path(name), self.access_points, self.unlinked_clients)
            except OSError as error:
                messagebox.showerror("Report failed", str(error), parent=self)

    def close(self) -> None:
        if self.capture and self.capture.running:
            if not messagebox.askyesno("Stop Wi-Fi Watch", "Stop passive Wi-Fi Watch and close?", parent=self):
                return
            self.stop()
        elif self.monitor_interface:
            self.stop()
        self.destroy()
