from __future__ import annotations

import queue
import shutil
import subprocess
import threading
import time
import tkinter as tk
from collections import defaultdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .packet_tools import CaptureSession, start_monitor_capture
from .monitoring import enforce_capture_retention
from .wifi_tools import (AccessPoint, WifiClient, analyze_wifi_capture,
                         append_wifi_history, compare_wifi_history,
                         create_monitor_interface, list_wireless_interfaces,
                         enrich_wifi_vendors, remove_monitor_interface, save_wifi_report,
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
        self.history_path = self.data_dir / "wifi-scan-history.jsonl"
        self.history_logged = False
        self.signal_history: dict[str, list[tuple[float, int, str]]] = defaultdict(list)
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
                                     values=("5 minutes", "15 minutes", "1 hour", "2 hours"))
        self.duration.set("15 minutes")
        self.duration.pack(side="left")
        self.start_button = ttk.Button(header, text="Start passive watch",
                                       command=self.start, style="Accent.TButton")
        self.start_button.pack(side="left", padx=(12, 4))
        self.stop_button = ttk.Button(header, text="Stop", command=self.stop,
                                      state="disabled", style="Danger.TButton")
        self.stop_button.pack(side="left")
        ttk.Label(header, text="Refresh").pack(side="left", padx=(12, 4))
        self.refresh_seconds = tk.IntVar(value=3)
        ttk.Combobox(header, width=3, state="readonly", textvariable=self.refresh_seconds,
                     values=(1, 2, 3, 4, 5)).pack(side="left")
        ttk.Label(header, text="sec").pack(side="left")

        options = ttk.Frame(self, padding=(12, 0, 12, 8))
        options.pack(fill="x")
        ttk.Label(options, text="Channels").pack(side="left")
        self.channels = ttk.Entry(options)
        self.channels.insert(0, DEFAULT_CHANNELS)
        self.channels.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(options, text="Save capture…", command=self.save_capture).pack(side="left")
        ttk.Button(options, text="Save report…", command=self.save_report).pack(side="left", padx=(8, 0))
        ttk.Button(options, text="Compare recent scans…", command=self.compare_scans).pack(side="left", padx=(8, 0))

        note = ttk.Label(self, padding=(12, 0, 12, 8),
                         text="Passive discovery only: this feature does not disconnect clients, inject packets, or attempt passwords.")
        note.pack(fill="x")

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=12)
        overview = ttk.Frame(tabs)
        history_page = ttk.Frame(tabs, padding=8)
        channels_page = ttk.Frame(tabs, padding=8)
        tabs.add(overview, text="Observed networks")
        tabs.add(history_page, text="Signal history")
        tabs.add(channels_page, text="Channel graph")
        panes = ttk.Panedwindow(overview, orient="horizontal")
        panes.pack(fill="both", expand=True)
        ap_frame = ttk.Frame(panes)
        client_frame = ttk.Frame(panes)
        panes.add(ap_frame, weight=4)
        panes.add(client_frame, weight=2)

        ap_columns = ("name", "bssid", "manufacturer", "channel", "bandwidth", "signal", "security",
                      "wps", "risk", "beacons", "data", "clients", "eapol", "findings")
        self.ap_table = ttk.Treeview(ap_frame, columns=ap_columns, show="headings", selectmode="browse")
        ap_widths = (150, 140, 170, 55, 80, 55, 90, 50, 80, 60, 60, 55, 70, 320)
        for column, width in zip(ap_columns, ap_widths):
            self.ap_table.heading(column, text=column.title())
            self.ap_table.column(column, width=width, anchor="w", stretch=column == "name")
        ap_scroll = ttk.Scrollbar(ap_frame, orient="horizontal", command=self.ap_table.xview)
        self.ap_table.configure(xscrollcommand=ap_scroll.set)
        self.ap_table.pack(fill="both", expand=True)
        ap_scroll.pack(fill="x")
        self.ap_table.bind("<<TreeviewSelect>>", self._show_clients)

        ttk.Label(client_frame, text="Observed clients and probe requests",
                  padding=(8, 0, 8, 6)).pack(anchor="w")
        client_columns = ("mac", "signal", "packets", "probes")
        self.client_table = ttk.Treeview(client_frame, columns=client_columns, show="headings")
        for column, width in zip(client_columns, (135, 55, 55, 180)):
            self.client_table.heading(column, text=column.title())
            self.client_table.column(column, width=width, anchor="w", stretch=column == "probes")
        client_scroll = ttk.Scrollbar(client_frame, orient="horizontal",
                                      command=self.client_table.xview)
        self.client_table.configure(xscrollcommand=client_scroll.set)
        self.client_table.pack(fill="both", expand=True)
        client_scroll.pack(fill="x")
        self._build_analysis_pages(history_page, channels_page)

        footer = ttk.Frame(self, padding=12)
        footer.pack(fill="x")
        self.status = ttk.Label(footer, text="Select a monitor-capable Wi-Fi adapter.")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=240,
                                        style="Green.Horizontal.TProgressbar")
        self.progress.pack(side="right")

    def _build_analysis_pages(self, history_page: ttk.Frame, channels_page: ttk.Frame) -> None:
        history_actions = ttk.Frame(history_page)
        history_actions.pack(fill="x", pady=(0, 6))
        ttk.Label(history_actions, text="Retains up to two hours; use the bottom scrollbar for earlier samples.").pack(side="left")
        ttk.Button(history_actions, text="Clear", command=self._clear_signal_history).pack(side="right")
        history_frame = ttk.Frame(history_page)
        history_frame.pack(fill="both", expand=True)
        self.history_canvas = tk.Canvas(history_frame, background="#08131f", highlightthickness=0)
        history_x = ttk.Scrollbar(history_frame, orient="horizontal", command=self.history_canvas.xview)
        self.history_canvas.configure(xscrollcommand=history_x.set)
        self.history_canvas.pack(fill="both", expand=True)
        history_x.pack(fill="x")
        self.history_canvas.bind("<Configure>", lambda _event: self._draw_signal_history())

        channel_actions = ttk.Frame(channels_page)
        channel_actions.pack(fill="x", pady=(0, 6))
        self.channel_band = tk.StringVar(value="2.4 GHz")
        ttk.Label(channel_actions, text="Band").pack(side="left")
        selector = ttk.Combobox(channel_actions, textvariable=self.channel_band,
                                values=("2.4 GHz", "5 GHz", "6 GHz"), width=8, state="readonly")
        selector.pack(side="left", padx=6)
        selector.bind("<<ComboboxSelected>>", lambda _event: self._draw_channel_graph())
        ttk.Label(channel_actions, text="Curve width uses advertised HT/VHT radio metadata.").pack(side="left")
        self.channel_canvas = tk.Canvas(channels_page, background="#08131f", highlightthickness=0)
        self.channel_canvas.pack(fill="both", expand=True)
        self.channel_canvas.bind("<Configure>", lambda _event: self._draw_channel_graph())

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
        seconds = {"5 minutes": 300, "15 minutes": 900, "1 hour": 3_600,
                   "2 hours": 7_200}[self.duration.get()]
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
        self.history_logged = False
        self.status.configure(text=f"Passively watching on {self.monitor_interface}…")
        self._schedule_refresh()

    def _schedule_refresh(self) -> None:
        if self.capture_path and self.capture_path.exists() and not self.worker_active:
            self.worker_active = True
            threading.Thread(target=self._worker, args=(self.capture_path,), daemon=True).start()
        if self.capture and self.capture.running:
            self.after(max(1, min(5, self.refresh_seconds.get())) * 1_000,
                       self._schedule_refresh)
        else:
            self.after(200, self.stop)

    def _worker(self, path: Path) -> None:
        try:
            aps, clients = analyze_wifi_capture(path)
            enrich_wifi_vendors(aps)
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
                    if (self.capture and not self.capture.running and self.access_points
                            and not self.history_logged):
                        try:
                            append_wifi_history(self.history_path, self.access_points)
                            self.history_logged = True
                        except OSError as error:
                            self.status.configure(text=f"Wi-Fi history could not be saved: {error}")
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
                ap.name or "<hidden>", ap.bssid, ap.manufacturer, ap.channel or "",
                f"{ap.channel_width_mhz} MHz" if ap.channel_width_mhz else "Unknown", ap.signal_dbm or "",
                ap.security, "Yes" if ap.wps_advertised else "", ap.risk_level,
                ap.beacons, ap.data_packets, len(ap.clients),
                "Observed" if ap.handshake_seen else "", "; ".join(ap.risk_reasons + ap.indicators)))
            self.ap_by_item[item] = ap
            if ap.bssid == selected_bssid:
                selected_item = item
        if selected_item:
            self.ap_table.selection_set(selected_item)
        indicator_count = sum(len(ap.indicators) for ap in self.access_points)
        self.status.configure(text=f"Observed {len(self.access_points)} access points and "
                                   f"{sum(len(ap.clients) for ap in self.access_points) + len(self.unlinked_clients)} clients"
                                   + (f" · {indicator_count} rogue-infrastructure indicator(s)" if indicator_count else ""))
        self._sample_signals()
        self._draw_signal_history()
        self._draw_channel_graph()
        self._show_clients()

    def _sample_signals(self) -> None:
        now = time.time()
        cutoff = now - 7_200
        for ap in self.access_points:
            if ap.signal_dbm is not None:
                self.signal_history[ap.bssid].append((now, ap.signal_dbm, ap.name or "<hidden>"))
        for bssid in list(self.signal_history):
            samples = self.signal_history[bssid]
            first = 0
            while first < len(samples) and samples[first][0] < cutoff:
                first += 1
            if first:
                del samples[:first]
            if not samples:
                del self.signal_history[bssid]

    def _clear_signal_history(self) -> None:
        self.signal_history.clear()
        self._draw_signal_history()
        self.status.configure(text="Signal history cleared.")

    def _draw_signal_history(self) -> None:
        canvas = getattr(self, "history_canvas", None)
        if canvas is None:
            return
        follow_latest = canvas.xview()[1] >= .98 if canvas.bbox("all") else True
        canvas.delete("all")
        view_width, height = max(640, canvas.winfo_width()), max(360, canvas.winfo_height())
        samples = [sample for values in self.signal_history.values() for sample in values]
        if not samples:
            canvas.create_text(view_width / 2, height / 2, text="Start passive watch to collect signal history",
                               fill="#9db3c8")
            canvas.configure(scrollregion=(0, 0, view_width, height))
            return
        start, end = min(item[0] for item in samples), max(item[0] for item in samples)
        scale = max(1.0, 6.0 / max(1, min(5, self.refresh_seconds.get())))
        strongest = sorted(self.signal_history.items(), key=lambda item: item[1][-1][1], reverse=True)[:12]
        legend_columns = max(2, int((view_width - 58) / 250))
        legend_rows = (len(strongest) + legend_columns - 1) // legend_columns
        left, top, bottom = 58, 24 + legend_rows * 18, height - 42
        width = max(view_width, left + (end - start) * scale + 80)
        for dbm in range(-100, -29, 10):
            y = top + (-30 - dbm) / 70 * (bottom - top)
            canvas.create_line(left, y, width - 20, y, fill="#284157")
            canvas.create_text(left - 8, y, text=str(dbm), fill="#9db3c8", anchor="e")
        colors = ("#22b8ff", "#56e05b", "#ffcc3d", "#ff6b6b", "#b884ff", "#31d6c4", "#ff8b3d")
        for index, (_bssid, values) in enumerate(strongest):
            color = colors[index % len(colors)]
            points = []
            for stamp, dbm, _name in values:
                points.extend((left + (stamp - start) * scale,
                               top + (-30 - max(-100, min(-30, dbm))) / 70 * (bottom - top)))
            if len(points) >= 4:
                canvas.create_line(*points, fill=color, width=2, smooth=True)
            legend_x = left + (index % legend_columns) * 250
            legend_y = 12 + (index // legend_columns) * 18
            canvas.create_text(legend_x, legend_y, text=values[-1][2][:32], fill=color, anchor="w")
        canvas.configure(scrollregion=(0, 0, width, height))
        if follow_latest:
            canvas.xview_moveto(1.0)

    def _draw_channel_graph(self) -> None:
        canvas = getattr(self, "channel_canvas", None)
        if canvas is None:
            return
        canvas.delete("all")
        width, height = max(640, canvas.winfo_width()), max(360, canvas.winfo_height())
        band = self.channel_band.get()
        if band == "2.4 GHz":
            low, high = 2400, 2500
        elif band == "5 GHz":
            low, high = 5000, 5900
        else:
            low, high = 5925, 7125
        left, right, top, bottom = 58, width - 24, 28, height - 38
        colors = ("#22b8ff", "#56e05b", "#ffcc3d", "#ff6b6b", "#b884ff", "#31d6c4")
        def frequency(ap: AccessPoint) -> int:
            if ap.frequency_mhz:
                return ap.frequency_mhz
            channel = ap.channel or 0
            if channel == 14:
                return 2484
            if channel <= 14:
                return 2407 + channel * 5
            return 5000 + channel * 5
        def x(value: float) -> float:
            return left + (value - low) / (high - low) * (right - left)
        def y(value: int) -> float:
            return top + (-30 - max(-100, min(-30, value))) / 70 * (bottom - top)
        for dbm in range(-100, -29, 10):
            canvas.create_line(left, y(dbm), right, y(dbm), fill="#284157")
            canvas.create_text(left - 8, y(dbm), text=str(dbm), fill="#9db3c8", anchor="e")
        shown = 0
        for ap in self.access_points:
            centre = frequency(ap)
            if not low <= centre <= high or ap.signal_dbm is None:
                continue
            radio_width = ap.channel_width_mhz or 4
            x1, peak, x2 = x(centre - radio_width / 2), x(centre), x(centre + radio_width / 2)
            color = colors[shown % len(colors)]
            canvas.create_polygon(x1, bottom, (x1 + peak) / 2, (bottom + y(ap.signal_dbm)) / 2,
                                  peak, y(ap.signal_dbm), (peak + x2) / 2,
                                  (bottom + y(ap.signal_dbm)) / 2, x2, bottom,
                                  fill=color, outline=color, stipple="gray50")
            detail = f"{ap.channel_width_mhz} MHz" if ap.channel_width_mhz else "width unavailable"
            canvas.create_text(peak, max(top, y(ap.signal_dbm) - 8),
                               text=f"{ap.name} · ch {ap.channel} · {detail}", fill=color, anchor="s")
            shown += 1
        if not shown:
            canvas.create_text(width / 2, height / 2, text=f"No {band} access points observed yet",
                               fill="#9db3c8")

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
        name = filedialog.asksaveasfilename(
            parent=self, defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("CSV report", "*.csv"),
                       ("JSON report", "*.json")])
        if name:
            try:
                save_wifi_report(Path(name), self.access_points, self.unlinked_clients)
            except (OSError, ValueError) as error:
                messagebox.showerror("Report failed", str(error), parent=self)

    def compare_scans(self) -> None:
        try:
            changes = compare_wifi_history(self.history_path)
        except (OSError, ValueError) as error:
            messagebox.showerror("Scan comparison failed", str(error), parent=self)
            return
        if not changes:
            messagebox.showinfo("Scan comparison", "Two saved Wi-Fi scan snapshots are required, or no differences were found.", parent=self)
            return
        window = tk.Toplevel(self)
        window.title("Recent Wi-Fi scan comparison")
        window.geometry("960x460")
        ttk.Label(window, text="Changes between the two most recent completed observations",
                  font=("TkDefaultFont", 13, "bold"), padding=12).pack(anchor="w")
        ttk.Label(window, text="Changes are observations to verify; range, channel timing, and adapter position can affect visibility.",
                  padding=(12, 0, 12, 8)).pack(anchor="w")
        columns = ("change", "network", "bssid", "detail")
        table = ttk.Treeview(window, columns=columns, show="headings")
        for column, width in zip(columns, (120, 180, 150, 470)):
            table.heading(column, text=column.title())
            table.column(column, width=width, anchor="w", stretch=column == "detail")
        for change in changes:
            table.insert("", "end", values=tuple(change[column] for column in columns))
        table.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def close(self) -> None:
        if self.capture and self.capture.running:
            if not messagebox.askyesno("Stop Wi-Fi Watch", "Stop passive Wi-Fi Watch and close?", parent=self):
                return
            self.stop()
        elif self.monitor_interface:
            self.stop()
        self.destroy()
