from __future__ import annotations

import csv
import os
import queue
import threading
import time
import tkinter as tk
from collections import defaultdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .windows_wifi import (NearbyWifiNetwork, SavedWifiProfile,
                           list_nearby_wifi_networks, list_saved_wifi_profiles,
                           list_wifi_interfaces, reveal_saved_wifi_password)
from .wifi_tools import spreadsheet_safe_cell


class WindowsWifiAnalyzer(tk.Toplevel):
    def __init__(self, parent: tk.Misc):
        super().__init__(parent)
        self.title("Wi-Fi Analyzer · Advanced IP Analyser")
        self.geometry("1080x680")
        self.minsize(780, 500)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.events: queue.Queue = queue.Queue()
        self.nearby: list[NearbyWifiNetwork] = []
        self.profiles: list[SavedWifiProfile] = []
        self.profile_by_item: dict[str, SavedWifiProfile] = {}
        self.revealed: dict[tuple[str, str], str] = {}
        self.clipboard_host = parent
        self.worker_active = False
        self.monitoring = False
        self.monitor_after: str | None = None
        self.signal_history: dict[str, list[tuple[float, int, str]]] = defaultdict(list)
        self._build()
        self.after(100, self._drain_events)
        self.refresh()

    def _build(self) -> None:
        header = ttk.Frame(self, padding=14)
        header.pack(fill="x")
        ttk.Label(header, text="Wi-Fi Analyzer",
                  font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Button(header, text="Refresh", command=self.refresh,
                   style="Accent.TButton").pack(side="right")
        ttk.Button(header, text="Export scan…", command=self.export_scan).pack(side="right", padx=(0, 8))

        self.summary = ttk.Label(self, padding=(14, 0, 14, 10),
                                 text="Reading Windows Wi-Fi information…")
        self.summary.pack(fill="x")

        tabs = ttk.Notebook(self)
        tabs.pack(fill="both", expand=True, padx=14)
        nearby_page = ttk.Frame(tabs, padding=8)
        profiles_page = ttk.Frame(tabs, padding=8)
        adapter_page = ttk.Frame(tabs, padding=8)
        history_page = ttk.Frame(tabs, padding=8)
        channels_page = ttk.Frame(tabs, padding=8)
        tabs.add(nearby_page, text="Nearby networks")
        tabs.add(history_page, text="Signal history")
        tabs.add(channels_page, text="Channel graph")
        tabs.add(profiles_page, text="Saved profiles")
        tabs.add(adapter_page, text="Adapters")

        self._build_history_page(history_page)
        self._build_channels_page(channels_page)

        columns = ("ssid", "channel", "bandwidth", "signal", "dbm", "security", "risk", "saved", "state", "adapter", "finding")
        self.nearby_table = ttk.Treeview(nearby_page, columns=columns, show="headings")
        widths = (200, 65, 90, 75, 75, 190, 100, 70, 90, 200, 340)
        labels = ("Network name", "Channel", "Bandwidth", "Signal", "dBm", "Security", "Review", "Saved", "State", "Adapter", "Finding")
        for column, width, label in zip(columns, widths, labels):
            self.nearby_table.heading(column, text=label)
            self.nearby_table.column(column, width=width, anchor="w", stretch=column in {"ssid", "security", "adapter"})
        nearby_y = ttk.Scrollbar(nearby_page, orient="vertical", command=self.nearby_table.yview)
        nearby_x = ttk.Scrollbar(nearby_page, orient="horizontal", command=self.nearby_table.xview)
        self.nearby_table.configure(yscrollcommand=nearby_y.set, xscrollcommand=nearby_x.set)
        self.nearby_table.grid(row=0, column=0, sticky="nsew")
        nearby_y.grid(row=0, column=1, sticky="ns")
        nearby_x.grid(row=1, column=0, sticky="ew")
        nearby_page.rowconfigure(0, weight=1)
        nearby_page.columnconfigure(0, weight=1)

        profile_actions = ttk.Frame(profiles_page)
        profile_actions.pack(fill="x", pady=(0, 8))
        ttk.Label(profile_actions,
                  text="Passwords stay hidden until you select one profile and confirm.").pack(side="left")
        ttk.Button(profile_actions, text="Reveal selected password",
                   command=self.reveal_selected).pack(side="right")
        ttk.Button(profile_actions, text="Copy revealed password",
                   command=self.copy_selected).pack(side="right", padx=(0, 8))
        ttk.Button(profile_actions, text="Hide passwords",
                   command=self.hide_passwords).pack(side="right", padx=(0, 8))

        profile_frame = ttk.Frame(profiles_page)
        profile_frame.pack(fill="both", expand=True)
        profile_columns = ("name", "security", "adapter", "password")
        self.profile_table = ttk.Treeview(profile_frame, columns=profile_columns,
                                          show="headings", selectmode="browse")
        for column, width, label in zip(profile_columns, (260, 230, 260, 220),
                                        ("Saved profile", "Security", "Adapter", "Password")):
            self.profile_table.heading(column, text=label)
            self.profile_table.column(column, width=width, anchor="w", stretch=True)
        profile_y = ttk.Scrollbar(profile_frame, orient="vertical", command=self.profile_table.yview)
        profile_x = ttk.Scrollbar(profile_frame, orient="horizontal", command=self.profile_table.xview)
        self.profile_table.configure(yscrollcommand=profile_y.set, xscrollcommand=profile_x.set)
        self.profile_table.grid(row=0, column=0, sticky="nsew")
        profile_y.grid(row=0, column=1, sticky="ns")
        profile_x.grid(row=1, column=0, sticky="ew")
        profile_frame.rowconfigure(0, weight=1)
        profile_frame.columnconfigure(0, weight=1)

        adapter_columns = ("name", "state", "guid")
        self.adapter_table = ttk.Treeview(adapter_page, columns=adapter_columns, show="headings")
        for column, width, label in zip(adapter_columns, (360, 170, 360),
                                        ("Adapter", "State", "Windows interface ID")):
            self.adapter_table.heading(column, text=label)
            self.adapter_table.column(column, width=width, anchor="w", stretch=True)
        self.adapter_table.pack(fill="both", expand=True)

        note = ttk.Label(
            self, padding=14, wraplength=1020,
            text="Nearby scanning is read-only. Password viewing requests one key already saved on this computer; "
                 "nothing is transmitted or included in scan exports. Windows may require administrator permission.")
        note.pack(fill="x")
        self.status = ttk.Label(self, padding=(14, 0, 14, 12), text="Ready")
        self.status.pack(fill="x")

    def _build_history_page(self, page: ttk.Frame) -> None:
        controls = ttk.Frame(page)
        controls.pack(fill="x", pady=(0, 8))
        self.refresh_seconds = tk.IntVar(value=3)
        ttk.Button(controls, text="Start monitoring", command=self.toggle_monitor,
                   style="Accent.TButton").pack(side="left")
        self.monitor_button = controls.winfo_children()[-1]
        ttk.Label(controls, text="Refresh every").pack(side="left", padx=(14, 5))
        ttk.Combobox(controls, textvariable=self.refresh_seconds, values=(1, 2, 3, 4, 5),
                     width=3, state="readonly").pack(side="left")
        ttk.Label(controls, text="second(s) · retains up to 2 hours").pack(side="left", padx=5)
        ttk.Button(controls, text="Clear history", command=self.clear_history).pack(side="right")
        ttk.Button(controls, text="?", width=3, command=self.show_analysis_help).pack(side="right", padx=8)

        frame = ttk.Frame(page)
        frame.pack(fill="both", expand=True)
        self.history_canvas = tk.Canvas(frame, background="#08131f", highlightthickness=0)
        history_y = ttk.Scrollbar(frame, orient="vertical", command=self.history_canvas.yview)
        history_x = ttk.Scrollbar(frame, orient="horizontal", command=self.history_canvas.xview)
        self.history_canvas.configure(yscrollcommand=history_y.set, xscrollcommand=history_x.set)
        self.history_canvas.grid(row=0, column=0, sticky="nsew")
        history_y.grid(row=0, column=1, sticky="ns")
        history_x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.history_canvas.bind("<Configure>", lambda _event: self._draw_history())

    def _build_channels_page(self, page: ttk.Frame) -> None:
        controls = ttk.Frame(page)
        controls.pack(fill="x", pady=(0, 8))
        self.channel_band = tk.StringVar(value="2.4 GHz")
        ttk.Label(controls, text="Band").pack(side="left")
        band_box = ttk.Combobox(controls, textvariable=self.channel_band,
                                values=("2.4 GHz", "5 GHz", "6 GHz"),
                                width=8, state="readonly")
        band_box.pack(side="left", padx=6)
        band_box.bind("<<ComboboxSelected>>", lambda _event: self._draw_channels())
        ttk.Label(controls, text="Curve width is the access point's advertised channel bandwidth.").pack(side="left", padx=8)
        ttk.Button(controls, text="?", width=3, command=self.show_analysis_help).pack(side="right")
        self.channel_canvas = tk.Canvas(page, background="#08131f", highlightthickness=0)
        self.channel_canvas.pack(fill="both", expand=True)
        self.channel_canvas.bind("<Configure>", lambda _event: self._draw_channels())

    def refresh(self) -> None:
        if self.worker_active:
            return
        self.revealed.clear()
        self.worker_active = True
        self.status.configure(text="Refreshing Wi-Fi adapters, nearby networks, and saved profiles…")
        threading.Thread(target=self._refresh_worker, daemon=True).start()

    def toggle_monitor(self) -> None:
        self.monitoring = not self.monitoring
        self.monitor_button.configure(text="Stop monitoring" if self.monitoring else "Start monitoring")
        if self.monitor_after:
            self.after_cancel(self.monitor_after)
            self.monitor_after = None
        if self.monitoring:
            self.refresh()
            self._schedule_monitor()
            self.status.configure(text="Signal monitoring started; use the scrollbar to review up to two hours.")
        else:
            self.status.configure(text="Signal monitoring stopped; collected history is retained.")

    def _schedule_monitor(self) -> None:
        if self.monitoring and self.winfo_exists():
            self.monitor_after = self.after(max(1, min(5, self.refresh_seconds.get())) * 1000,
                                              self._monitor_tick)

    def _monitor_tick(self) -> None:
        self.monitor_after = None
        if self.monitoring:
            self.refresh()
            self._schedule_monitor()

    def clear_history(self) -> None:
        self.signal_history.clear()
        self._draw_history()
        self.status.configure(text="Signal history cleared.")

    def show_analysis_help(self) -> None:
        messagebox.showinfo(
            "Wi-Fi analysis help",
            "Signal history samples the measured dBm value every 1–5 seconds and retains at most two hours. "
            "Use the bottom scrollbar to move back through time. Windows may reuse its last radio scan between samples.\n\n"
            "Channel graph places each access point on its centre channel. Curve width uses bandwidth advertised "
            "in the access point's HT/VHT information. ‘Width unavailable’ means Windows did not expose enough "
            "radio information; the app does not guess it.", parent=self)

    def _refresh_worker(self) -> None:
        try:
            interfaces = list_wifi_interfaces()
            networks = list_nearby_wifi_networks()
            profiles = list_saved_wifi_profiles()
            self.events.put(("refresh", interfaces, networks, profiles))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("error", str(error)))

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                self.worker_active = False
                if event[0] == "refresh":
                    self._show_results(event[1], event[2], event[3])
                elif event[0] == "password":
                    self._show_password(event[1], event[2])
                else:
                    self.status.configure(text="Wi-Fi operation failed.")
                    messagebox.showerror("Wi-Fi Analyzer", event[1], parent=self)
        except queue.Empty:
            if self.winfo_exists():
                self.after(100, self._drain_events)

    def _show_results(self, interfaces, networks, profiles) -> None:
        self.nearby = networks
        self.profiles = profiles
        self.nearby_table.delete(*self.nearby_table.get_children())
        for network in networks:
            self.nearby_table.insert("", "end", values=(
                network.ssid, network.channel or "", f"{network.channel_width_mhz} MHz" if network.channel_width_mhz else "Unknown",
                f"{network.signal_percent}%", network.signal_dbm,
                network.security, network.risk_level, "Yes" if network.profile_name else "No",
                "Connected" if network.connected else "Available", network.interface,
                network.risk_reason))
        self.profile_table.delete(*self.profile_table.get_children())
        self.profile_by_item.clear()
        for profile in profiles:
            key = (profile.interface_guid.casefold(), profile.name.casefold())
            password = self.revealed.get(key)
            item = self.profile_table.insert("", "end", values=(
                profile.name, profile.security, profile.interface,
                password if password is not None else "••••••••"))
            self.profile_by_item[item] = profile
        self.adapter_table.delete(*self.adapter_table.get_children())
        for interface in interfaces:
            self.adapter_table.insert("", "end", values=(interface.name, interface.state, interface.guid))
        connected = next((network.ssid for network in networks if network.connected), "Not connected")
        weak = sum(1 for network in networks if network.security.casefold().startswith(("open", "shared")))
        self.summary.configure(text=(f"Connected: {connected}   ·   {len(networks)} nearby network(s)   ·   "
                                     f"{len(profiles)} saved profile(s)   ·   {weak} open/legacy network(s)"))
        self.status.configure(text="Wi-Fi information refreshed.")
        self._record_signal_sample(networks)
        self._draw_history()
        self._draw_channels()

    def _record_signal_sample(self, networks: list[NearbyWifiNetwork]) -> None:
        now = time.time()
        cutoff = now - 2 * 60 * 60
        for network in networks:
            key = network.bssid or f"{network.interface}|{network.ssid}"
            self.signal_history[key].append((now, network.signal_dbm, network.ssid))
        for key in list(self.signal_history):
            samples = self.signal_history[key]
            first = 0
            while first < len(samples) and samples[first][0] < cutoff:
                first += 1
            if first:
                del samples[:first]
            if not samples:
                del self.signal_history[key]

    def _draw_history(self) -> None:
        canvas = getattr(self, "history_canvas", None)
        if canvas is None:
            return
        old_right = canvas.xview()[1] if canvas.bbox("all") else 1.0
        canvas.delete("all")
        view_width = max(640, canvas.winfo_width())
        height = max(360, canvas.winfo_height())
        strongest = sorted(self.signal_history.items(),
                           key=lambda item: item[1][-1][1], reverse=True)[:12]
        legend_columns = max(2, int((view_width - 58) / 250))
        legend_rows = (len(strongest) + legend_columns - 1) // legend_columns
        left, top, bottom = 58, 24 + legend_rows * 18, height - 48
        all_samples = [sample for values in self.signal_history.values() for sample in values]
        if not all_samples:
            canvas.create_text(view_width / 2, height / 2, text="Start monitoring to collect signal history",
                               fill="#9db3c8", font=("TkDefaultFont", 12))
            canvas.configure(scrollregion=(0, 0, view_width, height))
            return
        start = min(sample[0] for sample in all_samples)
        end = max(sample[0] for sample in all_samples)
        pixels_per_second = max(1.0, 6.0 / max(1, min(5, self.refresh_seconds.get())))
        width = max(view_width, left + (end - start) * pixels_per_second + 100)
        for dbm in range(-100, -29, 10):
            y = top + (-30 - dbm) / 70 * (bottom - top)
            canvas.create_line(left, y, width - 30, y, fill="#284157")
            canvas.create_text(left - 8, y, text=f"{dbm}", fill="#9db3c8", anchor="e")
        palette = ("#22b8ff", "#56e05b", "#ffcc3d", "#ff6b6b", "#b884ff", "#31d6c4",
                   "#ff8b3d", "#8dc5ff", "#d8ef62", "#f07bd6", "#9ce8c7", "#f5a9a9")
        for index, (_key, samples) in enumerate(strongest):
            color = palette[index % len(palette)]
            points: list[float] = []
            for stamp, dbm, _ssid in samples:
                x = left + (stamp - start) * pixels_per_second
                y = top + (-30 - max(-100, min(-30, dbm))) / 70 * (bottom - top)
                points.extend((x, y))
            if len(points) >= 4:
                canvas.create_line(*points, fill=color, width=2, smooth=True)
            elif points:
                canvas.create_oval(points[0] - 2, points[1] - 2, points[0] + 2, points[1] + 2,
                                   fill=color, outline=color)
            legend_x = left + (index % legend_columns) * 250
            legend_y = 12 + (index // legend_columns) * 18
            label = samples[-1][2]
            canvas.create_text(legend_x, legend_y, text=label[:32], fill=color, anchor="w")
        canvas.create_text(8, top - 10, text="dBm", fill="#d8e8f5", anchor="w")
        canvas.configure(scrollregion=(0, 0, width, height))
        if old_right >= .98:
            canvas.xview_moveto(1.0)

    def _draw_channels(self) -> None:
        canvas = getattr(self, "channel_canvas", None)
        if canvas is None:
            return
        canvas.delete("all")
        width, height = max(640, canvas.winfo_width()), max(360, canvas.winfo_height())
        left, right, top, bottom = 58, width - 28, 28, height - 50
        band = self.channel_band.get()
        if band == "2.4 GHz":
            low, high, channel_low, channel_high = 2400, 2500, 1, 14
        elif band == "5 GHz":
            low, high, channel_low, channel_high = 5000, 5900, 32, 177
        else:
            low, high, channel_low, channel_high = 5925, 7125, 1, 233
        def x_for_frequency(value: float) -> float:
            return left + (value - low) / (high - low) * (right - left)
        def y_for_dbm(value: int) -> float:
            return top + (-30 - max(-100, min(-30, value))) / 70 * (bottom - top)
        for dbm in range(-100, -29, 10):
            y = y_for_dbm(dbm)
            canvas.create_line(left, y, right, y, fill="#284157")
            canvas.create_text(left - 8, y, text=f"{dbm}", fill="#9db3c8", anchor="e")
        palette = ("#22b8ff", "#56e05b", "#ffcc3d", "#ff6b6b", "#b884ff", "#31d6c4", "#ff8b3d")
        shown = 0
        for network in self.nearby:
            frequency = network.frequency_mhz
            if not low <= frequency <= high:
                continue
            color = palette[shown % len(palette)]
            channel_width = network.channel_width_mhz
            half = (channel_width or 4) / 2
            x1, peak, x2 = x_for_frequency(frequency - half), x_for_frequency(frequency), x_for_frequency(frequency + half)
            y, base = y_for_dbm(network.signal_dbm), bottom
            canvas.create_polygon(x1, base, (x1 + peak) / 2, (base + y) / 2, peak, y,
                                  (peak + x2) / 2, (base + y) / 2, x2, base,
                                  fill=color, outline=color, stipple="gray50", width=2)
            label = f"{network.ssid} · ch {network.channel} · {channel_width} MHz" if channel_width else f"{network.ssid} · ch {network.channel} · width unavailable"
            canvas.create_text(peak, max(top + 8, y - 10), text=label, fill=color, anchor="s")
            shown += 1
        ticks = range(channel_low, channel_high + 1) if band == "2.4 GHz" else range(channel_low, channel_high + 1, 8 if band == "5 GHz" else 16)
        for channel in ticks:
            frequency = 2407 + channel * 5 if band == "2.4 GHz" and channel != 14 else 2484 if channel == 14 and band == "2.4 GHz" else (5000 + channel * 5 if band == "5 GHz" else 5950 + channel * 5)
            x = x_for_frequency(frequency)
            canvas.create_line(x, bottom, x, bottom + 5, fill="#9db3c8")
            canvas.create_text(x, bottom + 17, text=str(channel), fill="#9db3c8")
        canvas.create_text(8, top - 10, text="dBm", fill="#d8e8f5", anchor="w")
        if shown == 0:
            canvas.create_text(width / 2, height / 2, text=f"No {band} access points in the latest scan",
                               fill="#9db3c8")

    def _selected_profile(self) -> tuple[str, SavedWifiProfile] | None:
        selected = self.profile_table.selection()
        if not selected or selected[0] not in self.profile_by_item:
            messagebox.showinfo("Select a profile", "Select one saved Wi-Fi profile first.", parent=self)
            return None
        return selected[0], self.profile_by_item[selected[0]]

    def reveal_selected(self) -> None:
        selected = self._selected_profile()
        if not selected:
            return
        item, profile = selected
        if not messagebox.askyesno(
                "Reveal saved Wi-Fi password",
                f"Show the password already saved on this computer for “{profile.name}”?\n\n"
                "Only continue on a computer and network profile you are authorized to administer.",
                parent=self):
            return
        self.worker_active = True
        self.status.configure(text=f"Requesting the saved key for {profile.name}…")
        threading.Thread(target=self._password_worker, args=(item, profile), daemon=True).start()

    def _password_worker(self, item: str, profile: SavedWifiProfile) -> None:
        try:
            self.events.put(("password", item, reveal_saved_wifi_password(profile)))
        except (OSError, RuntimeError, ValueError, PermissionError) as error:
            self.events.put(("error", str(error)))

    def _show_password(self, item: str, password: str) -> None:
        profile = self.profile_by_item.get(item)
        if not profile:
            return
        key = (profile.interface_guid.casefold(), profile.name.casefold())
        self.revealed[key] = password
        values = list(self.profile_table.item(item, "values"))
        values[3] = password
        self.profile_table.item(item, values=values)
        self.status.configure(text=f"Password revealed for {profile.name}; use Hide passwords when finished.")

    def copy_selected(self) -> None:
        selected = self._selected_profile()
        if not selected:
            return
        _item, profile = selected
        key = (profile.interface_guid.casefold(), profile.name.casefold())
        password = self.revealed.get(key)
        if password is None:
            messagebox.showinfo("Password hidden", "Reveal this profile first.", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(password)
        self.status.configure(text="Password copied. The app will clear it from the clipboard after 30 seconds.")
        self.clipboard_host.after(30_000,
                                  lambda expected=password: self._clear_clipboard_if_unchanged(expected))

    def _clear_clipboard_if_unchanged(self, expected: str) -> None:
        try:
            if self.clipboard_host.clipboard_get() == expected:
                self.clipboard_host.clipboard_clear()
        except tk.TclError:
            pass

    def hide_passwords(self) -> None:
        try:
            if self.clipboard_host.clipboard_get() in self.revealed.values():
                self.clipboard_host.clipboard_clear()
        except tk.TclError:
            pass
        self.revealed.clear()
        for item in self.profile_table.get_children():
            values = list(self.profile_table.item(item, "values"))
            values[3] = "••••••••"
            self.profile_table.item(item, values=values)
        self.status.configure(text="Saved passwords hidden and removed from application memory.")

    def export_scan(self) -> None:
        if not self.nearby:
            messagebox.showinfo("No scan", "Refresh nearby networks first.", parent=self)
            return
        name = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            filetypes=[("CSV file", "*.csv")])
        if not name:
            return
        try:
            with Path(name).open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(("ssid", "bssid", "frequency_mhz", "channel", "channel_width_mhz",
                                 "signal_percent", "dbm", "security", "risk_level",
                                 "risk_reason", "saved_profile", "connected", "adapter"))
                for network in self.nearby:
                    writer.writerow(tuple(spreadsheet_safe_cell(value) for value in (
                        network.ssid, network.bssid, network.frequency_mhz, network.channel,
                        network.channel_width_mhz, network.signal_percent, network.signal_dbm,
                        network.security, network.risk_level, network.risk_reason,
                        bool(network.profile_name), network.connected, network.interface)))
            self.status.configure(text=f"Nearby network scan saved to {os.path.basename(name)}; passwords were excluded.")
        except OSError as error:
            messagebox.showerror("Export failed", str(error), parent=self)

    def close(self) -> None:
        self.monitoring = False
        if self.monitor_after:
            self.after_cancel(self.monitor_after)
        self.hide_passwords()
        self.destroy()
