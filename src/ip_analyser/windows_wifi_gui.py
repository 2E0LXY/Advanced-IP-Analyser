from __future__ import annotations

import csv
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .windows_wifi import (NearbyWifiNetwork, SavedWifiProfile,
                           list_nearby_wifi_networks, list_saved_wifi_profiles,
                           list_wifi_interfaces, reveal_saved_wifi_password)


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
        tabs.add(nearby_page, text="Nearby networks")
        tabs.add(profiles_page, text="Saved profiles")
        tabs.add(adapter_page, text="Adapters")

        columns = ("ssid", "signal", "dbm", "security", "saved", "state", "adapter")
        self.nearby_table = ttk.Treeview(nearby_page, columns=columns, show="headings")
        widths = (220, 85, 75, 210, 90, 95, 220)
        labels = ("Network name", "Signal", "Approx. dBm", "Security", "Saved", "State", "Adapter")
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

    def refresh(self) -> None:
        if self.worker_active:
            return
        self.revealed.clear()
        self.worker_active = True
        self.status.configure(text="Refreshing Wi-Fi adapters, nearby networks, and saved profiles…")
        threading.Thread(target=self._refresh_worker, daemon=True).start()

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
                network.ssid, f"{network.signal_percent}%", network.signal_dbm,
                network.security, "Yes" if network.profile_name else "No",
                "Connected" if network.connected else "Available", network.interface))
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
                writer.writerow(("ssid", "signal_percent", "approx_dbm", "security",
                                 "saved_profile", "connected", "adapter"))
                for network in self.nearby:
                    writer.writerow((network.ssid, network.signal_percent, network.signal_dbm,
                                     network.security, bool(network.profile_name), network.connected,
                                     network.interface))
            self.status.configure(text=f"Nearby network scan saved to {os.path.basename(name)}; passwords were excluded.")
        except OSError as error:
            messagebox.showerror("Export failed", str(error), parent=self)

    def close(self) -> None:
        self.hide_passwords()
        self.destroy()
