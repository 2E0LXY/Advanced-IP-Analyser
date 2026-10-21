"""Tk interface for TP-Link Kasa and Tapo discovery and control."""

from __future__ import annotations

import asyncio
import json
import queue
import threading
from collections.abc import Awaitable, Callable
from tkinter import messagebox, ttk

from .home_assistant import (
    call_service,
    list_entities,
    set_entity_brightness,
    set_entity_power,
)
from .local_smart_devices import (
    PROVIDERS,
    inspect_local_device,
    run_local_action,
    set_local_brightness,
    set_local_power,
)
from .smart_home import (
    SmartHomeDevice,
    discover_devices,
    inspect_device,
    set_brightness,
    set_power,
)


class SmartHomeView(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=12)
        self.events: queue.Queue = queue.Queue()
        self.devices: dict[str, SmartHomeDevice] = {}
        self.local_credentials: dict[tuple[str, str], tuple[str, str, str]] = {}
        self.busy = False
        self._build()
        self.after(100, self._drain_events)

    def _build(self) -> None:
        ttk.Label(self, text="TP-Link Smart Home", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        ttk.Label(
            self,
            text="Discover and control supported Kasa and Tapo plugs, bulbs, switches and strips.",
            foreground="#90abc4", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 12))

        credentials = ttk.LabelFrame(self, text="Device authentication (kept in memory only)", padding=10)
        credentials.pack(fill="x")
        ttk.Label(credentials, text="TP-Link email").grid(row=0, column=0, sticky="w")
        self.username = ttk.Entry(credentials, width=34)
        self.username.grid(row=0, column=1, sticky="ew", padx=(8, 18))
        ttk.Label(credentials, text="Password").grid(row=0, column=2, sticky="w")
        self.password = ttk.Entry(credentials, show="●", width=28)
        self.password.grid(row=0, column=3, sticky="ew", padx=(8, 0))
        credentials.columnconfigure(1, weight=1)
        credentials.columnconfigure(3, weight=1)

        home_assistant = ttk.LabelFrame(
            self, text="Universal local controller · Home Assistant", padding=10)
        home_assistant.pack(fill="x", pady=(10, 0))
        ttk.Label(home_assistant, text="Local URL").grid(row=0, column=0, sticky="w")
        self.ha_url = ttk.Entry(home_assistant, width=34)
        self.ha_url.insert(0, "http://homeassistant.local:8123")
        self.ha_url.grid(row=0, column=1, sticky="ew", padx=(8, 18))
        ttk.Label(home_assistant, text="Long-lived token").grid(row=0, column=2, sticky="w")
        self.ha_token = ttk.Entry(home_assistant, show="●", width=34)
        self.ha_token.grid(row=0, column=3, sticky="ew", padx=(8, 12))
        self.ha_button = ttk.Button(
            home_assistant, text="Load all local devices", command=self.load_home_assistant)
        self.ha_button.grid(row=0, column=4)
        home_assistant.columnconfigure(1, weight=1)
        home_assistant.columnconfigure(3, weight=1)

        local = ttk.LabelFrame(self, text="Other common local devices", padding=10)
        local.pack(fill="x", pady=(10, 0))
        for column, label in enumerate((
                "Provider", "Device IP / hostname", "Device ID / username",
                "Local key / password", "Version / channel / DPs")):
            ttk.Label(local, text=label).grid(row=0, column=column, sticky="w")
        self.local_provider = ttk.Combobox(
            local, values=PROVIDERS, state="readonly", width=18)
        self.local_provider.set(PROVIDERS[0])
        self.local_provider.grid(row=1, column=0, padx=(0, 8))
        self.local_provider.bind("<<ComboboxSelected>>", self._local_provider_changed)
        self.local_host = ttk.Entry(local, width=18)
        self.local_host.grid(row=1, column=1, sticky="ew", padx=(0, 8))
        self.local_identifier = ttk.Entry(local, width=24)
        self.local_identifier.grid(row=1, column=2, padx=(0, 8))
        self.local_secret = ttk.Entry(local, show="●", width=22)
        self.local_secret.grid(row=1, column=3, padx=(0, 8))
        self.local_config = ttk.Entry(local, width=16)
        self.local_config.insert(0, "3.3,1,3")
        self.local_config.grid(row=1, column=4, padx=(0, 8))
        self.local_button = ttk.Button(local, text="Add / inspect", command=self.connect_local)
        self.local_button.grid(row=1, column=5)
        local.columnconfigure(1, weight=1)

        connection = ttk.Frame(self, padding=(0, 10))
        connection.pack(fill="x")
        ttk.Label(connection, text="LAN broadcast").pack(side="left")
        self.broadcast = ttk.Entry(connection, width=18)
        self.broadcast.insert(0, "255.255.255.255")
        self.broadcast.pack(side="left", padx=(8, 12))
        self.discover_button = ttk.Button(
            connection, text="Discover LAN", command=self.discover, style="Accent.TButton")
        self.discover_button.pack(side="left")
        ttk.Label(connection, text="Direct / VPN address").pack(side="left", padx=(22, 0))
        self.direct_host = ttk.Entry(connection, width=24)
        self.direct_host.pack(side="left", padx=8)
        self.connect_button = ttk.Button(connection, text="Connect", command=self.connect_direct)
        self.connect_button.pack(side="left")
        ttk.Button(connection, text="Refresh selected", command=self.refresh_selected).pack(
            side="left", padx=(8, 0))

        columns = ("name", "provider", "model", "type", "address", "state",
                   "brightness", "signal", "mac")
        self.table = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")
        widths = (175, 110, 110, 95, 165, 70, 85, 75, 140)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.title())
            self.table.column(column, width=width, anchor="w")
        self.table.pack(fill="both", expand=True)
        self.table.bind("<<TreeviewSelect>>", self._selection_changed)
        self.table.tag_configure("on", foreground="#55d992")
        self.table.tag_configure("off", foreground="#d8e5f3")
        self.table.tag_configure("unknown", foreground="#e7bd65")

        controls = ttk.Frame(self, padding=(0, 10, 0, 0))
        controls.pack(fill="x")
        self.on_button = ttk.Button(controls, text="Activate", command=lambda: self.power(True))
        self.on_button.pack(side="left")
        self.off_button = ttk.Button(controls, text="Deactivate", command=lambda: self.power(False))
        self.off_button.pack(side="left", padx=(8, 20))
        ttk.Label(controls, text="Brightness").pack(side="left")
        self.brightness = ttk.Scale(controls, from_=1, to=100, length=220)
        self.brightness.set(50)
        self.brightness.pack(side="left", padx=8)
        self.brightness_button = ttk.Button(
            controls, text="Apply brightness", command=self.apply_brightness)
        self.brightness_button.pack(side="left")
        self.status = ttk.Label(
            controls, text="Credentials are required by many newer Kasa and Tapo devices.")
        self.status.pack(side="right")

        advanced = ttk.Frame(self, padding=(0, 8, 0, 0))
        advanced.pack(fill="x")
        ttk.Label(advanced, text="Advanced local action").pack(side="left")
        self.ha_action = ttk.Entry(advanced, width=25)
        self.ha_action.pack(side="left", padx=(8, 14))
        ttk.Label(advanced, text="JSON data").pack(side="left")
        self.ha_action_data = ttk.Entry(advanced)
        self.ha_action_data.insert(0, "{}")
        self.ha_action_data.pack(side="left", fill="x", expand=True, padx=8)
        self.ha_action_button = ttk.Button(
            advanced, text="Run selected action", command=self.run_advanced_action)
        self.ha_action_button.pack(side="left")
        self._update_controls()

        ttk.Label(
            self,
            text=("Remote control uses a secure VPN route to the home LAN. Do not forward smart-"
                  "device or controller management ports directly to the public internet."),
            foreground="#90abc4").pack(anchor="w", pady=(10, 0))

    def _credentials(self) -> tuple[str, str]:
        return self.username.get(), self.password.get()

    def _run(self, label: str, operation: Callable[[], Awaitable]) -> None:
        if self.busy:
            return
        self.busy = True
        self.status.configure(text=label)
        self._update_controls()

        def worker() -> None:
            try:
                result = asyncio.run(operation())
                self.events.put(("result", result))
            except Exception as error:  # Converted to a GUI error on the Tk thread.
                self.events.put(("error", error))

        threading.Thread(target=worker, daemon=True).start()

    def discover(self) -> None:
        username, password = self._credentials()
        target = self.broadcast.get()
        self._run("Discovering TP-Link devices on the LAN…",
                  lambda: discover_devices(username, password, target=target))

    def connect_direct(self) -> None:
        username, password = self._credentials()
        address = self.direct_host.get()
        self._run(f"Connecting to {address or 'device'}…",
                  lambda: inspect_device(address, username, password))

    def load_home_assistant(self) -> None:
        base_url, token = self.ha_url.get(), self.ha_token.get()
        self._run("Loading all controllable Home Assistant entities…",
                  lambda: asyncio.to_thread(list_entities, base_url, token))

    def _local_provider_changed(self, _event=None) -> None:
        defaults = {
            "Smart Life / Tuya": "3.3,1,3", "Shelly": "0",
            "Tasmota": "1", "WLED": "", "Philips Hue": "1",
        }
        self.local_config.delete(0, "end")
        self.local_config.insert(0, defaults[self.local_provider.get()])

    def connect_local(self) -> None:
        provider = self.local_provider.get()
        host = self.local_host.get().strip()
        identifier = self.local_identifier.get()
        secret = self.local_secret.get()
        config = self.local_config.get()
        self.local_credentials[(provider, host)] = (identifier, secret, config)
        self._run(f"Connecting to {provider} device at {host or 'local address'}…",
                  lambda: asyncio.to_thread(
                      inspect_local_device, provider, host, identifier, secret, config))

    def _selected(self) -> SmartHomeDevice | None:
        selection = self.table.selection()
        return self.devices.get(selection[0]) if selection else None

    def refresh_selected(self) -> None:
        device = self._selected()
        if device is None:
            messagebox.showinfo("Select a device", "Select a TP-Link device to refresh.", parent=self)
            return
        if device.provider == "Home Assistant":
            token = self.ha_token.get()
            self._run(f"Refreshing {device.alias}…",
                      lambda: asyncio.to_thread(list_entities, device.controller, token))
        elif device.provider in PROVIDERS:
            identifier, secret, config = self.local_credentials.get(
                (device.provider, device.address), ("", "", ""))
            self._run(f"Refreshing {device.alias}…", lambda: asyncio.to_thread(
                inspect_local_device, device.provider, device.address,
                identifier, secret, config))
        else:
            username, password = self._credentials()
            self._run(f"Refreshing {device.alias}…",
                      lambda: inspect_device(device.address, username, password))

    def power(self, enabled: bool) -> None:
        device = self._selected()
        if device is None:
            return
        action = "activating" if enabled else "deactivating"
        if device.provider == "Home Assistant":
            if device.kind == "Lock" and enabled and not messagebox.askyesno(
                    "Confirm unlock", f"Unlock {device.alias}?", parent=self):
                return
            token = self.ha_token.get()
            self._run(f"{action.title()} {device.alias}…", lambda: asyncio.to_thread(
                set_entity_power, device.controller, token, device.entity_id, enabled))
        elif device.provider in PROVIDERS:
            identifier, secret, config = self.local_credentials.get(
                (device.provider, device.address), ("", "", ""))
            self._run(f"{action.title()} {device.alias}…", lambda: asyncio.to_thread(
                set_local_power, device.provider, device.address, enabled,
                identifier, secret, config))
        else:
            username, password = self._credentials()
            self._run(f"{action.title()} {device.alias}…",
                      lambda: set_power(device.address, enabled, username, password))

    def apply_brightness(self) -> None:
        device = self._selected()
        if device is None:
            return
        value = round(self.brightness.get())
        if device.provider == "Home Assistant":
            token = self.ha_token.get()
            self._run(f"Setting {device.alias} brightness to {value}%…",
                      lambda: asyncio.to_thread(
                          set_entity_brightness, device.controller, token,
                          device.entity_id, value))
        elif device.provider in PROVIDERS:
            identifier, secret, config = self.local_credentials.get(
                (device.provider, device.address), ("", "", ""))
            self._run(f"Setting {device.alias} brightness to {value}%…",
                      lambda: asyncio.to_thread(
                          set_local_brightness, device.provider, device.address, value,
                          identifier, secret, config))
        else:
            username, password = self._credentials()
            self._run(f"Setting {device.alias} brightness to {value}%…",
                      lambda: set_brightness(device.address, value, username, password))

    def run_advanced_action(self) -> None:
        device = self._selected()
        if device is None or device.provider == "TP-Link":
            messagebox.showinfo(
                "Select a device", "Select a Home Assistant or common local device first.",
                parent=self)
            return
        try:
            data = json.loads(self.ha_action_data.get() or "{}")
            if not isinstance(data, dict):
                raise TypeError("Action data must be a JSON object.")
        except (json.JSONDecodeError, TypeError) as error:
            messagebox.showerror("Invalid action data", str(error), parent=self)
            return
        service = self.ha_action.get()
        if device.provider == "Home Assistant":
            token = self.ha_token.get()
            operation = lambda: asyncio.to_thread(
                call_service, device.controller, token, service, device.entity_id, data)
        else:
            identifier, secret, config = self.local_credentials.get(
                (device.provider, device.address), ("", "", ""))
            operation = lambda: asyncio.to_thread(
                run_local_action, device.provider, device.address, service, data,
                identifier, secret, config)
        self._run(f"Running {service} for {device.alias}…", operation)

    def _selection_changed(self, _event=None) -> None:
        device = self._selected()
        if device and device.provider == "Home Assistant":
            domain = device.entity_id.partition(".")[0]
            defaults = {
                "button": "button.press", "cover": "cover.open_cover",
                "lawn_mower": "lawn_mower.start_mowing", "lock": "lock.unlock",
                "scene": "scene.turn_on", "vacuum": "vacuum.start",
                "valve": "valve.open_valve",
            }
            self.ha_action.delete(0, "end")
            self.ha_action.insert(0, defaults.get(domain, f"{domain}.turn_on"))
        elif device and device.provider in PROVIDERS:
            defaults = {
                "Smart Life / Tuya": ("dp.1", '{"value": true}'),
                "Shelly": ("Switch.Toggle", '{"id": 0}'),
                "Tasmota": ("Power1", '{"value": "TOGGLE"}'),
                "WLED": ("state", '{"on": true}'),
                "Philips Hue": ("state", '{"on": true}'),
            }
            action, data = defaults[device.provider]
            self.ha_action.delete(0, "end")
            self.ha_action.insert(0, action)
            self.ha_action_data.delete(0, "end")
            self.ha_action_data.insert(0, data)
        self._update_controls()

    def _store(self, device: SmartHomeDevice) -> None:
        existing = next((item for item, current in self.devices.items()
                         if (current.provider, current.address) ==
                         (device.provider, device.address)), None)
        item = existing or self.table.insert("", "end")
        self.devices[item] = device
        state = "On" if device.is_on is True else "Off" if device.is_on is False else "Unknown"
        tag = "on" if device.is_on is True else "off" if device.is_on is False else "unknown"
        self.table.item(item, values=(
            device.alias, device.provider, device.model, device.kind, device.address, state,
            f"{device.brightness}%" if device.brightness is not None else "—",
            f"{device.signal} dBm" if device.signal is not None else "—", device.mac), tags=(tag,))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                self.busy = False
                if kind == "error":
                    self.status.configure(text="Smart-home operation failed")
                    messagebox.showerror("Smart-home control failed", str(payload), parent=self)
                else:
                    devices = payload if isinstance(payload, list) else [payload]
                    for device in devices:
                        self._store(device)
                    self.status.configure(text=f"Ready · {len(self.devices)} device(s)")
                self._update_controls()
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _update_controls(self) -> None:
        device = self._selected() if hasattr(self, "table") else None
        discovery_state = "disabled" if self.busy else "normal"
        self.discover_button.configure(state=discovery_state)
        self.connect_button.configure(state=discovery_state)
        self.ha_button.configure(state=discovery_state)
        self.local_button.configure(state=discovery_state)
        power_state = "normal" if device and device.can_power and not self.busy else "disabled"
        off_state = "normal" if device and device.can_deactivate and not self.busy else "disabled"
        brightness_state = "normal" if device and device.can_brightness and not self.busy else "disabled"
        self.on_button.configure(state=power_state)
        self.off_button.configure(state=off_state)
        self.brightness_button.configure(state=brightness_state)
        action_state = ("normal" if device and device.provider != "TP-Link"
                        and not self.busy else "disabled")
        self.ha_action_button.configure(state=action_state)
        if device and device.brightness is not None:
            self.brightness.set(device.brightness)
