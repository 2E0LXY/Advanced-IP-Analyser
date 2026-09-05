from __future__ import annotations

import queue
import threading
import tkinter as tk
import ipaddress
import getpass
import shutil
from dataclasses import replace
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import __version__
from .actions import open_network_tool, open_service, preferred_web_service, remote_power, service_url, wake
from .ai_analysis import ANALYSIS_MODES, SYSTEM_INSTRUCTION, build_analysis_preview
from .ai_providers import AIProviderError, generate_text, list_models
from .ai_settings import (AISettings, PROVIDERS, SecretStoreError, clear_api_key,
                          load_ai_settings, load_api_key,
                          save_ai_settings, save_api_key)
from .config import parse_ports
from .models import Host
from .network import active_ipv4_networks, broadcasts_for_host, current_ipv4_subnet, ipv4_24_target
from .packet_tools import (PacketRecord, capture_live, list_capture_interfaces,
                           packet_hex_preview, read_capture, validate_interface)
from .packet_filters import (FilterSyntaxError, QUICK_FILTERS, compile_filter,
                             load_saved_filters, save_saved_filters)
from .scanner import DEFAULT_PORTS, Scanner
from .scan_history import latest_evidence, latest_network_watch_evidence, record_scan
from .storage import export, import_inventory, load_favorites, merge_devices, save_favorites
from .targets import parse_targets
from .updater import Update, check_for_update, download_update, launch_installer
from .watch_gui import NetworkWatch
from .wifi_gui import WifiWatch
from .web_gui import WebSecurityAudit

OPENABLE_SERVICES = {"http", "https", "ftp", "smb", "ssh", "rdp", "telnet"}
COMMON_PORTS = ",".join(str(port) for port in DEFAULT_PORTS)
WEB_APP_PORTS = "80,443,3000,5000,8000,8080,8081,8443,8888,9000,9090"
GUI_PACKET_LIMIT = 20_000


class PacketViewer(tk.Toplevel):
    def __init__(self, parent: "Application", capture: Path, records: list[PacketRecord]):
        super().__init__(parent)
        self.capture = capture
        self.records = records
        self.records_by_item: dict[str, PacketRecord] = {}
        self.title(f"Packet analysis · {capture.name}")
        self.geometry("1180x700")
        self.minsize(760, 480)

        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text="Built-in packet analysis",
                  font=("TkDefaultFont", 14, "bold")).pack(side="left")
        self.match_count = ttk.Label(header, text=f"{len(records):,} displayed packet(s)")
        self.match_count.pack(side="left", padx=16)
        ttk.Button(header, text="Save capture as…", command=self.save_capture).pack(side="right")
        ttk.Button(header, text="Close", command=self.destroy).pack(side="right", padx=(0, 8))

        filter_bar = ttk.Frame(self, padding=(12, 0, 12, 8))
        filter_bar.pack(fill="x")
        ttk.Label(filter_bar, text="Display filter").pack(side="left")
        self.filter_text = tk.StringVar()
        self.filter_predicate = compile_filter("")
        self.saved_filters: dict[str, str] = {}
        try:
            self.saved_filters = load_saved_filters()
        except (OSError, ValueError):
            pass
        self.filter_entry = tk.Entry(filter_bar, textvariable=self.filter_text, relief="solid",
                                     borderwidth=1, background="#ffffff", foreground="#17324d")
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=(8, 4), ipady=3)
        self.filter_entry.bind("<Return>", lambda _event: self.apply_filter())
        ttk.Button(filter_bar, text="Apply", command=self.apply_filter).pack(side="left", padx=(0, 4))
        ttk.Button(filter_bar, text="Clear", command=lambda: self.set_filter("")).pack(side="left", padx=(0, 4))
        self.filter_button = ttk.Menubutton(filter_bar, text="Quick filters")
        self.filter_menu = tk.Menu(self.filter_button, tearoff=False)
        self.filter_button.configure(menu=self.filter_menu)
        self.filter_button.pack(side="left", padx=(0, 4))
        ttk.Button(filter_bar, text="Save filter…", command=self.save_filter).pack(side="left")
        self.filter_status = ttk.Label(self, text="Filters change the display only; capture data is unchanged.",
                                       padding=(12, 0, 12, 6))
        self.filter_status.pack(fill="x")
        self.rebuild_filter_menu()

        pane = ttk.Panedwindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        table_frame = ttk.Frame(pane)
        detail_frame = ttk.Frame(pane)
        pane.add(table_frame, weight=3)
        pane.add(detail_frame, weight=2)

        columns = ("number", "time", "source", "sport", "destination", "dport",
                   "protocol", "length", "info")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        widths = (60, 105, 190, 70, 190, 70, 85, 70, 180)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.title())
            self.table.column(column, width=width, anchor="w", stretch=column in {"source", "destination", "info"})
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self.show_detail)

        ttk.Label(detail_frame, text="Packet bytes (first 512 bytes)").pack(anchor="w", pady=(6, 4))
        self.detail = tk.Text(detail_frame, height=12, wrap="none", font=("TkFixedFont", 9), state="disabled")
        self.detail.pack(fill="both", expand=True)
        self.refresh()

    def refresh(self) -> None:
        self.table.delete(*self.table.get_children())
        self.records_by_item.clear()
        displayed = 0
        for record in self.records:
            if not self.filter_predicate(record):
                continue
            item = self.table.insert("", "end", values=(
                record.number, record.time_text, record.source, record.source_port or "",
                record.destination, record.destination_port or "", record.protocol,
                record.length, record.info))
            self.records_by_item[item] = record
            displayed += 1
        self.match_count.configure(text=f"{displayed:,} of {len(self.records):,} displayed packet(s)")

    def apply_filter(self) -> None:
        expression = self.filter_text.get().strip()
        try:
            predicate = compile_filter(expression)
        except FilterSyntaxError as error:
            self.filter_entry.configure(background="#ffd7d7")
            self.filter_status.configure(text=f"Filter error: {error}", foreground="#8b1a1a")
            return
        self.filter_predicate = predicate
        self.filter_entry.configure(background="#d9f7d9")
        self.filter_status.configure(
            text="Valid display filter · capture data is unchanged.", foreground="#176b31")
        self.refresh()

    def set_filter(self, expression: str) -> None:
        self.filter_text.set(expression)
        self.apply_filter()

    def rebuild_filter_menu(self) -> None:
        self.filter_menu.delete(0, "end")
        for name, expression in QUICK_FILTERS:
            self.filter_menu.add_command(label=name, command=lambda value=expression: self.set_filter(value))
        if self.saved_filters:
            self.filter_menu.add_separator()
            for name, expression in sorted(self.saved_filters.items(), key=lambda item: item[0].casefold()):
                submenu = tk.Menu(self.filter_menu, tearoff=False)
                submenu.add_command(label="Use", command=lambda value=expression: self.set_filter(value))
                submenu.add_command(label="Delete", command=lambda value=name: self.delete_filter(value))
                self.filter_menu.add_cascade(label=f"Saved · {name}", menu=submenu)

    def save_filter(self) -> None:
        expression = self.filter_text.get().strip()
        try:
            compile_filter(expression)
        except FilterSyntaxError as error:
            messagebox.showerror("Invalid filter", str(error), parent=self)
            return
        if not expression:
            messagebox.showinfo("Nothing to save", "Enter a display filter first.", parent=self)
            return
        name = simpledialog.askstring("Save display filter", "Filter name:", parent=self)
        if not name:
            return
        updated = dict(self.saved_filters)
        updated[name.strip()] = expression
        try:
            save_saved_filters(updated)
        except (OSError, ValueError) as error:
            messagebox.showerror("Could not save filter", str(error), parent=self)
            return
        self.saved_filters = updated
        self.rebuild_filter_menu()

    def delete_filter(self, name: str) -> None:
        if not messagebox.askyesno("Delete display filter", f"Delete {name!r}?", parent=self):
            return
        updated = dict(self.saved_filters)
        updated.pop(name, None)
        try:
            save_saved_filters(updated)
        except (OSError, ValueError) as error:
            messagebox.showerror("Could not delete filter", str(error), parent=self)
            return
        self.saved_filters = updated
        self.rebuild_filter_menu()

    def show_detail(self, _event=None) -> None:
        selected = self.table.selection()
        if not selected or selected[0] not in self.records_by_item:
            return
        record = self.records_by_item[selected[0]]
        heading = (f"Packet {record.number} · {record.protocol} · {record.source}"
                   f"{':' + str(record.source_port) if record.source_port else ''} → {record.destination}"
                   f"{':' + str(record.destination_port) if record.destination_port else ''}\n\n")
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", heading + packet_hex_preview(record))
        self.detail.configure(state="disabled")

    def save_capture(self) -> None:
        destination = filedialog.asksaveasfilename(
            parent=self, defaultextension=".pcap", initialfile=self.capture.name,
            filetypes=[("PCAP capture", "*.pcap"), ("All files", "*")])
        if not destination:
            return
        try:
            shutil.copyfile(self.capture, destination)
        except OSError as error:
            messagebox.showerror("Save failed", str(error), parent=self)


class Application(tk.Tk):
    def __init__(self):
        super().__init__(className="AdvancedIPAnalyser")
        self.title("Advanced IP Analyser")
        self.geometry("1200x620")
        self.minsize(720, 420)
        self.configure(background="#d9f0fb")
        self.results = []
        self.hosts_by_item = {}
        self.services_by_item = {}
        self.metadata_by_item = {}
        self.favorite_hosts_by_item = {}
        self.sort_descending = {}
        self.events: queue.Queue = queue.Queue()
        self.update_events: queue.Queue = queue.Queue()
        self.available_update: Update | None = None
        self.update_flash_on = False
        self.discovery_active = False
        self.discovery_flash_on = False
        self.scheduled_scan_id: str | None = None
        self.active_scan_target = ""
        self.ssh_username = getpass.getuser()
        self.cancel_scan = threading.Event()
        self.network_presets = []
        self.favorites_path = Path.home() / ".config" / "advanced-ip-analyser" / "favorites.json"
        try:
            self.app_icon = tk.PhotoImage(file=Path(__file__).with_name("assets") / "advanced-ip-analyser.png")
            self.iconphoto(True, self.app_icon)
        except tk.TclError:
            self.app_icon = None
        self._configure_styles()
        self._build()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#d9f0fb")
        style.configure("TLabel", background="#d9f0fb", foreground="#17324d")
        style.configure("TButton", padding=(9, 5), background="#d7eefa", foreground="#17324d")
        style.map("TButton", background=[("active", "#b9e0f4")])
        style.configure("Accent.TButton", background="#42b96d", foreground="#082b16", font=("TkDefaultFont", 9, "bold"))
        style.map("Accent.TButton", background=[("active", "#62c985"), ("disabled", "#b9d9c4")])
        style.configure("Danger.TButton", background="#f3c7c7", foreground="#6e1717")
        style.map("Danger.TButton", background=[("active", "#efa9a9")])
        style.configure("Update.TButton", background="#ffd34f", foreground="#3f2b00",
                        font=("TkDefaultFont", 9, "bold"))
        style.configure("UpdateFlash.TButton", background="#ff8a3d", foreground="#321300",
                        font=("TkDefaultFont", 9, "bold"))
        style.configure("Discovery.TButton", background="#77c8ee", foreground="#102f49",
                        font=("TkDefaultFont", 9, "bold"))
        style.configure("DiscoveryFlash.TButton", background="#c4ebff", foreground="#102f49",
                        font=("TkDefaultFont", 9, "bold"))
        style.configure("Green.Horizontal.TProgressbar", troughcolor="#d9eee0",
                        background="#31b85c", lightcolor="#54cd78", darkcolor="#249648",
                        bordercolor="#8bc9a0")
        style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#17324d", rowheight=25)
        style.configure("Treeview.Heading", background="#80c7e8", foreground="#102f49", font=("TkDefaultFont", 9, "bold"))
        style.map("Treeview", background=[("selected", "#4aa8d8")], foreground=[("selected", "#ffffff")])

    def _build(self) -> None:
        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text="Target").pack(side="left")
        self.target = ttk.Entry(header)
        self.target.insert(0, "192.168.1.0/24")
        self.target.pack(side="left", fill="x", expand=True, padx=8)
        self.subnets = ttk.Combobox(header, width=24, state="readonly")
        self.subnets.pack(side="left", padx=(0, 8))
        self.subnets.bind("<<ComboboxSelected>>", self.use_selected_subnet)
        ttk.Button(header, text="Interfaces", command=self.refresh_subnets).pack(side="left", padx=(0, 8))
        ttk.Button(header, text="/24", command=self.use_24_subnet).pack(side="left", padx=(0, 8))
        self.scan_button = ttk.Button(header, text="Scan", command=self.start_scan, style="Accent.TButton")
        self.scan_button.pack(side="left")
        self.cancel_button = ttk.Button(header, text="Cancel", command=self.cancel_current_scan, state="disabled")
        self.cancel_button.pack(side="left", padx=(8, 0))
        ttk.Button(header, text="Export…", command=self.save_export).pack(side="left", padx=(8, 0))
        ttk.Button(header, text="Import…", command=self.load_inventory).pack(side="left", padx=(8, 0))

        settings = ttk.Frame(self, padding=(12, 0, 12, 8))
        settings.pack(fill="x")
        ttk.Label(settings, text="TCP ports").pack(side="left")
        self.ports = ttk.Entry(settings, width=34)
        self.ports.insert(0, COMMON_PORTS)
        self.ports.pack(side="left", padx=(6, 12))
        self.ports.bind("<Button-3>", self._show_ports_menu)
        self.ports_menu = tk.Menu(self, tearoff=False)
        self.ports_menu.add_command(label="Common service ports", command=lambda: self.set_port_preset(COMMON_PORTS))
        self.ports_menu.add_command(label="Web and application ports", command=lambda: self.set_port_preset(WEB_APP_PORTS))
        self.ports_menu.add_command(label="All TCP ports (1–65535)", command=self.set_all_ports)
        self.ports_menu.add_separator()
        self.ports_menu.add_command(label="Clear", command=lambda: self.set_port_preset(""))
        ttk.Label(settings, text="Timeout (s)").pack(side="left")
        self.timeout = ttk.Spinbox(settings, from_=0.05, to=10, increment=0.05, width=6)
        self.timeout.set("0.35")
        self.timeout.pack(side="left", padx=(6, 12))
        ttk.Label(settings, text="Workers").pack(side="left")
        self.workers = ttk.Spinbox(settings, from_=1, to=512, width=6)
        self.workers.set("64")
        self.workers.pack(side="left", padx=(6, 12))
        ttk.Label(settings, text="Profile").pack(side="left")
        self.profile = ttk.Combobox(settings, values=("Fast", "Balanced", "Accurate", "Adaptive"),
                                    state="readonly", width=9)
        self.profile.set("Balanced")
        self.profile.pack(side="left", padx=(6, 12))
        self.profile.bind("<<ComboboxSelected>>", self.apply_scan_profile)
        ttk.Label(settings, text="Filter").pack(side="left")
        self.filter_text = tk.StringVar()
        self.filter_text.trace_add("write", lambda *_args: self._refresh_table())
        self.filter_entry = ttk.Entry(settings, textvariable=self.filter_text)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))

        scope_options = ttk.Frame(self, padding=(12, 0, 12, 8))
        scope_options.pack(fill="x")
        ttk.Label(scope_options, text="Exclude IP/range/CIDR").pack(side="left")
        self.exclusions = ttk.Entry(scope_options)
        self.exclusions.pack(side="left", fill="x", expand=True, padx=(6, 12))
        ttk.Label(scope_options, text="Repeat").pack(side="left")
        self.repeat_scan = ttk.Combobox(scope_options,
                                        values=("Off", "Every 5 minutes", "Every 15 minutes",
                                                "Every 30 minutes", "Every 60 minutes"),
                                        state="readonly", width=18)
        self.repeat_scan.set("Off")
        self.repeat_scan.pack(side="left", padx=(6, 0))

        actions = ttk.Frame(self, padding=(12, 0, 12, 8))
        actions.pack(fill="x")
        ttk.Button(actions, text="Copy IP", command=self.copy_selected_ips).pack(side="left")
        ttk.Button(actions, text="Add favorite", command=self.add_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="View favorites", command=self.show_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Refresh favorites", command=self.refresh_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Wake", command=self.wake_selected).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Ping", command=lambda: self.run_selected_tool("ping")).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Trace", command=lambda: self.run_selected_tool("trace")).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Web audit…", command=self.open_web_audit).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="AI analysis…", command=self.show_ai_analysis).pack(side="left", padx=(8, 0))
        packet_button = ttk.Menubutton(actions, text="Packets ▾")
        packet_button.pack(side="left", padx=(8, 0))
        packet_menu = tk.Menu(packet_button, tearoff=False)
        packet_menu.add_command(label="Network Watch…", command=self.open_network_watch)
        packet_menu.add_command(label="Passive Wi-Fi Watch…", command=self.open_wifi_watch)
        packet_menu.add_separator()
        packet_menu.add_command(label="Capture selected host/service",
                                command=self.capture_selected_packets)
        packet_menu.add_command(label="Open capture file for selection…",
                                command=self.open_packet_capture)
        packet_menu.add_command(label="Show capture interfaces", command=self.show_capture_interfaces)
        packet_button.configure(menu=packet_menu)
        ttk.Label(actions, text="Export uses selected rows when any are selected.").pack(side="right")

        remote_actions = ttk.Frame(self, padding=(12, 0, 12, 8))
        remote_actions.pack(fill="x")
        ttk.Label(remote_actions, text="Remote administration").pack(side="left")
        ttk.Button(remote_actions, text="Shutdown", command=lambda: self.power_selected("shutdown"),
                   style="Danger.TButton").pack(side="left", padx=(8, 0))
        ttk.Button(remote_actions, text="Reboot", command=lambda: self.power_selected("reboot"),
                   style="Danger.TButton").pack(side="left", padx=(8, 0))
        ttk.Button(remote_actions, text="Abort shutdown",
                   command=lambda: self.power_selected("cancel")).pack(side="left", padx=(8, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12)
        results_page = ttk.Frame(self.notebook)
        self.favorites_page = ttk.Frame(self.notebook)
        self.notebook.add(results_page, text="Scan results")
        self.notebook.add(self.favorites_page, text="Favorites")

        columns = ("address", "state", "hostname", "latency", "mac", "manufacturer",
                   "device_type", "operating_system", "model", "services")
        self.table = ttk.Treeview(results_page, columns=columns, show="tree headings", selectmode="extended")
        self.table.heading("#0", text="Ports")
        self.table.column("#0", width=70, minwidth=55, stretch=False, anchor="w")
        widths = (130, 55, 170, 75, 135, 170, 140, 150, 130, 260)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.replace("_", " ").title(),
                               command=lambda selected=column: self._sort_column(selected))
            self.table.column(column, width=width, anchor="w")
        table_scroll = ttk.Scrollbar(results_page, orient="horizontal", command=self.table.xview)
        self.table.configure(xscrollcommand=table_scroll.set)
        self.table.pack(fill="both", expand=True)
        table_scroll.pack(fill="x")
        self.table.tag_configure("even", background="#ffffff")
        self.table.tag_configure("odd", background="#e4f5ff")
        self.table.tag_configure("detail", background="#f1f9fe", foreground="#315c78")
        self.table.tag_configure("detail_click", background="#f1f9fe", foreground="#0969b0",
                                 font=("TkDefaultFont", 9, "underline"))
        self.table.tag_configure("metadata", background="#f8fcff", foreground="#315c78")
        self.table.bind("<<TreeviewSelect>>", self._show_web_links)
        self.table.bind("<Double-1>", self._open_row_web_service)
        self.table.bind("<Return>", self._activate_selected_row)
        self.table.bind("<Button-3>", self._show_table_menu)

        self.table_menu = tk.Menu(self, tearoff=False)
        self.table_menu.add_command(label="Open service", command=self._activate_selected_row)
        self.table_menu.add_command(label="Copy row detail", command=self.copy_selected_detail)
        self.table_menu.add_command(label="Ping", command=lambda: self.run_selected_tool("ping"))
        self.table_menu.add_command(label="Trace route", command=lambda: self.run_selected_tool("trace"))
        self.table_menu.add_command(label="Capture packets for selection", command=self.capture_selected_packets)
        self.table_menu.add_command(label="Open capture file…", command=self.open_packet_capture)
        self.table_menu.add_separator()
        self.table_menu.add_command(label="Expand all ports", command=lambda: self.set_all_expanded(True))
        self.table_menu.add_command(label="Collapse all ports", command=lambda: self.set_all_expanded(False))

        favorite_columns = ("address", "hostname", "mac", "manufacturer", "device_type",
                            "operating_system", "model", "services", "seen", "note")
        self.favorites_table = ttk.Treeview(
            self.favorites_page, columns=favorite_columns, show="headings", selectmode="extended")
        for column in favorite_columns:
            self.favorites_table.heading(column, text=column.title())
            self.favorites_table.column(column, width=145 if column != "note" else 240, anchor="w")
        self.favorites_table.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        favorite_actions = ttk.Frame(self.favorites_page, padding=8)
        favorite_actions.pack(fill="x")
        ttk.Button(favorite_actions, text="Edit note", command=self.edit_favorite_note).pack(side="left")
        ttk.Button(favorite_actions, text="Remove selected", command=self.remove_selected_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(favorite_actions, text="Export selected…", command=self.export_selected_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(favorite_actions, text="Refresh devices", command=self.refresh_favorites).pack(side="left", padx=(8, 0))
        self._refresh_favorites_table()

        self.links = ttk.Frame(self, padding=(12, 8, 12, 0))
        self.links.pack(fill="x")
        ttk.Label(self.links, text="Open services:").pack(side="left")
        self.link_area = ttk.Frame(self.links)
        self.link_area.pack(side="left", padx=8)

        footer = ttk.Frame(self, padding=12)
        footer.pack(fill="x")
        footer.columnconfigure(0, weight=1, uniform="footer-side")
        footer.columnconfigure(2, weight=1, uniform="footer-side")
        self.status = ttk.Label(footer, text="Only scan networks you are authorized to manage.")
        self.status.grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(footer, mode="determinate", length=260,
                                        style="Green.Horizontal.TProgressbar")
        self.progress.grid(row=0, column=1, padx=18)
        footer_actions = ttk.Frame(footer)
        footer_actions.grid(row=0, column=2, sticky="e")
        ttk.Label(footer_actions, text="© 2026 Daren Loxley (2E0LXY)").pack(side="right", padx=18)
        ttk.Label(footer_actions, text=f"Version {__version__}").pack(side="right", padx=(0, 12))
        ttk.Button(footer_actions, text="Help", command=self.show_help).pack(side="right", padx=(0, 8))
        ttk.Button(footer_actions, text="AI Settings", command=self.show_ai_settings).pack(
            side="right", padx=(0, 8))
        self.discovery_button = ttk.Button(footer_actions, text="Please wait · discovering details…",
                                           style="Discovery.TButton")
        self.discovery_button.pack(side="right", padx=(0, 8))
        self.discovery_button.pack_forget()
        self.update_button = ttk.Button(footer_actions, text="Update available", style="Update.TButton",
                                        command=self.install_available_update)
        self.update_button.pack(side="right", padx=(0, 8))
        self.update_button.pack_forget()
        self.bind_all("<F5>", lambda _event: self.start_scan())
        self.bind_all("<Escape>", lambda _event: self.cancel_current_scan())
        self.bind_all("<Control-f>", lambda _event: self.filter_entry.focus_set())
        self.bind_all("<Control-o>", lambda _event: self.load_inventory())
        self.bind_all("<Control-s>", lambda _event: self.save_export())
        self.bind_all("<Control-Shift-C>", lambda _event: self.copy_selected_detail())
        self.refresh_subnets(show_errors=False)
        self.after(1500, self.check_updates)

    def show_ai_analysis(self) -> None:
        try:
            settings = load_ai_settings()
        except (OSError, ValueError) as error:
            messagebox.showerror("AI settings unavailable", str(error), parent=self)
            return
        model_name = settings.selected_model()
        if not model_name:
            messagebox.showinfo(
                "Configure AI first",
                "Open AI Settings, select a provider, refresh its live models, and save a model.",
                parent=self)
            return
        selected = self.selected_hosts()
        hosts = selected or list(self.results)
        if not hosts:
            messagebox.showinfo("No evidence available", "Run a scan or select discovered assets first.", parent=self)
            return
        try:
            history = {
                "scan_history": latest_evidence(),
                "network_watch": latest_network_watch_evidence(),
            }
        except (OSError, ValueError):
            history = {"unavailable": "Scan history could not be read."}

        window = tk.Toplevel(self)
        window.title("AI Evidence Analysis")
        window.geometry("980x760")
        window.minsize(760, 600)
        window.transient(self)
        preview_holder = {"preview": None}
        result_events: queue.Queue = queue.Queue()

        controls = ttk.Frame(window, padding=14)
        controls.pack(fill="x")
        ttk.Label(controls, text="AI Evidence Analysis",
                  font=("TkDefaultFont", 15, "bold")).grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(controls, text=f"Provider: {settings.provider} · Model: {model_name} · Assets: {len(hosts)}",
                  wraplength=900).grid(row=1, column=0, columnspan=4, sticky="w", pady=(3, 10))
        ttk.Label(controls, text="Analysis").grid(row=2, column=0, sticky="w")
        mode = tk.StringVar(value=next(iter(ANALYSIS_MODES)))
        mode_box = ttk.Combobox(controls, textvariable=mode, values=tuple(ANALYSIS_MODES),
                                state="readonly", width=43)
        mode_box.grid(row=2, column=1, sticky="ew", padx=(8, 12))
        include_identifiers = tk.BooleanVar(value=False)
        include_metadata = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Include IP/MAC/hostnames",
                        variable=include_identifiers).grid(row=2, column=2, sticky="w")
        ttk.Checkbutton(controls, text="Include safe service metadata",
                        variable=include_metadata).grid(row=3, column=2, sticky="w")
        ttk.Label(controls, text="Question (optional)").grid(row=3, column=0, sticky="w", pady=(8, 0))
        question = ttk.Entry(controls)
        question.grid(row=3, column=1, sticky="ew", padx=(8, 12), pady=(8, 0))
        controls.columnconfigure(1, weight=1)

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        preview_page, result_page = ttk.Frame(notebook), ttk.Frame(notebook)
        notebook.add(preview_page, text="Outbound data preview")
        notebook.add(result_page, text="Advisory result")
        preview_text = tk.Text(preview_page, wrap="none", font=("TkFixedFont", 9), state="disabled")
        result_text = tk.Text(result_page, wrap="word", font=("TkDefaultFont", 10), state="disabled")
        preview_text.pack(fill="both", expand=True)
        result_text.pack(fill="both", expand=True)

        status = ttk.Label(window, text="Build and inspect the exact outbound preview before running AI.",
                           padding=(14, 4), wraplength=930)
        status.pack(fill="x")
        confirmed = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            window,
            text="I reviewed this preview and approve sending it to the selected provider.",
            variable=confirmed).pack(anchor="w", padx=14, pady=(2, 6))

        def set_text(widget: tk.Text, value: str) -> None:
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", value)
            widget.configure(state="disabled")

        def invalidate(_event=None) -> None:
            preview_holder["preview"] = None
            confirmed.set(False)
            run_button.configure(state="disabled")
            status.configure(text="Options changed. Build and review a new outbound preview.")

        def build_preview() -> None:
            try:
                preview = build_analysis_preview(
                    hosts, history, mode=mode.get(), provider=settings.provider, model=model_name,
                    question=question.get(), include_identifiers=include_identifiers.get(),
                    include_service_metadata=include_metadata.get(),
                    max_chars=settings.max_request_chars)
            except ValueError as error:
                messagebox.showerror("Could not build preview", str(error), parent=window)
                return
            preview_holder["preview"] = preview
            confirmed.set(False)
            set_text(preview_text, preview.payload)
            notebook.select(preview_page)
            run_button.configure(state="normal")
            status.configure(text=(f"Preview ready: {len(preview.payload):,} characters and "
                                   f"{preview.asset_count} asset(s). Review it before approval."))

        def drain_results() -> None:
            if not window.winfo_exists():
                return
            try:
                outcome, value = result_events.get_nowait()
            except queue.Empty:
                window.after(75, drain_results)
                return
            run_button.configure(state="normal")
            if outcome == "error":
                status.configure(text=str(value))
                messagebox.showerror("AI analysis failed", str(value), parent=window)
                return
            set_text(result_text, value)
            notebook.select(result_page)
            status.configure(text="Advisory analysis complete. Confirm important findings from primary evidence.")

        def run_analysis() -> None:
            preview = preview_holder["preview"]
            if preview is None:
                messagebox.showinfo("Preview required", "Build and inspect the outbound preview first.", parent=window)
                return
            if not confirmed.get():
                messagebox.showinfo("Approval required", "Approve the reviewed preview before sending it.", parent=window)
                return
            run_button.configure(state="disabled")
            status.configure(text=f"Waiting for {settings.provider}…")

            def worker() -> None:
                try:
                    key = load_api_key(settings.provider)
                    answer = generate_text(settings.provider, model_name, key, SYSTEM_INSTRUCTION,
                                           preview.prompt)
                    result_events.put(("result", answer))
                except (ValueError, SecretStoreError, AIProviderError) as error:
                    result_events.put(("error", error))

            threading.Thread(target=worker, daemon=True).start()
            window.after(75, drain_results)

        def copy_result() -> None:
            value = result_text.get("1.0", "end-1c")
            if not value:
                return
            self.clipboard_clear()
            self.clipboard_append(value)
            status.configure(text="Advisory result copied to the clipboard.")

        for variable in (mode, include_identifiers, include_metadata):
            variable.trace_add("write", invalidate)
        question.bind("<KeyRelease>", invalidate)
        buttons = ttk.Frame(window, padding=(14, 0, 14, 14))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        run_button = ttk.Button(buttons, text="Run approved analysis", command=run_analysis,
                                style="Accent.TButton", state="disabled")
        run_button.pack(side="right", padx=(0, 8))
        ttk.Button(buttons, text="Build preview", command=build_preview).pack(side="right", padx=(0, 8))
        ttk.Button(buttons, text="Copy result", command=copy_result).pack(side="left")

    def show_ai_settings(self) -> None:
        window = tk.Toplevel(self)
        window.title("AI Settings")
        window.geometry("700x570")
        window.minsize(620, 520)
        window.transient(self)

        try:
            saved = load_ai_settings()
            settings_error = ""
        except (OSError, ValueError) as error:
            saved = AISettings()
            settings_error = f"Existing settings could not be loaded: {error}"

        content = ttk.Frame(window, padding=18)
        content.pack(fill="both", expand=True)
        ttk.Label(content, text="AI Settings", font=("TkDefaultFont", 16, "bold")).pack(anchor="w")
        ttk.Label(
            content,
            text=("Choose OpenAI, Gemini, or OpenRouter and load the models currently available "
                  "to your own account. Each provider has a separate key. Nothing is sent to an "
                  "AI service until you explicitly approve an analysis preview."),
            justify="left", wraplength=610).pack(anchor="w", fill="x", pady=(6, 16))

        form = ttk.Frame(content)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        provider = tk.StringVar(value=saved.provider)
        selected_models = dict(saved.models)
        model = tk.StringVar(value=saved.selected_model())
        api_key = tk.StringVar()

        ttk.Label(form, text="Provider").grid(row=0, column=0, sticky="w", pady=5)
        provider_box = ttk.Combobox(form, textvariable=provider, values=PROVIDERS,
                                    state="readonly")
        provider_box.grid(row=0, column=1, sticky="ew", padx=(12, 0), pady=5)
        ttk.Label(form, text="Model").grid(row=1, column=0, sticky="w", pady=5)
        model_box = ttk.Combobox(form, textvariable=model, values=(), state="normal")
        model_box.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=5)
        refresh_button = ttk.Button(form, text="Refresh models")
        refresh_button.grid(row=1, column=2, padx=(8, 0), pady=5)
        ttk.Label(form, text="API key").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(form, textvariable=api_key, show="•").grid(
            row=2, column=1, sticky="ew", padx=(12, 0), pady=5)
        ttk.Label(form, text="Leave blank to use the saved key for this provider.",
                  font=("TkDefaultFont", 8)).grid(row=3, column=1, sticky="w", padx=(12, 0))

        status = ttk.Label(content, text=settings_error, justify="left", wraplength=610)
        status.pack(anchor="w", fill="x", pady=(14, 8))

        status.configure(text=settings_error or "Choose a provider, then save a key or refresh its live model list.")

        ttk.Separator(content).pack(fill="x", pady=8)
        ttk.Label(content, text="Safe AI feature direction", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
        ttk.Label(
            content,
            text=("• Explain selected ports, services, and configuration findings\n"
                  "• Summarize a scan or Network Watch session after a preview and confirmation\n"
                  "• Suggest display filters from plain language, then validate them locally\n"
                  "• Draft a redacted troubleshooting, topology, or inventory report\n"
                  "• Prioritize evidence-backed anomalies and defensive remediation drafts\n\n"
                  "AI output would be advisory and must not trigger scans, exploits, remote actions, "
                  "or configuration changes."),
            justify="left", wraplength=610).pack(anchor="w", fill="x", pady=(5, 10))

        model_events: queue.Queue = queue.Queue()

        def update_provider(_event=None) -> None:
            model.set(selected_models.get(provider.get(), ""))
            model_box.configure(values=())
            status.configure(
                text=f"{provider.get()} selected. Enter a key or use its saved key, then refresh models.")

        provider_box.bind("<<ComboboxSelected>>", update_provider)

        def drain_model_events() -> None:
            if not window.winfo_exists():
                return
            try:
                outcome, value = model_events.get_nowait()
            except queue.Empty:
                window.after(75, drain_model_events)
                return
            refresh_button.configure(state="normal")
            if outcome == "error":
                messagebox.showerror("Could not load models", str(value), parent=window)
                status.configure(text=str(value))
                return
            requested_provider, choices = value
            if provider.get() != requested_provider:
                status.configure(text=f"Loaded {len(choices)} {requested_provider} models; select that provider to view them.")
                return
            identifiers = tuple(choice.identifier for choice in choices)
            model_box.configure(values=identifiers)
            if model.get() not in identifiers:
                model.set(identifiers[0])
            status.configure(text=f"Loaded {len(identifiers)} live {requested_provider} text-generation models.")

        def refresh_models() -> None:
            requested_provider = provider.get()
            supplied_key = api_key.get()
            refresh_button.configure(state="disabled")
            status.configure(text=f"Loading live models from {requested_provider}…")

            def worker() -> None:
                try:
                    key = supplied_key or load_api_key(requested_provider)
                    choices = list_models(requested_provider, key)
                    model_events.put(("models", (requested_provider, choices)))
                except (ValueError, SecretStoreError, AIProviderError) as error:
                    model_events.put(("error", error))

            threading.Thread(target=worker, daemon=True).start()
            window.after(75, drain_model_events)

        refresh_button.configure(command=refresh_models)

        def save() -> None:
            try:
                selected_models[provider.get()] = model.get()
                clean = AISettings(provider.get(), selected_models, saved.max_request_chars)
                save_ai_settings(clean)
                if api_key.get():
                    save_api_key(provider.get(), api_key.get())
                    api_key.set("")
                    message = f"Settings saved. The {provider.get()} key is stored in the desktop keyring."
                else:
                    message = f"Settings saved. The {provider.get()} key was left unchanged."
            except (OSError, ValueError, SecretStoreError) as error:
                messagebox.showerror("Could not save AI settings", str(error), parent=window)
                return
            status.configure(text=message)

        def delete_key() -> None:
            if not messagebox.askyesno(
                    "Delete saved API key", f"Delete the {provider.get()} API key from your desktop keyring?",
                    parent=window):
                return
            try:
                clear_api_key(provider.get())
            except SecretStoreError as error:
                messagebox.showerror("Could not delete API key", str(error), parent=window)
                return
            api_key.set("")
            status.configure(text=f"The saved {provider.get()} API key was deleted from the desktop keyring.")

        buttons = ttk.Frame(content)
        buttons.pack(fill="x", side="bottom", pady=(8, 0))
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        ttk.Button(buttons, text="Save settings", command=save,
                   style="Accent.TButton").pack(side="right", padx=(0, 8))
        ttk.Button(buttons, text="Delete saved key", command=delete_key,
                   style="Danger.TButton").pack(side="left")
        update_provider()

    def show_help(self) -> None:
        window = tk.Toplevel(self)
        window.title(f"Advanced IP Analyser Help · {__version__}")
        window.geometry("1000x820")
        window.minsize(760, 560)
        window.transient(self)

        heading = ttk.Frame(window, padding=(18, 14, 18, 8))
        heading.pack(fill="x")
        ttk.Label(heading, text="Advanced IP Analyser Help",
                  font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Button(heading, text="Close", command=window.destroy).pack(side="right", padx=(12, 0))
        ttk.Button(heading, text="Check for updates",
                   command=lambda: self.check_updates(manual=True)).pack(side="right", padx=(12, 0))
        ttk.Label(heading, text=f"Version {__version__}").pack(side="right")

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        assets = Path(__file__).with_name("assets")
        window.help_images = []

        def add_tab(title: str, body: str, image_name: str | None = None) -> None:
            tab = ttk.Frame(notebook, padding=16)
            notebook.add(tab, text=title)
            ttk.Label(tab, text=title, font=("TkDefaultFont", 13, "bold")).pack(anchor="w")
            ttk.Label(tab, text=body, justify="left", wraplength=920).pack(anchor="w", fill="x", pady=(8, 12))
            if image_name:
                try:
                    picture = tk.PhotoImage(file=assets / image_name)
                    window.help_images.append(picture)
                    ttk.Label(tab, image=picture).pack(anchor="center", pady=(4, 0))
                except tk.TclError:
                    ttk.Label(tab, text="Help image is unavailable in this installation.").pack(anchor="w")

        add_tab("Getting started",
                "1. Choose an active interface preset or enter one IP, an inclusive range, or a CIDR.\n"
                "2. Set the TCP ports, timeout, and worker count. The defaults cover common network services.\n"
                "   Fast, Balanced, Accurate, and Adaptive profiles provide useful timeout/concurrency presets.\n"
                "3. Press Scan (F5). Reachable devices appear as they are found; press Escape to cancel safely.\n"
                "   The fast address/port scan completes first. A separate flashing discovery indicator then shows progress while server details are collected.\n"
                "4. Use Filter (Ctrl+F) to search addresses, names, MACs, manufacturers, services, and notes.\n\n"
                "Only scan networks and devices you own or are authorized to administer.",
                "help-overview.png")
        add_tab("Ports and services",
                "A disclosure arrow appears beside every host with detected TCP ports. Expand it to see one row per port.\n\n"
                "Blue underlined service rows are openable. Double-click one, select it and press Enter, or right-click and choose Open service. "
                "HTTP, HTTPS, and FTP use the desktop URL handler; SMB uses the file manager; SSH and Telnet open a terminal; RDP uses FreeRDP. "
                "When opening SSH, enter the remote account username first; the terminal then requests that account's password if needed. "
                "The most recent username is remembered only until the application closes. "
                "Expand a port row again to see safely discovered details such as the HTTP status, Apache/nginx/IIS Server header, page title, "
                "content type, redirect, authentication realm, TLS version/cipher, or a protocol greeting. Availability depends on what the server exposes.\n\n"
                "Right-click to copy a row detail or expand/collapse every host. Parent-row double-click opens HTTPS or HTTP when available. "
                "Discovery is read-only, bounded, and never attempts authentication.",
                "help-port-details.png")
        add_tab("Favorites and inventory",
                "Add favorite stores selected devices in ~/.config/advanced-ip-analyser/favorites.json and shows them in the Favorites tab. Devices are identified by MAC address first, "
                "so a later scan can update an IP address without losing the saved note. Refresh favorites rescans saved addresses.\n\n"
                "Export writes selected rows—or all visible rows when nothing is selected—to CSV, JSON, XML, or escaped HTML. "
                "Import accepts this application's bounded JSON and XML formats and merges devices into the table and favorites. "
                "Use Ctrl+O to import and Ctrl+S to export.")
        add_tab("Device actions",
                "Copy IP copies selected host addresses. Wake sends a confirmed Wake-on-LAN magic packet to selected devices with MAC addresses.\n\n"
                "Shutdown, Reboot, and Abort shutdown require confirmation and use non-interactive SSH. Configure SSH keys and passwordless permission for "
                "sudo shutdown on machines you administer. Power actions are delayed one minute so they can be aborted. The application never asks for, stores, or forwards passwords. "
                "Ping and Trace open bounded Debian diagnostic commands in a terminal. "
                "Remote results are reported per host. Detected service links never bypass authentication.")
        add_tab("Packet analysis",
                "Advanced IP Analyser includes its own Debian packet-capture and analysis engine; Wireshark is not required. Select a host row to capture only traffic to or from that IP. "
                "Select an individual service row to additionally limit capture to its TCP or UDP port. Choose the active interface when prompted; 'any' captures across Linux interfaces.\n\n"
                "A live capture is bounded by time and packet count. Debian may show an administrator authorization prompt because raw packet capture requires elevated permission; the main application remains unprivileged. "
                "Open capture file reads bounded Ethernet PCAP, PCAPNG, and gzip-compressed captures and displays packet endpoints, protocols, ports, flags, and a byte preview.\n\n"
                "The display-filter bar supports IP addresses and CIDRs, TCP/UDP ports, DNS, HTTP, TLS, ICMP, ARP, TCP flags, frame length, comparisons, text matching, AND (&&), OR (||), NOT (!), and parentheses. "
                "Quick filters provide 20 common starting points and named filters can be saved. These filters change only the displayed rows, never the recording.\n\n"
                "Capture only traffic you are authorized to inspect. Encrypted payloads remain encrypted and this tool does not bypass authentication or encryption.")
        add_tab("Network Watch",
                "Packets → Network Watch opens continuous, time-based analysis. Start with Headers only unless complete payload retention is specifically required. "
                "The dashboard shows traffic over time, devices, bidirectional conversations, DNS activity, protocol/service usage, TCP health, explainable findings, and saved session history.\n\n"
                "Findings highlight new devices, connection fan-out, traffic increases, DNS failures, resets, retransmissions, unanswered connections, and unusually regular timing. "
                "Alert rules can watch traffic thresholds, destinations, ports, domain text, failed connections, or new devices. Reports export to HTML, JSON, or CSV.\n\n"
                "Recordings and analysis remain local. Old unbookmarked watch captures are limited by age and storage; bookmarked recordings are retained. Encrypted content is never decrypted.")
        add_tab("Passive Wi-Fi Watch",
                "Packets → Passive Wi-Fi Watch discovers nearby access points and observed clients using a compatible Linux wireless adapter. "
                "It shows network name, BSSID, channel, approximate signal, security type, beacon/data counts, client addresses, probe names, and whether WPA authentication traffic was observed.\n\n"
                "The adapter must support monitor mode. A temporary virtual monitor interface is created through PolicyKit and removed when the watch stops, leaving the normal interface unchanged where the driver supports concurrent interfaces. "
                "The feature is passive: it does not send deauthentication frames, inject traffic, disconnect clients, or attempt password recovery.")
        add_tab("AI settings",
                "AI Settings supports OpenAI, Gemini, and OpenRouter with a separate key for each provider. "
                "Refresh models securely retrieves the live text-generation choices available to that key from the supplier's own API. "
                "Non-secret preferences are saved in ~/.config/advanced-ip-analyser/ai-settings.json; Debian's Secret Service keyring stores the keys through secret-tool.\n\n"
                "AI analysis builds a bounded evidence payload for classification, changes, exposure priorities, unknown services, rogue-infrastructure indicators, topology, natural-language search, defensive drafts, or capacity review. "
                "The exact outbound JSON is shown first. Identifiers are excluded by default, sensitive fields are removed, raw packet payloads are never included, and the request requires explicit approval. "
                "Results are advisory and cannot start scans, run privileged helpers, execute remote actions, or apply generated rules.")
        add_tab("Shortcuts",
                "F5 — start a scan\nEscape — cancel the active scan\nCtrl+F — focus the live filter\n"
                "Ctrl+O — import JSON or XML inventory\nCtrl+S — export inventory\nCtrl+Shift+C — copy selected host or service detail\n"
                "Enter — open the selected supported service\nDouble-click — open a service row or the preferred web service\n"
                "Right-click — open service, copy detail, expand all, or collapse all")

    def check_updates(self, manual: bool = False) -> None:
        if manual:
            self.status.configure(text="Checking GitHub for updates…")
        threading.Thread(target=self._check_updates_worker, args=(manual,), daemon=True).start()
        self.after(50, self._drain_update_events)

    def _check_updates_worker(self, manual: bool) -> None:
        try:
            update = check_for_update(__version__)
            self.update_events.put(("available" if update else "current", update, manual))
        except Exception as error:
            self.update_events.put(("check_error", error, manual))

    def _drain_update_events(self) -> None:
        try:
            event, value, manual = self.update_events.get_nowait()
        except queue.Empty:
            self.after(50, self._drain_update_events)
            return
        if event == "available":
            self.available_update = value
            self.update_button.configure(text=f"Update to v{value.version}")
            self.update_button.pack(side="right", padx=(0, 8))
            self.status.configure(text=f"Version {value.version} is available")
            self._flash_update_button()
        elif event == "current":
            if manual:
                messagebox.showinfo("No update available", f"Version {__version__} is the latest release.")
            self.status.configure(text=f"Version {__version__} is up to date")
        elif event == "downloaded":
            try:
                package, update = value
                launch_installer(package, update)
                self.status.configure(text="Starting the updater; the application will reopen when installation finishes…")
                self.after(350, self.destroy)
            except OSError as error:
                self.update_button.configure(state="normal")
                messagebox.showerror("Cannot start updater", str(error))
        else:
            self.update_button.configure(state="normal")
            if manual or event == "download_error":
                messagebox.showerror("Update failed", str(value))
            if manual:
                self.status.configure(text="Could not check for updates")

    def _flash_update_button(self) -> None:
        if not self.available_update or not self.update_button.winfo_ismapped():
            return
        self.update_flash_on = not self.update_flash_on
        self.update_button.configure(style="UpdateFlash.TButton" if self.update_flash_on else "Update.TButton")
        self.after(650, self._flash_update_button)

    def install_available_update(self) -> None:
        update = self.available_update
        if not update:
            return
        if not messagebox.askyesno(
                "Install update",
                f"Download and install Advanced IP Analyser v{update.version}?\n\n"
                "The application will close, Debian will request administrator authorization, "
                "and the updated version will reopen automatically."):
            return
        self.update_button.configure(state="disabled", text=f"Downloading v{update.version}…")
        self.status.configure(text=f"Downloading verified update v{update.version}…")
        threading.Thread(target=self._download_update_worker, args=(update,), daemon=True).start()
        self.after(50, self._drain_update_events)

    def _download_update_worker(self, update: Update) -> None:
        try:
            self.update_events.put(("downloaded", (download_update(update), update), True))
        except Exception as error:
            self.update_events.put(("download_error", error, True))


    def start_scan(self) -> None:
        if self.scheduled_scan_id is not None:
            try:
                self.after_cancel(self.scheduled_scan_id)
            except tk.TclError:
                pass
            self.scheduled_scan_id = None
        try:
            targets = parse_targets(self.target.get())
            if self.exclusions.get().strip():
                excluded = set(parse_targets(self.exclusions.get()))
                targets = [target for target in targets if target not in excluded]
                if not targets:
                    raise ValueError("all scan targets were excluded")
            ports = parse_ports(self.ports.get(), limit=65_535)
            timeout = float(self.timeout.get())
            workers = int(self.workers.get())
            if timeout < 0.05 or workers < 1 or workers > 512:
                raise ValueError("timeout must be at least 0.05 and workers must be from 1 to 512")
        except (ValueError, TypeError) as error:
            messagebox.showerror("Invalid scan settings", str(error))
            return
        if len(ports) > 1024 and not messagebox.askyesno(
                "Confirm full TCP scan",
                f"Scan {len(ports):,} TCP ports on {len(targets):,} target(s)?\n\n"
                "This can take a long time, especially when firewalls silently drop connections."):
            return
        self.results.clear()
        self.hosts_by_item.clear()
        self.services_by_item.clear()
        self.metadata_by_item.clear()
        self.table.delete(*self.table.get_children())
        self._stop_discovery_indicator()
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.cancel_scan = threading.Event()
        self.active_scan_target = self.target.get().strip()
        self.progress.configure(maximum=len(targets), value=0)
        adaptive = self.profile.get() == "Adaptive"
        threading.Thread(target=self._scan_worker,
                         args=(targets, ports, timeout, workers, adaptive), daemon=True).start()
        self.after(50, self._drain_events)

    def _show_ports_menu(self, event) -> None:
        self.ports_menu.tk_popup(event.x_root, event.y_root)

    def set_port_preset(self, value: str) -> None:
        self.ports.delete(0, "end")
        self.ports.insert(0, value)
        self.status.configure(text="TCP port preset updated")

    def set_all_ports(self) -> None:
        if messagebox.askyesno("Use all TCP ports",
                               "Set the scan to all 65,535 TCP ports?\n\n"
                               "Use this on a small number of authorized targets. A full subnet scan may take a long time."):
            self.set_port_preset("1-65535")

    def apply_scan_profile(self, _event=None) -> None:
        profiles = {"Fast": ("0.15", "128"), "Balanced": ("0.35", "64"),
                    "Accurate": ("1.00", "32"), "Adaptive": ("0.50", "32")}
        timeout, workers = profiles[self.profile.get()]
        self.timeout.set(timeout)
        self.workers.set(workers)
        self.status.configure(text=f"{self.profile.get()} scan profile selected")

    def _scan_worker(self, targets: list[str], ports: dict[int, str], timeout: float,
                     workers: int, adaptive: bool = False) -> None:
        try:
            scanner = Scanner(timeout, workers, ports, adaptive=adaptive)
            results = scanner.scan(
                targets, lambda done, total, host: self.events.put(("host", done, total, host)),
                self.cancel_scan, discover_services=False)
            candidates = sum(bool(host.reachable and host.ports) for host in results)
            self.events.put(("scan_complete", results, len(targets), self.cancel_scan.is_set(), candidates))
            if not self.cancel_scan.is_set() and candidates:
                results = scanner.discover_all(
                    results, lambda done, total, host: self.events.put(("discovery", done, total, host)),
                    self.cancel_scan)
            self.events.put(("discovery_done", results, len(targets), self.cancel_scan.is_set(), candidates))
        except Exception as error:
            self.events.put(("error", error))

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "host":
                    _, done, total, host = event
                    if host.reachable:
                        self.results.append(host)
                        if self._matches_filter(host):
                            self._insert_host(host)
                    self.progress.configure(value=done)
                    self.status.configure(text=f"Scanned {done} of {total}")
                elif event[0] == "scan_complete":
                    scanned, total, cancelled, candidates = event[1], event[2], event[3], event[4]
                    self.results = [host for host in scanned if host.reachable]
                    self._refresh_table()
                    if cancelled or not candidates:
                        prefix = "Cancelled" if cancelled else "Finished"
                        self.status.configure(text=f"{prefix}: {len(self.results)} reachable; {len(scanned)} of {total} checked")
                    else:
                        self.progress.configure(maximum=candidates, value=0)
                        self.status.configure(text=f"Scan complete: {len(self.results)} reachable · discovering service details 0 of {candidates}")
                        self._start_discovery_indicator(candidates)
                elif event[0] == "discovery":
                    _, done, total, host = event
                    self.results = [host if existing.identity == host.identity else existing for existing in self.results]
                    self.progress.configure(maximum=total, value=done)
                    self.discovery_button.configure(text=f"Please wait · discovering {done}/{total}")
                    self.status.configure(text=f"Scan complete · discovering service details {done} of {total}")
                elif event[0] == "discovery_done":
                    scanned, total, cancelled, candidates = event[1], event[2], event[3], event[4]
                    self.results = [host for host in scanned if host.reachable]
                    self._refresh_table()
                    self._stop_discovery_indicator()
                    self.scan_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    prefix = "Cancelled" if cancelled else "Finished"
                    suffix = " · discovery cancelled" if cancelled and candidates else (" · discovery complete" if candidates else "")
                    self.status.configure(text=f"{prefix}: {len(self.results)} reachable; {len(scanned)} of {total} checked{suffix}")
                    if not cancelled:
                        threading.Thread(
                            target=self._save_scan_history,
                            args=(list(self.results), self.active_scan_target), daemon=True).start()
                    self._merge_results_into_favorites()
                    self._schedule_next_scan()
                    return
                elif event[0] == "power_done":
                    results = event[1]
                    failed = [result for result in results if not result.succeeded]
                    self.status.configure(text=f"Remote {results[0].action}: {len(results) - len(failed)} succeeded, {len(failed)} failed")
                    if failed:
                        messagebox.showwarning("Remote action results", "\n".join(
                            f"{result.host}: {result.detail}" for result in failed))
                elif event[0] == "packet_done":
                    _, path, records = event
                    self.status.configure(text=f"Packet analysis ready: {len(records):,} matching packet(s)")
                    PacketViewer(self, path, records)
                    return
                elif event[0] == "packet_error":
                    self.status.configure(text="Packet operation failed")
                    messagebox.showerror("Packet operation failed", str(event[1]))
                    return
                else:
                    self._stop_discovery_indicator()
                    self.scan_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    messagebox.showerror("Scan failed", str(event[1]))
                    return
        except queue.Empty:
            self.after(50, self._drain_events)

    @staticmethod
    def _save_scan_history(hosts: list[Host], target: str) -> None:
        try:
            record_scan(hosts, target)
        except (OSError, ValueError):
            # Optional history must never turn a successful network scan into a failure.
            return

    def _schedule_next_scan(self) -> None:
        repeat = self.repeat_scan.get()
        if repeat == "Off":
            return
        match = next((value for value in repeat.split() if value.isdigit()), "")
        if not match:
            return
        minutes = int(match)
        self.status.configure(text=f"{self.status.cget('text')} · next scan in {minutes} minutes")
        if self.scheduled_scan_id is not None:
            self.after_cancel(self.scheduled_scan_id)
        self.scheduled_scan_id = self.after(minutes * 60_000, self.start_scan)

    def _start_discovery_indicator(self, total: int) -> None:
        self.discovery_active = True
        self.discovery_button.configure(text=f"Please wait · discovering 0/{total}")
        self.discovery_button.pack(side="right", padx=(0, 8))
        self._flash_discovery_indicator()

    def _flash_discovery_indicator(self) -> None:
        if not self.discovery_active:
            return
        self.discovery_flash_on = not self.discovery_flash_on
        self.discovery_button.configure(
            style="DiscoveryFlash.TButton" if self.discovery_flash_on else "Discovery.TButton")
        self.after(600, self._flash_discovery_indicator)

    def _stop_discovery_indicator(self) -> None:
        self.discovery_active = False
        self.discovery_flash_on = False
        if hasattr(self, "discovery_button"):
            self.discovery_button.pack_forget()

    def _insert_host(self, host: Host) -> None:
        web_services = [service_url(service, host.address, port) if service in {"http", "https"} else service
                        for port, service in zip(host.ports, host.services)]
        stripe = "even" if len(self.table.get_children("")) % 2 == 0 else "odd"
        item = self.table.insert("", "end", text=f"{len(host.ports)} port{'s' if len(host.ports) != 1 else ''}",
            values=(host.address, "Up", host.hostname, host.latency_ms or "", host.mac,
                    host.manufacturer, host.device_type,
                    " ".join(value for value in (host.operating_system, host.os_version) if value),
                    host.model, ", ".join(web_services)), tags=(stripe,))
        self.hosts_by_item[item] = host
        for port, service in zip(host.ports, host.services):
            detail = service_url(service, host.address, port) if service in {"http", "https", "ftp"} else f"TCP {port} · {service}"
            info = host.service_info.get(str(port), {})
            server = info.get("Server") or info.get("Banner", "")
            service_label = service.upper() + (f" · {server}" if server else "")
            summary = info.get("Page title") or info.get("Status") or detail
            clickable = service in OPENABLE_SERVICES
            child = self.table.insert(item, "end", text=str(port),
                                      values=("", "Open", service_label, "", "", "", "", "", "", summary),
                                      tags=(("detail_click" if clickable else "detail"),))
            self.services_by_item[child] = (host, service, port)
            for label, value in info.items():
                metadata = self.table.insert(child, "end", text="",
                    values=("", "Detail", label, "", "", "", "", "", "", value), tags=("metadata",))
                self.metadata_by_item[metadata] = (label, value)

    def _matches_filter(self, host: Host) -> bool:
        term = self.filter_text.get().strip().casefold()
        metadata = " ".join(f"{label} {value}" for details in host.service_info.values()
                            for label, value in details.items())
        return not term or term in " ".join((host.address, host.hostname, host.mac, host.manufacturer,
                                              host.device_type, host.operating_system, host.os_version,
                                              host.model, " ".join(host.services), metadata,
                                              host.note)).casefold()

    def _refresh_table(self) -> None:
        if not hasattr(self, "table"):
            return
        self.table.delete(*self.table.get_children())
        self.hosts_by_item.clear()
        self.services_by_item.clear()
        self.metadata_by_item.clear()
        for host in self.results:
            if self._matches_filter(host):
                self._insert_host(host)

    def cancel_current_scan(self) -> None:
        self.cancel_scan.set()
        self.cancel_button.configure(state="disabled")
        self.status.configure(text="Cancelling scan…")

    def use_current_subnet(self) -> None:
        try:
            subnet = current_ipv4_subnet()
        except RuntimeError as error:
            messagebox.showerror("Subnet unavailable", str(error))
            return
        self.target.delete(0, "end")
        self.target.insert(0, subnet)

    def use_24_subnet(self) -> None:
        try:
            subnet = ipv4_24_target(self.target.get())
        except ValueError as error:
            messagebox.showerror("/24 unavailable", str(error))
            return
        self.target.delete(0, "end")
        self.target.insert(0, subnet)
        self.status.configure(text=f"Selected class-C-style subnet {subnet}")

    def refresh_subnets(self, show_errors: bool = True) -> None:
        try:
            self.network_presets = active_ipv4_networks()
        except RuntimeError as error:
            self.network_presets = []
            if show_errors:
                messagebox.showerror("Interfaces unavailable", str(error))
        labels = [f"{interface}: {network}" for interface, network, _broadcast in self.network_presets]
        self.subnets.configure(values=labels)
        if labels:
            self.subnets.current(0)

    def use_selected_subnet(self, _event=None) -> None:
        index = self.subnets.current()
        if index < 0 or index >= len(self.network_presets):
            return
        interface, network, _broadcast = self.network_presets[index]
        self.target.delete(0, "end")
        self.target.insert(0, network)
        self.status.configure(text=f"Selected {network} on {interface}")

    def selected_hosts(self) -> list[Host]:
        selected: list[Host] = []
        seen: set[str] = set()
        for item in self.table.selection():
            host = self.hosts_by_item.get(item)
            if host is None and item in self.services_by_item:
                host = self.services_by_item[item][0]
            if host is None and item in self.metadata_by_item:
                service_item = self.table.parent(item)
                if service_item in self.services_by_item:
                    host = self.services_by_item[service_item][0]
            if host is not None and host.identity not in seen:
                selected.append(host)
                seen.add(host.identity)
        return selected

    def _selected_packet_scope(self) -> tuple[list[Host], int | None]:
        hosts = self.selected_hosts()
        ports: set[int] = set()
        for item in self.table.selection():
            detail = self.services_by_item.get(item)
            if detail is None and item in self.metadata_by_item:
                detail = self.services_by_item.get(self.table.parent(item))
            if detail is not None:
                ports.add(detail[2])
        port = next(iter(ports)) if len(hosts) == 1 and len(ports) == 1 else None
        return hosts, port

    def _capture_interface_hint(self) -> str:
        index = self.subnets.current()
        if 0 <= index < len(self.network_presets):
            return self.network_presets[index][0]
        return "any"

    def capture_selected_packets(self) -> None:
        hosts, port = self._selected_packet_scope()
        if not hosts:
            messagebox.showinfo("Nothing selected", "Select one or more hosts or a service row first.")
            return
        interface = simpledialog.askstring(
            "Capture interface",
            "Capture interface (use 'any' for all Linux interfaces):",
            initialvalue=self._capture_interface_hint(), parent=self)
        if interface is None:
            return
        try:
            interface = validate_interface(interface)
        except ValueError as error:
            messagebox.showerror("Invalid capture interface", str(error))
            return
        duration = simpledialog.askinteger(
            "Capture duration", "Maximum capture time in seconds (1–300):",
            initialvalue=10, minvalue=1, maxvalue=300, parent=self)
        if duration is None:
            return
        addresses = [host.address for host in hosts]
        scope = f"{len(addresses)} selected host(s)" + (f" on TCP port {port}" if port else "")
        if not messagebox.askyesno(
                "Start packet capture",
                f"Capture {scope} on {interface} for up to {duration} seconds?\n\n"
                "Debian may request administrator authorization. Capture only traffic you are authorized to inspect."):
            return
        self.status.configure(text=f"Capturing {scope}…")
        threading.Thread(target=self._capture_packets_worker,
                         args=(addresses, interface, port, duration), daemon=True).start()
        self.after(50, self._drain_events)

    def _capture_packets_worker(self, addresses: list[str], interface: str,
                                port: int | None, duration: int) -> None:
        try:
            path = capture_live(addresses, interface, port, duration)
            self.events.put(("packet_done", path, read_capture(
                path, addresses, port, GUI_PACKET_LIMIT)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("packet_error", error))

    def open_network_watch(self) -> None:
        known = load_favorites(self.favorites_path)
        NetworkWatch(self, known)

    def open_wifi_watch(self) -> None:
        WifiWatch(self)

    def open_web_audit(self) -> None:
        initial = ""
        selected = self.selected_hosts()
        if selected:
            preferred = preferred_web_service(selected[0].services)
            if preferred:
                index = selected[0].services.index(preferred)
                initial = service_url(preferred, selected[0].address, selected[0].ports[index])
        WebSecurityAudit(self, initial)

    def open_packet_capture(self) -> None:
        name = filedialog.askopenfilename(filetypes=[
            ("Packet captures", "*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz"),
            ("All files", "*")])
        if not name:
            return
        hosts, port = self._selected_packet_scope()
        addresses = [host.address for host in hosts] or None
        self.status.configure(text="Reading packet capture…")
        threading.Thread(target=self._open_capture_worker,
                         args=(Path(name), addresses, port), daemon=True).start()
        self.after(50, self._drain_events)

    def _open_capture_worker(self, path: Path, addresses: list[str] | None,
                             port: int | None) -> None:
        try:
            self.events.put(("packet_done", path, read_capture(
                path, addresses, port, GUI_PACKET_LIMIT)))
        except (OSError, RuntimeError, ValueError) as error:
            self.events.put(("packet_error", error))

    def show_capture_interfaces(self) -> None:
        try:
            interfaces = list_capture_interfaces()
            details = "\n".join(f"{name} — {description}" for name, description in interfaces[:30])
            if len(interfaces) > 30:
                details += f"\n… and {len(interfaces) - 30} more"
            messagebox.showinfo("Capture interfaces", details)
        except (OSError, RuntimeError) as error:
            messagebox.showerror("Cannot list capture interfaces", str(error))

    def copy_selected_ips(self) -> None:
        hosts = self.selected_hosts()
        if not hosts:
            messagebox.showinfo("Nothing selected", "Select one or more hosts first.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(host.address for host in hosts))
        self.status.configure(text=f"Copied {len(hosts)} IP address(es)")

    def add_favorites(self) -> None:
        hosts = self.selected_hosts()
        if not hosts:
            messagebox.showinfo("Nothing selected", "Select one or more hosts first.")
            return
        try:
            existing = load_favorites(self.favorites_path)
            save_favorites(self.favorites_path, merge_devices(existing, hosts))
            self._refresh_favorites_table()
            self.status.configure(text=f"Saved {len(hosts)} device(s) to favorites")
        except (OSError, ValueError) as error:
            messagebox.showerror("Favorites failed", str(error))

    def _merge_results_into_favorites(self) -> None:
        try:
            saved = load_favorites(self.favorites_path)
            if saved:
                save_favorites(self.favorites_path, merge_devices(saved, self.results))
                self._refresh_favorites_table()
        except (OSError, ValueError) as error:
            self.status.configure(text=f"Scan finished; favorites refresh failed: {error}")

    def refresh_favorites(self) -> None:
        try:
            favorites = load_favorites(self.favorites_path)
        except (OSError, ValueError) as error:
            messagebox.showerror("Favorites failed", str(error))
            return
        if not favorites:
            messagebox.showinfo("No favorites", "Add devices to favorites before refreshing them.")
            return
        targets = [host.address for host in favorites]
        try:
            ports = parse_ports(self.ports.get(), limit=65_535)
            timeout, workers = float(self.timeout.get()), int(self.workers.get())
        except ValueError as error:
            messagebox.showerror("Invalid scan settings", str(error))
            return
        self.results.clear()
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.cancel_scan = threading.Event()
        self.progress.configure(maximum=len(targets), value=0)
        self.status.configure(text=f"Refreshing {len(targets)} saved device(s)…")
        adaptive = self.profile.get() == "Adaptive"
        threading.Thread(target=self._scan_worker,
                         args=(targets, ports, timeout, workers, adaptive), daemon=True).start()
        self.after(50, self._drain_events)

    def show_favorites(self) -> None:
        self._refresh_favorites_table(show_errors=True)
        self.notebook.select(self.favorites_page)

    def _refresh_favorites_table(self, show_errors: bool = False) -> None:
        try:
            favorites = load_favorites(self.favorites_path)
        except (OSError, ValueError) as error:
            if show_errors:
                messagebox.showerror("Favorites failed", str(error))
            return
        self.favorites_table.delete(*self.favorites_table.get_children())
        self.favorite_hosts_by_item.clear()
        for host in favorites:
            item = self.favorites_table.insert("", "end", values=(
                host.address, host.hostname, host.mac, host.manufacturer,
                host.device_type, " ".join(value for value in (
                    host.operating_system, host.os_version) if value), host.model,
                ", ".join(host.services), host.seen_at, host.note))
            self.favorite_hosts_by_item[item] = host

    def selected_favorite_hosts(self) -> list[Host]:
        return [self.favorite_hosts_by_item[item] for item in self.favorites_table.selection()
                if item in self.favorite_hosts_by_item]

    def edit_favorite_note(self) -> None:
        selected = self.selected_favorite_hosts()
        if len(selected) != 1:
            messagebox.showinfo("Select one favorite", "Select exactly one favorite to edit its note.")
            return
        host = selected[0]
        note = simpledialog.askstring("Favorite note", f"Note for {host.address}:",
                                      initialvalue=host.note, parent=self)
        if note is None:
            return
        try:
            favorites = load_favorites(self.favorites_path)
            updated = [replace(item, note=note[:4096]) if item.identity == host.identity else item
                       for item in favorites]
            save_favorites(self.favorites_path, updated)
            self._refresh_favorites_table()
        except (OSError, ValueError) as error:
            messagebox.showerror("Favorites failed", str(error))

    def remove_selected_favorites(self) -> None:
        selected = {host.identity for host in self.selected_favorite_hosts()}
        if not selected:
            return
        if not messagebox.askyesno("Remove favorites",
                                   f"Remove {len(selected)} selected device(s) from favorites?"):
            return
        try:
            favorites = load_favorites(self.favorites_path)
            save_favorites(self.favorites_path, [host for host in favorites if host.identity not in selected])
            self._refresh_favorites_table()
        except (OSError, ValueError) as error:
            messagebox.showerror("Favorites failed", str(error))

    def export_selected_favorites(self) -> None:
        hosts = self.selected_favorite_hosts()
        if not hosts:
            messagebox.showinfo("Nothing selected", "Select one or more favorites first.")
            return
        name = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("XML", "*.xml"), ("HTML", "*.html")])
        if name:
            try:
                export(Path(name), hosts)
            except (OSError, ValueError) as error:
                messagebox.showerror("Export failed", str(error))

    def wake_selected(self) -> None:
        hosts = [host for host in self.selected_hosts() if host.mac]
        if not hosts:
            messagebox.showinfo("No MAC address", "Select hosts with discovered MAC addresses.")
            return
        if not messagebox.askyesno("Wake devices", f"Send Wake-on-LAN to {len(hosts)} device(s)?"):
            return
        try:
            sent = 0
            for host in hosts:
                for broadcast in broadcasts_for_host(host.address, self.network_presets):
                    wake(host.mac, broadcast)
                    sent += 1
            self.status.configure(text=f"Sent {sent} Wake-on-LAN packet(s) to {len(hosts)} device(s)")
        except (OSError, ValueError) as error:
            messagebox.showerror("Wake-on-LAN failed", str(error))

    def power_selected(self, action: str) -> None:
        hosts = self.selected_hosts()
        if not hosts:
            messagebox.showinfo("Nothing selected", "Select one or more hosts first.")
            return
        if not messagebox.askyesno(f"Confirm remote {action}",
                                   f"Send {action} to {len(hosts)} selected device(s) over SSH?"):
            return
        user = simpledialog.askstring("SSH user", "SSH user name (leave blank for your current user):", parent=self)
        if user is None:
            return
        self.status.configure(text=f"Sending remote {action}…")
        threading.Thread(target=self._power_worker, args=(hosts, action, user.strip()), daemon=True).start()
        self.after(50, self._drain_events)

    def run_selected_tool(self, tool: str) -> None:
        hosts = self.selected_hosts()
        if not hosts:
            messagebox.showinfo("Nothing selected", "Select one or more hosts first.")
            return
        try:
            for host in hosts:
                open_network_tool(tool, host.address)
        except (OSError, RuntimeError, ValueError) as error:
            messagebox.showerror("Tool unavailable", str(error))

    def _power_worker(self, hosts: list[Host], action: str, user: str) -> None:
        results = [remote_power(host.address, action, user) for host in hosts]
        self.events.put(("power_done", results))

    def load_inventory(self) -> None:
        name = filedialog.askopenfilename(filetypes=[("Inventory", "*.json *.xml"),
                                                     ("JSON", "*.json"), ("XML", "*.xml")])
        if not name:
            return
        try:
            imported = import_inventory(Path(name))
            self.results = merge_devices(self.results, imported)
            saved = merge_devices(load_favorites(self.favorites_path), imported)
            save_favorites(self.favorites_path, saved)
            self._refresh_favorites_table()
            self._refresh_table()
            self.status.configure(text=f"Imported {len(imported)} device(s)")
        except (OSError, ValueError) as error:
            messagebox.showerror("Import failed", str(error))

    def _show_web_links(self, _event=None) -> None:
        for widget in self.link_area.winfo_children():
            widget.destroy()
        selected = self.table.selection()
        if not selected:
            return
        selected_item = selected[0]
        service_detail = self.services_by_item.get(selected_item)
        if service_detail:
            _host, service, port = service_detail
            if service in OPENABLE_SERVICES:
                self.status.configure(text=f"Port {port} {service.upper()} · double-click or press Enter to open")
            else:
                self.status.configure(text=f"Port {port} {service.upper()} is open; no desktop opener is configured")
            return
        metadata = self.metadata_by_item.get(selected_item)
        if metadata:
            self.status.configure(text=f"{metadata[0]}: {metadata[1]}")
            return
        host = self.hosts_by_item.get(selected_item)
        if not host:
            return
        for service, port in zip(host.services, host.ports):
            if service in OPENABLE_SERVICES:
                label = service_url(service, host.address, port) if service in {"http", "https", "ftp"} else f"{service.upper()} :{port}"
                link = tk.Label(self.link_area, text=label, fg="#0969da", bg="#d9f0fb",
                                cursor="hand2", underline=True)
                link.pack(side="left", padx=(0, 12))
                link.bind("<Button-1>", lambda _click, selected_service=service, address=host.address,
                          selected_port=port: self._launch_service(selected_service, address, selected_port))

    def _open_row_web_service(self, event) -> None:
        item = self.table.identify_row(event.y)
        if item in self.services_by_item:
            self.table.selection_set(item)
            self._activate_selected_row()
            return
        host = self.hosts_by_item.get(item)
        if not host:
            return
        service = preferred_web_service(host.services)
        if service:
            port = next((port for port, name in zip(host.ports, host.services) if name == service), None)
            if self._launch_service(service, host.address, port):
                self.status.configure(text=f"Opened {service_url(service, host.address, port)}")
        else:
            self.status.configure(text=f"{host.address} has no discovered HTTP or HTTPS service")

    def _activate_selected_row(self, _event=None) -> None:
        selected = self.table.selection()
        if not selected:
            return
        item = selected[0]
        detail = self.services_by_item.get(item)
        if detail:
            host, service, port = detail
            try:
                if self._launch_service(service, host.address, port):
                    self.status.configure(text=f"Opened {service.upper()} on {host.address}:{port}")
            except (OSError, RuntimeError, ValueError) as error:
                messagebox.showerror("Cannot open service", str(error))
            return
        host = self.hosts_by_item.get(item)
        if host:
            service = preferred_web_service(host.services)
            if service:
                try:
                    port = next((port for port, name in zip(host.ports, host.services) if name == service), None)
                    if self._launch_service(service, host.address, port):
                        self.status.configure(text=f"Opened {service_url(service, host.address, port)}")
                except (OSError, RuntimeError, ValueError) as error:
                    messagebox.showerror("Cannot open service", str(error))
            elif host.ports:
                self.table.item(item, open=not bool(self.table.item(item, "open")))

    def _launch_service(self, service: str, address: str, port: int | None) -> bool:
        username = ""
        if service == "ssh":
            username = simpledialog.askstring(
                "SSH username", f"Username for SSH on {address}:", initialvalue=self.ssh_username,
                parent=self)
            if username is None:
                self.status.configure(text="SSH connection cancelled")
                return False
            username = username.strip()
            if not username:
                messagebox.showerror("Invalid SSH username", "Enter the remote account username.")
                return False
            self.ssh_username = username
        open_service(service, address, port, username=username)
        return True

    def _show_table_menu(self, event) -> None:
        item = self.table.identify_row(event.y)
        if not item:
            return
        self.table.selection_set(item)
        detail = self.services_by_item.get(item)
        can_open = bool(detail and detail[1] in OPENABLE_SERVICES)
        self.table_menu.entryconfigure("Open service", state=("normal" if can_open else "disabled"))
        self.table_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected_detail(self) -> None:
        selected = self.table.selection()
        if not selected:
            return
        item = selected[0]
        if item in self.services_by_item:
            host, service, port = self.services_by_item[item]
            value = service_url(service, host.address, port) if service in {"http", "https", "ftp"} else f"{host.address}:{port} ({service})"
        elif item in self.hosts_by_item:
            value = self.hosts_by_item[item].address
        elif item in self.metadata_by_item:
            label, detail = self.metadata_by_item[item]
            value = f"{label}: {detail}"
        else:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status.configure(text=f"Copied {value}")

    def set_all_expanded(self, expanded: bool) -> None:
        def set_branch(item: str) -> None:
            children = self.table.get_children(item)
            if children:
                self.table.item(item, open=expanded)
                for child in children:
                    set_branch(child)

        for item in self.table.get_children(""):
            set_branch(item)

    def _sort_column(self, column: str) -> None:
        descending = not self.sort_descending.get(column, True)
        items = list(self.table.get_children(""))

        def key(item: str):
            value = self.table.set(item, column)
            if column == "address":
                try:
                    address = ipaddress.ip_address(value)
                    return (address.version, int(address))
                except ValueError:
                    return (99, value.casefold())
            if column == "latency":
                try:
                    return (0, float(value))
                except ValueError:
                    return (1, 0.0)
            return value.casefold()

        items.sort(key=key, reverse=descending)
        for position, item in enumerate(items):
            self.table.move(item, "", position)
        self.sort_descending[column] = descending
        for name in self.table["columns"]:
            label = name.replace("_", " ").title()
            if name == column:
                label += " ▼" if descending else " ▲"
            self.table.heading(name, text=label,
                               command=lambda selected=name: self._sort_column(selected))

    def save_export(self) -> None:
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        name = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("XML", "*.xml"), ("HTML", "*.html")])
        if name:
            try:
                visible = list(self.hosts_by_item.values())
                export(Path(name), self.selected_hosts() or visible)
            except (OSError, ValueError) as error:
                messagebox.showerror("Export failed", str(error))


def main() -> None:
    Application().mainloop()


if __name__ == "__main__":
    main()
