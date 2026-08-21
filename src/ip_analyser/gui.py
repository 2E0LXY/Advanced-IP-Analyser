from __future__ import annotations

import queue
import threading
import tkinter as tk
import ipaddress
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import __version__
from .actions import open_service, preferred_web_service, remote_power, service_url, wake
from .config import parse_ports
from .models import Host
from .network import active_ipv4_networks, current_ipv4_subnet
from .scanner import DEFAULT_PORTS, Scanner
from .storage import export, import_inventory, load_favorites, merge_devices, save_favorites
from .targets import parse_targets
from .updater import Update, check_for_update, download_update, launch_installer

OPENABLE_SERVICES = {"http", "https", "ftp", "smb", "ssh", "rdp"}
COMMON_PORTS = ",".join(str(port) for port in DEFAULT_PORTS)
WEB_APP_PORTS = "80,443,3000,5000,8000,8080,8081,8443,8888,9000,9090"


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced IP Analyser")
        self.geometry("1200x620")
        self.minsize(720, 420)
        self.configure(background="#d9f0fb")
        self.results = []
        self.hosts_by_item = {}
        self.services_by_item = {}
        self.metadata_by_item = {}
        self.sort_descending = {}
        self.events: queue.Queue = queue.Queue()
        self.update_events: queue.Queue = queue.Queue()
        self.available_update: Update | None = None
        self.update_flash_on = False
        self.cancel_scan = threading.Event()
        self.network_presets = []
        self.favorites_path = Path.home() / ".config" / "advanced-ip-analyser" / "favorites.json"
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
        ttk.Label(settings, text="Filter").pack(side="left")
        self.filter_text = tk.StringVar()
        self.filter_text.trace_add("write", lambda *_args: self._refresh_table())
        self.filter_entry = ttk.Entry(settings, textvariable=self.filter_text)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))

        actions = ttk.Frame(self, padding=(12, 0, 12, 8))
        actions.pack(fill="x")
        ttk.Button(actions, text="Copy IP", command=self.copy_selected_ips).pack(side="left")
        ttk.Button(actions, text="Add favorite", command=self.add_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="View favorites", command=self.show_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Refresh favorites", command=self.refresh_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Wake", command=self.wake_selected).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Shutdown", command=lambda: self.power_selected("shutdown"), style="Danger.TButton").pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Reboot", command=lambda: self.power_selected("reboot"), style="Danger.TButton").pack(side="left", padx=(8, 0))
        ttk.Label(actions, text="Export uses selected rows when any are selected.").pack(side="right")

        columns = ("address", "state", "hostname", "latency", "mac", "manufacturer", "services")
        self.table = ttk.Treeview(self, columns=columns, show="tree headings", selectmode="extended")
        self.table.heading("#0", text="Ports")
        self.table.column("#0", width=70, minwidth=55, stretch=False, anchor="w")
        widths = (130, 55, 190, 75, 135, 210, 260)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.replace("_", " ").title(),
                               command=lambda selected=column: self._sort_column(selected))
            self.table.column(column, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, padx=12)
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
        self.table_menu.add_separator()
        self.table_menu.add_command(label="Expand all ports", command=lambda: self.set_all_expanded(True))
        self.table_menu.add_command(label="Collapse all ports", command=lambda: self.set_all_expanded(False))

        self.links = ttk.Frame(self, padding=(12, 8, 12, 0))
        self.links.pack(fill="x")
        ttk.Label(self.links, text="Open services:").pack(side="left")
        self.link_area = ttk.Frame(self.links)
        self.link_area.pack(side="left", padx=8)

        footer = ttk.Frame(self, padding=12)
        footer.pack(fill="x")
        self.status = ttk.Label(footer, text="Only scan networks you are authorized to manage.")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(footer, mode="determinate", length=220)
        self.progress.pack(side="right")
        ttk.Label(footer, text="© 2026 Daren Loxley (2E0LXY)").pack(side="right", padx=18)
        ttk.Label(footer, text=f"Version {__version__}").pack(side="right", padx=(0, 12))
        ttk.Button(footer, text="Help", command=self.show_help).pack(side="right", padx=(0, 8))
        self.update_button = ttk.Button(footer, text="Update available", style="Update.TButton",
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
                "3. Press Scan (F5). Reachable devices appear as they are found; press Escape to cancel safely.\n"
                "4. Use Filter (Ctrl+F) to search addresses, names, MACs, manufacturers, services, and notes.\n\n"
                "Only scan networks and devices you own or are authorized to administer.",
                "help-overview.png")
        add_tab("Ports and services",
                "A disclosure arrow appears beside every host with detected TCP ports. Expand it to see one row per port.\n\n"
                "Blue underlined service rows are openable. Double-click one, select it and press Enter, or right-click and choose Open service. "
                "HTTP, HTTPS, and FTP use the desktop URL handler; SMB uses the file manager; SSH opens a terminal; RDP uses FreeRDP. "
                "Expand a port row again to see safely discovered details such as the HTTP status, Apache/nginx/IIS Server header, page title, "
                "content type, redirect, authentication realm, TLS version/cipher, or a protocol greeting. Availability depends on what the server exposes.\n\n"
                "Right-click to copy a row detail or expand/collapse every host. Parent-row double-click opens HTTPS or HTTP when available. "
                "Discovery is read-only, bounded, and never attempts authentication.",
                "help-port-details.png")
        add_tab("Favorites and inventory",
                "Add favorite stores selected devices in ~/.config/advanced-ip-analyser/favorites.json. Devices are identified by MAC address first, "
                "so a later scan can update an IP address without losing the saved note. Refresh favorites rescans saved addresses.\n\n"
                "Export writes selected rows—or all visible rows when nothing is selected—to CSV, JSON, XML, or escaped HTML. "
                "Import accepts this application's bounded JSON and XML formats and merges devices into the table and favorites. "
                "Use Ctrl+O to import and Ctrl+S to export.")
        add_tab("Device actions",
                "Copy IP copies selected host addresses. Wake sends a confirmed Wake-on-LAN magic packet to selected devices with MAC addresses.\n\n"
                "Shutdown and Reboot require confirmation and use non-interactive SSH. Configure SSH keys and passwordless permission for "
                "systemctl poweroff or systemctl reboot on machines you administer. The application never asks for, stores, or forwards passwords. "
                "Remote results are reported per host. Detected service links never bypass authentication.")
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
                launch_installer(value)
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
            self.update_events.put(("downloaded", download_update(update), True))
        except Exception as error:
            self.update_events.put(("download_error", error, True))


    def start_scan(self) -> None:
        try:
            targets = parse_targets(self.target.get())
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
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.cancel_scan = threading.Event()
        self.progress.configure(maximum=len(targets), value=0)
        threading.Thread(target=self._scan_worker, args=(targets, ports, timeout, workers), daemon=True).start()
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

    def _scan_worker(self, targets: list[str], ports: dict[int, str], timeout: float, workers: int) -> None:
        try:
            results = Scanner(timeout, workers, ports).scan(
                targets, lambda done, total, host: self.events.put(("host", done, total, host)), self.cancel_scan)
            self.events.put(("done", results, len(targets), self.cancel_scan.is_set()))
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
                elif event[0] == "done":
                    scanned, total, cancelled = event[1], event[2], event[3]
                    self.results = [host for host in scanned if host.reachable]
                    self._refresh_table()
                    self.scan_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    prefix = "Cancelled" if cancelled else "Finished"
                    self.status.configure(text=f"{prefix}: {len(self.results)} reachable; {len(scanned)} of {total} checked")
                    self._merge_results_into_favorites()
                    return
                elif event[0] == "power_done":
                    results = event[1]
                    failed = [result for result in results if not result.succeeded]
                    self.status.configure(text=f"Remote {results[0].action}: {len(results) - len(failed)} succeeded, {len(failed)} failed")
                    if failed:
                        messagebox.showwarning("Remote action results", "\n".join(
                            f"{result.host}: {result.detail}" for result in failed))
                    return
                else:
                    self.scan_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    messagebox.showerror("Scan failed", str(event[1]))
                    return
        except queue.Empty:
            self.after(50, self._drain_events)

    def _insert_host(self, host: Host) -> None:
        web_services = [service_url(service, host.address, port) if service in {"http", "https"} else service
                        for port, service in zip(host.ports, host.services)]
        stripe = "even" if len(self.table.get_children("")) % 2 == 0 else "odd"
        item = self.table.insert("", "end", text=f"{len(host.ports)} port{'s' if len(host.ports) != 1 else ''}",
            values=(host.address, "Up", host.hostname, host.latency_ms or "", host.mac,
                    host.manufacturer, ", ".join(web_services)), tags=(stripe,))
        self.hosts_by_item[item] = host
        for port, service in zip(host.ports, host.services):
            detail = service_url(service, host.address, port) if service in {"http", "https", "ftp"} else f"TCP {port} · {service}"
            info = host.service_info.get(str(port), {})
            server = info.get("Server") or info.get("Banner", "")
            service_label = service.upper() + (f" · {server}" if server else "")
            summary = info.get("Page title") or info.get("Status") or detail
            clickable = service in OPENABLE_SERVICES
            child = self.table.insert(item, "end", text=str(port),
                                      values=("", "Open", service_label, "", "", "", summary),
                                      tags=(("detail_click" if clickable else "detail"),))
            self.services_by_item[child] = (host, service, port)
            for label, value in info.items():
                metadata = self.table.insert(child, "end", text="",
                    values=("", "Detail", label, "", "", "", value), tags=("metadata",))
                self.metadata_by_item[metadata] = (label, value)

    def _matches_filter(self, host: Host) -> bool:
        term = self.filter_text.get().strip().casefold()
        metadata = " ".join(f"{label} {value}" for details in host.service_info.values()
                            for label, value in details.items())
        return not term or term in " ".join((host.address, host.hostname, host.mac, host.manufacturer,
                                              " ".join(host.services), metadata, host.note)).casefold()

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
        return [self.hosts_by_item[item] for item in self.table.selection() if item in self.hosts_by_item]

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
            keyed = {(host.mac or host.address).casefold(): host for host in existing}
            for host in hosts:
                keyed[(host.mac or host.address).casefold()] = host
            save_favorites(self.favorites_path, list(keyed.values()))
            self.status.configure(text=f"Saved {len(hosts)} device(s) to favorites")
        except (OSError, ValueError) as error:
            messagebox.showerror("Favorites failed", str(error))

    def _merge_results_into_favorites(self) -> None:
        try:
            saved = load_favorites(self.favorites_path)
            if saved:
                save_favorites(self.favorites_path, merge_devices(saved, self.results))
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
        self.target.delete(0, "end")
        self.target.insert(0, f"{favorites[0].address}-{favorites[-1].address}" if len(favorites) > 1 else favorites[0].address)
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
        threading.Thread(target=self._scan_worker, args=(targets, ports, timeout, workers), daemon=True).start()
        self.after(50, self._drain_events)

    def show_favorites(self) -> None:
        try:
            favorites = load_favorites(self.favorites_path)
        except (OSError, ValueError) as error:
            messagebox.showerror("Favorites failed", str(error))
            return
        window = tk.Toplevel(self)
        window.title("Favorite devices")
        window.geometry("850x360")
        columns = ("address", "hostname", "mac", "manufacturer", "services", "seen")
        table = ttk.Treeview(window, columns=columns, show="headings", selectmode="extended")
        for column in columns:
            table.heading(column, text=column.title())
            table.column(column, width=130)
        for host in favorites:
            table.insert("", "end", values=(host.address, host.hostname, host.mac, host.manufacturer,
                                              ", ".join(host.services), host.seen_at))
        table.pack(fill="both", expand=True, padx=12, pady=12)

        def remove_selected() -> None:
            indexes = {table.index(item) for item in table.selection()}
            remaining = [host for index, host in enumerate(favorites) if index not in indexes]
            save_favorites(self.favorites_path, remaining)
            for item in table.selection():
                table.delete(item)
            favorites[:] = remaining

        ttk.Button(window, text="Remove selected", command=remove_selected).pack(pady=(0, 12))

    def wake_selected(self) -> None:
        hosts = [host for host in self.selected_hosts() if host.mac]
        if not hosts:
            messagebox.showinfo("No MAC address", "Select hosts with discovered MAC addresses.")
            return
        if not messagebox.askyesno("Wake devices", f"Send Wake-on-LAN to {len(hosts)} device(s)?"):
            return
        try:
            for host in hosts:
                wake(host.mac)
            self.status.configure(text=f"Sent Wake-on-LAN to {len(hosts)} device(s)")
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
                          selected_port=port: open_service(selected_service, address, selected_port))

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
            open_service(service, host.address, port)
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
                open_service(service, host.address, port)
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
                    open_service(service, host.address, port)
                    self.status.configure(text=f"Opened {service_url(service, host.address, port)}")
                except (OSError, RuntimeError, ValueError) as error:
                    messagebox.showerror("Cannot open service", str(error))
            elif host.ports:
                self.table.item(item, open=not bool(self.table.item(item, "open")))

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
