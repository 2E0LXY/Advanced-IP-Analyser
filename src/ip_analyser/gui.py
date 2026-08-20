from __future__ import annotations

import queue
import threading
import tkinter as tk
import ipaddress
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .actions import open_service, preferred_web_service, remote_power, service_url, wake
from .config import parse_ports
from .models import Host
from .network import active_ipv4_networks, current_ipv4_subnet
from .scanner import Scanner
from .storage import export, import_inventory, load_favorites, merge_devices, save_favorites
from .targets import parse_targets


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced IP Analyser")
        self.geometry("1200x620")
        self.minsize(720, 420)
        self.results = []
        self.hosts_by_item = {}
        self.sort_descending = {}
        self.events: queue.Queue = queue.Queue()
        self.cancel_scan = threading.Event()
        self.network_presets = []
        self.favorites_path = Path.home() / ".config" / "advanced-ip-analyser" / "favorites.json"
        self._build()

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
        self.scan_button = ttk.Button(header, text="Scan", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.cancel_button = ttk.Button(header, text="Cancel", command=self.cancel_current_scan, state="disabled")
        self.cancel_button.pack(side="left", padx=(8, 0))
        ttk.Button(header, text="Export…", command=self.save_export).pack(side="left", padx=(8, 0))
        ttk.Button(header, text="Import…", command=self.load_inventory).pack(side="left", padx=(8, 0))

        settings = ttk.Frame(self, padding=(12, 0, 12, 8))
        settings.pack(fill="x")
        ttk.Label(settings, text="TCP ports").pack(side="left")
        self.ports = ttk.Entry(settings, width=34)
        self.ports.insert(0, "21,22,53,80,139,443,445,3389")
        self.ports.pack(side="left", padx=(6, 12))
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
        ttk.Entry(settings, textvariable=self.filter_text).pack(side="left", fill="x", expand=True, padx=(6, 0))

        actions = ttk.Frame(self, padding=(12, 0, 12, 8))
        actions.pack(fill="x")
        ttk.Button(actions, text="Copy IP", command=self.copy_selected_ips).pack(side="left")
        ttk.Button(actions, text="Add favorite", command=self.add_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="View favorites", command=self.show_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Refresh favorites", command=self.refresh_favorites).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Wake", command=self.wake_selected).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Shutdown", command=lambda: self.power_selected("shutdown")).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Reboot", command=lambda: self.power_selected("reboot")).pack(side="left", padx=(8, 0))
        ttk.Label(actions, text="Export uses selected rows when any are selected.").pack(side="right")

        columns = ("address", "state", "hostname", "latency", "mac", "manufacturer", "services")
        self.table = ttk.Treeview(self, columns=columns, show="headings", selectmode="extended")
        widths = (130, 55, 190, 75, 135, 210, 260)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.replace("_", " ").title(),
                               command=lambda selected=column: self._sort_column(selected))
            self.table.column(column, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, padx=12)
        self.table.bind("<<TreeviewSelect>>", self._show_web_links)
        self.table.bind("<Double-1>", self._open_row_web_service)

        self.links = ttk.Frame(self, padding=(12, 8, 12, 0))
        self.links.pack(fill="x")
        ttk.Label(self.links, text="Web links:").pack(side="left")
        self.link_area = ttk.Frame(self.links)
        self.link_area.pack(side="left", padx=8)

        footer = ttk.Frame(self, padding=12)
        footer.pack(fill="x")
        self.status = ttk.Label(footer, text="Only scan networks you are authorized to manage.")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(footer, mode="determinate", length=220)
        self.progress.pack(side="right")
        ttk.Label(footer, text="© 2026 Daren Loxley (2E0LXY)").pack(side="right", padx=18)
        self.refresh_subnets(show_errors=False)

    def start_scan(self) -> None:
        try:
            targets = parse_targets(self.target.get())
            ports = parse_ports(self.ports.get())
            timeout = float(self.timeout.get())
            workers = int(self.workers.get())
            if timeout < 0.05 or workers < 1 or workers > 512:
                raise ValueError("timeout must be at least 0.05 and workers must be from 1 to 512")
        except (ValueError, TypeError) as error:
            messagebox.showerror("Invalid scan settings", str(error))
            return
        self.results.clear()
        self.hosts_by_item.clear()
        self.table.delete(*self.table.get_children())
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.cancel_scan = threading.Event()
        self.progress.configure(maximum=len(targets), value=0)
        threading.Thread(target=self._scan_worker, args=(targets, ports, timeout, workers), daemon=True).start()
        self.after(50, self._drain_events)

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
        web_services = [service_url(service, host.address) if service in {"http", "https"} else service
                        for service in host.services]
        item = self.table.insert("", "end", values=(host.address, "Up", host.hostname,
            host.latency_ms or "", host.mac, host.manufacturer, ", ".join(web_services)))
        self.hosts_by_item[item] = host

    def _matches_filter(self, host: Host) -> bool:
        term = self.filter_text.get().strip().casefold()
        return not term or term in " ".join((host.address, host.hostname, host.mac, host.manufacturer,
                                              " ".join(host.services), host.note)).casefold()

    def _refresh_table(self) -> None:
        if not hasattr(self, "table"):
            return
        self.table.delete(*self.table.get_children())
        self.hosts_by_item.clear()
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
            ports = parse_ports(self.ports.get())
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
        host = self.hosts_by_item.get(selected[0])
        if not host:
            return
        for service in ("http", "https"):
            if service in host.services:
                url = service_url(service, host.address)
                link = tk.Label(self.link_area, text=url, fg="#0969da", cursor="hand2", underline=True)
                link.pack(side="left", padx=(0, 12))
                link.bind("<Button-1>", lambda _click, selected_service=service, address=host.address:
                          open_service(selected_service, address))

    def _open_row_web_service(self, event) -> None:
        item = self.table.identify_row(event.y)
        host = self.hosts_by_item.get(item)
        if not host:
            return
        service = preferred_web_service(host.services)
        if service:
            open_service(service, host.address)
            self.status.configure(text=f"Opened {service_url(service, host.address)}")
        else:
            self.status.configure(text=f"{host.address} has no discovered HTTP or HTTPS service")

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
