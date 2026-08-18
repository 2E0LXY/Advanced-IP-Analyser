from __future__ import annotations

import queue
import threading
import tkinter as tk
import ipaddress
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .scanner import Scanner
from .actions import open_service
from .storage import export
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
        self._build()

    def _build(self) -> None:
        header = ttk.Frame(self, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text="Target").pack(side="left")
        self.target = ttk.Entry(header)
        self.target.insert(0, "192.168.1.0/24")
        self.target.pack(side="left", fill="x", expand=True, padx=8)
        self.scan_button = ttk.Button(header, text="Scan", command=self.start_scan)
        self.scan_button.pack(side="left")
        ttk.Button(header, text="Export…", command=self.save_export).pack(side="left", padx=(8, 0))

        columns = ("address", "state", "hostname", "latency", "mac", "manufacturer", "services")
        self.table = ttk.Treeview(self, columns=columns, show="headings", selectmode="extended")
        widths = (130, 55, 190, 75, 135, 210, 260)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.replace("_", " ").title(),
                               command=lambda selected=column: self._sort_column(selected))
            self.table.column(column, width=width, anchor="w")
        self.table.pack(fill="both", expand=True, padx=12)
        self.table.bind("<<TreeviewSelect>>", self._show_web_links)

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

    def start_scan(self) -> None:
        try:
            targets = parse_targets(self.target.get())
        except ValueError as error:
            messagebox.showerror("Invalid target", str(error))
            return
        self.results.clear()
        self.hosts_by_item.clear()
        self.table.delete(*self.table.get_children())
        self.scan_button.configure(state="disabled")
        self.progress.configure(maximum=len(targets), value=0)
        threading.Thread(target=self._scan_worker, args=(targets,), daemon=True).start()
        self.after(50, self._drain_events)

    def _scan_worker(self, targets: list[str]) -> None:
        try:
            results = Scanner().scan(targets, lambda done, total, host: self.events.put(("host", done, total, host)))
            self.events.put(("done", results))
        except Exception as error:
            self.events.put(("error", error))

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "host":
                    _, done, total, host = event
                    web_services = [f"{service}://{host.address}" if service in {"http", "https"} else service
                                    for service in host.services]
                    item = self.table.insert("", "end", values=(host.address, "Up" if host.reachable else "Down",
                        host.hostname, host.latency_ms or "", host.mac, host.manufacturer, ", ".join(web_services)))
                    self.hosts_by_item[item] = host
                    self.progress.configure(value=done)
                    self.status.configure(text=f"Scanned {done} of {total}")
                elif event[0] == "done":
                    self.results = event[1]
                    self.scan_button.configure(state="normal")
                    alive = sum(host.reachable for host in self.results)
                    self.status.configure(text=f"Finished: {alive} reachable of {len(self.results)} addresses")
                    return
                else:
                    self.scan_button.configure(state="normal")
                    messagebox.showerror("Scan failed", str(event[1]))
                    return
        except queue.Empty:
            self.after(50, self._drain_events)

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
                url = f"{service}://{host.address}"
                link = tk.Label(self.link_area, text=url, fg="#0969da", cursor="hand2", underline=True)
                link.pack(side="left", padx=(0, 12))
                link.bind("<Button-1>", lambda _click, selected_service=service, address=host.address:
                          open_service(selected_service, address))

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
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("HTML", "*.html")])
        if name:
            try:
                export(Path(name), self.results)
            except (OSError, ValueError) as error:
                messagebox.showerror("Export failed", str(error))


def main() -> None:
    Application().mainloop()


if __name__ == "__main__":
    main()
