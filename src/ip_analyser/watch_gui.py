from __future__ import annotations

import json
import os
import queue
import shutil
import sqlite3
import subprocess
import threading
import time
import tkinter as tk
from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from .models import Host
from .monitoring import (
    AlertRule,
    Analysis,
    MonitorAnalyzer,
    MonitorStore,
    enforce_capture_retention,
    export_analysis,
    load_rules,
    save_rules,
)
from .packet_tools import (
    CaptureSession,
    list_capture_interfaces,
    read_capture,
    start_monitor_capture,
    validate_interface,
)


class NetworkWatch(tk.Toplevel):
    def __init__(self, parent: tk.Misc, known_hosts: list[Host] | None = None):
        super().__init__(parent)
        self.title("Network Watch · Advanced IP Analyser")
        self.geometry("1280x760")
        self.minsize(880, 560)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.known_hosts = known_hosts or []
        self.capture: CaptureSession | None = None
        self.capture_path: Path | None = None
        self.analysis: Analysis | None = None
        self.saved_session = False
        self.final_generation: int | None = None
        self.refresh_generation = 0
        self.analysis_events: queue.Queue = queue.Queue()
        self.analysis_worker_active = False
        self.last_notification_keys: set[tuple] = set()
        self.close_after_final = False
        self.data_dir = Path.home() / ".local" / "share" / "advanced-ip-analyser"
        self.capture_dir = self.data_dir / "captures"
        self.rules_path = Path.home() / ".config" / "advanced-ip-analyser" / "alert-rules.json"
        self.store = MonitorStore(self.data_dir / "network-watch.sqlite3")
        try:
            self.rules = load_rules(self.rules_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            self.rules = []
            messagebox.showwarning("Alert rules", f"Rules could not be loaded: {error}", parent=self)
        self._build()
        self._load_interfaces()
        self._refresh_history()
        self.after(200, self._drain_analysis_events)

    def _build(self) -> None:
        controls = ttk.Frame(self, padding=12)
        controls.pack(fill="x")
        ttk.Label(controls, text="Network Watch", font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Label(controls, text="Interface").pack(side="left", padx=(24, 4))
        self.interface = ttk.Combobox(controls, width=17, state="readonly")
        self.interface.pack(side="left")
        ttk.Label(controls, text="Watch for").pack(side="left", padx=(12, 4))
        self.duration = ttk.Combobox(controls, width=13, state="readonly",
                                     values=("5 minutes", "15 minutes", "1 hour",
                                             "4 hours", "24 hours"))
        self.duration.set("15 minutes")
        self.duration.pack(side="left")
        ttk.Label(controls, text="Detail").pack(side="left", padx=(12, 4))
        self.detail_level = ttk.Combobox(controls, width=16, state="readonly",
                                         values=("Headers only", "Protocol details", "Full packets"))
        self.detail_level.set("Headers only")
        self.detail_level.pack(side="left")
        self.start_button = ttk.Button(controls, text="Start watching", command=self.start,
                                       style="Accent.TButton")
        self.start_button.pack(side="left", padx=(12, 4))
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop,
                                      state="disabled", style="Danger.TButton")
        self.stop_button.pack(side="left")

        tools = ttk.Frame(self, padding=(12, 0, 12, 8))
        tools.pack(fill="x")
        ttk.Button(tools, text="Open recording…", command=self.open_recording).pack(side="left")
        ttk.Button(tools, text="Save report…", command=self.save_report).pack(side="left", padx=(8, 0))
        ttk.Button(tools, text="Bookmark recording", command=self.bookmark).pack(side="left", padx=(8, 0))
        ttk.Button(tools, text="Alert rules…", command=self.edit_rules).pack(side="left", padx=(8, 0))
        self.notifications = tk.BooleanVar(value=False)
        ttk.Checkbutton(tools, text="Desktop alerts", variable=self.notifications).pack(side="left", padx=16)
        ttk.Label(tools, text="Capture only networks you are authorized to monitor.").pack(side="right")

        cards = ttk.Frame(self, padding=(12, 0, 12, 8))
        cards.pack(fill="x")
        self.card_values: dict[str, ttk.Label] = {}
        for title in ("Packets", "Traffic", "Devices", "Conversations", "Findings"):
            card = ttk.Frame(cards, padding=8, relief="ridge")
            card.pack(side="left", fill="x", expand=True, padx=(0, 6))
            ttk.Label(card, text=title).pack()
            value = ttk.Label(card, text="—", font=("TkDefaultFont", 14, "bold"))
            value.pack()
            self.card_values[title] = value

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12)
        self.timeline_page = ttk.Frame(self.tabs)
        self.conversations_page = ttk.Frame(self.tabs)
        self.devices_page = ttk.Frame(self.tabs)
        self.dns_page = ttk.Frame(self.tabs)
        self.findings_page = ttk.Frame(self.tabs)
        self.protocols_page = ttk.Frame(self.tabs)
        self.history_page = ttk.Frame(self.tabs)
        for page, title in ((self.timeline_page, "Timeline"),
                            (self.conversations_page, "Conversations"),
                            (self.devices_page, "Devices"), (self.dns_page, "DNS"),
                            (self.findings_page, "Findings & alerts"),
                            (self.protocols_page, "Protocols & services"),
                            (self.history_page, "History")):
            self.tabs.add(page, text=title)
        self.timeline = tk.Canvas(self.timeline_page, background="#ffffff", height=300,
                                  highlightthickness=0)
        self.timeline.pack(fill="both", expand=True, padx=8, pady=8)
        self.timeline.bind("<Configure>", lambda _event: self._draw_timeline())
        self.conversations = self._table(self.conversations_page,
            ("a", "pa", "b", "pb", "protocol", "packets", "bytes", "duration", "health"),
            (180, 65, 180, 65, 80, 80, 100, 85, 250))
        self.devices = self._table(self.devices_page,
            ("address", "sent", "received", "peers", "external", "ports", "protocols"),
            (190, 100, 100, 70, 75, 200, 280))
        self.dns = self._table(self.dns_page,
            ("time", "device", "server", "name", "result"), (110, 180, 180, 430, 100))
        self.findings = self._table(self.findings_page,
            ("time", "severity", "category", "subject", "explanation"),
            (110, 80, 170, 240, 500))
        self.protocols = self._table(self.protocols_page,
            ("type", "name", "packets", "share"), (100, 280, 120, 120))
        self.history = self._table(self.history_page,
            ("id", "started", "duration", "packets", "bytes", "recording"),
            (60, 180, 100, 100, 120, 560))

        footer = ttk.Frame(self, padding=12)
        footer.pack(fill="x")
        self.status = ttk.Label(footer, text="Ready. Header-only monitoring is recommended.")
        self.status.pack(side="left")
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=180,
                                        style="Green.Horizontal.TProgressbar")
        self.progress.pack(side="right")

    def _table(self, parent: ttk.Frame, columns: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        frame = ttk.Frame(parent, padding=8)
        frame.pack(fill="both", expand=True)
        table = ttk.Treeview(frame, columns=columns, show="headings")
        for column, width in zip(columns, widths):
            table.heading(column, text=column.replace("_", " ").title())
            table.column(column, width=width, anchor="w", stretch=width >= 200)
        scroll = ttk.Scrollbar(frame, command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return table

    def _load_interfaces(self) -> None:
        try:
            names = [name for name, _description in list_capture_interfaces()]
        except (OSError, RuntimeError):
            names = ["any"]
        self.interface.configure(values=names)
        self.interface.set("any" if "any" in names else names[0])

    def start(self) -> None:
        if self.capture and self.capture.running:
            return
        seconds = {"5 minutes": 300, "15 minutes": 900, "1 hour": 3_600,
                   "4 hours": 14_400, "24 hours": 86_400}[self.duration.get()]
        snaplen = {"Headers only": 128, "Protocol details": 512,
                   "Full packets": 65_535}[self.detail_level.get()]
        scope = "packet headers" if snaplen == 128 else (
            "up to 512 bytes per packet" if snaplen == 512 else "complete packet payloads")
        if not messagebox.askyesno(
                "Start Network Watch",
                f"Watch {self.interface.get()} for up to {self.duration.get()}?\n\n"
                f"This records {scope}. Debian may request administrator authorization. "
                "Captured data stays on this computer and is subject to the retention limit.", parent=self):
            return
        try:
            interface = validate_interface(self.interface.get())
            self.capture = start_monitor_capture(interface, seconds, snaplen=snaplen,
                                                 cache_dir=self.capture_dir)
        except (OSError, RuntimeError, ValueError) as error:
            messagebox.showerror("Network Watch could not start", str(error), parent=self)
            return
        self.capture_path = self.capture.path
        self.saved_session = False
        self.final_generation = None
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress.start(10)
        self.status.configure(text="Watching network activity…")
        self._schedule_refresh()

    def stop(self) -> None:
        if self.capture:
            self.capture.stop()
        self._finish_capture()

    def _schedule_refresh(self) -> None:
        self.refresh_generation += 1
        generation = self.refresh_generation
        path = self.capture_path
        if path and path.exists() and path.stat().st_size >= 24:
            baseline = self.store.baselines()
            self._start_analysis_worker(path, generation, baseline)
        if self.capture and self.capture.running:
            self.after(3_000, self._schedule_refresh)
        else:
            self.after(200, self._finish_capture)

    def _analyze_worker(self, path: Path, generation: int,
                        baseline: dict[str, float]) -> None:
        try:
            records = read_capture(path, limit=100_000, allow_incomplete=True)
            known = [host.address for host in self.known_hosts]
            analyzer = MonitorAnalyzer(known, list(self.rules), baseline)
            analysis = analyzer.analyze(records)
            self.analysis_events.put(("analysis", generation, analysis))
        except (OSError, RuntimeError, ValueError) as error:
            self.analysis_events.put(("error", str(error)))

    def _start_analysis_worker(self, path: Path, generation: int,
                               baseline: dict[str, float]) -> bool:
        if self.analysis_worker_active:
            return False
        self.analysis_worker_active = True
        threading.Thread(target=self._analyze_worker,
                         args=(path, generation, baseline), daemon=True).start()
        return True

    def _drain_analysis_events(self) -> None:
        try:
            while True:
                event = self.analysis_events.get_nowait()
                self.analysis_worker_active = False
                if event[0] == "analysis":
                    self._accept_analysis(event[1], event[2])
                else:
                    self.status.configure(text=f"Analysis waiting: {event[1]}")
                    if self.close_after_final:
                        self.store.close()
                        self.destroy()
                        return
        except queue.Empty:
            if self.winfo_exists():
                self.after(200, self._drain_analysis_events)

    def _accept_analysis(self, generation: int, analysis: Analysis) -> None:
        if generation < self.refresh_generation - 1:
            return
        self.analysis = analysis
        self._refresh_views()
        self._notify_findings()
        if generation == self.final_generation and not self.saved_session:
            self._save_session()

    def _finish_capture(self) -> None:
        if self.capture and self.capture.running:
            return
        self.progress.stop()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        capture_error = self.capture.error() if self.capture else ""
        if capture_error:
            self.status.configure(text=capture_error)
        else:
            self.status.configure(text="Watch stopped · analysis and recording retained locally")
        if (self.capture_path and self.capture_path.exists() and
                self.capture_path.stat().st_size >= 24 and not self.saved_session and
                self.final_generation is None):
            if self.analysis_worker_active:
                self.after(500, self._finish_capture)
                return
            self.refresh_generation += 1
            self.final_generation = self.refresh_generation
            self.status.configure(text="Finalising Network Watch analysis…")
            self._start_analysis_worker(self.capture_path, self.final_generation,
                                        self.store.baselines())

    def _save_session(self) -> None:
        if not self.analysis or self.saved_session:
            return
        try:
            self.store.save(self.analysis, self.capture_path)
            self.saved_session = True
            self.store.prune(7)
            enforce_capture_retention(self.capture_dir, days=7,
                                      protected=[self.capture_path] if self.capture_path else [])
            self._refresh_history()
            self.status.configure(text="Watch stopped · analysis and recording retained locally")
        except (OSError, RuntimeError, sqlite3.Error) as error:
            self.status.configure(text=f"Watch stopped · could not save history: {error}")
        if self.close_after_final:
            self.store.close()
            self.destroy()

    def _refresh_views(self) -> None:
        analysis = self.analysis
        if not analysis:
            return
        self.card_values["Packets"].configure(text=f"{analysis.packet_count:,}")
        self.card_values["Traffic"].configure(text=self._size(analysis.byte_count))
        self.card_values["Devices"].configure(text=f"{len(analysis.devices):,}")
        self.card_values["Conversations"].configure(text=f"{len(analysis.flows):,}")
        self.card_values["Findings"].configure(text=f"{len(analysis.findings):,}")
        self._replace(self.conversations, [(
            flow.endpoint_a, flow.port_a or "", flow.endpoint_b, flow.port_b or "",
            flow.protocol, flow.packets, self._size(flow.bytes), f"{flow.duration:.1f}s",
            self._flow_health(flow)) for flow in analysis.flows[:5_000]])
        self._replace(self.devices, [(
            device.address, self._size(device.bytes_sent), self._size(device.bytes_received),
            len(device.peers), len(device.external_peers),
            ", ".join(str(port) for port in sorted(device.ports)[:20]),
            ", ".join(f"{name} {count}" for name, count in device.protocols.most_common(8)))
            for device in analysis.devices])
        self._replace(self.dns, [(
            datetime.fromtimestamp(event.timestamp, UTC).astimezone().strftime("%H:%M:%S"), event.device,
            event.server, event.name, "OK" if not event.rcode else f"Error {event.rcode}")
            for event in reversed(analysis.dns[-5_000:])])
        self._replace(self.findings, [(
            datetime.fromtimestamp(item.timestamp, UTC).astimezone().strftime("%H:%M:%S"), item.severity,
            item.category, item.subject, item.explanation) for item in analysis.findings])
        protocol_total = max(1, sum(analysis.protocols.values()))
        protocol_rows = [("Protocol", name, count, f"{count / protocol_total:.1%}")
                         for name, count in sorted(analysis.protocols.items(),
                                                   key=lambda item: item[1], reverse=True)]
        service_rows = [("Port", str(port), count, f"{count / protocol_total:.1%}")
                        for port, count in sorted(analysis.services.items(),
                                                  key=lambda item: item[1], reverse=True)[:100]]
        self._replace(self.protocols, protocol_rows + service_rows)
        self._draw_timeline()

    @staticmethod
    def _replace(table: ttk.Treeview, rows: list[tuple]) -> None:
        table.delete(*table.get_children())
        for row in rows:
            table.insert("", "end", values=row)

    def _draw_timeline(self) -> None:
        canvas = getattr(self, "timeline", None)
        analysis = self.analysis
        if not canvas or not analysis:
            return
        canvas.delete("all")
        width = max(200, canvas.winfo_width())
        height = max(160, canvas.winfo_height())
        margin = 45
        buckets = analysis.buckets
        if not buckets:
            canvas.create_text(width / 2, height / 2, text="No traffic recorded")
            return
        peak = max(1, max(bucket.bytes for bucket in buckets))
        points = []
        for index, bucket in enumerate(buckets):
            x = margin + index * (width - margin * 2) / max(1, len(buckets) - 1)
            y = height - margin - bucket.bytes / peak * (height - margin * 2)
            points.extend((x, y))
        canvas.create_line(margin, height - margin, width - margin, height - margin, fill="#789")
        canvas.create_line(margin, margin, margin, height - margin, fill="#789")
        if len(points) >= 4:
            canvas.create_line(*points, fill="#1587bd", width=3, smooth=True)
        else:
            canvas.create_oval(points[0] - 3, points[1] - 3, points[0] + 3, points[1] + 3,
                               fill="#1587bd")
        canvas.create_text(margin, 18, anchor="w", text=f"Peak {self._size(peak)} per minute")
        canvas.create_text(margin, height - 18, anchor="w",
                           text=datetime.fromtimestamp(buckets[0].started, UTC).astimezone().strftime("%H:%M"))
        canvas.create_text(width - margin, height - 18, anchor="e",
                           text=datetime.fromtimestamp(buckets[-1].started, UTC).astimezone().strftime("%H:%M"))

    @staticmethod
    def _flow_health(flow) -> str:
        details = []
        for value, label in ((flow.resets, "resets"), (flow.retransmissions, "retransmissions"),
                             (flow.out_of_order, "out of order"),
                             (flow.zero_windows, "zero windows")):
            if value:
                details.append(f"{value} {label}")
        if flow.syns and not flow.syn_acks:
            details.append(f"{flow.syns} unanswered SYN")
        if flow.handshake_ms is not None:
            details.append(f"handshake {flow.handshake_ms:.1f} ms")
        return ", ".join(details) or "No obvious issue"

    @staticmethod
    def _size(value: int) -> str:
        amount = float(value)
        for unit in ("B", "KiB", "MiB", "GiB"):
            if amount < 1024 or unit == "GiB":
                return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount):,} B"
            amount /= 1024
        return f"{amount:.1f} GiB"

    def _notify_findings(self) -> None:
        if not self.notifications.get() or not self.analysis:
            return
        executable = shutil.which("notify-send")
        if not executable:
            return
        for finding in self.analysis.findings[:10]:
            key = (finding.category, finding.subject, finding.explanation)
            if key in self.last_notification_keys:
                continue
            self.last_notification_keys.add(key)
            subprocess.Popen([executable, "Advanced IP Analyser", f"{finding.category}: {finding.subject}"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def open_recording(self) -> None:
        name = filedialog.askopenfilename(parent=self, filetypes=[
            ("Packet recordings", "*.pcap *.pcapng *.pcap.gz *.pcapng.gz"), ("All files", "*")])
        if not name:
            return
        self.capture_path = Path(name)
        self.status.configure(text="Analysing recording…")
        self.refresh_generation += 1
        baseline = self.store.baselines()
        if not self._start_analysis_worker(self.capture_path, self.refresh_generation, baseline):
            self.status.configure(text="An analysis refresh is already running; try again shortly.")

    def save_report(self) -> None:
        if not self.analysis:
            messagebox.showinfo("No analysis", "Start Network Watch or open a recording first.", parent=self)
            return
        name = filedialog.asksaveasfilename(parent=self, defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("JSON data", "*.json"),
                       ("CSV conversations", "*.csv")])
        if not name:
            return
        try:
            export_analysis(Path(name), self.analysis)
            self.status.configure(text=f"Saved report to {name}")
        except (OSError, ValueError) as error:
            messagebox.showerror("Report failed", str(error), parent=self)

    def bookmark(self) -> None:
        if not self.capture_path or not self.capture_path.is_file():
            messagebox.showinfo("No recording", "Start or open a recording first.", parent=self)
            return
        note = simpledialog.askstring("Bookmark recording", "Optional note:", parent=self) or ""
        bookmarks = self.data_dir / "bookmarks"
        bookmarks.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            bookmarks.chmod(0o700)
        stamp = datetime.now(UTC).astimezone().strftime("%Y%m%d-%H%M%S")
        destination = bookmarks / f"bookmark-{stamp}{self.capture_path.suffix}"
        note_path = destination.with_suffix(destination.suffix + ".json")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(destination, flags, 0o600)
            with self.capture_path.open("rb") as source, os.fdopen(descriptor, "wb") as output:
                shutil.copyfileobj(source, output, length=64 * 1024)
            note_descriptor = os.open(note_path, flags, 0o600)
            with os.fdopen(note_descriptor, "w", encoding="utf-8") as stream:
                json.dump({"created": time.time(), "note": note[:4096]}, stream, indent=2)
                stream.write("\n")
            self.status.configure(text=f"Bookmarked recording as {destination.name}")
        except OSError as error:
            destination.unlink(missing_ok=True)
            note_path.unlink(missing_ok=True)
            messagebox.showerror("Bookmark failed", str(error), parent=self)

    def edit_rules(self) -> None:
        window = tk.Toplevel(self)
        window.title("Network Watch alert rules")
        window.geometry("760x430")
        table = self._table(window, ("name", "kind", "threshold", "device", "enabled"),
                            (180, 150, 130, 170, 70))

        def refresh():
            self._replace(table, [(rule.name, rule.kind.replace("_", " "), rule.threshold,
                                   rule.device, "Yes" if rule.enabled else "No") for rule in self.rules])

        def add():
            name = simpledialog.askstring("Rule name", "Name for this alert:", parent=window)
            if not name:
                return
            kind = simpledialog.askstring(
                "Rule type", "Type: new_device, traffic_bytes, failed_connections, destination, port, or dns_name",
                parent=window)
            if not kind:
                return
            threshold = "0" if kind == "new_device" else simpledialog.askstring(
                "Condition", "Threshold, destination, port, or domain text:", parent=window)
            if threshold is None:
                return
            device = simpledialog.askstring(
                "Optional device", "Limit to one IP address, or leave blank:", parent=window) or ""
            try:
                rule = AlertRule.from_dict({"name": name, "kind": kind.strip(),
                                            "threshold": threshold, "device": device, "enabled": True})
                self.rules.append(rule)
                save_rules(self.rules_path, self.rules)
                refresh()
            except (OSError, ValueError) as error:
                messagebox.showerror("Invalid rule", str(error), parent=window)

        def remove():
            selected = table.selection()
            if not selected:
                return
            index = table.index(selected[0])
            del self.rules[index]
            save_rules(self.rules_path, self.rules)
            refresh()

        buttons = ttk.Frame(window, padding=8)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Add rule", command=add).pack(side="left")
        ttk.Button(buttons, text="Remove selected", command=remove).pack(side="left", padx=8)
        ttk.Button(buttons, text="Close", command=window.destroy).pack(side="right")
        refresh()

    def _refresh_history(self) -> None:
        self._replace(self.history, [(
            session_id, datetime.fromtimestamp(started, UTC).astimezone().strftime("%Y-%m-%d %H:%M"),
            f"{max(0, ended - started):.0f}s", f"{packets:,}", self._size(size), capture)
            for session_id, started, ended, packets, size, capture in self.store.recent_sessions()])

    def close(self) -> None:
        if self.capture and self.capture.running:
            if not messagebox.askyesno("Stop Network Watch", "Stop the active watch and close?", parent=self):
                return
            self.close_after_final = True
            self.capture.stop()
            self._finish_capture()
            if self.final_generation is not None:
                return
        self.store.close()
        self.destroy()
