"""Integrated Network Operations workspace."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .network_operations import (
    MonitorPolicy,
    capture_capabilities,
    discover_local_services,
    discover_ssdp,
    export_operations_report,
    fetch_cisa_kev,
    find_address_conflicts,
    load_monitor_policy,
    match_kev,
    read_neighbor_table,
    run_iperf3,
    save_monitor_policy,
    scan_change_summary,
    snmp_system_summary,
    tcp_quality,
    top_talkers,
    topology_evidence,
)


class NetworkOperationsView(ttk.Frame):
    """One professional workspace for infrastructure and continuous operations."""

    def __init__(self, master, *, target_getter, start_scan, open_network_watch,
                 policy_changed=lambda _policy: None):
        super().__init__(master, padding=10)
        self.target_getter = target_getter
        self.start_scan = start_scan
        self.open_network_watch = open_network_watch
        self.policy_changed = policy_changed
        self.events: queue.Queue = queue.Queue()
        self.catalogue: dict[str, object] | None = None
        self._build()
        self.after(150, self._drain_events)

    def _build(self) -> None:
        heading = ttk.Frame(self)
        heading.pack(fill="x", pady=(0, 8))
        text = ttk.Frame(heading)
        text.pack(side="left", fill="x", expand=True)
        ttk.Label(text, text="Network Operations", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ttk.Label(text, text="Changes, infrastructure, traffic, performance, exposure and automation",
                  foreground="#8fb1d0").pack(anchor="w")
        ttk.Button(heading, text="Export operations report…", command=self._export_report).pack(side="right")
        ttk.Button(heading, text="Run inventory scan", style="Accent.TButton",
                   command=self.start_scan).pack(side="right", padx=(0, 8))

        self.tabs = ttk.Notebook(self, style="Dark.TNotebook")
        self.tabs.pack(fill="both", expand=True)
        self.changes_page = ttk.Frame(self.tabs, padding=10)
        self.infrastructure_page = ttk.Frame(self.tabs, padding=10)
        self.traffic_page = ttk.Frame(self.tabs, padding=10)
        self.performance_page = ttk.Frame(self.tabs, padding=10)
        self.exposure_page = ttk.Frame(self.tabs, padding=10)
        self.automation_page = ttk.Frame(self.tabs, padding=10)
        for page, label in (
            (self.changes_page, "Changes & conflicts"),
            (self.infrastructure_page, "SNMP & topology"),
            (self.traffic_page, "Traffic attribution"),
            (self.performance_page, "Quality & throughput"),
            (self.exposure_page, "Vulnerability lifecycle"),
            (self.automation_page, "Schedules & alerts"),
        ):
            self.tabs.add(page, text=label)
        self._build_changes()
        self._build_infrastructure()
        self._build_traffic()
        self._build_performance()
        self._build_exposure()
        self._build_automation()

        self.status = ttk.Label(self, text="Ready · operations remain local unless an external feed or webhook is explicitly used.",
                                foreground="#8fb1d0")
        self.status.pack(fill="x", pady=(8, 0))

    @staticmethod
    def _tree(parent, columns: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        holder = ttk.Frame(parent)
        holder.pack(fill="both", expand=True)
        table = ttk.Treeview(holder, columns=columns, show="headings")
        for name, width in zip(columns, widths):
            table.heading(name, text=name.replace("_", " ").title())
            table.column(name, width=width, anchor="w")
        vertical = ttk.Scrollbar(holder, orient="vertical", command=table.yview)
        horizontal = ttk.Scrollbar(holder, orient="horizontal", command=table.xview)
        table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        table.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        return table

    def _build_changes(self) -> None:
        tools = ttk.Frame(self.changes_page)
        tools.pack(fill="x", pady=(0, 8))
        ttk.Button(tools, text="Refresh baseline comparison", style="Accent.TButton",
                   command=self.refresh_changes).pack(side="left")
        ttk.Button(tools, text="Inspect neighbour conflicts", command=self.refresh_conflicts).pack(side="left", padx=8)
        ttk.Label(tools, text="Compares the latest two completed inventory snapshots and current ARP/NDP cache.",
                  foreground="#8fb1d0").pack(side="left", padx=12)
        self.change_summary = ttk.Label(self.changes_page, text="No comparison loaded.",
                                        font=("Segoe UI", 11, "bold"))
        self.change_summary.pack(anchor="w", pady=(0, 8))
        self.change_table = self._tree(self.changes_page,
                                       ("severity", "category", "device", "change", "explanation"),
                                       (80, 150, 180, 210, 600))

    def _build_infrastructure(self) -> None:
        connection = ttk.LabelFrame(self.infrastructure_page, text="Authorized infrastructure target", padding=8)
        connection.pack(fill="x", pady=(0, 8))
        ttk.Label(connection, text="IP").pack(side="left")
        self.infrastructure_target = ttk.Entry(connection, width=24)
        self.infrastructure_target.pack(side="left", padx=(6, 12))
        ttk.Button(connection, text="Use scan target", command=self._use_scan_target).pack(side="left", padx=(0, 12))
        ttk.Label(connection, text="SNMP").pack(side="left")
        self.snmp_version = ttk.Combobox(connection, values=("2c", "3"), state="readonly", width=5)
        self.snmp_version.set("2c")
        self.snmp_version.pack(side="left", padx=(6, 8))
        ttk.Label(connection, text="Community / user").pack(side="left")
        self.snmp_identity = ttk.Entry(connection, width=18, show="•")
        self.snmp_identity.pack(side="left", padx=(6, 8))
        ttk.Label(connection, text="Auth password").pack(side="left")
        self.snmp_auth = ttk.Entry(connection, width=16, show="•")
        self.snmp_auth.pack(side="left", padx=(6, 8))
        ttk.Label(connection, text="Privacy password").pack(side="left")
        self.snmp_privacy = ttk.Entry(connection, width=16, show="•")
        self.snmp_privacy.pack(side="left", padx=(6, 0))

        actions = ttk.Frame(self.infrastructure_page)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Read SNMP system", style="Accent.TButton",
                   command=self.read_snmp).pack(side="left")
        ttk.Button(actions, text="Read LLDP/CDP neighbours", command=self.read_topology).pack(side="left", padx=8)
        ttk.Button(actions, text="Resolve DNS + mDNS", command=self.resolve_services).pack(side="left")
        ttk.Button(actions, text="Discover SSDP/UPnP", command=self.resolve_ssdp).pack(side="left", padx=8)
        ttk.Label(actions, text="Credentials are used in memory for this request and are not saved.",
                  foreground="#8fb1d0").pack(side="right")
        self.infrastructure_table = self._tree(
            self.infrastructure_page, ("source", "subject", "value", "detail"), (150, 250, 330, 580))

    def _build_traffic(self) -> None:
        tools = ttk.Frame(self.traffic_page)
        tools.pack(fill="x", pady=(0, 8))
        ttk.Button(tools, text="Refresh top talkers", style="Accent.TButton",
                   command=self.refresh_talkers).pack(side="left")
        ttk.Button(tools, text="Detect capture providers", command=self.refresh_capture).pack(side="left", padx=8)
        ttk.Button(tools, text="Open Network Security Monitor",
                   command=self.open_network_watch).pack(side="left")
        ttk.Label(tools, text="Attribution requires a capture point that can observe the relevant LAN traffic.",
                  foreground="#8fb1d0").pack(side="right")
        self.traffic_table = self._tree(
            self.traffic_page, ("device_or_provider", "sent", "received", "peers", "protocols", "detail"),
            (210, 120, 120, 180, 260, 500))

    def _build_performance(self) -> None:
        quality = ttk.LabelFrame(self.performance_page, text="TCP quality test", padding=8)
        quality.pack(fill="x", pady=(0, 8))
        ttk.Label(quality, text="Target").pack(side="left")
        self.quality_target = ttk.Entry(quality, width=24)
        self.quality_target.pack(side="left", padx=(6, 12))
        ttk.Label(quality, text="Port").pack(side="left")
        self.quality_port = ttk.Spinbox(quality, from_=1, to=65_535, width=7)
        self.quality_port.set("443")
        self.quality_port.pack(side="left", padx=(6, 12))
        ttk.Label(quality, text="Samples").pack(side="left")
        self.quality_samples = ttk.Spinbox(quality, from_=1, to=200, width=6)
        self.quality_samples.set("10")
        self.quality_samples.pack(side="left", padx=(6, 12))
        ttk.Button(quality, text="Measure quality", style="Accent.TButton",
                   command=self.measure_quality).pack(side="left")

        throughput = ttk.LabelFrame(self.performance_page, text="iPerf3 throughput", padding=8)
        throughput.pack(fill="x", pady=(0, 8))
        ttk.Label(throughput, text="Server").pack(side="left")
        self.iperf_target = ttk.Entry(throughput, width=24)
        self.iperf_target.pack(side="left", padx=(6, 12))
        ttk.Label(throughput, text="Seconds").pack(side="left")
        self.iperf_seconds = ttk.Spinbox(throughput, from_=1, to=120, width=6)
        self.iperf_seconds.set("10")
        self.iperf_seconds.pack(side="left", padx=(6, 12))
        self.iperf_reverse = tk.BooleanVar()
        self.iperf_udp = tk.BooleanVar()
        ttk.Checkbutton(throughput, text="Reverse", variable=self.iperf_reverse).pack(side="left")
        ttk.Checkbutton(throughput, text="UDP", variable=self.iperf_udp).pack(side="left", padx=8)
        ttk.Label(throughput, text="UDP bitrate").pack(side="left")
        self.iperf_bandwidth = ttk.Entry(throughput, width=8)
        self.iperf_bandwidth.insert(0, "10M")
        self.iperf_bandwidth.pack(side="left", padx=(6, 12))
        ttk.Button(throughput, text="Run iPerf3", command=self.run_iperf).pack(side="left")
        ttk.Label(throughput, text="Requires an authorized iPerf3 server and local iperf3 executable.",
                  foreground="#8fb1d0").pack(side="right")
        self.performance_text = tk.Text(self.performance_page, wrap="word", state="disabled",
                                        bg="#0b1825", fg="#d8e5f3", relief="flat", padx=14, pady=12)
        self.performance_text.pack(fill="both", expand=True)

    def _build_exposure(self) -> None:
        tools = ttk.Frame(self.exposure_page)
        tools.pack(fill="x", pady=(0, 8))
        ttk.Label(tools, text="Vendor / product terms").pack(side="left")
        self.kev_terms = ttk.Entry(tools)
        self.kev_terms.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(tools, text="Refresh CISA KEV and search", style="Accent.TButton",
                   command=self.search_kev).pack(side="left")
        ttk.Label(self.exposure_page,
                  text="Matches are review leads only. A product-name match does not prove the detected version is vulnerable.",
                  foreground="#f5c46b").pack(anchor="w", pady=(0, 8))
        self.exposure_table = self._tree(
            self.exposure_page, ("cve", "vendor", "product", "name", "added", "due", "action"),
            (130, 150, 160, 300, 95, 95, 500))

    def _build_automation(self) -> None:
        policy = load_monitor_policy()
        panel = ttk.LabelFrame(self.automation_page, text="Persistent monitoring policy", padding=12)
        panel.pack(fill="x", pady=(0, 10))
        self.policy_enabled = tk.BooleanVar(value=policy.enabled)
        ttk.Checkbutton(panel, text="Enable scheduled inventory while the desktop app is running",
                        variable=self.policy_enabled).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))
        ttk.Label(panel, text="Interval (minutes)").grid(row=1, column=0, sticky="w")
        self.policy_interval = ttk.Spinbox(panel, from_=1, to=10_080, width=8)
        self.policy_interval.set(str(policy.interval_minutes))
        self.policy_interval.grid(row=1, column=1, sticky="w", padx=(6, 22))
        ttk.Label(panel, text="Quiet hours").grid(row=1, column=2, sticky="w")
        self.policy_quiet_start = ttk.Entry(panel, width=7)
        self.policy_quiet_start.insert(0, policy.quiet_start)
        self.policy_quiet_start.grid(row=1, column=3, sticky="w", padx=(6, 4))
        ttk.Label(panel, text="to").grid(row=1, column=4)
        self.policy_quiet_end = ttk.Entry(panel, width=7)
        self.policy_quiet_end.insert(0, policy.quiet_end)
        self.policy_quiet_end.grid(row=1, column=5, sticky="w", padx=(4, 0))
        self.policy_new = tk.BooleanVar(value=policy.notify_new_devices)
        self.policy_missing = tk.BooleanVar(value=policy.notify_missing_devices)
        self.policy_ports = tk.BooleanVar(value=policy.notify_port_changes)
        ttk.Checkbutton(panel, text="New devices", variable=self.policy_new).grid(row=2, column=0, sticky="w", pady=8)
        ttk.Checkbutton(panel, text="Missing devices", variable=self.policy_missing).grid(row=2, column=1, sticky="w", pady=8)
        ttk.Checkbutton(panel, text="Port changes", variable=self.policy_ports).grid(row=2, column=2, sticky="w", pady=8)
        ttk.Label(panel, text="HTTPS webhook").grid(row=3, column=0, sticky="w")
        self.policy_webhook = ttk.Entry(panel)
        self.policy_webhook.insert(0, policy.webhook_url)
        self.policy_webhook.grid(row=3, column=1, columnspan=5, sticky="ew", padx=(6, 0))
        ttk.Label(panel, text="Report folder").grid(row=4, column=0, sticky="w", pady=(8, 0))
        self.policy_report = ttk.Entry(panel)
        self.policy_report.insert(0, policy.report_directory)
        self.policy_report.grid(row=4, column=1, columnspan=4, sticky="ew", padx=(6, 8), pady=(8, 0))
        ttk.Button(panel, text="Choose…", command=self._choose_report_folder).grid(row=4, column=5, pady=(8, 0))
        panel.columnconfigure(3, weight=1)
        buttons = ttk.Frame(self.automation_page)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Save monitoring policy", style="Accent.TButton",
                   command=self.save_policy).pack(side="left")
        ttk.Label(buttons, text="Webhooks are only used after an observed change and remain disabled until configured.",
                  foreground="#8fb1d0").pack(side="left", padx=12)

    def _background(self, label: str, function, callback) -> None:
        self.status.configure(text=label)
        def worker() -> None:
            try:
                result = function()
                self.events.put(("ok", callback, result))
            except Exception as error:  # UI boundary: explain optional tool/network failures.
                self.events.put(("error", None, f"{type(error).__name__}: {error}"))
        threading.Thread(target=worker, daemon=True).start()

    def _drain_events(self) -> None:
        try:
            while True:
                kind, callback, payload = self.events.get_nowait()
                if kind == "ok":
                    callback(payload)
                    self.status.configure(text="Completed.")
                else:
                    self.status.configure(text=str(payload))
                    messagebox.showerror("Network Operations", str(payload), parent=self)
        except queue.Empty:
            pass
        self.after(150, self._drain_events)

    @staticmethod
    def _clear(table: ttk.Treeview) -> None:
        table.delete(*table.get_children())

    def refresh_changes(self) -> None:
        summary = scan_change_summary()
        self._clear(self.change_table)
        for category in ("new", "missing", "changed"):
            for item in summary[category]:
                if category == "changed":
                    device = str(item.get("after", {}).get("address") or item.get("identity", ""))
                    change = ", ".join(item.get("fields", []))
                else:
                    device = str(item.get("address") or item.get("hostname") or "Unknown")
                    change = "First observed" if category == "new" else "Not present in latest scan"
                self.change_table.insert("", "end", values=(
                    "review", category.title(), device, change,
                    "Compare both snapshots and verify expected DHCP, maintenance or firewall changes."))
        self.change_summary.configure(text=(f"{len(summary['new'])} new · {len(summary['missing'])} missing · "
                                            f"{len(summary['changed'])} changed devices"))

    def refresh_conflicts(self) -> None:
        self._background("Reading the local neighbour cache…", read_neighbor_table, self._show_conflicts)

    def _show_conflicts(self, entries) -> None:
        self._clear(self.change_table)
        findings = find_address_conflicts(entries)
        for item in findings:
            self.change_table.insert("", "end", values=(item.severity, item.category, item.subject, "Current cache", item.explanation))
        self.change_summary.configure(text=f"{len(entries)} neighbour entries · {len(findings)} conflict finding(s)")

    def _use_scan_target(self) -> None:
        target = self.target_getter().split(",")[0].strip()
        if "/" in target:
            target = target.split("/", 1)[0]
        self.infrastructure_target.delete(0, "end")
        self.infrastructure_target.insert(0, target)

    def _target(self) -> str:
        value = self.infrastructure_target.get().strip()
        if not value:
            raise ValueError("enter one infrastructure IP address")
        return value

    def _credentials(self) -> dict[str, str]:
        if self.snmp_version.get() == "3":
            return {"username": self.snmp_identity.get(), "auth_password": self.snmp_auth.get(),
                    "privacy_password": self.snmp_privacy.get(), "auth_protocol": "SHA", "privacy_protocol": "AES"}
        return {"community": self.snmp_identity.get()}

    def read_snmp(self) -> None:
        target, identity = self._target(), self.snmp_identity.get()
        if self.snmp_version.get() != "2c":
            messagebox.showinfo("SNMPv3", "Use Read LLDP/CDP neighbours for authenticated SNMPv3 table access. "
                                "The compact system-summary reader uses native SNMPv2c.", parent=self)
            return
        self._background("Reading bounded SNMP system objects…",
                         lambda: snmp_system_summary(target, identity), self._show_snmp)

    def _show_snmp(self, values) -> None:
        self._clear(self.infrastructure_table)
        for item in values:
            self.infrastructure_table.insert("", "end", values=("SNMP", item.oid, item.value, item.value_type))

    def read_topology(self) -> None:
        target, version, credentials = self._target(), self.snmp_version.get(), self._credentials()
        self._background("Walking LLDP and CDP neighbour tables…",
                         lambda: topology_evidence(target, version, credentials), self._show_topology)

    def _show_topology(self, groups) -> None:
        self._clear(self.infrastructure_table)
        for group, values in groups.items():
            for item in values:
                self.infrastructure_table.insert("", "end", values=(group, item.oid, item.value, item.value_type))

    def resolve_services(self) -> None:
        target = self._target()
        self._background("Collecting DNS and mDNS evidence…",
                         lambda: discover_local_services(target), self._show_services)

    def resolve_ssdp(self) -> None:
        self._background("Listening briefly for SSDP/UPnP replies…", discover_ssdp, self._show_services)

    def _show_services(self, values) -> None:
        self._clear(self.infrastructure_table)
        for item in values:
            self.infrastructure_table.insert("", "end", values=(item.source, item.address, item.name, item.service + " " + item.detail))

    def refresh_talkers(self) -> None:
        self._clear(self.traffic_table)
        for item in top_talkers():
            self.traffic_table.insert("", "end", values=(item.get("address"), item.get("sent"), item.get("received"),
                                                         ", ".join(item.get("peers", [])[:8]),
                                                         json.dumps(item.get("protocols", {}), sort_keys=True), "Network Watch evidence"))

    def refresh_capture(self) -> None:
        self._clear(self.traffic_table)
        for item in capture_capabilities():
            self.traffic_table.insert("", "end", values=(item["provider"], "", "", item["available"], item["command"],
                                                         item["path"] or item["note"]))

    def measure_quality(self) -> None:
        target = self.quality_target.get().strip() or self.infrastructure_target.get().strip()
        port, samples = int(self.quality_port.get()), int(self.quality_samples.get())
        self._background("Measuring connection loss, latency, p95 and jitter…",
                         lambda: tcp_quality(target, port, samples), self._show_quality)

    def _set_performance_text(self, value: str) -> None:
        self.performance_text.configure(state="normal")
        self.performance_text.delete("1.0", "end")
        self.performance_text.insert("1.0", value)
        self.performance_text.configure(state="disabled")

    def _show_quality(self, result) -> None:
        self._set_performance_text(
            f"TCP quality for {result.target}:{result.port}\n\n"
            f"Successful: {result.successful} of {result.attempted}\nLoss: {result.loss_percent}%\n"
            f"Minimum: {result.minimum_ms} ms\nAverage: {result.average_ms} ms\n"
            f"95th percentile: {result.p95_ms} ms\nMean absolute jitter: {result.jitter_ms} ms\n\n"
            "A refused or filtered port counts as unsuccessful. This measures TCP connection setup, not payload throughput.")

    def run_iperf(self) -> None:
        target = self.iperf_target.get().strip()
        seconds = int(self.iperf_seconds.get())
        reverse = self.iperf_reverse.get()
        udp = self.iperf_udp.get()
        bandwidth = self.iperf_bandwidth.get().strip()
        self._background("Running the authorized iPerf3 test…",
                         lambda: run_iperf3(target, seconds, reverse=reverse, udp=udp,
                                            bandwidth=bandwidth),
                         lambda value: self._set_performance_text(json.dumps(value, indent=2)[:200_000]))

    def search_kev(self) -> None:
        terms = self.kev_terms.get().replace(",", " ").split()
        def work():
            self.catalogue = fetch_cisa_kev()
            return match_kev(self.catalogue, terms)
        self._background("Downloading the current CISA Known Exploited Vulnerabilities catalogue…",
                         work, self._show_kev)

    def _show_kev(self, matches) -> None:
        self._clear(self.exposure_table)
        for item in matches:
            self.exposure_table.insert("", "end", values=(item.get("cveID"), item.get("vendorProject"),
                                                           item.get("product"), item.get("vulnerabilityName"),
                                                           item.get("dateAdded"), item.get("dueDate"),
                                                           item.get("requiredAction")))
        self.status.configure(text=f"{len(matches)} evidence match(es). Verify exact product and version before acting.")

    def _choose_report_folder(self) -> None:
        value = filedialog.askdirectory(parent=self)
        if value:
            self.policy_report.delete(0, "end")
            self.policy_report.insert(0, value)

    def save_policy(self) -> None:
        try:
            policy = MonitorPolicy(
                enabled=self.policy_enabled.get(), interval_minutes=int(self.policy_interval.get()),
                quiet_start=self.policy_quiet_start.get().strip(), quiet_end=self.policy_quiet_end.get().strip(),
                notify_new_devices=self.policy_new.get(), notify_missing_devices=self.policy_missing.get(),
                notify_port_changes=self.policy_ports.get(), webhook_url=self.policy_webhook.get().strip(),
                report_directory=self.policy_report.get().strip())
            path = save_monitor_policy(policy)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            messagebox.showerror("Monitoring policy", str(error), parent=self)
            return
        self.policy_changed(policy)
        self.status.configure(text=f"Monitoring policy saved to {path}")

    def _export_report(self) -> None:
        value = filedialog.asksaveasfilename(parent=self, defaultextension=".json",
                                             initialfile="network-operations-report.json",
                                             filetypes=[("JSON report", "*.json")])
        if not value:
            return
        self._background("Building the bounded operations report…",
                         lambda: export_operations_report(Path(value)),
                         lambda path: self.status.configure(text=f"Report saved to {path}"))
