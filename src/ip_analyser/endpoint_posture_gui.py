"""Tk workspace for the read-only endpoint posture report."""

from __future__ import annotations

import json
import threading
import tkinter as tk
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .endpoint_posture import PostureReport, collect_endpoint_posture


class EndpointPostureView(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=16)
        self.report: PostureReport | None = None
        self.summary = tk.StringVar(value="Select Refresh posture to inspect this PC.")
        self._build()

    def _build(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 12))
        title = ttk.Frame(header)
        title.pack(side="left", fill="x", expand=True)
        ttk.Label(title, text="Endpoint Security Posture", font=("Segoe UI", 21, "bold")).pack(anchor="w")
        ttk.Label(
            title,
            text="Read-only Windows checks - no firewall, antivirus, privacy or DNS setting is changed.",
            foreground="#90abc4",
        ).pack(anchor="w")
        self.refresh_button = ttk.Button(
            header, text="Refresh posture", command=self.refresh, style="Accent.TButton")
        self.refresh_button.pack(side="right")
        ttk.Button(header, text="Export JSON...", command=self.export_json).pack(side="right", padx=(0, 8))
        ttk.Button(header, text="Copy report", command=self.copy_report).pack(side="right", padx=(0, 8))

        ttk.Label(self, textvariable=self.summary, foreground="#7ed6a5").pack(fill="x", pady=(0, 10))
        columns = ("status", "check", "result", "recommendation")
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        widths = (105, 190, 470, 470)
        for column, width in zip(columns, widths):
            self.table.heading(column, text=column.title())
            self.table.column(column, width=width, minwidth=80, anchor="w")
        scroll_y = ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        self.table.pack(fill="both", expand=True)
        self.table.tag_configure("good", foreground="#83dfa9")
        self.table.tag_configure("attention", foreground="#ffae6d")
        self.table.tag_configure("info", foreground="#7fc9ff")
        self.table.tag_configure("unknown", foreground="#b9c2cb")

        note = (
            "What this is: a transparent configuration snapshot inspired by desktop-security status views. "
            "It does not scan file contents, block ransomware, judge whether a process is malicious, or replace antivirus. "
            "Unknown means unverified - never silently treated as safe."
        )
        ttk.Label(self, text=note, foreground="#7896b1", wraplength=1120,
                  justify="left").pack(fill="x", pady=(10, 0))

    def refresh(self) -> None:
        self.refresh_button.configure(state="disabled")
        self.summary.set("Reading Windows security providers...")
        threading.Thread(target=self._collect, daemon=True).start()

    def _collect(self) -> None:
        report = collect_endpoint_posture()
        self.after(0, lambda: self._show(report))

    def _show(self, report: PostureReport) -> None:
        self.report = report
        self.table.delete(*self.table.get_children())
        for finding in report.findings:
            self.table.insert("", "end", values=(
                finding.status.upper(), finding.title, finding.summary,
                finding.recommendation or "No action suggested.",
            ), tags=(finding.status,))
        unknown = sum(item.status == "unknown" for item in report.findings)
        self.summary.set(
            f"{len(report.findings)} checks - {report.attention_count} need attention - "
            f"{unknown} unverified - collected locally on {report.platform}"
        )
        self.refresh_button.configure(state="normal")

    def _report_text(self) -> str:
        if self.report is None:
            return "No endpoint posture report has been collected."
        lines = ["Advanced IP Analyser - Endpoint Security Posture",
                 f"Collected: {self.report.collected_at}", f"Platform: {self.report.platform}", ""]
        for item in self.report.findings:
            lines.append(f"[{item.status.upper()}] {item.title}: {item.summary}")
            if item.recommendation:
                lines.append(f"  Suggested review: {item.recommendation}")
        lines.extend(("", "Read-only status report; not proof that a device is safe or compromised."))
        return "\n".join(lines)

    def copy_report(self) -> None:
        self.clipboard_clear()
        self.clipboard_append(self._report_text())
        self.update_idletasks()

    def export_json(self) -> None:
        if self.report is None:
            messagebox.showinfo("Nothing to export", "Refresh the posture report first.", parent=self)
            return
        selected = filedialog.asksaveasfilename(
            parent=self, defaultextension=".json",
            filetypes=(("Posture JSON", "*.json"),), initialfile="endpoint-posture.json")
        if selected:
            Path(selected).write_text(json.dumps(asdict(self.report), indent=2), encoding="utf-8")
            messagebox.showinfo("Export complete", "The local posture report was saved.", parent=self)
