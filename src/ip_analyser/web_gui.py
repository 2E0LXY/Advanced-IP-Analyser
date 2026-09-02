from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .web_audit import WebAuditReport, audit_site, export_web_audit


class WebSecurityAudit(tk.Toplevel):
    def __init__(self, parent: tk.Misc, initial_url: str = ""):
        super().__init__(parent)
        self.title("Web Security Audit")
        self.geometry("1180x760")
        self.minsize(860, 580)
        self.report: WebAuditReport | None = None
        self.events: queue.Queue = queue.Queue()
        self._build(initial_url)

    def _build(self, initial_url: str) -> None:
        target = ttk.Frame(self, padding=12)
        target.pack(fill="x")
        ttk.Label(target, text="Authorized URL").grid(row=0, column=0, sticky="w")
        self.url = ttk.Entry(target)
        self.url.insert(0, initial_url or "https://")
        self.url.grid(row=0, column=1, columnspan=7, sticky="ew", padx=(8, 0))
        target.columnconfigure(1, weight=1)

        ttk.Label(target, text="Pages").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.pages = ttk.Spinbox(target, from_=1, to=100, width=6)
        self.pages.set("25")
        self.pages.grid(row=1, column=1, sticky="w", padx=(8, 16), pady=(8, 0))
        ttk.Label(target, text="Depth").grid(row=1, column=2, sticky="w", pady=(8, 0))
        self.depth = ttk.Spinbox(target, from_=0, to=5, width=5)
        self.depth.set("2")
        self.depth.grid(row=1, column=3, sticky="w", padx=(8, 16), pady=(8, 0))
        ttk.Label(target, text="Timeout").grid(row=1, column=4, sticky="w", pady=(8, 0))
        self.timeout = ttk.Spinbox(target, from_=0.5, to=20, increment=.5, width=6)
        self.timeout.set("5")
        self.timeout.grid(row=1, column=5, sticky="w", padx=(8, 16), pady=(8, 0))
        ttk.Label(target, text="Exclude paths").grid(row=1, column=6, sticky="w", pady=(8, 0))
        self.excludes = ttk.Entry(target, width=28)
        self.excludes.grid(row=1, column=7, sticky="ew", padx=(8, 0), pady=(8, 0))

        ttk.Label(target, text="Allowed extra hosts").grid(row=2, column=0, sticky="w", pady=(8, 0))
        self.allowed_hosts = ttk.Entry(target)
        self.allowed_hosts.grid(row=2, column=1, columnspan=3, sticky="ew", padx=(8, 16), pady=(8, 0))
        ttk.Label(target, text="Custom headers").grid(row=2, column=4, sticky="w", pady=(8, 0))
        self.headers = ttk.Entry(target)
        self.headers.grid(row=2, column=5, columnspan=3, sticky="ew", padx=(8, 0), pady=(8, 0))
        ttk.Label(target, text="Comma-separated. Headers use Name: value; separate multiple headers with |.",
                  foreground="#536579").grid(row=3, column=1, columnspan=7, sticky="w", padx=(8, 0))

        controls = ttk.Frame(self, padding=(12, 0, 12, 8))
        controls.pack(fill="x")
        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, variable=self.authorized,
                        text="I confirm I own or am explicitly authorized to audit this target",
                        command=self._authorization_changed).pack(side="left")
        self.start_button = ttk.Button(controls, text="Start audit", command=self.start,
                                       state="disabled", style="Accent.TButton")
        self.start_button.pack(side="right")
        self.save_button = ttk.Button(controls, text="Save report…", command=self.save, state="disabled")
        self.save_button.pack(side="right", padx=(0, 8))

        summary = ttk.Frame(self, padding=(12, 0, 12, 8))
        summary.pack(fill="x")
        self.summary_labels = {}
        for name in ("Pages", "High", "Medium", "Low", "Info"):
            box = ttk.LabelFrame(summary, text=name, padding=(18, 5))
            box.pack(side="left", fill="x", expand=True, padx=(0, 6))
            label = ttk.Label(box, text="0", font=("TkDefaultFont", 14, "bold"))
            label.pack()
            self.summary_labels[name] = label

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12)
        findings_page = ttk.Frame(notebook)
        pages_page = ttk.Frame(notebook)
        errors_page = ttk.Frame(notebook)
        notebook.add(findings_page, text="Findings")
        notebook.add(pages_page, text="Crawled pages")
        notebook.add(errors_page, text="Errors and TLS")

        self.findings = self._table(findings_page,
                                    ("severity", "title", "url", "evidence", "recommendation"),
                                    (80, 230, 280, 260, 340))
        self.pages_table = self._table(pages_page,
                                       ("status", "url", "title", "technology", "bytes", "links", "forms"),
                                       (70, 330, 250, 180, 90, 70, 70))
        self.details = tk.Text(errors_page, wrap="word", state="disabled", background="#f8fcff")
        self.details.pack(fill="both", expand=True)
        self.status = ttk.Label(self, text="Read-only audit ready. No exploit payloads are sent.", padding=12)
        self.status.pack(fill="x")

    @staticmethod
    def _table(parent: ttk.Frame, columns: tuple[str, ...], widths: tuple[int, ...]) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        table = ttk.Treeview(frame, columns=columns, show="headings")
        for column, width in zip(columns, widths):
            table.heading(column, text=column.title())
            table.column(column, width=width, anchor="w")
        vertical = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=table.xview)
        table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        table.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return table

    def _authorization_changed(self) -> None:
        self.start_button.configure(state="normal" if self.authorized.get() else "disabled")

    def _request_headers(self) -> dict[str, str]:
        result = {}
        for item in self.headers.get().split("|"):
            if not item.strip():
                continue
            name, separator, value = item.partition(":")
            if not separator:
                raise ValueError("custom headers must use Name: value")
            result[name.strip()] = value.strip()
        return result

    def start(self) -> None:
        if not self.authorized.get():
            return
        try:
            options = (self.url.get(), int(self.pages.get()), int(self.depth.get()), float(self.timeout.get()),
                       tuple(item.strip() for item in self.excludes.get().split(",") if item.strip()),
                       tuple(item.strip() for item in self.allowed_hosts.get().split(",") if item.strip()),
                       self._request_headers())
        except (ValueError, TypeError) as error:
            messagebox.showerror("Invalid audit settings", str(error), parent=self)
            return
        self.report = None
        self.findings.delete(*self.findings.get_children())
        self.pages_table.delete(*self.pages_table.get_children())
        self.start_button.configure(state="disabled")
        self.save_button.configure(state="disabled")
        self.status.configure(text="Starting bounded web audit…")
        threading.Thread(target=self._worker, args=options, daemon=True).start()
        self.after(80, self._drain)

    def _worker(self, url: str, pages: int, depth: int, timeout: float,
                excludes: tuple[str, ...], hosts: tuple[str, ...], headers: dict[str, str]) -> None:
        try:
            report = audit_site(url, max_pages=pages, max_depth=depth, timeout=timeout,
                                excluded_paths=excludes, allowed_hosts=hosts,
                                request_headers=headers,
                                progress=lambda number, current: self.events.put(("progress", number, current)))
            self.events.put(("done", report))
        except Exception as error:
            self.events.put(("error", error))

    def _drain(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    self.status.configure(text=f"Auditing page {event[1]}: {event[2]}")
                elif event[0] == "done":
                    self.report = event[1]
                    self._show_report()
                    return
                else:
                    self.start_button.configure(state="normal")
                    self.status.configure(text="Audit failed")
                    messagebox.showerror("Web audit failed", str(event[1]), parent=self)
                    return
        except queue.Empty:
            self.after(80, self._drain)

    def _show_report(self) -> None:
        assert self.report is not None
        for item in self.report.findings:
            self.findings.insert("", "end", values=(item.severity, item.title, item.url,
                                                     item.evidence, item.recommendation))
        for page in self.report.pages:
            self.pages_table.insert("", "end", values=(page.status, page.url, page.title,
                                                        ", ".join(page.technologies), page.size,
                                                        page.links, page.forms))
        counts = {severity: sum(item.severity == severity for item in self.report.findings)
                  for severity in ("High", "Medium", "Low", "Info")}
        self.summary_labels["Pages"].configure(text=str(len(self.report.pages)))
        for severity, count in counts.items():
            self.summary_labels[severity].configure(text=str(count))
        detail = "TLS\n" + "\n".join(f"{key}: {value}" for key, value in self.report.tls.items())
        detail += "\n\nErrors\n" + ("\n".join(self.report.errors) or "None")
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", detail)
        self.details.configure(state="disabled")
        self.start_button.configure(state="normal")
        self.save_button.configure(state="normal")
        self.status.configure(text=f"Complete: {len(self.report.pages)} pages and "
                                   f"{len(self.report.findings)} observations")

    def save(self) -> None:
        if not self.report:
            return
        filename = filedialog.asksaveasfilename(parent=self, title="Save web audit report",
                                                defaultextension=".html",
                                                filetypes=(("HTML report", "*.html"),
                                                           ("JSON report", "*.json")))
        if not filename:
            return
        try:
            export_web_audit(Path(filename), self.report)
        except (OSError, ValueError) as error:
            messagebox.showerror("Could not save report", str(error), parent=self)
            return
        self.status.configure(text=f"Saved report to {filename}")
