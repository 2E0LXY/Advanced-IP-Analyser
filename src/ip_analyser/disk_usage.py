"""Read-only disk usage analysis and its desktop view."""

from __future__ import annotations

import csv
import heapq
import os
import queue
import threading
import time
import tkinter as tk
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


@dataclass(frozen=True)
class FileUsage:
    path: Path
    size: int
    modified: float


@dataclass(frozen=True)
class FolderUsage:
    path: Path
    size: int
    files: int


@dataclass(frozen=True)
class DiskUsageResult:
    root: Path
    total_size: int
    file_count: int
    folder_count: int
    skipped: int
    elapsed: float
    largest_files: tuple[FileUsage, ...]
    folders: tuple[FolderUsage, ...]
    limited: bool


def format_bytes(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if amount < 1024 or unit == "PB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PB"


def analyze_path(root: Path, *, max_files: int = 250_000, min_size: int = 0,
                 largest_limit: int = 1_000,
                 cancelled: threading.Event | None = None,
                 progress: Callable[[int, int], None] | None = None) -> DiskUsageResult:
    """Walk *root* without following links and return bounded, read-only usage data."""
    started = time.monotonic()
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Not a folder: {root}")
    max_files = max(1, int(max_files))
    min_size = max(0, int(min_size))
    largest_limit = max(1, int(largest_limit))
    direct_size: dict[Path, int] = defaultdict(int)
    direct_files: dict[Path, int] = defaultdict(int)
    folders: set[Path] = {root}
    largest: list[tuple[int, int, FileUsage]] = []
    total_size = file_count = skipped = 0
    limited = False
    serial = 0

    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        if cancelled is not None and cancelled.is_set():
            break
        folder = Path(directory)
        folders.add(folder)
        names[:] = [name for name in names if not (folder / name).is_symlink()]
        for name in files:
            if cancelled is not None and cancelled.is_set():
                break
            if file_count >= max_files:
                limited = True
                break
            path = folder / name
            try:
                stat = path.stat(follow_symlinks=False)
                if path.is_symlink() or not path.is_file():
                    continue
            except (OSError, ValueError):
                skipped += 1
                continue
            size = max(0, stat.st_size)
            file_count += 1
            total_size += size
            direct_size[folder] += size
            direct_files[folder] += 1
            if size >= min_size:
                usage = FileUsage(path=path, size=size, modified=stat.st_mtime)
                serial += 1
                item = (size, serial, usage)
                if len(largest) < largest_limit:
                    heapq.heappush(largest, item)
                elif size > largest[0][0]:
                    heapq.heapreplace(largest, item)
            if progress is not None and file_count % 500 == 0:
                progress(file_count, total_size)
        if limited:
            break

    recursive_size = dict(direct_size)
    recursive_files = dict(direct_files)
    for folder in sorted(folders, key=lambda item: len(item.parts), reverse=True):
        if folder == root:
            continue
        parent = folder.parent
        recursive_size[parent] = recursive_size.get(parent, 0) + recursive_size.get(folder, 0)
        recursive_files[parent] = recursive_files.get(parent, 0) + recursive_files.get(folder, 0)
    folder_rows = tuple(
        FolderUsage(path=folder, size=recursive_size.get(folder, 0),
                    files=recursive_files.get(folder, 0))
        for folder in sorted(folders, key=lambda item: recursive_size.get(item, 0), reverse=True)
    )
    files_descending = tuple(item[2] for item in sorted(largest, reverse=True))
    return DiskUsageResult(
        root=root, total_size=total_size, file_count=file_count, folder_count=len(folders),
        skipped=skipped, elapsed=time.monotonic() - started,
        largest_files=files_descending, folders=folder_rows, limited=limited,
    )


class DiskUsageView(tk.Frame):
    """A bounded folder scanner with sortable evidence and a proportional size map."""

    BACKGROUND = "#0d1b29"
    PANEL = "#152535"
    BORDER = "#294155"
    TEXT = "#e8f1fc"
    MUTED = "#9fb4ca"
    COLORS = ("#1688e7", "#36cf83", "#ff9b36", "#9b7cff", "#37bffc", "#ef6473")

    def __init__(self, parent: tk.Misc):
        super().__init__(parent, bg=self.BACKGROUND)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.cancel_event = threading.Event()
        self.result: DiskUsageResult | None = None
        self._folder_rows: dict[str, FolderUsage] = {}
        self._file_rows: dict[str, FileUsage] = {}
        self._build()

    def _build(self) -> None:
        header = tk.Frame(self, bg=self.BACKGROUND, padx=10, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="Disk Usage", bg=self.BACKGROUND, fg=self.TEXT,
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(header, text="Find the folders and files using your storage. Analysis is read-only.",
                 bg=self.BACKGROUND, fg=self.MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 10))
        controls = tk.Frame(header, bg=self.BACKGROUND)
        controls.pack(fill="x")
        self.path_var = tk.StringVar(value=str(Path.home()))
        ttk.Entry(controls, textvariable=self.path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(controls, text="Browse…", command=self._browse).pack(side="left", padx=(8, 0))
        ttk.Label(controls, text="File limit").pack(side="left", padx=(16, 5))
        self.limit_var = tk.StringVar(value="250000")
        ttk.Combobox(controls, textvariable=self.limit_var, width=9, state="readonly",
                     values=("50000", "100000", "250000", "500000", "1000000")).pack(side="left")
        self.scan_button = ttk.Button(controls, text="Analyze", style="Accent.TButton", command=self.start)
        self.scan_button.pack(side="left", padx=(8, 0))
        self.cancel_button = ttk.Button(controls, text="Cancel", state="disabled", command=self.cancel)
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.export_button = ttk.Button(controls, text="Export CSV…", state="disabled", command=self.export_csv)
        self.export_button.pack(side="left", padx=(8, 0))

        self.status = tk.Label(header, text="Choose a folder and select Analyze.", bg=self.BACKGROUND,
                               fg=self.MUTED, font=("Segoe UI", 9), anchor="w")
        self.status.pack(fill="x", pady=(8, 0))

        metrics = tk.Frame(self, bg=self.BACKGROUND, padx=10)
        metrics.pack(fill="x")
        self.metric_values: dict[str, tk.Label] = {}
        for column, (key, label) in enumerate((("size", "Space analyzed"), ("files", "Files"),
                                               ("folders", "Folders"), ("largest", "Largest file"))):
            metrics.columnconfigure(column, weight=1, uniform="disk-metric")
            card = tk.Frame(metrics, bg=self.PANEL, highlightbackground=self.BORDER,
                            highlightthickness=1, padx=13, pady=9)
            card.grid(row=0, column=column, sticky="ew", padx=(0, 8 if column < 3 else 0))
            tk.Label(card, text=label, bg=self.PANEL, fg=self.MUTED,
                     font=("Segoe UI", 8)).pack(anchor="w")
            value = tk.Label(card, text="—", bg=self.PANEL, fg=self.TEXT,
                             font=("Segoe UI", 14, "bold"), anchor="w")
            value.pack(anchor="w", pady=(3, 0))
            self.metric_values[key] = value

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=10)
        folder_panel = ttk.Frame(body)
        file_panel = ttk.Frame(body)
        body.add(folder_panel, weight=2)
        body.add(file_panel, weight=3)
        ttk.Label(folder_panel, text="Largest folders", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
        self.folder_table = ttk.Treeview(folder_panel, columns=("folder", "size", "share", "files"),
                                         show="headings", selectmode="browse")
        for key, label, width, anchor in (("folder", "Folder", 240, "w"), ("size", "Size", 90, "e"),
                                          ("share", "%", 55, "e"), ("files", "Files", 75, "e")):
            self.folder_table.heading(key, text=label)
            self.folder_table.column(key, width=width, anchor=anchor)
        self.folder_table.pack(fill="both", expand=True)

        ttk.Label(file_panel, text="Largest files", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))
        search_row = ttk.Frame(file_panel)
        search_row.pack(fill="x", pady=(0, 6))
        ttk.Label(search_row, text="Filter").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self._render_files())
        ttk.Entry(search_row, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=(7, 0))
        self.file_table = ttk.Treeview(file_panel, columns=("file", "size", "folder"),
                                       show="headings", selectmode="browse", height=10)
        for key, label, width, anchor in (("file", "File", 230, "w"), ("size", "Size", 90, "e"),
                                          ("folder", "Folder", 290, "w")):
            self.file_table.heading(key, text=label)
            self.file_table.column(key, width=width, anchor=anchor)
        self.file_table.pack(fill="both", expand=True)
        ttk.Label(file_panel, text="Size map", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(8, 4))
        self.map = tk.Canvas(file_panel, bg="#101f2e", highlightthickness=1,
                             highlightbackground=self.BORDER, height=115)
        self.map.pack(fill="x")
        self.map.bind("<Configure>", lambda _event: self._draw_map())

    def _browse(self) -> None:
        selected = filedialog.askdirectory(parent=self, initialdir=self.path_var.get() or str(Path.home()))
        if selected:
            self.path_var.set(selected)

    def start(self) -> None:
        try:
            root = Path(self.path_var.get().strip()).expanduser()
            limit = int(self.limit_var.get())
            if not root.is_dir():
                raise ValueError("Choose an existing folder.")
        except (ValueError, OSError) as error:
            messagebox.showerror("Cannot analyze folder", str(error), parent=self)
            return
        self.cancel_event = threading.Event()
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.status.configure(text=f"Analyzing {root}…")
        threading.Thread(target=self._worker, args=(root, limit), daemon=True).start()
        self.after(70, self._drain_events)

    def _worker(self, root: Path, limit: int) -> None:
        try:
            result = analyze_path(root, max_files=limit, cancelled=self.cancel_event,
                                  progress=lambda files, size: self.events.put(("progress", (files, size))))
            self.events.put(("done", result))
        except (OSError, ValueError) as error:
            self.events.put(("error", error))

    def _drain_events(self) -> None:
        finished = False
        while True:
            try:
                event, value = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "progress":
                files, size = value
                self.status.configure(text=f"Analyzing… {files:,} files · {format_bytes(size)}")
            elif event == "done":
                self._show_result(value)
                finished = True
            else:
                messagebox.showerror("Disk analysis failed", str(value), parent=self)
                finished = True
        if finished:
            self.scan_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
        else:
            self.after(70, self._drain_events)

    def cancel(self) -> None:
        self.cancel_event.set()
        self.cancel_button.configure(state="disabled")
        self.status.configure(text="Stopping after the current file…")

    def _show_result(self, result: DiskUsageResult) -> None:
        self.result = result
        self.metric_values["size"].configure(text=format_bytes(result.total_size))
        self.metric_values["files"].configure(text=f"{result.file_count:,}")
        self.metric_values["folders"].configure(text=f"{result.folder_count:,}")
        self.metric_values["largest"].configure(
            text=format_bytes(result.largest_files[0].size) if result.largest_files else "—")
        self.folder_table.delete(*self.folder_table.get_children())
        self._folder_rows.clear()
        for folder in result.folders[:500]:
            relative = "." if folder.path == result.root else str(folder.path.relative_to(result.root))
            share = (folder.size / result.total_size * 100) if result.total_size else 0
            item = self.folder_table.insert("", "end", values=(relative, format_bytes(folder.size),
                                                                 f"{share:.1f}", f"{folder.files:,}"))
            self._folder_rows[item] = folder
        self._render_files()
        self._draw_map()
        note = " · file limit reached" if result.limited else ""
        cancelled = " · cancelled" if self.cancel_event.is_set() else ""
        self.status.configure(text=(f"Completed in {result.elapsed:.1f}s · {result.skipped:,} inaccessible item(s)"
                                    f"{note}{cancelled}"))
        self.export_button.configure(state="normal")

    def _render_files(self) -> None:
        self.file_table.delete(*self.file_table.get_children())
        self._file_rows.clear()
        if self.result is None:
            return
        query = self.search_var.get().strip().casefold()
        for usage in self.result.largest_files:
            relative = str(usage.path.relative_to(self.result.root))
            if query and query not in relative.casefold():
                continue
            item = self.file_table.insert("", "end", values=(usage.path.name, format_bytes(usage.size),
                                                               str(usage.path.parent.relative_to(self.result.root))))
            self._file_rows[item] = usage
            if len(self._file_rows) >= 500:
                break

    def _draw_map(self) -> None:
        canvas = self.map
        canvas.delete("all")
        width, height = canvas.winfo_width(), canvas.winfo_height()
        if self.result is None or width < 20 or height < 20:
            canvas.create_text(12, 12, text="Folder proportions appear after analysis", anchor="nw",
                               fill=self.MUTED, font=("Segoe UI", 9))
            return
        children = [folder for folder in self.result.folders
                    if folder.path.parent == self.result.root and folder.size > 0][:16]
        total = sum(folder.size for folder in children)
        if not total:
            return
        x = 0.0
        for index, folder in enumerate(children):
            next_x = width if index == len(children) - 1 else x + width * folder.size / total
            color = self.COLORS[index % len(self.COLORS)]
            canvas.create_rectangle(x, 0, next_x, height, fill=color, outline="#0d1b29", width=2)
            if next_x - x > 68:
                canvas.create_text(x + 6, 8, text=folder.path.name, anchor="nw", fill="#ffffff",
                                   font=("Segoe UI", 8, "bold"), width=max(40, int(next_x - x - 12)))
                canvas.create_text(x + 6, height - 8, text=format_bytes(folder.size), anchor="sw",
                                   fill="#ffffff", font=("Segoe UI", 8))
            x = next_x

    def export_csv(self) -> None:
        if self.result is None:
            return
        destination = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                                    filetypes=[("CSV", "*.csv")],
                                                    initialfile="disk-usage.csv")
        if not destination:
            return
        try:
            with Path(destination).open("w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(("path", "bytes", "formatted_size", "modified"))
                for usage in self.result.largest_files:
                    writer.writerow((str(usage.path), usage.size, format_bytes(usage.size),
                                     time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(usage.modified))))
            self.status.configure(text=f"Saved {destination}")
        except OSError as error:
            messagebox.showerror("Cannot export report", str(error), parent=self)
