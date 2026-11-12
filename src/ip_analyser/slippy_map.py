"""Small, dependency-free OpenStreetMap widget for Tk applications."""

from __future__ import annotations

import base64
import math
import queue
import threading
import time
import tkinter as tk
import urllib.request
from dataclasses import dataclass
from collections.abc import Callable

from . import __version__


TILE_SIZE = 256
MIN_ZOOM = 1
MAX_ZOOM = 18
MAX_TILE_BYTES = 2 * 1024 * 1024
TILE_URL = "https://tile.openstreetmap.org/{zoom}/{x}/{y}.png"


@dataclass(frozen=True, slots=True)
class MapMarker:
    latitude: float
    longitude: float
    label: str
    address: str
    colour: str = "#31b8ff"
    payload: tuple[object, ...] = ()


def world_pixel(latitude: float, longitude: float, zoom: int) -> tuple[float, float]:
    """Convert WGS84 coordinates to Web Mercator world pixels."""
    latitude = max(-85.05112878, min(85.05112878, latitude))
    scale = TILE_SIZE * (2 ** zoom)
    x = (longitude + 180.0) / 360.0 * scale
    sin_latitude = math.sin(math.radians(latitude))
    y = (0.5 - math.log((1 + sin_latitude) / (1 - sin_latitude)) / (4 * math.pi)) * scale
    return x, y


def pixel_location(x: float, y: float, zoom: int) -> tuple[float, float]:
    """Convert Web Mercator world pixels back to latitude and longitude."""
    scale = TILE_SIZE * (2 ** zoom)
    y = max(0.0, min(scale, y))
    longitude = x / scale * 360.0 - 180.0
    mercator = math.pi * (1 - 2 * y / scale)
    latitude = math.degrees(math.atan(math.sinh(mercator)))
    return latitude, longitude


class SlippyMap(tk.Canvas):
    """Interactive tiled map with clustered destination markers."""

    def __init__(self, parent, *, on_marker_click: Callable[[list[MapMarker]], None] | None = None,
                 **kwargs):
        super().__init__(parent, bg="#07131f", highlightthickness=1,
                         highlightbackground="#2c4860", **kwargs)
        self.zoom = 2
        self.center_latitude = 25.0
        self.center_longitude = 0.0
        self.markers: list[MapMarker] = []
        self.on_marker_click = on_marker_click
        self._tile_bytes: dict[tuple[int, int, int], bytes] = {}
        self._tile_images: dict[tuple[int, int, int], tk.PhotoImage] = {}
        self._pending_tiles: set[tuple[int, int, int]] = set()
        self._failed_tiles: dict[tuple[int, int, int], float] = {}
        self._download_slots = threading.BoundedSemaphore(2)
        self._tile_events: queue.Queue = queue.Queue()
        self._drag_origin: tuple[int, int] | None = None
        self._drag_center: tuple[float, float] | None = None
        self._did_auto_fit = False
        self._drag_moved = False

        self.bind("<Configure>", lambda _event: self.redraw())
        self.bind("<ButtonPress-1>", self._start_drag)
        self.bind("<B1-Motion>", self._drag)
        self.bind("<ButtonRelease-1>", self._end_drag)
        self.bind("<MouseWheel>", self._wheel)
        self.bind("<Button-4>", lambda event: self.zoom_by(1, event.x, event.y))
        self.bind("<Button-5>", lambda event: self.zoom_by(-1, event.x, event.y))
        self.after(100, self._drain_tiles)

    def set_markers(self, markers: list[MapMarker]) -> None:
        self.markers = markers
        if markers and not self._did_auto_fit:
            self._did_auto_fit = True
            self.fit_markers()
        else:
            self.redraw()

    def fit_markers(self) -> None:
        if not self.markers:
            self.zoom = 2
            self.center_latitude = 25.0
            self.center_longitude = 0.0
            self.redraw()
            return
        latitudes = [marker.latitude for marker in self.markers]
        longitudes = [marker.longitude for marker in self.markers]
        self.center_latitude = (min(latitudes) + max(latitudes)) / 2
        self.center_longitude = (min(longitudes) + max(longitudes)) / 2
        width = max(self.winfo_width() - 100, 250)
        height = max(self.winfo_height() - 80, 140)
        for candidate in range(12, MIN_ZOOM - 1, -1):
            points = [world_pixel(marker.latitude, marker.longitude, candidate)
                      for marker in self.markers]
            if (max(point[0] for point in points) - min(point[0] for point in points) <= width and
                    max(point[1] for point in points) - min(point[1] for point in points) <= height):
                self.zoom = candidate
                break
        self.redraw()

    def zoom_by(self, amount: int, screen_x: int | None = None,
                screen_y: int | None = None) -> None:
        new_zoom = max(MIN_ZOOM, min(MAX_ZOOM, self.zoom + amount))
        if new_zoom == self.zoom:
            return
        width, height = max(self.winfo_width(), 1), max(self.winfo_height(), 1)
        screen_x = width // 2 if screen_x is None else screen_x
        screen_y = height // 2 if screen_y is None else screen_y
        center_x, center_y = world_pixel(self.center_latitude, self.center_longitude, self.zoom)
        focus_x = center_x + screen_x - width / 2
        focus_y = center_y + screen_y - height / 2
        focus_latitude, focus_longitude = pixel_location(focus_x, focus_y, self.zoom)
        new_focus_x, new_focus_y = world_pixel(focus_latitude, focus_longitude, new_zoom)
        new_center_x = new_focus_x - screen_x + width / 2
        new_center_y = new_focus_y - screen_y + height / 2
        self.zoom = new_zoom
        self.center_latitude, self.center_longitude = pixel_location(new_center_x, new_center_y, new_zoom)
        self.redraw()

    def redraw(self) -> None:
        self.delete("all")
        width, height = max(self.winfo_width(), 400), max(self.winfo_height(), 180)
        center_x, center_y = world_pixel(self.center_latitude, self.center_longitude, self.zoom)
        left, top = center_x - width / 2, center_y - height / 2
        tiles_across = 2 ** self.zoom
        first_x, last_x = math.floor(left / TILE_SIZE), math.floor((left + width) / TILE_SIZE)
        first_y, last_y = math.floor(top / TILE_SIZE), math.floor((top + height) / TILE_SIZE)
        visible: set[tuple[int, int, int]] = set()

        for tile_y in range(first_y, last_y + 1):
            if tile_y < 0 or tile_y >= tiles_across:
                continue
            for unwrapped_x in range(first_x, last_x + 1):
                tile_x = unwrapped_x % tiles_across
                key = (self.zoom, tile_x, tile_y)
                visible.add(key)
                screen_tile_x = unwrapped_x * TILE_SIZE - left
                screen_tile_y = tile_y * TILE_SIZE - top
                image = self._tile_images.get(key)
                if image is not None:
                    self.create_image(screen_tile_x, screen_tile_y, image=image, anchor="nw")
                else:
                    self.create_rectangle(screen_tile_x, screen_tile_y,
                                          screen_tile_x + TILE_SIZE, screen_tile_y + TILE_SIZE,
                                          fill="#0b1d2b", outline="#173149")
                    self._request_tile(key)

        self._draw_markers(left, top)
        self.create_rectangle(8, height - 26, 174, height - 6, fill="#07131f", outline="#36536a")
        self.create_text(15, height - 16, text="© OpenStreetMap contributors",
                         fill="#b6c8d8", anchor="w", font=("Segoe UI", 8))
        self.create_rectangle(width - 67, 8, width - 8, 30, fill="#07131f", outline="#36536a")
        self.create_text(width - 37, 19, text=f"Zoom {self.zoom}", fill="#dcecff",
                         font=("Segoe UI", 8))
        if not self._tile_images and self._pending_tiles:
            self.create_text(width / 2, height / 2, text="Loading map…",
                             fill="#dcecff", font=("Segoe UI", 12, "bold"))
        elif not self._tile_images and self._failed_tiles:
            self.create_text(width / 2, height / 2, text="Map tiles unavailable · check connection",
                             fill="#ffbf69", font=("Segoe UI", 11, "bold"))
        self._trim_cache(visible)

    def _draw_markers(self, left: float, top: float) -> None:
        clusters: dict[tuple[int, int], list[tuple[MapMarker, float, float]]] = {}
        width, height = self.winfo_width(), self.winfo_height()
        world_width = TILE_SIZE * (2 ** self.zoom)
        for marker in self.markers:
            x, y = world_pixel(marker.latitude, marker.longitude, self.zoom)
            while x - left < -world_width / 2:
                x += world_width
            while x - left > world_width / 2 + width:
                x -= world_width
            screen_x, screen_y = x - left, y - top
            if -30 <= screen_x <= width + 30 and -30 <= screen_y <= height + 30:
                key = (round(screen_x / 42), round(screen_y / 34))
                clusters.setdefault(key, []).append((marker, screen_x, screen_y))

        for marker_index, members in enumerate(clusters.values()):
            marker, x, y = members[0]
            count = len(members)
            radius = 9 if count == 1 else min(16, 9 + count)
            tag = f"destination-marker-{marker_index}"
            self.create_oval(x - radius - 5, y - radius - 5, x + radius + 5, y + radius + 5,
                             fill="#183a55", outline="", stipple="gray50", tags=(tag,))
            self.create_oval(x - radius, y - radius, x + radius, y + radius,
                             fill=marker.colour, outline="#ffffff", width=2, tags=(tag,))
            if count > 1:
                self.create_text(x, y, text=str(count), fill="#06111b",
                                 font=("Segoe UI", 9, "bold"), tags=(tag,))
                label = f"{marker.label} · {count} endpoints"
            else:
                label = marker.label or marker.address
            label_item = self.create_text(x + radius + 5, y, text=label, fill="#ffffff", anchor="w",
                                          font=("Segoe UI", 9, "bold"), tags=(tag,))
            bounds = self.bbox(label_item)
            if bounds:
                background = self.create_rectangle(
                    bounds[0] - 3, bounds[1] - 2, bounds[2] + 3, bounds[3] + 2,
                    fill="#07131f", outline="#36536a", tags=(tag,))
                self.tag_lower(background, label_item)
            cluster_markers = [member[0] for member in members]
            self.tag_bind(tag, "<ButtonRelease-1>",
                          lambda _event, selected=cluster_markers: self._activate_marker(selected))
            self.tag_bind(tag, "<Enter>", lambda _event: self.configure(cursor="hand2"))
            self.tag_bind(tag, "<Leave>", lambda _event: self.configure(cursor=""))

    def _activate_marker(self, markers: list[MapMarker]) -> None:
        if not self._drag_moved and self.on_marker_click is not None:
            self.after_idle(lambda: self.on_marker_click(markers))

    def _request_tile(self, key: tuple[int, int, int]) -> None:
        if key in self._pending_tiles:
            return
        failed_at = self._failed_tiles.get(key)
        if failed_at is not None and time.monotonic() - failed_at < 60:
            return
        cached = self._tile_bytes.get(key)
        if cached is not None:
            self._make_photo(key, cached)
            return
        self._pending_tiles.add(key)
        threading.Thread(target=self._download_tile, args=(key,), daemon=True).start()

    def _download_tile(self, key: tuple[int, int, int]) -> None:
        zoom, tile_x, tile_y = key
        try:
            with self._download_slots:
                request = urllib.request.Request(
                    TILE_URL.format(zoom=zoom, x=tile_x, y=tile_y),
                    headers={"User-Agent": f"Advanced-IP-Analyser/{__version__} destination-map"},
                )
                with urllib.request.urlopen(request, timeout=8) as response:  # nosec B310 - fixed HTTPS host
                    payload = response.read(MAX_TILE_BYTES + 1)
            if len(payload) > MAX_TILE_BYTES or not payload.startswith(b"\x89PNG\r\n\x1a\n"):
                raise ValueError("invalid map tile")
            self._tile_events.put((key, payload))
        except (OSError, ValueError):
            self._tile_events.put((key, None))

    def _drain_tiles(self) -> None:
        changed = False
        try:
            while True:
                key, payload = self._tile_events.get_nowait()
                self._pending_tiles.discard(key)
                if payload:
                    self._failed_tiles.pop(key, None)
                    self._tile_bytes[key] = payload
                    self._make_photo(key, payload)
                    changed = True
                else:
                    self._failed_tiles[key] = time.monotonic()
                    changed = True
        except queue.Empty:
            pass
        if changed:
            self.redraw()
        self.after(100, self._drain_tiles)

    def _make_photo(self, key: tuple[int, int, int], payload: bytes) -> None:
        if key not in self._tile_images:
            self._tile_images[key] = tk.PhotoImage(data=base64.b64encode(payload).decode("ascii"))

    def _trim_cache(self, visible: set[tuple[int, int, int]]) -> None:
        if len(self._tile_images) <= 160:
            return
        for key in list(self._tile_images):
            if key not in visible:
                self._tile_images.pop(key, None)
                if len(self._tile_images) <= 120:
                    break
        if len(self._tile_bytes) > 320:
            for key in list(self._tile_bytes):
                if key not in visible and key not in self._tile_images:
                    self._tile_bytes.pop(key, None)
                    if len(self._tile_bytes) <= 240:
                        break

    def _start_drag(self, event) -> None:
        self._drag_origin = (event.x, event.y)
        self._drag_center = world_pixel(self.center_latitude, self.center_longitude, self.zoom)
        self._drag_moved = False
        self.configure(cursor="fleur")

    def _drag(self, event) -> None:
        if self._drag_origin is None or self._drag_center is None:
            return
        start_x, start_y = self._drag_origin
        if abs(event.x - start_x) > 3 or abs(event.y - start_y) > 3:
            self._drag_moved = True
        center_x, center_y = self._drag_center
        self.center_latitude, self.center_longitude = pixel_location(
            center_x - (event.x - start_x), center_y - (event.y - start_y), self.zoom)
        self.redraw()

    def _end_drag(self, _event) -> None:
        self._drag_origin = None
        self._drag_center = None
        self.configure(cursor="")

    def _wheel(self, event) -> None:
        self.zoom_by(1 if event.delta > 0 else -1, event.x, event.y)
