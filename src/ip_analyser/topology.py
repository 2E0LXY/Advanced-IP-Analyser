"""Export a readable PNG map of discovered hosts and observed services."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from .models import Host


BACKGROUND = "#0b1420"
CARD = "#16283b"
CARD_BORDER = "#2e4b62"
NETWORK_CARD = "#1b4161"
NETWORK_BORDER = "#368cc4"
CONNECTION = "#365d7a"
TITLE = "#edf6ff"
HOST_TEXT = "#eef6ff"
MUTED = "#a9bfd3"
SUBTITLE = "#93adc7"
ONLINE = "#42d391"


def _font(size: int, *, bold: bool = False) -> ImageFont.ImageFont:
    names = (
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def _shorten(value: str, limit: int = 38) -> str:
    clean = " ".join(value.split())
    return clean if len(clean) <= limit else clean[:limit - 1] + "…"


def export_topology(path: Path, target: str, hosts: list[Host]) -> None:
    """Render the current scan topology directly to a lossless PNG image."""
    columns = 4
    rows = max(1, (len(hosts) + columns - 1) // columns)
    width = 1200
    height = 170 + rows * 112
    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)
    title_font = _font(21, bold=True)
    host_font = _font(15, bold=True)
    metadata_font = _font(11)
    subtitle_font = _font(12)

    network_label = target or "Network"
    draw.text((34, 24), "Network topology", font=title_font, fill=TITLE)
    draw.text((34, 52), f"{network_label} · {len(hosts)} discovered hosts",
              font=subtitle_font, fill=SUBTITLE)
    draw.rounded_rectangle((448, 82, 752, 142), radius=10, fill=NETWORK_CARD,
                           outline=NETWORK_BORDER, width=2)
    draw.text((467, 96), _shorten(network_label, 32), font=host_font, fill=HOST_TEXT)
    draw.text((467, 120), "Scan target", font=metadata_font, fill=MUTED)

    trunk_x = 613  # The gap between the second and third card columns.
    first_bus_y = 158
    draw.line((600, 142, trunk_x, first_bus_y), fill=CONNECTION, width=2)
    for row in range(rows):
        row_count = min(columns, max(0, len(hosts) - row * columns))
        if not row_count:
            continue
        node_y = 180 + row * 112
        bus_y = node_y - 22
        centers = [34 + column * 294 + 138 for column in range(row_count)]
        draw.line((trunk_x, first_bus_y, trunk_x, bus_y), fill=CONNECTION, width=2)
        draw.line((min([trunk_x, *centers]), bus_y, max([trunk_x, *centers]), bus_y),
                  fill=CONNECTION, width=2)
        for center in centers:
            draw.line((center, bus_y, center, node_y), fill=CONNECTION, width=2)

    for index, host in enumerate(hosts):
        column, row = index % columns, index // columns
        x, y = 34 + column * 294, 180 + row * 112
        draw.rounded_rectangle((x, y, x + 276, y + 88), radius=9, fill=CARD,
                               outline=CARD_BORDER, width=2)
        draw.ellipse((x + 12, y + 18, x + 22, y + 28), fill=ONLINE)
        draw.text((x + 31, y + 12), _shorten(host.address, 30),
                  font=host_font, fill=HOST_TEXT)
        identity = host.hostname or host.mac or "Unresolved host"
        draw.text((x + 17, y + 43), _shorten(identity), font=metadata_font, fill=MUTED)
        draw.text((x + 17, y + 64), f"{len(host.ports)} open TCP port(s)",
                  font=metadata_font, fill=MUTED)

    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG", optimize=True)
