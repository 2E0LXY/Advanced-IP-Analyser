"""Export a readable SVG map of discovered hosts and their observed services."""

from __future__ import annotations

from html import escape
from pathlib import Path

from .models import Host


def export_topology(path: Path, target: str, hosts: list[Host]) -> None:
    columns = 4
    rows = max(1, (len(hosts) + columns - 1) // columns)
    width = 1200
    height = 170 + rows * 112
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#0b1420"/>',
        ('<style>text{font-family:Segoe UI,Arial,sans-serif}.title{font-size:21px;font-weight:700;fill:#edf6ff}'
         '.sub{font-size:12px;fill:#93adc7}.host{font-size:15px;font-weight:600;fill:#eef6ff}'
         '.meta{font-size:11px;fill:#a9bfd3}</style>'),
        '<text x="34" y="42" class="title">Network topology</text>',
        f'<text x="34" y="65" class="sub">{escape(target or "Scan results")} · {len(hosts)} discovered hosts</text>',
        '<rect x="448" y="82" width="304" height="60" rx="10" fill="#1b4161" stroke="#368cc4"/>',
        f'<text x="467" y="108" class="host">{escape(target or "Network")}</text>',
        '<text x="467" y="128" class="meta">Scan target</text>',
    ]
    for index, host in enumerate(hosts):
        column, row = index % columns, index // columns
        x, y = 34 + column * 294, 180 + row * 112
        center = x + 138
        lines.extend((
            f'<path d="M 600 142 V 157 H {center} V {y}" fill="none" stroke="#365d7a" stroke-width="1.5"/>',
            f'<rect x="{x}" y="{y}" width="276" height="88" rx="9" fill="#16283b" stroke="#2e4b62"/>',
            f'<circle cx="{x+17}" cy="{y+23}" r="5" fill="#42d391"/>',
            f'<text x="{x+31}" y="{y+28}" class="host">{escape(host.address)}</text>',
            f'<text x="{x+17}" y="{y+52}" class="meta">{escape(host.hostname or host.mac or "Unresolved host")}</text>',
            f'<text x="{x+17}" y="{y+72}" class="meta">{len(host.ports)} open TCP port(s)</text>',
        ))
    lines.append('</svg>')
    path.write_text("\n".join(lines), encoding="utf-8")
