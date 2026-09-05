#!/usr/bin/env python3
"""Render the Markdown instruction book as a stable A4 PDF."""

from __future__ import annotations

import html
import re
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "USER_GUIDE.md"
OUTPUT = ROOT / "output" / "pdf" / "Advanced-IP-Analyser-Instruction-Book.pdf"
NAVY = colors.HexColor("#102f49")
BLUE = colors.HexColor("#1976a8")
PALE = colors.HexColor("#e8f5fb")
INK = colors.HexColor("#17324d")
MUTED = colors.HexColor("#557184")
GREEN = colors.HexColor("#31a85a")


def _fonts() -> tuple[str, str, str]:
    candidates = (
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
         Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
         Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")),
        (Path("C:/Windows/Fonts/arial.ttf"), Path("C:/Windows/Fonts/arialbd.ttf"),
         Path("C:/Windows/Fonts/consola.ttf")),
    )
    for regular, bold, mono in candidates:
        if regular.is_file() and bold.is_file() and mono.is_file():
            pdfmetrics.registerFont(TTFont("GuideSans", regular))
            pdfmetrics.registerFont(TTFont("GuideSansBold", bold))
            pdfmetrics.registerFont(TTFont("GuideMono", mono))
            return "GuideSans", "GuideSansBold", "GuideMono"
    return "Helvetica", "Helvetica-Bold", "Courier"


REGULAR, BOLD, MONO = _fonts()
styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="GuideTitle", fontName=BOLD, fontSize=27, leading=31,
                          textColor=NAVY, alignment=TA_CENTER, spaceAfter=7 * mm))
styles.add(ParagraphStyle(name="GuideH1", fontName=BOLD, fontSize=17, leading=21,
                          textColor=NAVY, spaceBefore=4 * mm, spaceAfter=2.5 * mm))
styles.add(ParagraphStyle(name="GuideH2", fontName=BOLD, fontSize=12, leading=15,
                          textColor=BLUE, spaceBefore=3 * mm, spaceAfter=1.5 * mm))
styles.add(ParagraphStyle(name="GuideBody", fontName=REGULAR, fontSize=8.6, leading=12.1,
                          textColor=INK, spaceAfter=2.3 * mm))
styles.add(ParagraphStyle(name="GuideBullet", parent=styles["GuideBody"], leftIndent=5 * mm,
                          firstLineIndent=-3.5 * mm, bulletIndent=1 * mm))
styles.add(ParagraphStyle(name="GuideCode", fontName=MONO, fontSize=7.2, leading=9.7,
                          textColor=INK, backColor=colors.HexColor("#f2f6f8"),
                          borderColor=colors.HexColor("#c6d9e3"), borderWidth=.5,
                          borderPadding=5, spaceAfter=2.5 * mm))
styles.add(ParagraphStyle(name="GuideSmall", fontName=REGULAR, fontSize=7.2, leading=9.5,
                          textColor=MUTED, alignment=TA_CENTER, spaceAfter=2 * mm))
styles.add(ParagraphStyle(name="GuideTableHead", fontName=BOLD, fontSize=7.8, leading=10.5,
                          textColor=colors.white))


def _inline(text: str) -> str:
    value = html.escape(text, quote=False)
    value = re.sub(r"`([^`]+)`", rf"<font name='{MONO}'>\1</font>", value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"\[([^]]+)]\(([^)]+)\)", r"<u>\1</u>", value)
    return value


def _header_footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 13 * mm, A4[0], 13 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont(BOLD, 8)
    canvas.drawString(15 * mm, A4[1] - 8.5 * mm, "ADVANCED IP ANALYSER - DEBIAN 13")
    canvas.setFillColor(GREEN)
    canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 8.5 * mm, "SAFE NETWORK EVIDENCE")
    canvas.setStrokeColor(colors.HexColor("#b9ccd6"))
    canvas.line(15 * mm, 12 * mm, A4[0] - 15 * mm, 12 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont(REGULAR, 7)
    canvas.drawString(15 * mm, 7.5 * mm, "Copyright 2026 Daren Loxley (2E0LXY) - GPL-3.0-or-later")
    canvas.drawRightString(A4[0] - 15 * mm, 7.5 * mm, f"Page {document.page}")
    canvas.restoreState()


def _table(rows: list[list[str]], width: float) -> Table:
    columns = max(len(row) for row in rows)
    normalized = [row + [""] * (columns - len(row)) for row in rows]
    data = [[Paragraph(_inline(cell.strip()),
                       styles["GuideTableHead"] if row_index == 0 else styles["GuideBody"])
             for cell in row] for row_index, row in enumerate(normalized)]
    table = Table(data, colWidths=[width / columns] * columns, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), BOLD),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#b9ccd6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def build() -> None:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = BaseDocTemplate(
        str(OUTPUT), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
        topMargin=19 * mm, bottomMargin=17 * mm,
        title=lines[0].removeprefix("# "), author="Daren Loxley (2E0LXY)",
        subject="Debian 13 user, administrator, and AI safety guide",
        creator="Advanced IP Analyser documentation build")
    document.addPageTemplates(PageTemplate(
        id="guide", frames=[Frame(document.leftMargin, document.bottomMargin,
                                  document.width, document.height, id="body")],
        onPage=_header_footer))
    story = []
    paragraph: list[str] = []
    code: list[str] = []
    table_rows: list[list[str]] = []
    in_code = False

    def flush_paragraph() -> None:
        if paragraph:
            story.append(Paragraph(_inline(" ".join(paragraph)), styles["GuideBody"]))
            paragraph.clear()

    def flush_table() -> None:
        if table_rows:
            rows = [row for index, row in enumerate(table_rows)
                    if not (index == 1 and all(set(cell.strip()) <= {"-", ":"} for cell in row))]
            story.append(_table(rows, document.width))
            story.append(Spacer(1, 2.5 * mm))
            table_rows.clear()

    for line in lines:
        if line.startswith("```"):
            flush_paragraph()
            flush_table()
            if in_code:
                story.append(Paragraph("<br/>".join(html.escape(item) or " " for item in code),
                                       styles["GuideCode"]))
                code.clear()
            in_code = not in_code
            continue
        if in_code:
            code.append(line)
            continue
        image_match = re.fullmatch(r"!\[([^]]*)]\(([^)]+)\)", line.strip())
        if image_match:
            flush_paragraph()
            flush_table()
            image_path = (SOURCE.parent / image_match.group(2)).resolve()
            if image_path.is_file():
                with PILImage.open(image_path) as source_image:
                    width, height = source_image.size
                scale = min(document.width / width, 105 * mm / height)
                story.append(KeepTogether([
                    Image(str(image_path), width=width * scale, height=height * scale),
                    Paragraph(_inline(image_match.group(1)), styles["GuideSmall"]),
                ]))
            continue
        if line.startswith("|") and line.endswith("|"):
            flush_paragraph()
            table_rows.append(line.strip("|").split("|"))
            continue
        flush_table()
        if line.startswith("# "):
            flush_paragraph()
            story.append(Spacer(1, 18 * mm))
            story.append(Paragraph(_inline(line[2:]), styles["GuideTitle"]))
        elif line.startswith("## "):
            flush_paragraph()
            if story:
                story.append(PageBreak())
            story.append(Paragraph(_inline(line[3:]), styles["GuideH1"]))
        elif line.startswith("### "):
            flush_paragraph()
            story.append(Paragraph(_inline(line[4:]), styles["GuideH2"]))
        elif re.match(r"^[-*] ", line):
            flush_paragraph()
            story.append(Paragraph("• " + _inline(line[2:]), styles["GuideBullet"]))
        elif re.match(r"^\d+\. ", line):
            flush_paragraph()
            number, value = line.split(". ", 1)
            story.append(Paragraph(f"{number}. " + _inline(value), styles["GuideBullet"]))
        elif line.startswith("> "):
            flush_paragraph()
            story.append(Paragraph(_inline(line[2:]), ParagraphStyle(
                name=f"Callout{len(story)}", parent=styles["GuideBody"], leftIndent=5 * mm,
                borderColor=GREEN, borderWidth=1, borderPadding=6, backColor=PALE)))
        elif not line.strip():
            flush_paragraph()
        else:
            paragraph.append(line.strip())
    flush_paragraph()
    flush_table()
    document.build(story)


if __name__ == "__main__":
    build()
