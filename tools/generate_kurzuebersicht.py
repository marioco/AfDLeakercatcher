#!/usr/bin/env python3
"""Erzeugt die einseitige AfDLeakerCatcher-Kurzuebersicht als PDF."""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen.canvas import Canvas

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "AfDLeakerCatcher-Kurzuebersicht.pdf"

PAGE_BACKGROUND = HexColor("#F4F7F8")
NAVY = HexColor("#14232E")
TEXT = HexColor("#17242C")
MUTED_TEXT = HexColor("#4F5D65")
BLUE = HexColor("#4F879B")
LIGHT_BLUE = HexColor("#E5EFF2")
GREEN = HexColor("#4E7563")
WHITE = HexColor("#FFFFFF")
SHADOW = HexColor("#DDE3E6")
SEPARATOR = HexColor("#C7D4D9")

CARD_WIDTH = 60 * mm
CARD_HEIGHT = 76 * mm
CARD_GAP = 11 * mm
CARD_BOTTOM = 70 * mm
CARD_START_X = 12 * mm

LOGGER = logging.getLogger(__name__)


def _wrap_text(text: str, font_name: str, font_size: float, max_width: float) -> list[str]:
    """Bricht Text anhand der tatsächlichen PDF-Schriftbreite um."""

    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if stringWidth(candidate, font_name, font_size) <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _draw_wrapped_text(
    pdf: Canvas,
    text: str,
    *,
    x: float,
    top: float,
    max_width: float,
    font_name: str,
    font_size: float,
    leading: float,
    color: object = TEXT,
    max_lines: int | None = None,
) -> float:
    """Zeichnet einen kurzen Textblock und liefert die nächste Oberkante zurück."""

    lines = _wrap_text(text, font_name, font_size, max_width)
    if max_lines is not None and len(lines) > max_lines:
        raise ValueError(f"Text benötigt {len(lines)} statt höchstens {max_lines} Zeilen: {text}")
    pdf.setFillColor(color)
    pdf.setFont(font_name, font_size)
    baseline = top - font_size
    for line in lines:
        pdf.drawString(x, baseline, line)
        baseline -= leading
    return baseline


def _draw_arrow(pdf: Canvas, center_x: float, center_y: float) -> None:
    """Zeichnet einen klaren Richtungspfeil zwischen zwei Prozessschritten."""

    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(BLUE)
    pdf.setLineWidth(2.2)
    pdf.line(center_x - 3.5 * mm, center_y, center_x + 2.5 * mm, center_y)
    arrow = pdf.beginPath()
    arrow.moveTo(center_x + 4.8 * mm, center_y)
    arrow.lineTo(center_x + 1.5 * mm, center_y + 2.4 * mm)
    arrow.lineTo(center_x + 1.5 * mm, center_y - 2.4 * mm)
    arrow.close()
    pdf.drawPath(arrow, fill=1, stroke=0)


def _draw_file_network_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(LIGHT_BLUE)
    pdf.setLineWidth(1.6)
    pdf.roundRect(center_x - 8 * mm, center_y - 7 * mm, 12 * mm, 15 * mm, 1.5 * mm, 1, 1)
    pdf.line(center_x - 5.5 * mm, center_y + 3.5 * mm, center_x + 1.5 * mm, center_y + 3.5 * mm)
    pdf.line(center_x - 5.5 * mm, center_y, center_x + 1.5 * mm, center_y)
    nodes = ((7.5, 5.5), (9.5, -1.0), (5.5, -6.0))
    for x_offset, y_offset in nodes:
        pdf.setFillColor(WHITE)
        pdf.circle(center_x + x_offset * mm, center_y + y_offset * mm, 1.7 * mm, 1, 1)
    pdf.line(center_x + 4 * mm, center_y + 2 * mm, center_x + 7.5 * mm, center_y + 5.5 * mm)
    pdf.line(center_x + 4 * mm, center_y, center_x + 9.5 * mm, center_y - 1 * mm)
    pdf.line(center_x + 4 * mm, center_y - 2 * mm, center_x + 5.5 * mm, center_y - 6 * mm)


def _draw_search_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setLineWidth(1.7)
    for x_offset, y_offset in ((-6, 4), (3, 6), (5, -3), (-5, -5)):
        pdf.setFillColor(LIGHT_BLUE)
        pdf.circle(center_x + x_offset * mm, center_y + y_offset * mm, 1.8 * mm, 1, 1)
    pdf.line(center_x - 4.5 * mm, center_y + 3 * mm, center_x + 1.5 * mm, center_y + 5.3 * mm)
    pdf.line(center_x + 3.5 * mm, center_y + 4.5 * mm, center_x + 4.6 * mm, center_y - 1.5 * mm)
    pdf.setFillColor(WHITE)
    pdf.circle(center_x - 1 * mm, center_y, 7 * mm, 1, 1)
    pdf.line(center_x + 4 * mm, center_y - 5 * mm, center_x + 9 * mm, center_y - 10 * mm)


def _draw_check_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(LIGHT_BLUE)
    pdf.setLineWidth(1.6)
    pdf.roundRect(center_x - 8 * mm, center_y - 8 * mm, 16 * mm, 17 * mm, 1.5 * mm, 1, 1)
    pdf.setStrokeColor(GREEN)
    pdf.setLineWidth(2.4)
    pdf.line(center_x - 4.5 * mm, center_y, center_x - 1 * mm, center_y - 3.2 * mm)
    pdf.line(center_x - 1 * mm, center_y - 3.2 * mm, center_x + 5.2 * mm, center_y + 4 * mm)


def _draw_report_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(LIGHT_BLUE)
    pdf.setLineWidth(1.6)
    pdf.roundRect(center_x - 8 * mm, center_y - 8 * mm, 16 * mm, 17 * mm, 1.5 * mm, 1, 1)
    pdf.line(center_x - 4.5 * mm, center_y + 4 * mm, center_x + 4.5 * mm, center_y + 4 * mm)
    pdf.line(center_x - 4.5 * mm, center_y, center_x + 4.5 * mm, center_y)
    pdf.line(center_x - 4.5 * mm, center_y - 4 * mm, center_x + 1.5 * mm, center_y - 4 * mm)
    pdf.setFillColor(GREEN)
    pdf.setStrokeColor(WHITE)
    pdf.circle(
        center_x + 7 * mm,
        center_y - 6 * mm,
        4.6 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setLineWidth(1.8)
    pdf.line(center_x + 4.7 * mm, center_y - 6 * mm, center_x + 6.4 * mm, center_y - 7.6 * mm)
    pdf.line(center_x + 6.4 * mm, center_y - 7.6 * mm, center_x + 9.3 * mm, center_y - 4.3 * mm)


def _draw_flow_card(
    pdf: Canvas,
    *,
    index: int,
    x: float,
    title: str,
    body: str,
    icon: Callable[[Canvas, float, float], None],
    note: str | None = None,
) -> None:
    pdf.setFillColor(SHADOW)
    pdf.roundRect(
        x + 1.1 * mm,
        CARD_BOTTOM - 1.1 * mm,
        CARD_WIDTH,
        CARD_HEIGHT,
        3 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(WHITE)
    pdf.roundRect(
        x,
        CARD_BOTTOM,
        CARD_WIDTH,
        CARD_HEIGHT,
        3 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(BLUE)
    pdf.roundRect(
        x,
        CARD_BOTTOM + CARD_HEIGHT - 3 * mm,
        CARD_WIDTH,
        3 * mm,
        3 * mm,
        stroke=0,
        fill=1,
    )

    number_x = x + 8 * mm
    number_y = CARD_BOTTOM + CARD_HEIGHT - 11 * mm
    pdf.setFillColor(NAVY)
    pdf.circle(number_x, number_y, 4.2 * mm, stroke=0, fill=1)
    pdf.setFillColor(WHITE)
    pdf.setFont("Helvetica-Bold", 11)
    number = str(index)
    pdf.drawCentredString(number_x, number_y - 3.7, number)

    icon(pdf, x + CARD_WIDTH / 2, CARD_BOTTOM + CARD_HEIGHT - 25 * mm)

    _draw_wrapped_text(
        pdf,
        title,
        x=x + 6 * mm,
        top=CARD_BOTTOM + CARD_HEIGHT - 39 * mm,
        max_width=CARD_WIDTH - 12 * mm,
        font_name="Helvetica-Bold",
        font_size=12.2,
        leading=14.2,
        max_lines=2,
    )
    _draw_wrapped_text(
        pdf,
        body,
        x=x + 6 * mm,
        top=CARD_BOTTOM + CARD_HEIGHT - 50 * mm,
        max_width=CARD_WIDTH - 12 * mm,
        font_name="Helvetica",
        font_size=9.5,
        leading=12.2,
        color=MUTED_TEXT,
        max_lines=5,
    )
    if note:
        pdf.setFillColor(GREEN)
        pdf.setFont("Helvetica-Bold", 8.5)
        pdf.drawString(x + 6 * mm, CARD_BOTTOM + 5.5 * mm, note)


def _draw_benefit_column(
    pdf: Canvas,
    *,
    x: float,
    title: str,
    detail: str,
) -> None:
    pdf.setFillColor(GREEN)
    pdf.circle(x + 4 * mm, 40.8 * mm, 2.2 * mm, stroke=0, fill=1)
    pdf.setFillColor(TEXT)
    pdf.setFont("Helvetica-Bold", 10.2)
    pdf.drawString(x + 9 * mm, 42.5 * mm, title)
    _draw_wrapped_text(
        pdf,
        detail,
        x=x + 9 * mm,
        top=39.5 * mm,
        max_width=73 * mm,
        font_name="Helvetica",
        font_size=8.9,
        leading=10.6,
        color=MUTED_TEXT,
        max_lines=2,
    )


def _build_pdf(output_path: Path) -> None:
    page_width, page_height = landscape(A4)
    pdf = Canvas(
        str(output_path),
        pagesize=(page_width, page_height),
        pageCompression=0,
        invariant=1,
    )
    pdf.setTitle("AfDLeakerCatcher \N{EN DASH} Kurzüberblick")
    pdf.setAuthor("AfDLeakerCatcher")
    pdf.setCreator("AfDLeakerCatcher")
    pdf.setSubject("Vom BitTorrent-Datenleck zum prüfbaren Ermittlungsansatz")

    pdf.setFillColor(PAGE_BACKGROUND)
    pdf.rect(0, 0, page_width, page_height, stroke=0, fill=1)

    pdf.setFillColor(NAVY)
    pdf.rect(0, 166 * mm, page_width, 44 * mm, stroke=0, fill=1)
    pdf.setFillColor(HexColor("#8CC2D2"))
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(14 * mm, 197 * mm, "AfDLeakerCatcher")
    pdf.setFillColor(WHITE)
    pdf.setFont("Helvetica-Bold", 23)
    pdf.drawString(14 * mm, 184 * mm, "Vom BitTorrent-Datenleck zum prüfbaren Ermittlungsansatz")
    pdf.setFont("Helvetica", 10.7)
    pdf.drawString(
        14 * mm,
        173.5 * mm,
        (
            "Findet erreichbare Teilnehmer, prüft sie technisch und dokumentiert "
            "die Spur \N{EN DASH} ohne Dateien herunterzuladen."
        ),
    )

    pdf.setFillColor(TEXT)
    pdf.setFont("Helvetica-Bold", 12.8)
    pdf.drawString(12 * mm, 155.5 * mm, "So funktioniert es")

    cards = (
        (
            "Datenleck über BitTorrent",
            ("Ein bekannter digitaler Fingerabdruck bezeichnet den mutmaßlichen Datenbestand."),
            _draw_file_network_icon,
            None,
        ),
        (
            "Teilnehmer finden",
            (
                "Die Software sucht im öffentlichen BitTorrent-Netz gezielt nach "
                "Rechnern mit genau diesem Fingerabdruck."
            ),
            _draw_search_icon,
            None,
        ),
        (
            "Treffer direkt prüfen",
            (
                "60 Sekunden Direktprüfung: Der Client bestätigt die Spur, meldet "
                "Teile und gibt Anfragen frei."
            ),
            _draw_check_icon,
            "Kein Download des Datenlecks",
        ),
        (
            "Nachweis sichern",
            (
                "IP-Adresse, Port, UTC-Zeit, Fundweg und technische Signale werden "
                "nachvollziehbar dokumentiert."
            ),
            _draw_report_icon,
            None,
        ),
    )
    for index, (title, body, icon, note) in enumerate(cards, start=1):
        x = CARD_START_X + (index - 1) * (CARD_WIDTH + CARD_GAP)
        _draw_flow_card(
            pdf,
            index=index,
            x=x,
            title=title,
            body=body,
            icon=icon,
            note=note,
        )
        if index < len(cards):
            _draw_arrow(
                pdf,
                x + CARD_WIDTH + CARD_GAP / 2,
                CARD_BOTTOM + CARD_HEIGHT / 2,
            )

    pdf.setFillColor(LIGHT_BLUE)
    pdf.roundRect(
        12 * mm,
        25 * mm,
        273 * mm,
        37 * mm,
        3 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(NAVY)
    pdf.setFont("Helvetica-Bold", 12.3)
    pdf.drawString(17 * mm, 54.5 * mm, "Was am Ende vorliegt")
    pdf.setStrokeColor(SEPARATOR)
    pdf.setLineWidth(0.8)
    pdf.line(102 * mm, 30 * mm, 102 * mm, 51 * mm)
    pdf.line(193 * mm, 30 * mm, 193 * mm, 51 * mm)
    _draw_benefit_column(
        pdf,
        x=18 * mm,
        title="Konkrete Spur",
        detail="IP-Adresse, Port, Datum und Uhrzeit",
    )
    _draw_benefit_column(
        pdf,
        x=109 * mm,
        title="Prüfbarer Nachweis",
        detail="Protokollierte Signale und SHA-256-Prüfsummen",
    )
    _draw_benefit_column(
        pdf,
        x=200 * mm,
        title="Direkt nutzbare Unterlagen",
        detail="PDF, CSV und vorbereitete Anzeige gegen Unbekannt",
    )

    pdf.setFillColor(GREEN)
    pdf.setFont("Helvetica-Bold", 10.7)
    pdf.drawCentredString(
        page_width / 2,
        18.2 * mm,
        (
            "Konkrete Anknüpfungstatsachen für die behördliche Bewertung eines "
            "möglichen Anfangsverdachts."
        ),
    )
    pdf.setFillColor(MUTED_TEXT)
    pdf.setFont("Helvetica", 7.7)
    pdf.drawCentredString(
        page_width / 2,
        8.5 * mm,
        (
            "Rechtliche Bewertung und Anschlusszuordnung erfolgen durch die "
            "zuständigen Behörden und Provider."
        ),
    )

    pdf.showPage()
    pdf.save()


def generate_onepager(output_path: Path) -> None:
    """Erzeugt die PDF atomar am gewünschten Zielpfad."""

    output_path = output_path.resolve(strict=False)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_path.parent,
        prefix=f".{output_path.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        _build_pdf(temporary_path)
        temporary_path.chmod(0o644)
        os.replace(temporary_path, output_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Einseitige AfDLeakerCatcher-Kurzuebersicht erzeugen.",
    )
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Ziel-PDF (Standard: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = _parse_args()
    try:
        generate_onepager(args.output)
    except (OSError, ValueError):
        LOGGER.exception("Kurzuebersicht konnte nicht erzeugt werden")
        return 1
    LOGGER.info("Kurzuebersicht erzeugt: %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
