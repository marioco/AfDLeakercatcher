#!/usr/bin/env python3
"""Erzeugt die zweiseitige AfDLeakerCatcher-Kurzuebersicht als PDF."""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from PIL import Image
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen.canvas import Canvas

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "AfDLeakerCatcher-Kurzuebersicht.pdf"
SCREENSHOT_DIRECTORY = PROJECT_ROOT / "assets" / "kurzuebersicht"
ENDPOINT_SCREENSHOT = SCREENSHOT_DIRECTORY / "gefundene-ip-adressen.png"
PROGRAM_SCREENSHOT = SCREENSHOT_DIRECTORY / "programmoberflaeche.png"

ENDPOINT_IMAGE_SIZE = (1622, 935)
PROGRAM_IMAGE_SIZE = (2290, 1427)
ENDPOINT_CROP = (0, 0, 1622, 657)
PROGRAM_CROP = (0, 286, 2290, 1427)

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

PAGE_WIDTH, PAGE_HEIGHT = landscape(A4)
FLOW_CARD_WIDTH = 60 * mm
FLOW_CARD_HEIGHT = 60 * mm
FLOW_CARD_GAP = 11 * mm
FLOW_CARD_BOTTOM = 104 * mm
FLOW_CARD_START_X = 12 * mm

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
    color: Color = TEXT,
    max_lines: int | None = None,
) -> float:
    """Zeichnet einen Textblock und liefert die nächste Oberkante zurück."""

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


def _draw_header(
    pdf: Canvas,
    *,
    kicker: str,
    title: str,
    subtitle: str,
    page_number: int,
) -> None:
    """Zeichnet den einheitlichen Kopf einer Übersichtsseite."""

    pdf.setFillColor(NAVY)
    pdf.rect(0, 174 * mm, PAGE_WIDTH, 36 * mm, stroke=0, fill=1)
    pdf.setFillColor(HexColor("#8CC2D2"))
    pdf.setFont("Helvetica-Bold", 9.2)
    pdf.drawString(12 * mm, 201 * mm, kicker)
    pdf.setFont("Helvetica", 8.2)
    pdf.drawRightString(PAGE_WIDTH - 12 * mm, 201 * mm, f"SEITE {page_number} VON 2")
    pdf.setFillColor(WHITE)
    pdf.setFont("Helvetica-Bold", 20.5)
    pdf.drawString(12 * mm, 187.3 * mm, title)
    pdf.setFont("Helvetica", 9.7)
    pdf.drawString(12 * mm, 178.8 * mm, subtitle)


def _draw_cropped_image(
    pdf: Canvas,
    *,
    source_path: Path,
    expected_size: tuple[int, int],
    crop: tuple[int, int, int, int],
    x: float,
    y: float,
    width: float,
    height: float,
) -> None:
    """Zeichnet einen reproduzierbar zugeschnittenen Screenshot proportional."""

    with Image.open(source_path) as source:
        source.load()
        if source.size != expected_size:
            raise ValueError(
                f"Unerwartete Bildgröße für {source_path.name}: {source.size[0]}x{source.size[1]}"
            )
        cropped = source.crop(crop).convert("RGB")
        pdf.drawImage(
            ImageReader(cropped),
            x,
            y,
            width=width,
            height=height,
            preserveAspectRatio=True,
            anchor="c",
            mask=None,
        )


def _draw_program_screenshot(pdf: Canvas) -> None:
    """Zeichnet den aktuellen Prüflauf als großflächigen Seitenhintergrund."""

    x = 12 * mm
    y = 34 * mm
    width = 273 * mm
    height = 136 * mm
    pdf.setFillColor(SHADOW)
    pdf.roundRect(
        x + 1.2 * mm,
        y - 1.2 * mm,
        width,
        height,
        2 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(WHITE)
    pdf.roundRect(x, y, width, height, 2 * mm, stroke=0, fill=1)
    _draw_cropped_image(
        pdf,
        source_path=PROGRAM_SCREENSHOT,
        expected_size=PROGRAM_IMAGE_SIZE,
        crop=PROGRAM_CROP,
        x=x,
        y=y,
        width=width,
        height=height,
    )
    pdf.setStrokeColor(BLUE)
    pdf.setLineWidth(0.7)
    pdf.roundRect(x, y, width, height, 2 * mm, stroke=1, fill=0)


def _draw_endpoint_inset(pdf: Canvas) -> None:
    """Legt den lesbaren IP-/Provider-Auszug über den Programmscreenshot."""

    card_x = 105 * mm
    card_y = 38 * mm
    card_width = 176 * mm
    card_height = 82 * mm
    header_height = 9 * mm
    pdf.setFillColor(HexColor("#C9D1D5"))
    pdf.roundRect(
        card_x + 1.5 * mm,
        card_y - 1.5 * mm,
        card_width,
        card_height,
        2.2 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(WHITE)
    pdf.roundRect(
        card_x,
        card_y,
        card_width,
        card_height,
        2.2 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(NAVY)
    pdf.roundRect(
        card_x,
        card_y + card_height - header_height,
        card_width,
        header_height,
        2.2 * mm,
        stroke=0,
        fill=1,
    )
    pdf.rect(
        card_x,
        card_y + card_height - header_height,
        card_width,
        header_height / 2,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(WHITE)
    pdf.setFont("Helvetica-Bold", 8.4)
    pdf.drawString(
        card_x + 4 * mm,
        card_y + card_height - 5.8 * mm,
        "BEISPIELAUSZUG GEFUNDENER IP-ADRESSEN",
    )
    _draw_cropped_image(
        pdf,
        source_path=ENDPOINT_SCREENSHOT,
        expected_size=ENDPOINT_IMAGE_SIZE,
        crop=ENDPOINT_CROP,
        x=card_x + 3 * mm,
        y=card_y + 4 * mm,
        width=170 * mm,
        height=69 * mm,
    )


def _draw_capability_strip(pdf: Canvas) -> None:
    """Fasst die vier leicht verständlichen Programmleistungen zusammen."""

    x = 12 * mm
    y = 10 * mm
    width = 273 * mm
    height = 19 * mm
    pdf.setFillColor(LIGHT_BLUE)
    pdf.roundRect(x, y, width, height, 2.5 * mm, stroke=0, fill=1)
    entries = (
        ("SUCHT", "DHT und Tracker nach dem bekannten Infohash"),
        ("PRÜFT", "Direkte Bestätigung über volle 60 Sekunden"),
        ("SICHERT", "IP, Port, UTC-Zeit und Prüfsummen"),
        ("LIEFERT", "PDF, CSV und Strafanzeige gegen Unbekannt"),
    )
    column_width = width / len(entries)
    for index, (title, detail) in enumerate(entries):
        column_x = x + index * column_width
        if index:
            pdf.setStrokeColor(SEPARATOR)
            pdf.setLineWidth(0.7)
            pdf.line(column_x, y + 3 * mm, column_x, y + height - 3 * mm)
        pdf.setFillColor(BLUE)
        pdf.setFont("Helvetica-Bold", 9.2)
        pdf.drawString(column_x + 5 * mm, y + 12.4 * mm, title)
        _draw_wrapped_text(
            pdf,
            detail,
            x=column_x + 5 * mm,
            top=y + 10.2 * mm,
            max_width=column_width - 9 * mm,
            font_name="Helvetica",
            font_size=7.4,
            leading=8.5,
            color=MUTED_TEXT,
            max_lines=2,
        )


def _draw_arrow(pdf: Canvas, center_x: float, center_y: float) -> None:
    """Zeichnet einen klaren Richtungspfeil zwischen zwei Schritten."""

    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(BLUE)
    pdf.setLineWidth(2.1)
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
    pdf.setLineWidth(1.5)
    pdf.roundRect(center_x - 7 * mm, center_y - 6 * mm, 11 * mm, 13 * mm, 1.5 * mm, 1, 1)
    pdf.line(center_x - 4.5 * mm, center_y + 2.5 * mm, center_x + 1 * mm, center_y + 2.5 * mm)
    pdf.line(center_x - 4.5 * mm, center_y - 0.5 * mm, center_x + 1 * mm, center_y - 0.5 * mm)
    for x_offset, y_offset in ((7, 4.5), (8.5, -1), (5.5, -5.5)):
        pdf.setFillColor(WHITE)
        pdf.circle(center_x + x_offset * mm, center_y + y_offset * mm, 1.5 * mm, 1, 1)
    pdf.line(center_x + 4 * mm, center_y + 1.5 * mm, center_x + 7 * mm, center_y + 4.5 * mm)
    pdf.line(center_x + 4 * mm, center_y, center_x + 8.5 * mm, center_y - 1 * mm)
    pdf.line(center_x + 4 * mm, center_y - 2 * mm, center_x + 5.5 * mm, center_y - 5.5 * mm)


def _draw_search_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setLineWidth(1.6)
    for x_offset, y_offset in ((-5.5, 3.5), (2.8, 5), (4.5, -2.8), (-4.5, -4.5)):
        pdf.setFillColor(LIGHT_BLUE)
        pdf.circle(center_x + x_offset * mm, center_y + y_offset * mm, 1.6 * mm, 1, 1)
    pdf.setFillColor(WHITE)
    pdf.circle(center_x - 1 * mm, center_y, 6.3 * mm, 1, 1)
    pdf.line(center_x + 3.7 * mm, center_y - 4.5 * mm, center_x + 8.2 * mm, center_y - 9 * mm)


def _draw_check_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(LIGHT_BLUE)
    pdf.setLineWidth(1.5)
    pdf.roundRect(center_x - 7 * mm, center_y - 7 * mm, 14 * mm, 15 * mm, 1.5 * mm, 1, 1)
    pdf.setStrokeColor(GREEN)
    pdf.setLineWidth(2.2)
    pdf.line(center_x - 4 * mm, center_y, center_x - 1 * mm, center_y - 3 * mm)
    pdf.line(center_x - 1 * mm, center_y - 3 * mm, center_x + 4.8 * mm, center_y + 3.8 * mm)


def _draw_report_icon(pdf: Canvas, center_x: float, center_y: float) -> None:
    pdf.setStrokeColor(BLUE)
    pdf.setFillColor(LIGHT_BLUE)
    pdf.setLineWidth(1.5)
    pdf.roundRect(center_x - 7 * mm, center_y - 7 * mm, 14 * mm, 15 * mm, 1.5 * mm, 1, 1)
    pdf.line(center_x - 4 * mm, center_y + 3.5 * mm, center_x + 4 * mm, center_y + 3.5 * mm)
    pdf.line(center_x - 4 * mm, center_y, center_x + 4 * mm, center_y)
    pdf.line(center_x - 4 * mm, center_y - 3.5 * mm, center_x + 1.2 * mm, center_y - 3.5 * mm)
    pdf.setFillColor(GREEN)
    pdf.circle(center_x + 6.3 * mm, center_y - 5.3 * mm, 4 * mm, stroke=0, fill=1)
    pdf.setStrokeColor(WHITE)
    pdf.setLineWidth(1.7)
    pdf.line(center_x + 4.3 * mm, center_y - 5.2 * mm, center_x + 5.8 * mm, center_y - 6.7 * mm)
    pdf.line(center_x + 5.8 * mm, center_y - 6.7 * mm, center_x + 8.4 * mm, center_y - 3.7 * mm)


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
        FLOW_CARD_BOTTOM - 1.1 * mm,
        FLOW_CARD_WIDTH,
        FLOW_CARD_HEIGHT,
        3 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(WHITE)
    pdf.roundRect(
        x,
        FLOW_CARD_BOTTOM,
        FLOW_CARD_WIDTH,
        FLOW_CARD_HEIGHT,
        3 * mm,
        stroke=0,
        fill=1,
    )
    pdf.setFillColor(BLUE)
    pdf.roundRect(
        x,
        FLOW_CARD_BOTTOM + FLOW_CARD_HEIGHT - 3 * mm,
        FLOW_CARD_WIDTH,
        3 * mm,
        3 * mm,
        stroke=0,
        fill=1,
    )
    number_x = x + 8 * mm
    number_y = FLOW_CARD_BOTTOM + FLOW_CARD_HEIGHT - 10 * mm
    pdf.setFillColor(NAVY)
    pdf.circle(number_x, number_y, 4 * mm, stroke=0, fill=1)
    pdf.setFillColor(WHITE)
    pdf.setFont("Helvetica-Bold", 10.5)
    pdf.drawCentredString(number_x, number_y - 3.5, str(index))
    icon(pdf, x + FLOW_CARD_WIDTH / 2, FLOW_CARD_BOTTOM + FLOW_CARD_HEIGHT - 22 * mm)
    _draw_wrapped_text(
        pdf,
        title,
        x=x + 6 * mm,
        top=FLOW_CARD_BOTTOM + FLOW_CARD_HEIGHT - 35 * mm,
        max_width=FLOW_CARD_WIDTH - 12 * mm,
        font_name="Helvetica-Bold",
        font_size=11.2,
        leading=12.6,
        max_lines=2,
    )
    _draw_wrapped_text(
        pdf,
        body,
        x=x + 6 * mm,
        top=FLOW_CARD_BOTTOM + FLOW_CARD_HEIGHT - 44 * mm,
        max_width=FLOW_CARD_WIDTH - 12 * mm,
        font_name="Helvetica",
        font_size=8.7,
        leading=10.2,
        color=MUTED_TEXT,
        max_lines=5,
    )
    if note:
        pdf.setFillColor(GREEN)
        pdf.setFont("Helvetica-Bold", 8.1)
        pdf.drawString(x + 6 * mm, FLOW_CARD_BOTTOM + 4.5 * mm, note)


def _draw_reason_column(
    pdf: Canvas,
    *,
    x: float,
    title: str,
    detail: str,
) -> None:
    pdf.setFillColor(GREEN)
    pdf.circle(x + 4 * mm, 67.5 * mm, 2.1 * mm, stroke=0, fill=1)
    pdf.setFillColor(TEXT)
    pdf.setFont("Helvetica-Bold", 10.4)
    pdf.drawString(x + 9 * mm, 69.2 * mm, title)
    _draw_wrapped_text(
        pdf,
        detail,
        x=x + 9 * mm,
        top=65.5 * mm,
        max_width=74 * mm,
        font_name="Helvetica",
        font_size=8.8,
        leading=10.6,
        color=MUTED_TEXT,
        max_lines=4,
    )


def _draw_program_page(pdf: Canvas) -> None:
    pdf.setFillColor(PAGE_BACKGROUND)
    pdf.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, stroke=0, fill=1)
    _draw_header(
        pdf,
        kicker="1 · DAS PROGRAMM",
        title="AfDLeakerCatcher ermittelt die technische Spur eines Datenlecks",
        subtitle=(
            "Findet BitTorrent-Teilnehmer zum bekannten Datenleck und sichert "
            "IP-Adresse, Port, UTC-Zeit und technische Bestätigung."
        ),
        page_number=1,
    )
    _draw_program_screenshot(pdf)
    _draw_endpoint_inset(pdf)
    _draw_capability_strip(pdf)
    pdf.showPage()


def _draw_evidence_page(pdf: Canvas) -> None:
    pdf.setFillColor(PAGE_BACKGROUND)
    pdf.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, stroke=0, fill=1)
    _draw_header(
        pdf,
        kicker="2 · VOM TREFFER ZUR ANZEIGE",
        title="Warum diese Daten einen Anfangsverdacht begründen",
        subtitle=(
            "Netzfund, direkte Protokollbestätigung und gesicherte Dokumentation "
            "bilden eine geschlossene technische Tatsachenkette."
        ),
        page_number=2,
    )
    cards = (
        (
            "Infohash festlegen",
            "Der bekannte digitale Fingerabdruck bezeichnet exakt das untersuchte Datenleck.",
            _draw_file_network_icon,
            None,
        ),
        (
            "Teilnehmer finden",
            "DHT und Tracker liefern IP-Adresse und Port für genau diesen Infohash.",
            _draw_search_icon,
            None,
        ),
        (
            "Direkt bestätigen",
            (
                "Der Gegenclient bestätigt den Infohash, meldet verfügbare Teile und "
                "sendet UNCHOKE. Die Prüfung läuft 60 Sekunden."
            ),
            _draw_check_icon,
            None,
        ),
        (
            "Nachweis erzeugen",
            (
                "UTC-Zeit, Fundweg, Protokollsignale, Lauf-ID und SHA-256-Prüfsummen "
                "werden nachvollziehbar gesichert."
            ),
            _draw_report_icon,
            None,
        ),
    )
    for index, (title, body, icon, note) in enumerate(cards, start=1):
        x = FLOW_CARD_START_X + (index - 1) * (FLOW_CARD_WIDTH + FLOW_CARD_GAP)
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
                x + FLOW_CARD_WIDTH + FLOW_CARD_GAP / 2,
                FLOW_CARD_BOTTOM + FLOW_CARD_HEIGHT / 2,
            )

    pdf.setFillColor(LIGHT_BLUE)
    pdf.roundRect(12 * mm, 31 * mm, 273 * mm, 61 * mm, 3 * mm, stroke=0, fill=1)
    pdf.setFillColor(NAVY)
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(17 * mm, 83.5 * mm, "Warum die Tatsachenkette ausreicht")
    pdf.setStrokeColor(SEPARATOR)
    pdf.setLineWidth(0.8)
    pdf.line(102 * mm, 38 * mm, 102 * mm, 75 * mm)
    pdf.line(193 * mm, 38 * mm, 193 * mm, 75 * mm)
    _draw_reason_column(
        pdf,
        x=18 * mm,
        title="Eindeutiger Bezug",
        detail=(
            "Der bestätigte Infohash ordnet die Verbindung exakt dem untersuchten Datenleck zu."
        ),
    )
    _draw_reason_column(
        pdf,
        x=109 * mm,
        title="Aktive Bereitstellung",
        detail=(
            "Der Gegenclient meldet vorhandene Teile und gibt deren Übertragung durch UNCHOKE frei."
        ),
    )
    _draw_reason_column(
        pdf,
        x=200 * mm,
        title="Ermittlungsfähige Zuordnung",
        detail=(
            "IP-Adresse, Port und exakte UTC-Zeit ermöglichen die zeitbezogene "
            "Anschlusszuordnung über den Provider."
        ),
    )

    pdf.setFillColor(GREEN)
    pdf.roundRect(12 * mm, 10 * mm, 273 * mm, 15 * mm, 2.5 * mm, stroke=0, fill=1)
    pdf.setFillColor(WHITE)
    pdf.setFont("Helvetica-Bold", 10.3)
    pdf.drawString(
        17 * mm,
        19.1 * mm,
        "Zureichende tatsächliche Anhaltspunkte nach § 152 Abs. 2 StPO",
    )
    pdf.setFont("Helvetica", 8.7)
    pdf.drawString(
        17 * mm,
        14.1 * mm,
        (
            "Die Dokumentation trägt die Strafanzeige gegen Unbekannt und gibt der "
            "Polizei einen unmittelbar nutzbaren Ermittlungsansatz."
        ),
    )
    pdf.showPage()


def _build_pdf(output_path: Path) -> None:
    pdf = Canvas(
        str(output_path),
        pagesize=(PAGE_WIDTH, PAGE_HEIGHT),
        pageCompression=0,
        invariant=1,
    )
    pdf.setTitle("AfDLeakerCatcher \N{EN DASH} Kurzüberblick")
    pdf.setAuthor("AfDLeakerCatcher")
    pdf.setCreator("AfDLeakerCatcher")
    pdf.setSubject("Vom BitTorrent-Datenleck zum dokumentierten Anfangsverdacht")
    _draw_program_page(pdf)
    _draw_evidence_page(pdf)
    pdf.save()


def generate_overview(output_path: Path) -> None:
    """Erzeugt die zweiseitige PDF atomar am gewünschten Zielpfad."""

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
        description="Zweiseitige AfDLeakerCatcher-Kurzuebersicht erzeugen.",
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
        generate_overview(args.output)
    except (OSError, ValueError):
        LOGGER.exception("Kurzuebersicht konnte nicht erzeugt werden")
        return 1
    LOGGER.info("Kurzuebersicht erzeugt: %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
