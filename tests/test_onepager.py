"""Regressionstests für die öffentliche AfDLeakerCatcher-Kurzuebersicht."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from PIL import Image

from tools.generate_kurzuebersicht import (
    ENDPOINT_CROP,
    ENDPOINT_IMAGE_SIZE,
    ENDPOINT_SCREENSHOT,
    PROGRAM_CROP,
    PROGRAM_IMAGE_SIZE,
    PROGRAM_SCREENSHOT,
    generate_overview,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMMITTED_PDF = PROJECT_ROOT / "AfDLeakerCatcher-Kurzuebersicht.pdf"
GENERATOR = PROJECT_ROOT / "tools" / "generate_kurzuebersicht.py"
EXPECTED_PDF_SHA256 = "639d0d8469908a1417519e0f0c96173d3bec7d3c4f2252e50206d9e912e1ac1f"
EXPECTED_IMAGE_HASHES = {
    ENDPOINT_SCREENSHOT: "b4901f6c0f4312d13a01f9abc2e4a4e881ea192d5c6fa3932135e6271ed81ce8",
    PROGRAM_SCREENSHOT: "8e31c8ad8ef20166f54fea0ccd8a79dadfadd55769b61a51261195dc1afbc1f9",
}


def test_overview_is_exactly_two_deterministic_pages(tmp_path: Path) -> None:
    first = tmp_path / "first.pdf"
    second = tmp_path / "second.pdf"

    generate_overview(first)
    generate_overview(second)

    generated_payload = first.read_bytes()
    committed_payload = COMMITTED_PDF.read_bytes()
    assert generated_payload == second.read_bytes()
    assert hashlib.sha256(committed_payload).hexdigest() == EXPECTED_PDF_SHA256

    for payload in (generated_payload, committed_payload):
        assert payload.startswith(b"%PDF-1.4")
        assert len(re.findall(rb"/Type /Page(?!s)", payload)) == 2
        assert b"/Count 2" in payload
        assert payload.count(b"/MediaBox [ 0 0 841.8898 595.2756 ]") >= 1
        assert payload.count(b"/Subtype /Image") == 2
        assert b"/JavaScript" not in payload
        assert len(payload) < 1_000_000


def test_overview_uses_the_exact_supplied_screenshots() -> None:
    expected_sizes = {
        ENDPOINT_SCREENSHOT: ENDPOINT_IMAGE_SIZE,
        PROGRAM_SCREENSHOT: PROGRAM_IMAGE_SIZE,
    }
    for image_path, expected_hash in EXPECTED_IMAGE_HASHES.items():
        payload = image_path.read_bytes()
        assert payload.startswith(b"\x89PNG\r\n\x1a\n")
        assert hashlib.sha256(payload).hexdigest() == expected_hash
        with Image.open(image_path) as image:
            image.verify()
        with Image.open(image_path) as image:
            assert image.size == expected_sizes[image_path]

    assert ENDPOINT_CROP == (0, 0, 1622, 657)
    assert PROGRAM_CROP == (0, 286, 2290, 1427)


def test_overview_copy_explains_program_and_initial_suspicion_without_disclaimer() -> None:
    source = GENERATOR.read_text(encoding="utf-8")

    for expected_text in (
        "AfDLeakerCatcher ermittelt die technische Spur eines Datenlecks",
        "BEISPIELAUSZUG GEFUNDENER IP-ADRESSEN",
        "DHT und Tracker nach dem bekannten Infohash",
        "Direkte Bestätigung über volle 60 Sekunden",
        "PDF, CSV und Strafanzeige gegen Unbekannt",
        "Warum diese Daten einen Anfangsverdacht begründen",
        "Der Gegenclient bestätigt den Infohash",
        "Warum die Tatsachenkette ausreicht",
        "Zureichende tatsächliche Anhaltspunkte nach § 152 Abs. 2 StPO",
        "unmittelbar nutzbaren Ermittlungsansatz",
    ):
        assert expected_text in source

    for unwanted_text in (
        "möglicher Anfangsverdacht",
        "mutmaßlicher Datenbestand",
        "rechtliche Bewertung",
        "behördliche Bewertung",
        "reicht nicht",
        "kein Beweis",
        "möglicherweise",
    ):
        assert unwanted_text.casefold() not in source.casefold()
