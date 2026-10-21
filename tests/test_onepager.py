"""Regressionstests für die öffentliche AfDLeakerCatcher-Kurzuebersicht."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from tools.generate_kurzuebersicht import generate_onepager

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMMITTED_PDF = PROJECT_ROOT / "AfDLeakerCatcher-Kurzuebersicht.pdf"
GENERATOR = PROJECT_ROOT / "tools" / "generate_kurzuebersicht.py"
EXPECTED_SHA256 = "8c3ab4ec26ffa978a5059b2367b7d52669d3da195627ca2c5b9ec0b46522fbd1"


def test_onepager_is_exactly_one_deterministic_vector_page(tmp_path: Path) -> None:
    first = tmp_path / "first.pdf"
    second = tmp_path / "second.pdf"

    generate_onepager(first)
    generate_onepager(second)

    payload = first.read_bytes()
    assert payload == second.read_bytes() == COMMITTED_PDF.read_bytes()
    assert payload.startswith(b"%PDF-1.4")
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_SHA256
    assert len(re.findall(rb"/Type /Page(?!s)", payload)) == 1
    assert b"/Count 1" in payload
    assert b"/MediaBox [ 0 0 841.8898 595.2756 ]" in payload
    assert b"/Subtype /Image" not in payload
    assert b"/JavaScript" not in payload
    assert len(payload) < 100_000


def test_onepager_copy_is_simple_and_contains_no_real_endpoint_data() -> None:
    source = GENERATOR.read_text(encoding="utf-8")

    for expected_text in (
        "Vom BitTorrent-Datenleck zum prüfbaren Ermittlungsansatz",
        "Datenleck über BitTorrent",
        "Teilnehmer finden",
        "60 Sekunden Direktprüfung",
        "Kein Download des Datenlecks",
        "IP-Adresse, Port, UTC-Zeit",
        "behördliche Bewertung eines ",
        "möglichen Anfangsverdachts.",
        "Rechtliche Bewertung und Anschlusszuordnung",
    ):
        assert expected_text in source

    assert re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", source) is None
    assert re.search(r"\b[0-9a-fA-F]{40}\b", source) is None
    assert re.search(r"\b[0-9a-fA-F]{64}\b", source) is None
