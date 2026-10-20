"""Statische Tests für das einmal entpackbare Windows-Paket."""

from __future__ import annotations

import hashlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PDF_NAME = "Cybercrime-E-Mail-Kontakte_BKA-und-LKA_Deutschland_Stand-2026-10-20.pdf"
PDF_SHA256 = "75585bb562b705f5644734299f78d1b26f1bd083a4acd962d21704041feb2f12"


def test_reference_pdf_is_the_reviewed_document() -> None:
    pdf_path = PROJECT_ROOT / "assets" / PDF_NAME
    payload = pdf_path.read_bytes()

    assert payload.startswith(b"%PDF-1.4")
    assert hashlib.sha256(payload).hexdigest() == PDF_SHA256


def test_windows_build_places_pdf_beside_executable() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    local_build = (PROJECT_ROOT / "build_windows.ps1").read_text(encoding="utf-8")

    assert PDF_NAME in workflow
    assert PDF_NAME in local_build
    assert "dist/BitTorrent-Beobachter/" + PDF_NAME in workflow
    assert PDF_SHA256 in workflow
    assert PDF_SHA256 in local_build


def test_actions_artifact_contains_the_raw_app_folder() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")

    assert "name: AfDLeakercatcher-Windows-x64" in workflow
    assert "path: dist/BitTorrent-Beobachter\n" in workflow
    assert "path: release/package" in workflow
    assert "zip -r ../AfDLeakercatcher-Windows-x64.zip ." in workflow
    assert "dist/BitTorrent-Beobachter-Windows-x64.zip" not in workflow
    assert "subject-path: attest/BitTorrent-Beobachter.exe" in workflow


def test_readme_verifies_the_attested_executable() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "gh attestation verify BitTorrent-Beobachter.exe" in readme
    assert "gh attestation verify BitTorrent-Beobachter-Windows-x64.zip" not in readme
