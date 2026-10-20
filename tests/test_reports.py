"""Fokussierte Tests fuer die lokale Berichtserzeugung."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import os
import stat
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest import mock

from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerCandidate,
    ScanResult,
    VpnClassification,
)
from bittorrent_beobachter.reports import (
    EVIDENCE_LIMITATIONS,
    ReportConfig,
    _format_endpoint,
    _publish_staged_files,
    generate_reports,
    safe_ip_filename,
)

REPORTLAB_AVAILABLE = importlib.util.find_spec("reportlab") is not None


def _evidence_record(
    ip: str,
    port: int,
    sequence: int,
    *,
    vpn_status: str = "not_known_vpn",
    vpn_provider: str | None = None,
    confirmed: bool = True,
    source_note: str = "",
) -> EvidenceRecord:
    minute = f"{sequence:02d}"
    candidate = PeerCandidate(
        target_label=f"Ziel {sequence}",
        info_hash_hex=(f"{sequence:x}" * 40)[:40],
        ip=ip,
        port=port,
        discovered_at_utc=f"2026-10-20T10:{minute}:00Z",
        dht_node_ip="192.0.2.53",
        dht_node_port=6881,
        transaction_id_hex=f"{sequence:04x}",
        response_sha256=f"{sequence:064x}",
        source_note=source_note,
    )
    handshake = HandshakeResult(
        candidate=candidate,
        attempted_at_utc=f"2026-10-20T10:{minute}:01Z",
        completed_at_utc=(f"2026-10-20T10:{minute}:02Z" if confirmed else None),
        confirmed=confirmed,
        remote_peer_id_hex=(f"{sequence:040x}" if confirmed else None),
        reserved_bits_hex=("0000000000100005" if confirmed else None),
        local_ip="203.0.113.200",
        local_port=40000 + sequence,
        bytes_sent=68,
        bytes_received=68 if confirmed else 0,
        error=None if confirmed else "Verbindung abgelehnt",
    )
    enrichment = NetworkEnrichment(
        ip=ip,
        enriched_at_utc="2026-10-20T10:30:00Z",
        prefix="198.51.100.0/24" if ":" not in ip else "2001:db8::/32",
        asns=(64500,),
        holder="Beispielnetz GmbH",
        rdap_name="EXAMPLE-NET",
        rdap_handle="NET-EXAMPLE",
        country="DE",
        abuse_email="abuse@example.invalid",
        source_urls=("https://rdap.example.invalid/object",),
        source_fetched_at_utc=(
            ("rdap", "2026-10-20T10:20:00Z"),
            ("ripestat-prefix-overview", "2026-10-20T10:21:00Z"),
        ),
        cached_sources=("rdap",),
    )
    vpn = VpnClassification(
        status=vpn_status,
        provider=vpn_provider,
        reason="expliziter Testpraefix" if vpn_status == "known_vpn" else None,
        source="https://vpn.example.invalid/list" if vpn_status == "known_vpn" else None,
    )
    return EvidenceRecord(
        handshake=handshake,
        enrichment=enrichment,
        vpn=vpn,
        evidence_event_sha256=f"{sequence + 100:064x}",
    )


def _scan_result() -> ScanResult:
    records = [
        _evidence_record("198.51.100.10", 51414, 2),
        _evidence_record("198.51.100.10", 51413, 1),
        _evidence_record(
            "2001:db8::5",
            6881,
            3,
            vpn_status="known_vpn",
            vpn_provider="Beispiel VPN",
        ),
    ]
    handshakes = [record.handshake for record in records]
    return ScanResult(
        run_id="run/42",
        started_at_utc="2026-10-20T10:00:00Z",
        completed_at_utc="2026-10-20T11:00:00Z",
        candidates=[handshake.candidate for handshake in handshakes],
        handshakes=handshakes,
        records=records,
    )


@unittest.skipUnless(REPORTLAB_AVAILABLE, "ReportLab ist nicht installiert")
class ReportGenerationTests(unittest.TestCase):
    """Prueft Berichtsaufteilung, Integritaet und Reproduzierbarkeit."""

    def test_generates_aggregated_reports_drafts_and_manifest(self) -> None:
        result = _scan_result()
        config = ReportConfig(
            reporter_name="Test Meldestelle",
            reporter_contact="Nur fuer diesen Test",
            legal_notes=("Moegliche rechtliche Relevanz bitte eigenstaendig pruefen.",),
        )

        with tempfile.TemporaryDirectory() as temp_name:
            if os.name != "nt":
                Path(temp_name).chmod(0o775)
            paths = generate_reports(
                result,
                Path(temp_name),
                config,
                generated_at_utc="2026-10-20T11:05:00Z",
            )
            by_name = {path.name: path for path in paths}

            self.assertEqual(paths, result.report_paths)
            self.assertTrue(all(path.is_absolute() and path.is_file() for path in paths))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(Path(temp_name).stat().st_mode), 0o700)
                self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths))
            self.assertEqual(paths[-1].name, "run_42_SHA256SUMS.txt")
            self.assertIn("run_42_hinweis_ipv4_198_51_100_10.pdf", by_name)
            self.assertIn("run_42_entwurf_ipv4_198_51_100_10.eml", by_name)
            self.assertNotIn("run_42_hinweis_ipv6_2001_db8_5.pdf", by_name)
            self.assertNotIn("run_42_entwurf_ipv6_2001_db8_5.eml", by_name)

            with by_name["run_42_beobachtungen.csv"].open(encoding="utf-8", newline="") as handle:
                all_rows = list(csv.DictReader(handle, delimiter=";"))
            self.assertEqual([row["ip"] for row in all_rows], ["198.51.100.10", "2001:db8::5"])
            self.assertEqual(all_rows[0]["bestaetigte_handshakes"], "2")
            self.assertEqual(all_rows[0]["ports"], "51413 | 51414")
            self.assertEqual(all_rows[1]["vpn_status"], "bekannter VPN")
            self.assertEqual(
                all_rows[0]["lokaler_dht_antwort_fingerabdruck_sha256"],
                f"{1:064x} | {2:064x}",
            )
            self.assertIn(
                "rdap: 2026-10-20T10:20:00Z",
                all_rows[0]["netzregistrierung_quellen_abruf_utc"],
            )
            self.assertEqual(all_rows[0]["netzregistrierung_cache_quellen"], "rdap")
            self.assertEqual(
                all_rows[0]["angefragte_bzw_weitergeleitete_quellen"],
                "https://rdap.example.invalid/object",
            )
            self.assertNotIn("netzregistrierungs_quellen", all_rows[0])

            with by_name["run_42_vpn_liste.csv"].open(encoding="utf-8", newline="") as handle:
                vpn_rows = list(csv.DictReader(handle, delimiter=";"))
            self.assertEqual(len(vpn_rows), 1)
            self.assertEqual(vpn_rows[0]["ip"], "2001:db8::5")
            self.assertEqual(vpn_rows[0]["vpn_anbieter"], "Beispiel VPN")

            draft_path = by_name["run_42_entwurf_ipv4_198_51_100_10.eml"]
            message = BytesParser(policy=policy.default).parsebytes(draft_path.read_bytes())
            self.assertEqual(message["X-Unsent"], "1")
            self.assertIsNone(message["To"])
            self.assertIsNone(message["From"])
            plain_body = message.get_body(preferencelist=("plain",)).get_content()
            for limitation in EVIDENCE_LIMITATIONS:
                self.assertIn(limitation, plain_body)
            self.assertIn("keine digitale Signatur", plain_body)
            self.assertIn("kein vertrauenswürdiger externer Zeitstempel", plain_body)
            self.assertIn("nicht unabhängig reproduzierbar", plain_body)
            self.assertIn("Quellenspezifische Abrufzeitpunkte", plain_body)
            self.assertIn("Angefragte bzw. weitergeleitete Quellen", plain_body)
            self.assertIn("Aus lokalem Cache: rdap", plain_body)
            attachments = list(message.iter_attachments())
            self.assertEqual(len(attachments), 1)
            notice_path = by_name["run_42_hinweis_ipv4_198_51_100_10.pdf"]
            self.assertEqual(attachments[0].get_payload(decode=True), notice_path.read_bytes())

            manifest_lines = (
                by_name["run_42_SHA256SUMS.txt"].read_text(encoding="utf-8").splitlines()
            )
            manifest_entries = [line for line in manifest_lines if not line.startswith("#")]
            self.assertEqual(len(manifest_entries), len(paths) - 1)
            for entry in manifest_entries:
                expected_hash, filename = entry.split(" *", maxsplit=1)
                actual_hash = hashlib.sha256(by_name[filename].read_bytes()).hexdigest()
                self.assertEqual(expected_hash, actual_hash)

    @unittest.skipIf(os.name == "nt", "POSIX-Dateimodi sind unter Windows anders")
    def test_staged_report_is_private_before_atomic_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "staging" / "report.pdf"
            source.parent.mkdir()
            source.write_bytes(b"report")
            source.chmod(0o644)
            output_dir = root / "output"
            output_dir.mkdir()

            with (
                mock.patch(
                    "bittorrent_beobachter.reports.os.replace",
                    side_effect=OSError("simulierter Abbruch"),
                ),
                self.assertRaises(OSError),
            ):
                _publish_staged_files((source,), output_dir)

            self.assertTrue(source.exists())
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)

    def test_output_is_reproducible_with_fixed_input_and_timestamp(self) -> None:
        config = ReportConfig(
            reporter_name="Alice Beispiel",
            reporter_email="alice@example.invalid",
            recipient_name="Polizei Teststadt",
            recipient_email="poststelle@example.invalid",
        )
        with (
            tempfile.TemporaryDirectory() as first_name,
            tempfile.TemporaryDirectory() as second_name,
        ):
            first = generate_reports(
                _scan_result(),
                Path(first_name),
                config,
                generated_at_utc="2026-10-20T11:05:00Z",
            )
            second = generate_reports(
                _scan_result(),
                Path(second_name),
                config,
                generated_at_utc="2026-10-20T11:05:00Z",
            )

            first_bytes = {path.name: path.read_bytes() for path in first}
            second_bytes = {path.name: path.read_bytes() for path in second}
            self.assertEqual(first_bytes, second_bytes)

    def test_source_notes_are_isolated_per_confirmed_ip(self) -> None:
        alpha = _evidence_record(
            "198.51.100.21",
            6001,
            7,
            source_note="SOURCE_NOTE_ALPHA_ONLY",
        )
        beta = _evidence_record(
            "198.51.100.22",
            6002,
            8,
            source_note="SOURCE_NOTE_BETA_ONLY",
        )
        result = ScanResult(
            run_id="source-isolation",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[alpha, beta],
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            by_name = {path.name: path for path in paths}
            alpha_pdf = by_name["source-isolation_hinweis_ipv4_198_51_100_21.pdf"].read_bytes()
            beta_pdf = by_name["source-isolation_hinweis_ipv4_198_51_100_22.pdf"].read_bytes()
            self.assertIn(b"SOURCE_NOTE_ALPHA_ONLY", alpha_pdf)
            self.assertNotIn(b"SOURCE_NOTE_BETA_ONLY", alpha_pdf)
            self.assertIn(b"SOURCE_NOTE_BETA_ONLY", beta_pdf)
            self.assertNotIn(b"SOURCE_NOTE_ALPHA_ONLY", beta_pdf)

            alpha_message = BytesParser(policy=policy.default).parsebytes(
                by_name["source-isolation_entwurf_ipv4_198_51_100_21.eml"].read_bytes()
            )
            alpha_body = alpha_message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("SOURCE_NOTE_ALPHA_ONLY", alpha_body)
            self.assertNotIn("SOURCE_NOTE_BETA_ONLY", alpha_body)

            observations_path = by_name["source-isolation_beobachtungen.csv"]
            with observations_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle, delimiter=";"))
            alpha_row = next(row for row in rows if row["ip"] == "198.51.100.21")
            self.assertIn(
                "SOURCE_NOTE_ALPHA_ONLY",
                alpha_row["quellen_sachverhaltshinweise"],
            )
            self.assertNotIn(
                "SOURCE_NOTE_BETA_ONLY",
                alpha_row["quellen_sachverhaltshinweise"],
            )

    def test_any_known_vpn_classification_suppresses_individual_draft(self) -> None:
        ordinary = _evidence_record("198.51.100.40", 6000, 4)
        vpn = _evidence_record(
            "198.51.100.40",
            6001,
            5,
            vpn_status="known_vpn",
            vpn_provider="Beispiel VPN",
        )
        result = ScanResult(
            run_id="vpn-conflict",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[ordinary, vpn],
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            names = {path.name for path in paths}
            self.assertFalse(any("_hinweis_" in name for name in names))
            self.assertFalse(any("_entwurf_" in name for name in names))
            vpn_csv = next(path for path in paths if path.name.endswith("_vpn_liste.csv"))
            with vpn_csv.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle, delimiter=";"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["bestaetigte_handshakes"], "2")

    def test_unconfirmed_record_is_not_reported(self) -> None:
        unconfirmed = _evidence_record(
            "198.51.100.99",
            6881,
            6,
            confirmed=False,
        )
        result = ScanResult(
            run_id="unconfirmed",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[unconfirmed],
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            self.assertEqual(len(paths), 5)
            self.assertFalse(any("_hinweis_" in path.name for path in paths))
            observations_csv = next(
                path for path in paths if path.name.endswith("_beobachtungen.csv")
            )
            with observations_csv.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle, delimiter=";"))
            self.assertEqual(rows, [])


class FilenameAndValidationTests(unittest.TestCase):
    """Prueft sichere Dateinamen und Konfigurationsschutz."""

    def test_safe_ip_filename_handles_ipv4_and_ipv6(self) -> None:
        self.assertEqual(safe_ip_filename("198.51.100.7"), "ipv4_198_51_100_7")
        self.assertEqual(safe_ip_filename("2001:0db8:0:0::1"), "ipv6_2001_db8_1")
        with self.assertRaises(ValueError):
            safe_ip_filename("../../bericht")
        self.assertEqual(_format_endpoint("198.51.100.7", 6881), "198.51.100.7:6881")
        self.assertEqual(_format_endpoint("2001:db8::7", 6881), "[2001:db8::7]:6881")

    @unittest.skipUnless(REPORTLAB_AVAILABLE, "ReportLab ist nicht installiert")
    def test_header_injection_is_rejected_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            with self.assertRaisesRegex(ValueError, "Zeilenumbruch"):
                generate_reports(
                    _scan_result(),
                    Path(temp_name),
                    ReportConfig(recipient_name="Polizei\nBcc: fremd@example.invalid"),
                )
            self.assertEqual(list(Path(temp_name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
