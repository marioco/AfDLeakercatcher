"""Fokussierte Tests fuer die lokale Berichtserzeugung."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest import mock

import bittorrent_beobachter.reports as reports_module
from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    ScanResult,
    VpnClassification,
)
from bittorrent_beobachter.reports import (
    PROJECT_LEGAL_REVIEW_POINTS,
    PROJECT_ORIGINAL_MAGNET_LINKS,
    ReportConfig,
    _format_endpoint,
    _publish_staged_files,
    generate_reports,
    safe_ip_filename,
)

REPORTLAB_AVAILABLE = importlib.util.find_spec("reportlab") is not None

EXPECTED_PROJECT_MAGNET_LINKS = (
    (
        "magnet:?xt=urn:btih:852795102149749ad91123af01ceac5da6f9eb5a"
        "&dn=hexane-corpus-tar"
        "&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce"
        "&tr=udp%3A%2F%2Fopen.demonii.com%3A1337%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce"
        "&tr=udp%3A%2F%2Fexodus.desync.com%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce"
        "&tr=udp%3A%2F%2Fexplodie.org%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.dler.org%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.bittor.pw%3A1337%2Fannounce"
        "&tr=udp%3A%2F%2Fretracker01-msk-virt.corbina.net%3A80%2Fannounce"
    ),
    (
        "magnet:?xt=urn:btih:db503db679f508aa31a9e07913b2aa8cf7aa6dff"
        "&dn=hexane-corpus"
        "&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce"
        "&tr=udp%3A%2F%2Fopen.demonii.com%3A1337%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce"
        "&tr=udp%3A%2F%2Fexodus.desync.com%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce"
        "&tr=udp%3A%2F%2Fexplodie.org%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.dler.org%3A6969%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker.bittor.pw%3A1337%2Fannounce"
        "&tr=udp%3A%2F%2Fretracker01-msk-virt.corbina.net%3A80%2Fannounce"
    ),
)


def _evidence_record(
    ip: str,
    port: int,
    sequence: int,
    *,
    vpn_status: str = "not_known_vpn",
    vpn_provider: str | None = None,
    confirmed: bool = True,
    source_note: str = "",
    info_hash_hex: str | None = None,
    availability: PeerAvailabilityObservation | None = None,
    reportable: bool = True,
) -> EvidenceRecord:
    minute = f"{sequence:02d}"
    candidate = PeerCandidate(
        target_label=f"Ziel {sequence}",
        info_hash_hex=info_hash_hex or (f"{sequence:x}" * 40)[:40],
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
        availability=(
            availability
            if availability is not None
            else _availability_observation()
            if confirmed and reportable
            else None
        ),
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


def _availability_observation() -> PeerAvailabilityObservation:
    return PeerAvailabilityObservation(
        started_at_utc="2026-10-20T10:09:02Z",
        ended_at_utc="2026-10-20T10:10:02Z",
        requested_duration_seconds=60.0,
        duration_seconds=60.0,
        completed_full_window=True,
        interested_sent=True,
        non_empty_bitfield=True,
        have_announced=False,
        piece_availability_announced=True,
        unchoked=True,
        peer_choking_at_end=False,
        unchoked_duration_seconds=59.5,
        messages_received=4,
        bytes_received=128,
        request_messages_sent=0,
        piece_payload_bytes_received=0,
        metadata_requests_sent=0,
        termination_reason="Beobachtungszeit vollständig erreicht",
        control_events=(),
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
        notices=["DHT-Suche fuer Ziel 1: 3 verwertbare Antworten, 1 Anfrage ohne Antwort."],
    )


@unittest.skipUnless(REPORTLAB_AVAILABLE, "ReportLab ist nicht installiert")
class ReportGenerationTests(unittest.TestCase):
    """Prueft Berichtsaufteilung, Integritaet und Reproduzierbarkeit."""

    def test_generates_aggregated_reports_emails_and_manifest(self) -> None:
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
            self.assertIn("run_42_anlage_ipv4_198_51_100_10.pdf", by_name)
            self.assertIn("run_42_strafanzeige_ipv4_198_51_100_10.eml", by_name)
            self.assertFalse(any("_anlage_ipv6_" in name for name in by_name))
            self.assertFalse(any("_strafanzeige_ipv6_" in name for name in by_name))

            with by_name["run_42_beobachtungen.csv"].open(encoding="utf-8", newline="") as handle:
                all_rows = list(csv.DictReader(handle, delimiter=";"))
            self.assertEqual([row["ip"] for row in all_rows], ["198.51.100.10"])
            self.assertEqual(all_rows[0]["bestaetigte_handshakes"], "2")
            self.assertEqual(all_rows[0]["ports"], "51413 | 51414")
            self.assertEqual(
                all_rows[0]["erste_beobachtung_utc"],
                "2026-10-20T10:01:00Z",
            )
            self.assertEqual(
                all_rows[0]["letzte_beobachtung_utc"],
                "2026-10-20T10:10:02Z",
            )
            self.assertEqual(
                all_rows[0]["lokaler_dht_antwort_fingerabdruck_sha256"],
                f"{1:064x} | {2:064x}",
            )
            self.assertEqual(
                all_rows[0]["netzangaben_zusammengestellt_utc"],
                "2026-10-20T10:30:00Z",
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
            self.assertEqual(
                tuple(vpn_rows[0]),
                ("ip", "vpn_anbieter", "vpn_begruendung", "vpn_quellen"),
            )
            self.assertNotIn("ports", vpn_rows[0])
            self.assertNotIn("infohashes", vpn_rows[0])

            email_path = by_name["run_42_strafanzeige_ipv4_198_51_100_10.eml"]
            message = BytesParser(policy=policy.default).parsebytes(email_path.read_bytes())
            self.assertEqual(message["X-Unsent"], "1")
            self.assertIsNone(message["To"])
            self.assertIsNone(message["From"])
            self.assertEqual(
                message["Subject"],
                "Strafanzeige gegen Unbekannt - BitTorrent-Endpunkt 198.51.100.10",
            )
            plain_body = message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("Hiermit erstatte ich Strafanzeige gegen Unbekannt", plain_body)
            self.assertIn("Vorgangsnummer oder das Aktenzeichen", plain_body)
            self.assertIn("1. Gegenstand der Strafanzeige", plain_body)
            self.assertIn("2. Ermittlung der IP-Adresse", plain_body)
            self.assertIn("3. Direkte Überprüfung des BitTorrent-Clients", plain_body)
            self.assertIn("4. Technischer Beleg", plain_body)
            self.assertIn("meldete, dass bei ihm Teile verfügbar seien", plain_body)
            self.assertIn("technische Nachricht: UNCHOKE", plain_body)
            self.assertIn("forderte diese Teile nicht an", plain_body)
            self.assertIn("https://github.com/marioco/AfDLeakercatcher", plain_body)
            self.assertNotIn("AfD-Datenleak", plain_body)
            self.assertNotIn("Entwurf", plain_body)
            self.assertNotIn("Quellenspezifische Abrufzeitpunkte", plain_body)
            attachments = list(message.iter_attachments())
            self.assertEqual(len(attachments), 1)
            notice_path = by_name["run_42_anlage_ipv4_198_51_100_10.pdf"]
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

    def test_project_case_creates_complete_complaint_email(self) -> None:
        project_hash = "852795102149749ad91123af01ceac5da6f9eb5a"
        custom_hash = "f" * 40
        result = ScanResult(
            run_id="project-case",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[
                _evidence_record(
                    "198.51.100.80",
                    6009,
                    9,
                    info_hash_hex=project_hash,
                ),
                _evidence_record(
                    "198.51.100.80",
                    6010,
                    10,
                    info_hash_hex=custom_hash,
                ),
            ],
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            by_name = {path.name: path for path in paths}
            email_path = by_name["project-case_strafanzeige_ipv4_198_51_100_80.eml"]
            message = BytesParser(policy=policy.default).parsebytes(email_path.read_bytes())
            self.assertEqual(
                message["Subject"],
                "Strafanzeige gegen Unbekannt - Verdacht der Verbreitung von 281 GB "
                "mutmaßlich unbefugt kopierter AfD-Daten - IP 198.51.100.80",
            )
            body = message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("Hiermit erstatte ich Strafanzeige gegen Unbekannt", body)
            headings = (
                "1. Gegenstand der Strafanzeige",
                "2. Ermittlung der IP-Adresse",
                "3. Direkte Überprüfung des BitTorrent-Clients",
                "4. Technischer Beleg",
            )
            heading_positions = [body.index(heading) for heading in headings]
            self.assertEqual(heading_positions, sorted(heading_positions))
            self.assertIn("2026-10-20T10:09:02Z", body)
            self.assertIn("2026-10-20T10:10:02Z", body)
            self.assertIn("(60.0 Sekunden; vorgesehen: 60.0 Sekunden)", body)
            self.assertIn(
                "Am 19. Oktober 2026 wurden auf der Internetseite "
                "https://hexane.cc/ zwei BitTorrent-Links veröffentlicht:",
                body,
            )
            self.assertIn("ohne Berechtigung von Servern", body)
            self.assertIn("nun über BitTorrent verbreitet werden", body)
            self.assertIn("281,2 GB", body)
            self.assertIn("102.985 Dateien", body)
            self.assertIn("39.000 bewertete Dokumente", body)
            self.assertIn("35.000 Korrespondenzen", body)
            self.assertIn("3.230 sensible Datensätze", body)
            self.assertIn("57.000 Einträge", body)
            self.assertIn("180 Datenbanken", body)
            self.assertEqual(PROJECT_ORIGINAL_MAGNET_LINKS, EXPECTED_PROJECT_MAGNET_LINKS)
            for magnet in EXPECTED_PROJECT_MAGNET_LINKS:
                self.assertIn(magnet, body)
            self.assertEqual(body.count("magnet:?xt=urn:btih:"), 2)
            self.assertEqual(body.count("tracker.openbittorrent.com%3A6969"), 2)
            self.assertNotIn("tracker.openbittorent.com", body)
            self.assertIn(
                "Unter dieser IP wurden nach dem dokumentierten "
                "BitTorrent-Protokollbefund Teile des mutmaßlich rechtswidrig "
                "entwendeten Datenbestands \N{EN DASH} möglicherweise auch der vollständige "
                "Bestand \N{EN DASH} zum Download angeboten.",
                body,
            )
            self.assertIn("Aufnahme der Ermittlungen gegen Unbekannt", body)
            self.assertIn("zeitnahe Sicherung", body)
            self.assertIn("Ermittlung der verantwortlichen Person", body)
            self.assertIn("Vorgangsnummer oder das Aktenzeichen", body)
            self.assertIn("https://github.com/marioco/AfDLeakercatcher", body)
            for point in PROJECT_LEGAL_REVIEW_POINTS:
                self.assertIn(point, body)
            self.assertNotIn(custom_hash, body)
            self.assertNotIn("Eine IP-Adresse identifiziert", body)
            self.assertNotIn("belegt keines der gesetzlichen Tatbestandsmerkmale", body)
            self.assertNotIn("belegt nicht für sich allein die konkrete Beobachtung", body)
            self.assertNotIn("ENTWURF", body)

            pdf_path = by_name["project-case_anlage_ipv4_198_51_100_80.pdf"]
            attachments = list(message.iter_attachments())
            self.assertEqual(len(attachments), 1)
            self.assertEqual(attachments[0].get_filename(), pdf_path.name)
            self.assertEqual(attachments[0].get_payload(decode=True), pdf_path.read_bytes())
            pdf_bytes = pdf_path.read_bytes()
            self.assertIn(b"Technische Anlage zur Strafanzeige", pdf_bytes)
            self.assertNotIn(b"ENTWURF", pdf_bytes)
            self.assertNotIn(b"Adressat", pdf_bytes)

    def test_complaint_attachment_uses_requested_evidence_first_structure(self) -> None:
        project_hash = "852795102149749ad91123af01ceac5da6f9eb5a"
        result = ScanResult(
            run_id="attachment-structure",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[
                _evidence_record(
                    "198.51.100.83",
                    6013,
                    13,
                    info_hash_hex=project_hash,
                )
            ],
        )
        aggregate = reports_module._aggregate_reportable_records(result.records)[0]
        captured_story: list[object] = []

        def capture_pdf(
            _path: Path,
            _title: str,
            story: list[object],
            *_args: object,
        ) -> None:
            captured_story.extend(story)

        with mock.patch.object(reports_module, "_build_pdf", side_effect=capture_pdf):
            reports_module._write_complaint_attachment_pdf(
                Path("unused.pdf"),
                result,
                aggregate,
                ReportConfig(),
                "2026-10-20T11:05:00Z",
                reports_module._load_reportlab(),
            )

        paragraph_text = "\n".join(
            flowable.getPlainText()
            for flowable in captured_story
            if callable(getattr(flowable, "getPlainText", None))
        )
        expected_sections = (
            "1. Möglicher Tatgegenstand",
            "2. Anzeige gegen Unbekannt - ermittelter BitTorrent-Endpunkt",
            "3. So wurde der Endpunkt gefunden",
            "4. So wurde direkt geprüft",
            "Technische Zusammenfassung",
            "Öffentliche Routing-/Registry-Angaben",
            "Technische Einzelbeobachtungen",
        )
        section_positions = [paragraph_text.index(section) for section in expected_sections]
        self.assertEqual(section_positions, sorted(section_positions))
        self.assertIn("Die Strafanzeige richtet sich gegen Unbekannt.", paragraph_text)
        self.assertIn(
            "bestätigte den dokumentierten Infohash, meldete verfügbare Teile und gab mit UNCHOKE",
            paragraph_text,
        )
        self.assertIn("nannten DHT-Antworten den Endpunkt", paragraph_text)
        self.assertIn("direkte TCP-Verbindung", paragraph_text)
        self.assertNotIn("Täter", paragraph_text)
        self.assertNotIn("Aussagegrenze", paragraph_text)
        self.assertNotIn("belegt keines der gesetzlichen Tatbestandsmerkmale", paragraph_text)
        self.assertNotIn("nicht gerichtlich bewiesen", paragraph_text)
        self.assertNotIn("belegt nicht für sich allein die konkrete Beobachtung", paragraph_text)

    def test_offering_claim_requires_positive_overall_gate(self) -> None:
        project_hash = "852795102149749ad91123af01ceac5da6f9eb5a"
        positive = _availability_observation()
        incomplete = replace(
            positive,
            duration_seconds=12.0,
            completed_full_window=False,
            termination_reason="Gegenstelle schloss die Verbindung",
        )
        result = ScanResult(
            run_id="availability-gate",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[
                _evidence_record(
                    "198.51.100.81",
                    6011,
                    11,
                    info_hash_hex=project_hash,
                    availability=positive,
                ),
                _evidence_record(
                    "198.51.100.82",
                    6012,
                    12,
                    info_hash_hex=project_hash,
                    availability=incomplete,
                ),
            ],
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            by_name = {path.name: path for path in paths}
            positive_message = BytesParser(policy=policy.default).parsebytes(
                by_name["availability-gate_strafanzeige_ipv4_198_51_100_81.eml"].read_bytes()
            )
            positive_body = positive_message.get_body(preferencelist=("plain",)).get_content()
            self.assertIn("meldete, dass bei ihm Teile verfügbar seien", positive_body)
            self.assertIn("technische Nachricht: UNCHOKE", positive_body)
            self.assertIn("vollständig durchgeführten Beobachtungszeit", positive_body)
            self.assertIn("forderte diese Teile nicht an", positive_body)

            self.assertNotIn(
                "availability-gate_strafanzeige_ipv4_198_51_100_82.eml",
                by_name,
            )
            self.assertNotIn(
                "availability-gate_anlage_ipv4_198_51_100_82.pdf",
                by_name,
            )

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
            alpha_pdf = by_name["source-isolation_anlage_ipv4_198_51_100_21.pdf"].read_bytes()
            beta_pdf = by_name["source-isolation_anlage_ipv4_198_51_100_22.pdf"].read_bytes()
            self.assertIn(b"SOURCE_NOTE_ALPHA_ONLY", alpha_pdf)
            self.assertNotIn(b"SOURCE_NOTE_BETA_ONLY", alpha_pdf)
            self.assertIn(b"SOURCE_NOTE_BETA_ONLY", beta_pdf)
            self.assertNotIn(b"SOURCE_NOTE_ALPHA_ONLY", beta_pdf)

            alpha_message = BytesParser(policy=policy.default).parsebytes(
                by_name["source-isolation_strafanzeige_ipv4_198_51_100_21.eml"].read_bytes()
            )
            alpha_body = alpha_message.get_body(preferencelist=("plain",)).get_content()
            self.assertNotIn("SOURCE_NOTE_ALPHA_ONLY", alpha_body)
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

    def test_any_known_vpn_classification_suppresses_individual_complaint(self) -> None:
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
            self.assertFalse(any("_anlage_" in name for name in names))
            self.assertFalse(any("_strafanzeige_" in name for name in names))
            summary_pdf = next(path for path in paths if path.name.endswith("_laufbericht.pdf"))
            self.assertNotIn(b"198.51.100.40", summary_pdf.read_bytes())
            observations_csv = next(
                path for path in paths if path.name.endswith("_beobachtungen.csv")
            )
            with observations_csv.open(encoding="utf-8", newline="") as handle:
                self.assertEqual(list(csv.DictReader(handle, delimiter=";")), [])
            vpn_csv = next(path for path in paths if path.name.endswith("_vpn_liste.csv"))
            with vpn_csv.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle, delimiter=";"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["ip"], "198.51.100.40")
            self.assertEqual(rows[0]["vpn_anbieter"], "Beispiel VPN")

    def test_large_registry_provenance_can_split_across_pdf_pages(self) -> None:
        records: list[EvidenceRecord] = []
        for sequence in range(1, 31):
            record = _evidence_record("198.51.100.70", 6_000 + sequence, sequence)
            enrichment = replace(
                record.enrichment,
                enriched_at_utc=f"2026-10-20T11:{sequence:02d}:00Z",
                source_urls=(
                    f"https://rdap.example.invalid/object/{sequence}",
                    f"https://stat.example.invalid/object/{sequence}",
                ),
                source_fetched_at_utc=(
                    ("rdap", f"2026-10-20T10:{sequence:02d}:00Z"),
                    (
                        "ripestat-prefix-overview",
                        f"2026-10-20T10:{sequence:02d}:30Z",
                    ),
                ),
                error=f"Quelle {sequence}: " + ("x" * 480),
            )
            records.append(replace(record, enrichment=enrichment))
        result = ScanResult(
            run_id="long-provenance",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T12:00:00Z",
            records=records,
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            self.assertTrue(paths)
            self.assertTrue(all(path.stat().st_size > 0 for path in paths))

    def test_confirmed_handshake_without_offering_creates_no_complaint(self) -> None:
        handshake_only = _evidence_record(
            "198.51.100.98",
            6881,
            13,
            confirmed=True,
            reportable=False,
        )
        self.assertTrue(handshake_only.handshake.confirmed)
        self.assertFalse(handshake_only.handshake.offering_observed)
        result = ScanResult(
            run_id="handshake-only",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T11:00:00Z",
            records=[handshake_only],
        )

        with tempfile.TemporaryDirectory() as temp_name:
            paths = generate_reports(result, Path(temp_name), ReportConfig())
            self.assertEqual(len(paths), 5)
            self.assertFalse(any("_anlage_" in path.name for path in paths))
            self.assertFalse(any("_strafanzeige_" in path.name for path in paths))
            observations_csv = next(
                path for path in paths if path.name.endswith("_beobachtungen.csv")
            )
            with observations_csv.open(encoding="utf-8", newline="") as handle:
                self.assertEqual(list(csv.DictReader(handle, delimiter=";")), [])

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
            self.assertFalse(any("_anlage_" in path.name for path in paths))
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
        self.assertEqual(
            safe_ip_filename("2001:0db8:0:0::1"),
            "ipv6_2001_0db8_0000_0000_0000_0000_0000_0001",
        )
        self.assertNotEqual(
            safe_ip_filename("2001:db8:0:1::"),
            safe_ip_filename("2001:db8:0::1"),
        )
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

    @unittest.skipUnless(REPORTLAB_AVAILABLE, "ReportLab ist nicht installiert")
    def test_naive_report_timestamp_is_rejected_instead_of_assumed_utc(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            with self.assertRaisesRegex(ValueError, "UTC-Bezug"):
                generate_reports(
                    _scan_result(),
                    Path(temp_name),
                    ReportConfig(),
                    generated_at_utc="2026-10-20T11:05:00",
                )
            self.assertEqual(list(Path(temp_name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
