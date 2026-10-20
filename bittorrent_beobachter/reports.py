"""Erzeugt nachvollziehbare Anzeigen und Berichte aus bestaetigten Beobachtungen.

Das Modul versendet nichts. E-Mail-Ausgaben werden ausschliesslich als lokale
versandfertige ``.eml``-Dateien mit angehaengtem PDF erstellt. ReportLab wird erst beim
Erzeugen der PDFs importiert, damit alle anderen Programmteile auch ohne die
optionale PDF-Abhaengigkeit importierbar bleiben.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import html
import ipaddress
import os
import re
import tempfile
import textwrap
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TextIO

from .models import EvidenceRecord, PeerCandidate, ScanResult
from .run_store import RunStore

PROJECT_REPOSITORY_URL = "https://github.com/marioco/AfDLeakercatcher"
PUBLISHED_SOURCE_URL = "https://hexane.cc/"
PROJECT_ORIGINAL_MAGNET_LINKS = (
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
PROJECT_LEAK_INFO_HASHES = frozenset(
    {
        "852795102149749ad91123af01ceac5da6f9eb5a",
        "db503db679f508aa31a9e07913b2aa8cf7aa6dff",
    }
)
PROJECT_LEGAL_REVIEW_POINTS = (
    "Datenhehlerei (§ 202d StGB)",
    "Strafvorschriften des Datenschutzrechts (§ 42 BDSG)",
    "unerlaubte Verwertung urheberrechtlich geschützter Werke (§ 106 UrhG)",
    "gefährdendes Verbreiten personenbezogener Daten (§ 126a StGB)",
    "Verletzung von Geschäftsgeheimnissen (§ 23 GeschGehG)",
)
PUBLISHED_DATASET_FACTS = (
    "Gesamtumfang: 281,2 GB mit 102.985 Dateien",
    "rund 39.000 bewertete Dokumente",
    "rund 35.000 Korrespondenzen",
    "3.230 sensible Datensätze",
    "rund 57.000 Einträge der Kategorie „Postfach“",
    "180 Datenbanken",
)

EVIDENCE_LIMITATIONS = (
    "Es wurden keine Inhalte und keine Torrent-Metadaten heruntergeladen oder hochgeladen.",
    "Die behauptete Zuordnung des Infohashes zu einem bezeichneten Inhalt "
    "wurde deshalb nicht verifiziert; Magnetname, Zielbezeichnung und "
    "Infohash allein beweisen den Inhalt nicht.",
    "Jeder bestätigte Datensatz belegt, dass der öffentliche Netzwerkendpunkt "
    "den BitTorrent-Handshake für den genannten Infohash beantwortet hat. Ein "
    "positiver Verfügbarkeits-Gesamtbefund dokumentiert zusätzlich nur gemeldete "
    "Stückverfügbarkeit und ein empfangenes UNCHOKE-Signal.",
    "Auch ein positiver Gesamtbefund beweist keinen tatsächlichen Download oder "
    "Upload von Inhaltsblöcken.",
    "Die technische Beobachtung belegt weder Eigentum am Anschluss oder Endgerät "
    "noch die Identität "
    "einer Person, deren Handeln oder deren Schuld.",
    "Öffentliche Routing-/Registry-Angaben beschreiben einen Netzbetreiber "
    "oder Adressbereich; sie sind keine Auskunft über die Anschlussinhaberin oder "
    "den Anschlussinhaber.",
    "Die lokalen SHA-256-Hashes und die lokale Hash-Kette unterstützen nur "
    "die Integritätsprüfung der lokalen Aufzeichnung; sie sind keine digitale "
    "Signatur und kein vertrauenswürdiger externer Zeitstempel.",
    "Die Hash-Kette bestätigt nicht die sachliche Richtigkeit der vor ihrer "
    "Berechnung gespeicherten Angaben.",
    "Der SHA-256-Wert der DHT- oder UDP-Tracker-Antwort ist nur ein lokal "
    "berechneter Fingerabdruck. Das Rohpaket wird datensparsam nicht gespeichert; "
    "der Wert "
    "ist deshalb später nicht unabhängig reproduzierbar oder extern bestätigt.",
    "Die rechtliche Bewertung und alle weiteren Ermittlungen obliegen "
    "ausschließlich den zuständigen Behörden.",
)

CSV_FIELDNAMES = (
    "ip",
    "ports",
    "zielbezeichnungen",
    "infohashes",
    "quellen_sachverhaltshinweise",
    "erste_beobachtung_utc",
    "letzte_beobachtung_utc",
    "bestaetigte_handshakes",
    "fundquellen",
    "lokaler_fundantwort_fingerabdruck_sha256",
    "beweisereignis_sha256",
    "remote_peer_ids",
    "bytes_gesendet_summe",
    "bytes_empfangen_summe",
    "netzpraefixe",
    "asns",
    "routing_netzbetreiberangaben",
    "rdap_namen",
    "rdap_handles",
    "laender",
    "abuse_kontakte",
    "vpn_status",
    "vpn_anbieter",
    "vpn_begruendung",
    "vpn_quellen",
    "angefragte_bzw_weitergeleitete_quellen",
    "netzangaben_zusammengestellt_utc",
    "netzregistrierung_quellen_abruf_utc",
    "netzregistrierung_cache_quellen",
    "netzregistrierungs_fehler",
    "aussagegrenze",
)

VPN_CSV_FIELDNAMES = (
    "ip",
    "vpn_anbieter",
    "vpn_begruendung",
    "vpn_quellen",
)

MAX_SUMMARY_PDF_ROWS = 100
MAX_SUMMARY_SOURCE_NOTES = 50


@dataclass(frozen=True, slots=True)
class ReportConfig:
    """Konfigurierbare Absender-, Empfaenger- und Rechtshinweise.

    Das Modul erfindet keine E-Mail- oder Postadresse. Nicht ausgefüllte
    Absender- und Empfängerfelder bleiben leer.
    """

    reporter_name: str = ""
    reporter_contact: str = ""
    reporter_email: str | None = None
    recipient_name: str = ""
    recipient_address: str = ""
    recipient_email: str | None = None
    legal_notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _IpAggregate:
    """Kleiner IP-Handle, der Evidenz bei jedem Durchlauf batchweise neu liest."""

    ip: str
    record_count: int
    is_known_vpn: bool
    records_factory: Callable[[], Iterator[EvidenceRecord]]

    def iter_records(self) -> Iterator[EvidenceRecord]:
        """Liefert exakt die positive Evidenz dieser IP ohne Gruppentupel."""

        yielded = 0
        for record in self.records_factory():
            candidate = record.handshake.candidate
            if _canonical_ip(candidate.ip) != self.ip:
                raise ValueError(
                    f"Evidenz-Iterator für {self.ip} lieferte abweichende IP {candidate.ip}."
                )
            if not record.handshake.offering_observed:
                raise ValueError("IP-Aggregat enthält keinen positiven Gesamtbefund.")
            yielded += 1
            yield record
        if yielded != self.record_count:
            raise ValueError(
                f"Evidenzanzahl für {self.ip} ist inkonsistent: "
                f"{self.record_count} erwartet, {yielded} gelesen."
            )


@dataclass(frozen=True, slots=True)
class _IpSummary:
    """Kleine IP-Bilanz ohne die zugrunde liegenden Evidenzobjekte."""

    ip: str
    is_known_vpn: bool
    row: dict[str, str]
    source_notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ReportIndex:
    """Begrenzter Laufindex ohne eine mit der Trefferzahl wachsende IP-Liste."""

    positive_ip_count: int
    reportable_ip_count: int
    vpn_ip_count: int
    reportable_preview: tuple[_IpSummary, ...]
    source_notes: tuple[str, ...]
    source_notes_truncated: bool


def _project_leak_hashes(aggregate: _IpAggregate) -> tuple[str, ...]:
    """Liefert nur die fest im Projekt hinterlegten, fallbezogenen Infohashes."""

    return tuple(
        sorted(
            {
                record.handshake.candidate.info_hash_hex
                for record in aggregate.iter_records()
                if record.handshake.candidate.info_hash_hex in PROJECT_LEAK_INFO_HASHES
            }
        )
    )


def _discovery_source_label(candidate: PeerCandidate) -> str:
    """Bezeichnet die protokollierte Fundquelle ohne DHT/Tracker-Verwechslung."""

    if candidate.discovery_source == "tracker":
        return "UDP-Tracker"
    return "BitTorrent-DHT"


def _discovery_method_statement(aggregate: _IpAggregate) -> str:
    """Erklaert die fuer diese IP tatsaechlich protokollierten Fundwege."""

    sources = {record.handshake.candidate.discovery_source for record in aggregate.iter_records()}
    if sources == {"tracker"}:
        return (
            "Das Prüfprogramm fragte die konfigurierten öffentlichen UDP-Tracker "
            "gezielt nach den dokumentierten Infohashes ab. Dabei nannte mindestens "
            f"eine Tracker-Antwort den Endpunkt mit der IP-Adresse {aggregate.ip} "
            "als Peer. Antwortender UDP-Tracker, Transaktions-ID, Empfangszeitpunkt "
            "und lokaler SHA-256-Fingerabdruck jeder Antwort sind in den technischen "
            "Einzelbeobachtungen aufgeführt."
        )
    if sources == {"dht"}:
        return (
            "Das Prüfprogramm fragte das öffentliche BitTorrent-DHT gezielt nach "
            "den dokumentierten Infohashes ab. Dabei nannten DHT-Antworten den "
            f"Endpunkt mit der IP-Adresse {aggregate.ip} als Peer. Antwortender "
            "DHT-Knoten, Transaktions-ID, Empfangszeitpunkt und lokaler "
            "SHA-256-Fingerabdruck jeder Antwort sind in den technischen "
            "Einzelbeobachtungen aufgeführt."
        )
    return (
        "Das Prüfprogramm fragte sowohl das öffentliche BitTorrent-DHT als auch "
        "die konfigurierten öffentlichen UDP-Tracker gezielt nach den dokumentierten "
        f"Infohashes ab. Beide Fundwege nannten die IP-Adresse {aggregate.ip} als "
        "Peer-Endpunkt. Fundquelle, antwortender DHT-Knoten oder UDP-Tracker, "
        "Transaktions-ID, Empfangszeitpunkt und lokaler SHA-256-Fingerabdruck "
        "jeder Antwort sind in den technischen Einzelbeobachtungen aufgeführt."
    )


def _discovery_detail_rows(
    candidate: PeerCandidate,
) -> tuple[tuple[str, str], ...]:
    """Formatiert DHT- und Tracker-Nachweise mit eindeutig passenden Feldnamen."""

    if candidate.discovery_source == "tracker":
        return (
            ("Fundquelle", "UDP-Tracker"),
            ("Vom UDP-Tracker genannt (UTC)", candidate.discovered_at_utc),
            (
                "UDP-Tracker-Antwort von",
                _format_endpoint(candidate.dht_node_ip, candidate.dht_node_port),
            ),
            ("Tracker-Transaktions-ID", candidate.transaction_id_hex),
            (
                "Lokaler SHA-256-Fingerabdruck der UDP-Tracker-Antwort",
                candidate.response_sha256,
            ),
        )
    return (
        ("Fundquelle", "BitTorrent-DHT"),
        ("Von DHT genannt (UTC)", candidate.discovered_at_utc),
        (
            "DHT-Antwort von",
            _format_endpoint(candidate.dht_node_ip, candidate.dht_node_port),
        ),
        ("DHT-Transaktions-ID", candidate.transaction_id_hex),
        (
            "Lokaler SHA-256-Fingerabdruck der DHT-Antwort",
            candidate.response_sha256,
        ),
    )


def _availability_statement(record: EvidenceRecord) -> str:
    """Formuliert den vollständigen Angebotsbefund genau eines Records."""

    handshake = record.handshake
    observation = handshake.availability
    if observation is None or not handshake.offering_observed:
        raise ValueError("Verfügbarkeitstext erfordert einen positiven Gesamtbefund.")
    if observation.completed_full_window:
        duration_statement = (
            "Der Client blieb während der vollständig durchgeführten Beobachtungszeit erreichbar. "
        )
    else:
        duration_statement = (
            "Die Verbindung endete nach der bereits positiven Beobachtung; "
            f"Beendigungsgrund: {observation.termination_reason}. "
        )
    return (
        "Das Prüfprogramm stellte eine direkte Verbindung zum BitTorrent-Client "
        "her. Der Client bestätigte die eindeutige digitale Kennung (Infohash). "
        "Er meldete, dass bei ihm Teile verfügbar seien; außerdem teilte er dem "
        "Prüfprogramm mit, dass es diese Teile nun anfordern dürfe (technische "
        "Nachricht: UNCHOKE). "
        f"{duration_statement}"
        "Beobachtet wurde von "
        f"{observation.started_at_utc} bis {observation.ended_at_utc} "
        f"({observation.duration_seconds:.1f} Sekunden; vorgesehen: "
        f"{observation.requested_duration_seconds:.1f} Sekunden). Das "
        "Prüfprogramm forderte diese Teile nicht an und lud keine Inhalte herunter."
    )


def _availability_overview(aggregate: _IpAggregate) -> str:
    """Verdichtet beliebig viele positive Prüfungen in konstantem Speicher."""

    first_record: EvidenceRecord | None = None
    first_seen: tuple[datetime, str] | None = None
    last_seen: tuple[datetime, str] | None = None
    full_windows = 0
    early_endings = 0
    for record in aggregate.iter_records():
        if first_record is None:
            first_record = record
        observation = record.handshake.availability
        if observation is None or not record.handshake.offering_observed:
            raise ValueError("IP-Aggregat enthält keinen positiven Gesamtbefund.")
        full_windows += int(observation.completed_full_window)
        early_endings += int(not observation.completed_full_window)
        for timestamp in (observation.started_at_utc, observation.ended_at_utc):
            parsed = _timestamp_as_datetime(timestamp)
            if first_seen is None or parsed < first_seen[0]:
                first_seen = (parsed, timestamp)
            if last_seen is None or parsed > last_seen[0]:
                last_seen = (parsed, timestamp)

    if first_record is None or first_seen is None or last_seen is None:
        raise ValueError(f"IP-Aggregat {aggregate.ip} ist leer.")
    if aggregate.record_count == 1:
        return _availability_statement(first_record)
    first_statement = _availability_statement(first_record)
    return (
        f"Das Prüfprogramm führte {aggregate.record_count} direkte Prüfungen von "
        f"BitTorrent-Endpunkten unter der IP-Adresse {aggregate.ip} durch. Bei jeder "
        "protokollierten positiven Prüfung bestätigte der Client den jeweiligen "
        "Infohash, meldete verfügbare Teile und gab mit UNCHOKE das Anfordern dieser "
        "Teile frei. Eine der Prüfungen ist wie folgt dokumentiert: "
        f"{first_statement} "
        f"Insgesamt erreichten {full_windows} Prüfung(en) die vollständig vorgesehene "
        f"Beobachtungszeit; {early_endings} Verbindung(en) endeten erst nach dem "
        "bereits positiven Befund. Der gesamte Beobachtungszeitraum reichte von "
        f"{first_seen[1]} bis {last_seen[1]}. Alle weiteren Einzelzeiten und "
        "Beendigungsgründe stehen vollständig in den technischen Einzelbeobachtungen."
    )


def _availability_detail_rows(record: EvidenceRecord) -> tuple[tuple[str, str], ...]:
    """Zeigt Einzelfelder erst nach einem positiven, vollständigen Gesamtbefund."""

    handshake = record.handshake
    observation = handshake.availability
    if observation is None:
        return (
            (
                "Direkte Verfügbarkeitsbeobachtung",
                "für diesen älteren Datensatz nicht erfasst",
            ),
        )
    if not handshake.offering_observed:
        return (
            (
                "Direkte Verfügbarkeitsbeobachtung",
                "kein vollständiger positiver Gesamtbefund",
            ),
            ("Angeforderte oder geladene Inhaltsblöcke", "keine"),
        )

    control_events = (
        " | ".join(event.kind for event in observation.control_events) or "keine protokolliert"
    )
    return (
        ("Verfügbarkeitsprüfung begonnen (UTC)", observation.started_at_utc),
        ("Verfügbarkeitsprüfung beendet (UTC)", observation.ended_at_utc),
        (
            "Beobachtungsdauer",
            f"{observation.duration_seconds:.1f} von vorgesehenen "
            f"{observation.requested_duration_seconds:.1f} Sekunden",
        ),
        (
            "Vollständige Beobachtungszeit erreicht",
            "ja" if observation.completed_full_window else "nein",
        ),
        ("Peer meldete Stückverfügbarkeit", "ja"),
        ("Peer sendete UNCHOKE", "ja"),
        ("Empfangene Protokollnachrichten", str(observation.messages_received)),
        ("Empfangene Bytes der Protokollprüfung", str(observation.bytes_received)),
        ("Gesendete REQUEST-Nachrichten", str(observation.request_messages_sent)),
        ("Empfangene Inhaltsbytes", str(observation.piece_payload_bytes_received)),
        ("Gesendete Metadatenanfragen", str(observation.metadata_requests_sent)),
        ("Beendigungsgrund", observation.termination_reason),
        ("Protokollierte Steuerereignisse", control_events),
        ("Fehler der Verfügbarkeitsprüfung", observation.error or "keiner"),
        ("Angeforderte oder geladene Inhaltsblöcke", "keine"),
    )


def safe_ip_filename(ip: str) -> str:
    """Gibt eine kanonische, betriebssystemuebergreifend sichere IP-Kennung zurueck."""

    if "%" in ip:
        raise ValueError("IP-Adressen mit Zonenkennung sind nicht zulaessig")
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Ungueltige IP-Adresse fuer Bericht: {ip!r}") from exc
    if parsed.version == 6:
        # Die ausgeschriebene Form verhindert Kollisionen, die beim blossen
        # Ersetzen von ':' und '::' durch denselben Trenner entstehen koennten.
        safe_address = parsed.exploded.lower().replace(":", "_")
    else:
        safe_address = parsed.compressed.replace(".", "_")
    return f"ipv{parsed.version}_{safe_address}"


def generate_reports(
    result: ScanResult,
    output_dir: Path,
    config: ReportConfig,
    *,
    generated_at_utc: str | None = None,
) -> list[Path]:
    """Erzeugt alle Dateien streamend und merkt nur fünf feste Kernpfade.

    Die vollständige Dateiliste mit SHA-256-Werten steht im Manifest. Im
    ScanResult verbleiben nur Laufbericht, beide CSV-Dateien, VPN-PDF und
    Manifest, damit GUI und CLI den Ergebnisordner ohne wachsende Pfadliste
    finden. Ohne Laufdatenbank bleibt result.records nur für ältere Ergebnisse.
    """

    _validate_report_config(config)
    _single_line(result.run_id, "run_id")
    report_index = _build_report_index(result)
    generated_timestamp = _normalise_utc_timestamp(
        generated_at_utc or result.completed_at_utc or result.started_at_utc
    )
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        output_dir.chmod(0o700)
    if not output_dir.is_dir():
        raise NotADirectoryError(f"Berichtsziel ist kein Verzeichnis: {output_dir}")

    run_slug = _safe_component(result.run_id, fallback="lauf")
    toolkit = _load_reportlab()

    with tempfile.TemporaryDirectory(prefix=".berichte-", dir=output_dir) as temp_name:
        staging_dir = Path(temp_name)
        manifest_path = staging_dir / f"{run_slug}_SHA256SUMS.txt"
        manifest_handle = _start_manifest(
            manifest_path,
            result.run_id,
            generated_timestamp,
        )
        manifest_entry_count = 0

        def record_generated(path: Path) -> None:
            nonlocal manifest_entry_count
            _append_manifest_entry(manifest_handle, path)
            manifest_entry_count += 1

        try:
            summary_path = staging_dir / f"{run_slug}_laufbericht.pdf"
            _write_summary_pdf(
                summary_path,
                result,
                report_index,
                config,
                generated_timestamp,
                toolkit,
            )
            record_generated(summary_path)

            csv_path = staging_dir / f"{run_slug}_beobachtungen.csv"
            _write_csv(csv_path, _iter_csv_rows(result, known_vpn=False))
            record_generated(csv_path)

            vpn_csv_path = staging_dir / f"{run_slug}_vpn_liste.csv"
            _write_vpn_csv(vpn_csv_path, _iter_csv_rows(result, known_vpn=True))
            record_generated(vpn_csv_path)

            vpn_pdf_path = staging_dir / f"{run_slug}_vpn_liste.pdf"
            _write_vpn_pdf(
                vpn_pdf_path,
                result,
                _iter_ip_summaries(result, known_vpn=True),
                report_index.vpn_ip_count,
                config,
                generated_timestamp,
                toolkit,
            )
            record_generated(vpn_pdf_path)

            for aggregate in _iter_ip_aggregates(result):
                if aggregate.is_known_vpn:
                    continue
                ip_slug = safe_ip_filename(aggregate.ip)
                attachment_path = staging_dir / f"{run_slug}_anlage_{ip_slug}.pdf"
                _write_complaint_attachment_pdf(
                    attachment_path,
                    result,
                    aggregate,
                    config,
                    generated_timestamp,
                    toolkit,
                )
                record_generated(attachment_path)

                complaint_path = staging_dir / f"{run_slug}_strafanzeige_{ip_slug}.eml"
                _write_complaint_email(
                    complaint_path,
                    result,
                    aggregate,
                    config,
                    generated_timestamp,
                    attachment_path,
                )
                record_generated(complaint_path)
        finally:
            manifest_handle.close()

        published_count = _publish_staged_files(staging_dir, output_dir)
        if published_count != manifest_entry_count + 1:
            raise RuntimeError(
                "Anzahl veröffentlichter Berichtsdateien stimmt nicht mit dem Manifest überein."
            )

    core_paths = [
        output_dir / f"{run_slug}_laufbericht.pdf",
        output_dir / f"{run_slug}_beobachtungen.csv",
        output_dir / f"{run_slug}_vpn_liste.csv",
        output_dir / f"{run_slug}_vpn_liste.pdf",
        output_dir / f"{run_slug}_SHA256SUMS.txt",
    ]
    if not all(path.is_file() for path in core_paths):
        raise RuntimeError("Mindestens eine Kern-Berichtsdatei fehlt nach der Veröffentlichung.")
    result.report_paths[:] = core_paths
    return core_paths


def _load_reportlab() -> SimpleNamespace:
    """Importiert ReportLab erst dann, wenn tatsaechlich PDFs erzeugt werden."""

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfgen.canvas import Canvas
        from reportlab.platypus import (
            LongTable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError(
            "PDF-Berichte benoetigen das optionale Python-Paket 'reportlab'."
        ) from exc

    return SimpleNamespace(
        colors=colors,
        TA_CENTER=TA_CENTER,
        A4=A4,
        ParagraphStyle=ParagraphStyle,
        getSampleStyleSheet=getSampleStyleSheet,
        mm=mm,
        Canvas=Canvas,
        LongTable=LongTable,
        Paragraph=Paragraph,
        SimpleDocTemplate=SimpleDocTemplate,
        Spacer=Spacer,
        Table=Table,
        TableStyle=TableStyle,
    )


def _validate_report_config(config: ReportConfig) -> None:
    """Verhindert ungueltige oder in Header einschleusbare Konfigurationen."""

    for label, value in (
        ("reporter_name", config.reporter_name),
        ("recipient_name", config.recipient_name),
    ):
        if "\r" in value or "\n" in value:
            raise ValueError(f"{label} darf keinen Zeilenumbruch enthalten")

    if isinstance(config.legal_notes, str):
        raise TypeError("legal_notes muss ein Tupel aus Texten sein")
    if not all(isinstance(note, str) for note in config.legal_notes):
        raise TypeError("legal_notes darf nur Texte enthalten")

    for label, value in (
        ("reporter_email", config.reporter_email),
        ("recipient_email", config.recipient_email),
    ):
        if not value:
            continue
        if "\r" in value or "\n" in value:
            raise ValueError(f"{label} darf keinen Zeilenumbruch enthalten")
        try:
            Address(addr_spec=value.strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Ungueltige E-Mail-Adresse in {label}") from exc


def _iter_evidence_records(result: ScanResult) -> Iterable[EvidenceRecord]:
    """Liest Laufbefunde bevorzugt in Fünferbatches aus der privaten Datenbank."""

    if result.run_store_path is None:
        yield from result.records
        return
    store = RunStore(result.run_store_path)
    yield from store.iter_evidence_records(batch_size=5)


def _iter_ip_aggregates(result: ScanResult) -> Iterator[_IpAggregate]:
    """Liefert kleine IP-Handles; Evidenz bleibt in SQLite oder der Legacy-Liste."""

    if result.run_store_path is not None:
        store_path = result.run_store_path
        for group in RunStore(store_path).iter_positive_ip_groups(batch_size=5):
            yield _IpAggregate(
                ip=group.ip,
                record_count=group.record_count,
                is_known_vpn=group.is_known_vpn,
                records_factory=lambda ip=group.ip: RunStore(
                    store_path
                ).iter_positive_evidence_for_ip(ip, batch_size=5),
            )
        return

    yield from _aggregate_reportable_records(result.records)


def _aggregate_reportable_records(
    records: Iterable[EvidenceRecord],
) -> tuple[_IpAggregate, ...]:
    """Baut Legacy-IP-Handles ohne eine zweite Records-Liste je IP."""

    source_records = records if isinstance(records, (list, tuple)) else list(records)
    group_state: dict[str, tuple[int, bool]] = {}
    for record in source_records:
        if not record.handshake.offering_observed:
            continue
        candidate_ip = _canonical_ip(record.handshake.candidate.ip)
        enrichment_ip = _canonical_ip(record.enrichment.ip)
        if candidate_ip != enrichment_ip:
            raise ValueError(
                "IP-Adresse der Netzregistrierung passt nicht zum Handshake: "
                f"{enrichment_ip} != {candidate_ip}"
            )
        count, is_known_vpn = group_state.get(candidate_ip, (0, False))
        group_state[candidate_ip] = (
            count + 1,
            is_known_vpn or record.vpn.status == "known_vpn",
        )

    aggregates: list[_IpAggregate] = []
    for ip in sorted(group_state, key=_ip_sort_key):
        count, is_known_vpn = group_state[ip]

        def records_for_ip(
            selected_ip: str = ip,
            source: Iterable[EvidenceRecord] = source_records,
        ) -> Iterator[EvidenceRecord]:
            for record in source:
                if (
                    record.handshake.offering_observed
                    and _canonical_ip(record.handshake.candidate.ip) == selected_ip
                ):
                    yield record

        aggregates.append(
            _IpAggregate(
                ip=ip,
                record_count=count,
                is_known_vpn=is_known_vpn,
                records_factory=records_for_ip,
            )
        )
    return tuple(aggregates)


def _summarize_aggregate(aggregate: _IpAggregate) -> _IpSummary:
    """Verdichtet eine IP-Gruppe, bevor ihre Evidenzobjekte freigegeben werden."""

    return _IpSummary(
        ip=aggregate.ip,
        is_known_vpn=aggregate.is_known_vpn,
        row=_aggregate_row(aggregate),
        source_notes=_source_note_lines(aggregate.iter_records()),
    )


def _build_report_index(result: ScanResult) -> _ReportIndex:
    """Zaehlt IP-Gruppen und behaelt nur eine fest begrenzte PDF-Vorschau."""

    positive_ip_count = 0
    reportable_ip_count = 0
    vpn_ip_count = 0
    preview: list[_IpSummary] = []
    source_notes: list[str] = []
    seen_source_notes: set[str] = set()
    source_notes_truncated = False

    for aggregate in _iter_ip_aggregates(result):
        positive_ip_count += 1
        if aggregate.is_known_vpn:
            vpn_ip_count += 1
            continue

        reportable_ip_count += 1
        if len(preview) < MAX_SUMMARY_PDF_ROWS:
            preview.append(_summarize_aggregate(aggregate))
        for note in _source_note_lines(aggregate.iter_records()):
            if note in seen_source_notes:
                continue
            if len(source_notes) >= MAX_SUMMARY_SOURCE_NOTES:
                source_notes_truncated = True
                continue
            seen_source_notes.add(note)
            source_notes.append(note)

    return _ReportIndex(
        positive_ip_count=positive_ip_count,
        reportable_ip_count=reportable_ip_count,
        vpn_ip_count=vpn_ip_count,
        reportable_preview=tuple(preview),
        source_notes=tuple(source_notes),
        source_notes_truncated=source_notes_truncated,
    )


def _iter_ip_summaries(
    result: ScanResult,
    *,
    known_vpn: bool,
) -> Iterable[_IpSummary]:
    """Verdichtet beim Lesen jeweils nur die aktuelle IP-Gruppe."""

    for aggregate in _iter_ip_aggregates(result):
        if aggregate.is_known_vpn == known_vpn:
            yield _summarize_aggregate(aggregate)


def _canonical_ip(value: str) -> str:
    if "%" in value:
        raise ValueError("IP-Adressen mit Zonenkennung sind nicht zulaessig")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise ValueError(f"Ungueltige IP-Adresse in Evidenzdaten: {value!r}") from exc


def _ip_sort_key(value: str) -> tuple[int, bytes]:
    parsed = ipaddress.ip_address(value)
    return parsed.version, parsed.packed


def _record_sort_key(record: EvidenceRecord) -> tuple[datetime, int, str, str]:
    candidate = record.handshake.candidate
    return (
        _timestamp_as_datetime(record.handshake.attempted_at_utc),
        candidate.port,
        candidate.info_hash_hex,
        record.evidence_event_sha256,
    )


def _normalise_utc_timestamp(value: str) -> str:
    """Normalisiert einen ISO-8601-Zeitpunkt fuer reproduzierbare Ausgaben."""

    if not value or not value.strip():
        raise ValueError("Ein UTC-Erstellungszeitpunkt ist erforderlich")
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"Ungueltiger ISO-8601-Zeitpunkt: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"Zeitpunkt benoetigt einen eindeutigen UTC-Bezug: {value!r}")
    parsed = parsed.astimezone(UTC)
    timespec = "microseconds" if parsed.microsecond else "seconds"
    return parsed.isoformat(timespec=timespec).replace("+00:00", "Z")


def _safe_component(value: str, *, fallback: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")[:80]
    return safe or fallback


def _iter_staged_files(staging_dir: Path) -> Iterable[Path]:
    """Liest Staging-Dateien ohne eine mit der Dateizahl wachsende Pfadliste."""

    with os.scandir(staging_dir) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                raise RuntimeError(f"Unerwarteter Eintrag im Berichts-Staging: {entry.name}")
            yield Path(entry.path)


def _publish_staged_files(staging_dir: Path, output_dir: Path) -> int:
    """Veröffentlicht Staging-Dateien iteratorbasiert und liefert nur ihre Anzahl."""

    published_count = 0
    for source in _iter_staged_files(staging_dir):
        target = output_dir / source.name
        _set_private_mode(source, 0o600)
        os.replace(source, target)
        _set_private_mode(target, 0o600)
        published_count += 1
    return published_count


def _set_private_mode(path: Path, mode: int) -> None:
    """Erzwinge POSIX-Rechte; unter Windows bleibt die geerbte Benutzer-ACL massgeblich."""

    try:
        path.chmod(mode)
    except OSError:
        if os.name != "nt":
            raise


def _styles(toolkit: SimpleNamespace) -> SimpleNamespace:
    sample = toolkit.getSampleStyleSheet()
    sample["Title"].fontName = "Helvetica-Bold"
    sample["Title"].fontSize = 18
    sample["Title"].leading = 22
    sample["Title"].spaceAfter = 12
    sample["Heading1"].fontName = "Helvetica-Bold"
    sample["Heading1"].fontSize = 13
    sample["Heading1"].leading = 16
    sample["Heading1"].spaceBefore = 10
    sample["Heading1"].spaceAfter = 6
    sample["Heading2"].fontName = "Helvetica-Bold"
    sample["Heading2"].fontSize = 10
    sample["Heading2"].leading = 13
    sample["Heading2"].spaceBefore = 8
    sample["Heading2"].spaceAfter = 4
    sample["BodyText"].fontName = "Helvetica"
    sample["BodyText"].fontSize = 9
    sample["BodyText"].leading = 12
    sample["BodyText"].spaceAfter = 5
    sample.add(
        toolkit.ParagraphStyle(
            "SmallReportText",
            parent=sample["BodyText"],
            fontSize=7.5,
            leading=9.5,
            spaceAfter=0,
        )
    )
    sample.add(
        toolkit.ParagraphStyle(
            "EvidenceBox",
            parent=sample["BodyText"],
            backColor=toolkit.colors.HexColor("#EEF3F8"),
            borderColor=toolkit.colors.HexColor("#7890A8"),
            borderWidth=0.6,
            borderPadding=7,
            leading=12,
            spaceBefore=4,
            spaceAfter=9,
        )
    )
    sample.add(
        toolkit.ParagraphStyle(
            "CenteredSmall",
            parent=sample["SmallReportText"],
            alignment=toolkit.TA_CENTER,
        )
    )
    return sample


class _StreamingFlowables:
    """Listenähnlicher, lazy ReportLab-Puffer mit konstanter Vorhaltebreite."""

    def __init__(self, flowables: Iterable[Any]) -> None:
        self._iterator = iter(flowables)
        self._buffer: list[Any] = []
        self._exhausted = False
        self.peak_buffered = 0

    def _fill(self, minimum: int = 2) -> None:
        while not self._exhausted and len(self._buffer) < minimum:
            try:
                self._buffer.append(next(self._iterator))
            except StopIteration:
                self._exhausted = True
                break
        self.peak_buffered = max(self.peak_buffered, len(self._buffer))

    def __len__(self) -> int:
        self._fill()
        return len(self._buffer)

    def __getitem__(self, index: int | slice) -> Any:
        if isinstance(index, slice):
            if index.stop is None:
                raise TypeError("Offene Slices sind für Streaming-Flowables nicht erlaubt.")
            self._fill(max(0, index.stop))
            return self._buffer[index]
        if index >= 0:
            self._fill(index + 1)
        return self._buffer[index]

    def __setitem__(self, index: int | slice, value: Any) -> None:
        if isinstance(index, slice):
            if index.stop is None:
                raise TypeError("Offene Slices sind für Streaming-Flowables nicht erlaubt.")
            self._fill(max(0, index.stop))
            self._buffer[index] = value
        else:
            if index >= 0:
                self._fill(index + 1)
            self._buffer[index] = value
        self.peak_buffered = max(self.peak_buffered, len(self._buffer))

    def __delitem__(self, index: int | slice) -> None:
        if isinstance(index, slice):
            if index.stop is None:
                raise TypeError("Offene Slices sind für Streaming-Flowables nicht erlaubt.")
            self._fill(max(0, index.stop))
        elif index >= 0:
            self._fill(index + 1)
        del self._buffer[index]

    def insert(self, index: int, value: Any) -> None:
        if index >= 0:
            self._fill(index)
        self._buffer.insert(index, value)
        self.peak_buffered = max(self.peak_buffered, len(self._buffer))

    def __iter__(self) -> Iterator[Any]:
        while len(self):
            value = self[0]
            del self[0]
            yield value


def _build_pdf(
    path: Path,
    title: str,
    story: Iterable[Any],
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    """Baut ein reproduzierbares PDF mit Seitenkopf und -fuss."""

    margin = 15 * toolkit.mm
    document = toolkit.SimpleDocTemplate(
        str(path),
        pagesize=toolkit.A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=19 * toolkit.mm,
        bottomMargin=18 * toolkit.mm,
        pageCompression=0,
    )

    def canvas_maker(filename: str, **kwargs: Any) -> Any:
        kwargs["invariant"] = 1
        kwargs["pageCompression"] = 0
        return toolkit.Canvas(filename, **kwargs)

    def decorate_page(canvas: Any, doc: Any) -> None:
        width, height = toolkit.A4
        canvas.saveState()
        canvas.setTitle(title)
        canvas.setCreator("BitTorrent-Beobachter")
        canvas.setAuthor(config.reporter_name.strip() or "BitTorrent-Beobachter")
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(toolkit.colors.HexColor("#5B6670"))
        canvas.drawString(margin, height - 11 * toolkit.mm, title[:88])
        canvas.drawRightString(width - margin, 9 * toolkit.mm, f"Seite {doc.page}")
        canvas.drawString(margin, 9 * toolkit.mm, f"Erstellt: {generated_at_utc}")
        canvas.restoreState()

    flowables = story if isinstance(story, list) else _StreamingFlowables(story)
    document.build(
        flowables,
        onFirstPage=decorate_page,
        onLaterPages=decorate_page,
        canvasmaker=canvas_maker,
    )


def _failure_reason_text(reason: str) -> str:
    """Uebersetzt kompakte interne Kategorien fuer den menschenlesbaren Bericht."""

    labels = {
        "confirmation:not_confirmed": "Handshake nicht bestätigt",
        "availability:missing": "keine Verfügbarkeitsbeobachtung",
        "availability:no_piece": "keine Stückverfügbarkeit gemeldet",
        "availability:no_unchoke": "kein UNCHOKE empfangen",
    }
    if reason in labels:
        return labels[reason]
    prefix, separator, detail = reason.partition(":")
    if separator and prefix == "termination":
        return f"Beendigung: {detail}"
    if separator and prefix == "error":
        return f"Fehlerkategorie: {detail}"
    return reason


def _target_metrics_story(
    result: ScanResult,
    styles: Any,
    toolkit: SimpleNamespace,
) -> list[Any]:
    """Erzeugt fuer jedes Ziel eine vollstaendige, auch bei Nullwerten sichtbare Bilanz."""

    if not result.target_metrics:
        return [
            _paragraph(
                "Für diesen Lauf liegen keine zielbezogenen Abschlusszahlen vor.",
                styles["BodyText"],
                toolkit,
            )
        ]

    story: list[Any] = []
    for metric in result.target_metrics:
        failure_reasons = (
            " | ".join(
                f"{_failure_reason_text(reason)}: {count}"
                for reason, count in metric.failure_reasons
            )
            or "keine"
        )
        story.extend(
            [
                _paragraph(
                    f"{_escape_text(metric.target_label)} - {_escape_text(metric.info_hash_hex)}",
                    styles["Heading2"],
                    toolkit,
                    already_escaped=True,
                ),
                _key_value_table(
                    (
                        ("DHT-Anfragen gestartet", str(metric.dht_queries_started)),
                        ("DHT-Anfragen abgeschlossen", str(metric.dht_queries_completed)),
                        ("DHT-Anfragen fehlgeschlagen", str(metric.dht_queries_failed)),
                        (
                            "Tracker-Anfragen abgeschlossen",
                            str(metric.tracker_queries_completed),
                        ),
                        (
                            "Tracker-Anfragen fehlgeschlagen",
                            str(metric.tracker_queries_failed),
                        ),
                        ("Gefundene Kandidaten", str(metric.candidates_discovered)),
                        ("Direkt geprüfte Kandidaten", str(metric.candidates_checked)),
                        ("Verbindungsversuche", str(metric.verification_attempts)),
                        ("Bestätigte Handshakes", str(metric.confirmed_handshakes)),
                        (
                            "Gemeldete Stückverfügbarkeit",
                            str(metric.piece_availability_observed),
                        ),
                        ("Empfangene UNCHOKE-Signale", str(metric.unchoke_observed)),
                        ("Positive Gesamtbefunde", str(metric.positive_findings)),
                        ("Abschließende Fehlschläge", str(metric.terminal_failures)),
                        ("Fehlergründe", failure_reasons),
                    ),
                    styles,
                    toolkit,
                ),
            ]
        )
    return story


def _write_summary_pdf(
    path: Path,
    result: ScanResult,
    report_index: _ReportIndex,
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    styles = _styles(toolkit)
    reportable = report_index.reportable_preview
    story: list[Any] = [
        _paragraph("Technischer Laufbericht", styles["Title"], toolkit),
        _paragraph(
            "Zusammenfassung einer gezielten technischen Überprüfung der "
            "dokumentierten Infohashes im BitTorrent-Netzwerk. Dieser "
            "Bericht ist eine technische Dokumentation und keine Feststellung "
            "einer Straftat.",
            styles["BodyText"],
            toolkit,
        ),
        _key_value_table(
            (
                ("Lauf-ID", result.run_id),
                (
                    "Laufstatus",
                    "kontrolliert abgebrochen"
                    if result.cancelled
                    else ("abgeschlossen" if result.completed_at_utc else "läuft"),
                ),
                ("Beginn (UTC)", result.started_at_utc),
                ("Abschluss (UTC)", result.completed_at_utc or "nicht abgeschlossen"),
                ("Bericht erstellt (UTC)", generated_at_utc),
                ("Gefundene Kandidaten", str(result.total_candidate_count)),
                ("Direkt geprüfte Kandidaten", str(result.total_handshake_count)),
                ("Bestätigte Handshakes", str(result.confirmed_count)),
                ("IP-Adressen mit positivem Gesamtbefund", str(report_index.positive_ip_count)),
                ("Anlagen zu Strafanzeigen", str(report_index.reportable_ip_count)),
                ("Bekannte VPN-IP-Adressen", str(report_index.vpn_ip_count)),
            ),
            styles,
            toolkit,
        ),
        toolkit.Spacer(1, 6),
        _paragraph("Ergebnisse pro Infohash", styles["Heading1"], toolkit),
        *_target_metrics_story(result, styles, toolkit),
        _paragraph("Aussagegrenze", styles["Heading1"], toolkit),
        _limitations_paragraph(styles["EvidenceBox"], toolkit),
        _paragraph("Vorgehensweise", styles["Heading1"], toolkit),
        _paragraph(
            "Ein Kandidat wurde aus einer DHT-Antwort oder aus der Antwort "
            "eines konfigurierten UDP-Trackers übernommen. Danach wurde eine "
            "TCP-Verbindung aufgebaut und der BitTorrent-Handshake für "
            "den konfigurierten Infohash geprüft. Nach bestätigtem Handshake wird "
            "eine inhaltsfreie Verfügbarkeitsprüfung durchgeführt. Sie beobachtet "
            "nur Bitfield-/Have- und Choke-/Unchoke-Signale; Piece-, Datei- oder "
            "Metadaten werden weder angefordert noch geladen. Die protokollierten Hashes "
            "dienen der Integritätsprüfung der lokal erfassten Ereignisse; sie "
            "sind keine digitale Signatur und kein vertrauenswürdiger externer "
            "Zeitstempel. Der lokale Fingerabdruck einer DHT- oder "
            "UDP-Tracker-Antwort ist später nicht unabhängig reproduzierbar, "
            "weil das Rohpaket datensparsam "
            "nicht gespeichert wird.",
            styles["BodyText"],
            toolkit,
        ),
        _paragraph(
            "Übersicht der Anlagen (ohne VPN-Liste)",
            styles["Heading1"],
            toolkit,
        ),
    ]

    if reportable:
        table_rows: list[list[Any]] = [
            [
                _paragraph("IP-Adresse", styles["SmallReportText"], toolkit),
                _paragraph("Einordnung", styles["SmallReportText"], toolkit),
                _paragraph("Anzahl", styles["SmallReportText"], toolkit),
                _paragraph("Infohashes", styles["SmallReportText"], toolkit),
                _paragraph("Zeitraum UTC", styles["SmallReportText"], toolkit),
            ]
        ]
        for summary in reportable:
            row = summary.row
            table_rows.append(
                [
                    _paragraph(summary.ip, styles["SmallReportText"], toolkit),
                    _paragraph(row["vpn_status"], styles["SmallReportText"], toolkit),
                    _paragraph(
                        row["bestaetigte_handshakes"],
                        styles["CenteredSmall"],
                        toolkit,
                    ),
                    _paragraph(row["infohashes"], styles["SmallReportText"], toolkit),
                    _paragraph(
                        f"{row['erste_beobachtung_utc']} bis {row['letzte_beobachtung_utc']}",
                        styles["SmallReportText"],
                        toolkit,
                    ),
                ]
            )
        story.append(
            _data_table(
                table_rows,
                (82, 88, 42, 142, 157),
                toolkit,
                repeat_rows=1,
            )
        )
    else:
        story.append(
            _paragraph(
                "In diesem Lauf lagen keine bestätigten Nicht-VPN-Evidenzdatensätze "
                "für Anlagen vor. Bekannte VPN-Endpunkte stehen ausschließlich "
                "in der gesonderten VPN-Liste.",
                styles["BodyText"],
                toolkit,
            )
        )

    if report_index.reportable_ip_count > len(reportable):
        story.append(
            _paragraph(
                f"Die PDF-Vorschau zeigt die ersten {len(reportable)} von "
                f"{report_index.reportable_ip_count} Anlagen. Die CSV-Datei und "
                "die Einzelanlagen enthalten sämtliche positiven Nicht-VPN-Befunde.",
                styles["BodyText"],
                toolkit,
            )
        )

    source_notes = report_index.source_notes
    if report_index.source_notes_truncated:
        source_notes += ("Weitere Sachverhaltshinweise stehen in der vollständigen CSV-Datei.",)
    if source_notes:
        story.extend(
            [
                _paragraph(
                    "Hashgebundene Sachverhaltshinweise",
                    styles["Heading1"],
                    toolkit,
                ),
                _paragraph(
                    "Die folgenden Zuordnungen sind unbestätigte Nutzerangaben. "
                    "Das Programm hat den bezeichneten Inhalt nicht abgerufen "
                    "oder verifiziert.",
                    styles["BodyText"],
                    toolkit,
                ),
                _paragraph(
                    "<br/>".join(f"- {_escape_text(note)}" for note in source_notes),
                    styles["BodyText"],
                    toolkit,
                    already_escaped=True,
                ),
            ]
        )

    if result.notices:
        story.extend(
            [
                _paragraph(
                    "Technische Laufhinweise (kein Programmfehler)",
                    styles["Heading1"],
                    toolkit,
                ),
                _paragraph(
                    "Diese Hinweise dokumentieren die Erreichbarkeit während dieses "
                    "einzelnen Laufs. Sie sind kein Nachweis für Inhalt, Besitz, "
                    "Übertragung, Person oder Straftat.",
                    styles["BodyText"],
                    toolkit,
                ),
                _paragraph(
                    "<br/>".join(f"- {_escape_text(notice)}" for notice in sorted(result.notices)),
                    styles["BodyText"],
                    toolkit,
                    already_escaped=True,
                ),
            ]
        )

    if result.errors:
        story.extend(
            [
                _paragraph("Lauffehler und Warnungen", styles["Heading1"], toolkit),
                _paragraph(
                    "<br/>".join(f"- {_escape_text(error)}" for error in sorted(result.errors)),
                    styles["BodyText"],
                    toolkit,
                    already_escaped=True,
                ),
            ]
        )
    _append_legal_notes(story, config, styles, toolkit)
    _build_pdf(path, "Technischer Laufbericht", story, config, generated_at_utc, toolkit)


def _write_complaint_attachment_pdf(
    path: Path,
    result: ScanResult,
    aggregate: _IpAggregate,
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    """Schreibt alle IP-Befunde lazy, ohne sie als ReportLab-Story zu sammeln."""

    styles = _styles(toolkit)
    row = _aggregate_row(aggregate)
    project_hashes = _project_leak_hashes(aggregate)
    availability_overview = _availability_overview(aggregate)

    if project_hashes:
        core_finding = (
            "Anlass dieser Strafanzeige: Der positive technische Gesamtbefund "
            f"legt nahe, dass unter der IP-Adresse {aggregate.ip} mindestens Teile "
            "des mutmaßlich gestohlenen, als „AfD-Datenleak“ bezeichneten "
            "Datenbestands zum Download angeboten wurden. Der unter dieser "
            "IP-Adresse erreichbare BitTorrent-Client bestätigte hierfür einen "
            "der veröffentlichten Infohashes, meldete verfügbare Teile und gab "
            "mit UNCHOKE das Anfordern dieser Teile protokollseitig frei."
        )
    else:
        core_finding = (
            "Technischer Kernbefund: Der unter dieser IP-Adresse erreichbare "
            "BitTorrent-Client bestätigte den dokumentierten Infohash, meldete "
            "verfügbare Teile und gab mit UNCHOKE das Anfordern dieser Teile "
            "protokollseitig frei."
        )

    def iter_story() -> Iterator[Any]:
        yield _paragraph(
            "Technische Anlage zur Strafanzeige gegen Unbekannt",
            styles["Title"],
            toolkit,
        )
        yield _paragraph("1. Möglicher Tatgegenstand", styles["Heading1"], toolkit)
        if project_hashes:
            yield _paragraph(
                "Am 19. Oktober 2026 wurden auf der Internetseite "
                f"{PUBLISHED_SOURCE_URL} zwei BitTorrent-Links veröffentlicht. "
                "Die Seite beschreibt den damit bezeichneten Datenbestand als "
                "„AfD-Datenleak“ und gibt an, die Daten seien ohne Berechtigung "
                "von Servern bzw. Postfächern der AfD kopiert worden und würden "
                "über BitTorrent verbreitet. Als Umfang nennt die Seite:",
                styles["BodyText"],
                toolkit,
            )
            yield _paragraph(
                "<br/>".join(f"- {_escape_text(fact)}" for fact in PUBLISHED_DATASET_FACTS),
                styles["BodyText"],
                toolkit,
                already_escaped=True,
            )
            yield _paragraph(
                "Die Strafanzeige bittet um Prüfung eines möglichen "
                "Anfangsverdachts insbesondere hinsichtlich:",
                styles["BodyText"],
                toolkit,
            )
            yield _paragraph(
                "<br/>".join(f"- {_escape_text(point)}" for point in PROJECT_LEGAL_REVIEW_POINTS),
                styles["BodyText"],
                toolkit,
                already_escaped=True,
            )
        else:
            yield _paragraph(
                "Gegenstand der technischen Prüfung waren die in dieser Anlage "
                "aufgeführten, individuell vorgegebenen Infohashes.",
                styles["BodyText"],
                toolkit,
            )

        yield _paragraph(
            "2. Anzeige gegen Unbekannt - ermittelter BitTorrent-Endpunkt",
            styles["Heading1"],
            toolkit,
        )
        yield _paragraph(
            "Die Strafanzeige richtet sich gegen Unbekannt. Als technischer "
            "Ermittlungsansatz wurde der öffentlich erreichbare BitTorrent-Endpunkt "
            f"mit der IP-Adresse {aggregate.ip}, den nachfolgend aufgeführten "
            "Ports und den genauen Beobachtungszeiten dokumentiert.",
            styles["BodyText"],
            toolkit,
        )
        yield _paragraph(core_finding, styles["EvidenceBox"], toolkit)
        yield _key_value_table(
            (
                ("IP-Adresse", aggregate.ip),
                ("Infohashes", row["infohashes"]),
                ("Erste Beobachtung (UTC)", row["erste_beobachtung_utc"]),
                ("Letzte Beobachtung (UTC)", row["letzte_beobachtung_utc"]),
                ("Lauf-ID", result.run_id),
                ("Anlage erstellt (UTC)", generated_at_utc),
            ),
            styles,
            toolkit,
        )
        yield _paragraph("3. So wurde der Endpunkt gefunden", styles["Heading1"], toolkit)
        yield _paragraph(
            _discovery_method_statement(aggregate),
            styles["BodyText"],
            toolkit,
        )
        yield _paragraph("4. So wurde direkt geprüft", styles["Heading1"], toolkit)
        yield _paragraph(
            "Anschließend stellte das Prüfprogramm eine direkte TCP-Verbindung "
            "zu den aufgeführten BitTorrent-Endpunkten her und führte den "
            "BitTorrent-Handshake für den jeweiligen Infohash aus.",
            styles["BodyText"],
            toolkit,
        )
        yield _paragraph(
            _escape_text(availability_overview),
            styles["EvidenceBox"],
            toolkit,
            already_escaped=True,
        )
        yield _paragraph(
            "Quellcode und Beschreibung der eingesetzten Messmethode sind unter "
            f"{PROJECT_REPOSITORY_URL} öffentlich einsehbar.",
            styles["BodyText"],
            toolkit,
        )
        yield _paragraph("Technische Zusammenfassung", styles["Heading1"], toolkit)
        yield _key_value_table(
            (
                ("IP-Adresse", aggregate.ip),
                ("Beobachtete Ports", row["ports"]),
                ("Bestätigte Handshakes", row["bestaetigte_handshakes"]),
                ("Zielbezeichnungen", row["zielbezeichnungen"]),
                ("Infohashes", row["infohashes"]),
                (
                    "Vom Nutzer angegebene Sachverhaltshinweise",
                    row["quellen_sachverhaltshinweise"],
                ),
                ("VPN-Einordnung", row["vpn_status"]),
            ),
            styles,
            toolkit,
        )
        yield _paragraph(
            "Öffentliche Routing-/Registry-Angaben",
            styles["Heading1"],
            toolkit,
        )
        yield _paragraph(
            "Die vollständigen Angaben für jeden Befund stehen in den "
            "technischen Einzelbeobachtungen.",
            styles["BodyText"],
            toolkit,
        )
        yield _key_value_table(
            (
                ("Präfix(e)", row["netzpraefixe"]),
                ("ASN", row["asns"]),
                (
                    "Öffentliche Routing-/Netzbetreiberangabe",
                    row["routing_netzbetreiberangaben"],
                ),
                ("RDAP-Name", row["rdap_namen"]),
                ("RDAP-Handle", row["rdap_handles"]),
                ("Registrierungsland des Netzes", row["laender"]),
                ("Öffentlicher Abuse-Kontakt", row["abuse_kontakte"]),
                (
                    "Angefragte bzw. weitergeleitete Quellen",
                    row["angefragte_bzw_weitergeleitete_quellen"],
                ),
                (
                    "Netzangaben zusammengestellt (UTC)",
                    row["netzangaben_zusammengestellt_utc"],
                ),
                (
                    "Quellenspezifischer Abrufzeitpunkt (UTC)",
                    row["netzregistrierung_quellen_abruf_utc"],
                ),
                ("Aus lokalem Cache", row["netzregistrierung_cache_quellen"]),
                ("Abruffehler", row["netzregistrierungs_fehler"]),
            ),
            styles,
            toolkit,
        )
        yield _paragraph("Technische Einzelbeobachtungen", styles["Heading1"], toolkit)

        for index, record in enumerate(aggregate.iter_records(), start=1):
            candidate = record.handshake.candidate
            handshake = record.handshake
            enrichment = record.enrichment
            vpn = record.vpn
            yield _paragraph(f"Beobachtung {index}", styles["Heading2"], toolkit)
            yield _key_value_table(
                (
                    ("Zielbezeichnung", candidate.target_label),
                    ("Infohash", candidate.info_hash_hex),
                    (
                        "Vom Nutzer angegebener Sachverhaltshinweis",
                        candidate.source_note or "nicht angegeben",
                    ),
                    ("Endpunkt", _format_endpoint(aggregate.ip, candidate.port)),
                    *_discovery_detail_rows(candidate),
                    ("Handshake begonnen (UTC)", handshake.attempted_at_utc),
                    (
                        "Handshake abgeschlossen (UTC)",
                        handshake.completed_at_utc or "nicht angegeben",
                    ),
                    ("Remote Peer-ID", handshake.remote_peer_id_hex or "nicht angegeben"),
                    ("Reserved Bits", handshake.reserved_bits_hex or "nicht angegeben"),
                    (
                        "Lokaler Messendpunkt",
                        _format_endpoint(handshake.local_ip, handshake.local_port),
                    ),
                    ("Gesendete Bytes", str(handshake.bytes_sent)),
                    ("Empfangene Bytes", str(handshake.bytes_received)),
                    *_availability_detail_rows(record),
                    ("Netzpräfix", enrichment.prefix or "nicht angegeben"),
                    (
                        "ASN",
                        " | ".join(str(asn) for asn in enrichment.asns) or "nicht angegeben",
                    ),
                    ("Routing-/Netzbetreiberangabe", enrichment.holder or "nicht angegeben"),
                    ("RDAP-Name", enrichment.rdap_name or "nicht angegeben"),
                    ("RDAP-Handle", enrichment.rdap_handle or "nicht angegeben"),
                    ("Registrierungsland", enrichment.country or "nicht angegeben"),
                    ("Öffentlicher Abuse-Kontakt", enrichment.abuse_email or "nicht angegeben"),
                    (
                        "Angefragte bzw. weitergeleitete Quellen",
                        " | ".join(enrichment.source_urls) or "nicht angegeben",
                    ),
                    ("Netzangaben zusammengestellt (UTC)", enrichment.enriched_at_utc),
                    (
                        "Quellenspezifischer Abrufzeitpunkt (UTC)",
                        " | ".join(
                            f"{source}: {timestamp}"
                            for source, timestamp in enrichment.source_fetched_at_utc
                        )
                        or "nicht angegeben",
                    ),
                    (
                        "Aus lokalem Cache",
                        " | ".join(enrichment.cached_sources) or "nicht angegeben",
                    ),
                    ("Abruffehler", enrichment.error or "nicht angegeben"),
                    (
                        "VPN-Einordnung",
                        "bekannter VPN"
                        if vpn.status == "known_vpn"
                        else "kein bekannter VPN-Treffer",
                    ),
                    ("VPN-Anbieter", vpn.provider or "nicht angegeben"),
                    ("VPN-Begründung", vpn.reason or "nicht angegeben"),
                    ("VPN-Quelle", _vpn_source_text(vpn.source) or "nicht angegeben"),
                    ("SHA-256 des Evidenzereignisses", record.evidence_event_sha256),
                ),
                styles,
                toolkit,
            )

        legal_story: list[Any] = []
        _append_legal_notes(legal_story, config, styles, toolkit)
        yield from legal_story

    _build_pdf(
        path,
        f"Technische Anlage zur Strafanzeige - {aggregate.ip}",
        iter_story(),
        config,
        generated_at_utc,
        toolkit,
    )


def _write_vpn_pdf(
    path: Path,
    result: ScanResult,
    vpn_only: Iterable[_IpSummary],
    vpn_count: int,
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    """Schreibt die vollständige VPN-Liste zeilenweise direkt auf PDF-Seiten."""

    width, height = toolkit.A4
    margin = 15 * toolkit.mm
    bottom = 18 * toolkit.mm
    title = "Liste bekannter VPN-Endpunkte"
    canvas = toolkit.Canvas(
        str(path),
        pagesize=toolkit.A4,
        invariant=1,
        pageCompression=0,
    )
    canvas.setTitle(title)
    canvas.setCreator("BitTorrent-Beobachter")
    canvas.setAuthor(config.reporter_name.strip() or "BitTorrent-Beobachter")
    page = 0
    y = 0.0

    def start_page() -> None:
        nonlocal page, y
        if page:
            canvas.showPage()
        page += 1
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(toolkit.colors.HexColor("#5B6670"))
        canvas.drawString(margin, height - 11 * toolkit.mm, title)
        canvas.drawRightString(width - margin, 9 * toolkit.mm, f"Seite {page}")
        canvas.drawString(margin, 9 * toolkit.mm, f"Erstellt: {generated_at_utc}")
        canvas.setFillColor(toolkit.colors.black)
        y = height - 20 * toolkit.mm

    def draw_wrapped(text: str, *, bold: bool = False, size: int = 9) -> None:
        nonlocal y
        cleaned = " ".join(text.split())
        lines = textwrap.wrap(
            cleaned,
            width=105,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        leading = size + 3
        for line in lines:
            if y < bottom + leading:
                start_page()
            canvas.setFont("Helvetica-Bold" if bold else "Helvetica", size)
            canvas.drawString(margin, y, line)
            y -= leading
        y -= 3

    def table_header() -> None:
        nonlocal y
        if y < bottom + 24:
            start_page()
        canvas.setFillColor(toolkit.colors.HexColor("#EEF3F8"))
        canvas.rect(margin, y - 3, width - (2 * margin), 14, fill=1, stroke=0)
        canvas.setFillColor(toolkit.colors.black)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawString(margin + 3, y, "IP-Adresse")
        canvas.drawString(margin + 153, y, "Anbieter")
        canvas.drawString(margin + 283, y, "Grund / Quelle")
        y -= 17

    def cell(value: str, limit: int) -> str:
        cleaned = " ".join(value.split()) or "nicht angegeben"
        if len(cleaned) <= limit:
            return cleaned
        return f"{cleaned[: limit - 1]}…"

    start_page()
    canvas.setFont("Helvetica-Bold", 18)
    canvas.drawString(margin, y, title)
    y -= 27
    draw_wrapped(
        "Diese separate Liste enthält IP-Adressen, für die mindestens eine "
        "konservative Klassifikation als bekannter VPN-Endpunkt vorliegt. Für "
        "diese Einträge werden keine Einzelanlagen und keine E-Mail-Dateien erzeugt."
    )
    draw_wrapped(f"Lauf-ID: {result.run_id}")
    draw_wrapped(f"Bericht erstellt (UTC): {generated_at_utc}")
    draw_wrapped(f"Anzahl IP-Adressen: {vpn_count}")
    draw_wrapped("Aussagegrenze", bold=True, size=13)
    for limitation in EVIDENCE_LIMITATIONS:
        draw_wrapped(f"- {limitation}")

    written = 0
    if vpn_count:
        draw_wrapped("Bekannte VPN-Endpunkte", bold=True, size=13)
        table_header()
        for summary in vpn_only:
            if y < bottom + 14:
                start_page()
                table_header()
            row = summary.row
            reason_source = (
                " | ".join(
                    value
                    for value in (row["vpn_begruendung"], row["vpn_quellen"])
                    if value and value != "nicht angegeben"
                )
                or "nicht angegeben"
            )
            canvas.setFont("Helvetica", 7)
            canvas.drawString(margin + 3, y, cell(summary.ip, 45))
            canvas.drawString(margin + 153, y, cell(row["vpn_anbieter"], 34))
            canvas.drawString(margin + 283, y, cell(reason_source, 62))
            y -= 12
            written += 1
    else:
        draw_wrapped("Keine als bekannter VPN klassifizierte IP-Adresse vorhanden.")

    if config.legal_notes:
        draw_wrapped("Zusätzliche Prüfpunkte", bold=True, size=13)
        for note in config.legal_notes:
            if note.strip():
                draw_wrapped(f"- {note}")

    canvas.save()
    _set_private_mode(path, 0o600)
    if written != vpn_count:
        raise ValueError(
            "VPN-Laufindex und gestreamte VPN-Berichtsdaten stimmen nicht überein: "
            f"{vpn_count} erwartet, {written} geschrieben."
        )


def _paragraph(
    text: object,
    style: Any,
    toolkit: SimpleNamespace,
    *,
    already_escaped: bool = False,
) -> Any:
    rendered = str(text) if already_escaped else _escape_text(text)
    return toolkit.Paragraph(rendered.replace("\n", "<br/>"), style)


def _escape_text(value: object) -> str:
    return html.escape(str(value), quote=True)


def _limitations_paragraph(style: Any, toolkit: SimpleNamespace) -> Any:
    content = "<br/>".join(
        f"{index}. {_escape_text(text)}" for index, text in enumerate(EVIDENCE_LIMITATIONS, start=1)
    )
    return _paragraph(content, style, toolkit, already_escaped=True)


def _key_value_table(
    rows: Iterable[tuple[str, object]],
    styles: Any,
    toolkit: SimpleNamespace,
) -> Any:
    rendered_rows = [
        [
            _paragraph(label, styles["SmallReportText"], toolkit),
            _paragraph(value, styles["SmallReportText"], toolkit),
        ]
        for label, value in rows
    ]
    table = toolkit.Table(
        rendered_rows,
        colWidths=(132, 379),
        hAlign="LEFT",
        splitByRow=1,
        splitInRow=1,
    )
    table.setStyle(
        toolkit.TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), toolkit.colors.HexColor("#F1F3F5")),
                ("GRID", (0, 0), (-1, -1), 0.35, toolkit.colors.HexColor("#C7CDD3")),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _data_table(
    rows: list[list[Any]],
    widths: tuple[int, ...],
    toolkit: SimpleNamespace,
    *,
    repeat_rows: int,
) -> Any:
    table = toolkit.LongTable(
        rows,
        colWidths=widths,
        repeatRows=repeat_rows,
        hAlign="LEFT",
        splitByRow=1,
        splitInRow=1,
    )
    table.setStyle(
        toolkit.TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), toolkit.colors.HexColor("#DCE6F0")),
                ("GRID", (0, 0), (-1, -1), 0.35, toolkit.colors.HexColor("#AAB4BE")),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _append_legal_notes(
    story: list[Any],
    config: ReportConfig,
    styles: Any,
    toolkit: SimpleNamespace,
) -> None:
    if not config.legal_notes:
        return
    story.append(
        _paragraph(
            "Vom meldenden Nutzer angegebene Sachverhalts- und rechtliche Prüfhinweise",
            styles["Heading1"],
            toolkit,
        )
    )
    story.append(
        _paragraph(
            "Diese Angaben wurden durch das Programm weder inhaltlich noch rechtlich bewertet. "
            "Die Einordnung bleibt der zuständigen Behörde vorbehalten.",
            styles["BodyText"],
            toolkit,
        )
    )
    notes = "<br/>".join(f"- {_escape_text(note)}" for note in config.legal_notes if note.strip())
    if notes:
        story.append(_paragraph(notes, styles["BodyText"], toolkit, already_escaped=True))


def _format_endpoint(ip: str | None, port: int | None) -> str:
    if not ip and port is None:
        return "nicht angegeben"
    if ip and port is not None:
        if ":" in ip:
            return f"[{ip}]:{port}"
        return f"{ip}:{port}"
    return ip or f"Port {port}"


def _vpn_source_text(source: str | None) -> str | None:
    """Uebersetze interne Klassifikationscodes fuer die Laienausgabe."""

    if source == "configured_cidr":
        return "lokal konfigurierte VPN-IP-Liste"
    if source and source.startswith("configured_exact_marker:"):
        fields = source.partition(":")[2].split(",")
        labels = {
            "holder": "Routing-Netzbetreiberangabe",
            "rdap_name": "RDAP-Netzname",
        }
        matched = ", ".join(labels.get(field, field) for field in fields if field)
        return "lokal konfigurierter exakter VPN-Anbietername" + (
            f" ({matched})" if matched else ""
        )
    return source


def _source_note_lines(
    records: Iterable[EvidenceRecord],
    *,
    limit: int = MAX_SUMMARY_SOURCE_NOTES,
) -> tuple[str, ...]:
    """Bindet eine begrenzte Summary an Infohash; Details bleiben recordweise erhalten."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit muss eine positive Ganzzahl sein.")
    lines: list[str] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        candidate = record.handshake.candidate
        note = " ".join(candidate.source_note.split())
        if not note:
            continue
        key = (candidate.info_hash_hex, note.casefold())
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"Unbestätigte Nutzerangabe zu {candidate.target_label} "
            f"(Infohash {candidate.info_hash_hex}): {note}"
        )
        if len(lines) == limit:
            break
    return tuple(lines)


class _CompactValues:
    """Haelt nur wenige Summary-Werte; vollständige Werte stehen in Detailzeilen."""

    def __init__(self, *, maximum: int = 2) -> None:
        if maximum < 1:
            raise ValueError("maximum muss positiv sein.")
        self.maximum = maximum
        self.values: set[str] = set()
        self.overflow = False

    def add(self, value: object | None) -> None:
        if value is None:
            return
        cleaned = str(value).strip()
        if not cleaned or cleaned in self.values:
            return
        if len(self.values) < self.maximum:
            self.values.add(cleaned)
        else:
            self.overflow = True

    def render(self) -> str:
        rendered = " | ".join(sorted(self.values))
        if self.overflow:
            suffix = "weitere Werte vollständig in CSV und technischen Einzelbeobachtungen"
            return f"{rendered} | {suffix}" if rendered else suffix
        return rendered or "nicht angegeben"


def _record_timestamps(record: EvidenceRecord) -> Iterator[str]:
    handshake = record.handshake
    observation = handshake.availability
    for timestamp in (
        handshake.candidate.discovered_at_utc,
        handshake.attempted_at_utc,
        handshake.completed_at_utc,
        observation.started_at_utc if observation is not None else None,
        observation.ended_at_utc if observation is not None else None,
    ):
        if timestamp:
            yield timestamp


def _aggregate_row(aggregate: _IpAggregate) -> dict[str, str]:
    """Erstellt eine konstante Summary; vollständige Werte bleiben in Detailzeilen."""

    ports = _CompactValues()
    target_labels = _CompactValues()
    info_hashes = _CompactValues()
    source_notes = _CompactValues()
    discovery_sources = _CompactValues()
    first_seen: tuple[datetime, str] | None = None
    last_seen: tuple[datetime, str] | None = None
    bytes_sent = 0
    bytes_received = 0
    representative: EvidenceRecord | None = None

    for record in aggregate.iter_records():
        if representative is None or (
            aggregate.is_known_vpn
            and representative.vpn.status != "known_vpn"
            and record.vpn.status == "known_vpn"
        ):
            representative = record
        candidate = record.handshake.candidate
        ports.add(candidate.port)
        target_labels.add(candidate.target_label)
        info_hashes.add(candidate.info_hash_hex)
        discovery_sources.add(_discovery_source_label(candidate))
        note = " ".join(candidate.source_note.split())
        if note:
            source_notes.add(
                f"Unbestätigte Nutzerangabe zu {candidate.target_label} "
                f"(Infohash {candidate.info_hash_hex}): {note}"
            )
        bytes_sent += record.handshake.bytes_sent
        bytes_received += record.handshake.bytes_received
        for timestamp in _record_timestamps(record):
            parsed = _timestamp_as_datetime(timestamp)
            if first_seen is None or parsed < first_seen[0]:
                first_seen = (parsed, timestamp)
            if last_seen is None or parsed > last_seen[0]:
                last_seen = (parsed, timestamp)

    if representative is None:
        raise ValueError(f"IP-Aggregat {aggregate.ip} ist leer.")
    if aggregate.record_count == 1:
        return _record_row(representative, ip_is_known_vpn=aggregate.is_known_vpn)
    enrichment = representative.enrichment
    vpn = representative.vpn
    return {
        "ip": aggregate.ip,
        "ports": ports.render(),
        "zielbezeichnungen": target_labels.render(),
        "infohashes": info_hashes.render(),
        "quellen_sachverhaltshinweise": source_notes.render(),
        "erste_beobachtung_utc": first_seen[1] if first_seen else "nicht angegeben",
        "letzte_beobachtung_utc": last_seen[1] if last_seen else "nicht angegeben",
        "bestaetigte_handshakes": str(aggregate.record_count),
        "fundquellen": discovery_sources.render(),
        "lokaler_fundantwort_fingerabdruck_sha256": (
            "vollständig in CSV und technischen Einzelbeobachtungen"
        ),
        "beweisereignis_sha256": "vollständig in CSV und technischen Einzelbeobachtungen",
        "remote_peer_ids": "vollständig in CSV und technischen Einzelbeobachtungen",
        "bytes_gesendet_summe": str(bytes_sent),
        "bytes_empfangen_summe": str(bytes_received),
        "netzpraefixe": enrichment.prefix or "nicht angegeben",
        "asns": " | ".join(str(asn) for asn in enrichment.asns) or "nicht angegeben",
        "routing_netzbetreiberangaben": enrichment.holder or "nicht angegeben",
        "rdap_namen": enrichment.rdap_name or "nicht angegeben",
        "rdap_handles": enrichment.rdap_handle or "nicht angegeben",
        "laender": enrichment.country or "nicht angegeben",
        "abuse_kontakte": enrichment.abuse_email or "nicht angegeben",
        "vpn_status": ("bekannter VPN" if aggregate.is_known_vpn else "kein bekannter VPN-Treffer"),
        "vpn_anbieter": vpn.provider or "nicht angegeben",
        "vpn_begruendung": vpn.reason or "nicht angegeben",
        "vpn_quellen": _vpn_source_text(vpn.source) or "nicht angegeben",
        "angefragte_bzw_weitergeleitete_quellen": (
            "vollständig in CSV und technischen Einzelbeobachtungen"
        ),
        "netzangaben_zusammengestellt_utc": enrichment.enriched_at_utc,
        "netzregistrierung_quellen_abruf_utc": (
            "vollständig in CSV und technischen Einzelbeobachtungen"
        ),
        "netzregistrierung_cache_quellen": (
            " | ".join(enrichment.cached_sources) or "nicht angegeben"
        ),
        "netzregistrierungs_fehler": enrichment.error or "nicht angegeben",
        "aussagegrenze": " ".join(EVIDENCE_LIMITATIONS),
    }


def _record_row(record: EvidenceRecord, *, ip_is_known_vpn: bool) -> dict[str, str]:
    """Formatiert genau einen vollständigen positiven Befund als CSV-Zeile."""

    candidate = record.handshake.candidate
    enrichment = record.enrichment
    vpn = record.vpn
    timestamps = sorted(_record_timestamps(record), key=_timestamp_as_datetime)
    source_note = " ".join(candidate.source_note.split())
    return {
        "ip": _canonical_ip(candidate.ip),
        "ports": str(candidate.port),
        "zielbezeichnungen": candidate.target_label,
        "infohashes": candidate.info_hash_hex,
        "quellen_sachverhaltshinweise": (
            f"Unbestätigte Nutzerangabe zu {candidate.target_label} "
            f"(Infohash {candidate.info_hash_hex}): {source_note}"
            if source_note
            else "nicht angegeben"
        ),
        "erste_beobachtung_utc": timestamps[0] if timestamps else "nicht angegeben",
        "letzte_beobachtung_utc": timestamps[-1] if timestamps else "nicht angegeben",
        "bestaetigte_handshakes": "1",
        "fundquellen": _discovery_source_label(candidate),
        "lokaler_fundantwort_fingerabdruck_sha256": candidate.response_sha256,
        "beweisereignis_sha256": record.evidence_event_sha256,
        "remote_peer_ids": record.handshake.remote_peer_id_hex or "nicht angegeben",
        "bytes_gesendet_summe": str(record.handshake.bytes_sent),
        "bytes_empfangen_summe": str(record.handshake.bytes_received),
        "netzpraefixe": enrichment.prefix or "nicht angegeben",
        "asns": " | ".join(str(asn) for asn in enrichment.asns) or "nicht angegeben",
        "routing_netzbetreiberangaben": enrichment.holder or "nicht angegeben",
        "rdap_namen": enrichment.rdap_name or "nicht angegeben",
        "rdap_handles": enrichment.rdap_handle or "nicht angegeben",
        "laender": enrichment.country or "nicht angegeben",
        "abuse_kontakte": enrichment.abuse_email or "nicht angegeben",
        "vpn_status": "bekannter VPN" if ip_is_known_vpn else "kein bekannter VPN-Treffer",
        "vpn_anbieter": vpn.provider or "nicht angegeben",
        "vpn_begruendung": vpn.reason or "nicht angegeben",
        "vpn_quellen": _vpn_source_text(vpn.source) or "nicht angegeben",
        "angefragte_bzw_weitergeleitete_quellen": (
            " | ".join(enrichment.source_urls) or "nicht angegeben"
        ),
        "netzangaben_zusammengestellt_utc": enrichment.enriched_at_utc,
        "netzregistrierung_quellen_abruf_utc": (
            " | ".join(
                f"{source}: {timestamp}" for source, timestamp in enrichment.source_fetched_at_utc
            )
            or "nicht angegeben"
        ),
        "netzregistrierung_cache_quellen": (
            " | ".join(enrichment.cached_sources) or "nicht angegeben"
        ),
        "netzregistrierungs_fehler": enrichment.error or "nicht angegeben",
        "aussagegrenze": " ".join(EVIDENCE_LIMITATIONS),
    }


def _iter_csv_rows(
    result: ScanResult,
    *,
    known_vpn: bool,
) -> Iterator[dict[str, str]]:
    """Liefert Nicht-VPN-Befunde einzeln und bekannte VPN-IP-Adressen einmal."""

    for aggregate in _iter_ip_aggregates(result):
        if aggregate.is_known_vpn != known_vpn:
            continue
        if known_vpn:
            for record in aggregate.iter_records():
                if record.vpn.status == "known_vpn":
                    yield _record_row(record, ip_is_known_vpn=True)
                    break
            continue
        for record in aggregate.iter_records():
            yield _record_row(record, ip_is_known_vpn=False)


def _write_csv(path: Path, rows: Iterable[dict[str, str]]) -> None:
    """Schreibt vollständige Beobachtungen recordweise in die Staging-Datei."""

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_FIELDNAMES,
            delimiter=";",
            lineterminator="\n",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_safe(row[key]) for key in CSV_FIELDNAMES})
    _set_private_mode(path, 0o600)


def _write_vpn_csv(path: Path, rows: Iterable[dict[str, str]]) -> None:
    """Schreibt jede bekannte VPN-IP einmal in die separate Minimalliste."""

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=VPN_CSV_FIELDNAMES,
            delimiter=";",
            lineterminator="\n",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_safe(row[key]) for key in VPN_CSV_FIELDNAMES})
    _set_private_mode(path, 0o600)


def _csv_safe(value: str) -> str:
    """Verhindert Formelausfuehrung beim Oeffnen externer Texte in Tabellenkalkulationen."""

    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _write_mime_headers(
    handle: Any,
    message: EmailMessage,
    email_policy: Any,
) -> None:
    """Schreibt nur den Headerblock eines kleinen MIME-Objekts."""

    serialized = message.as_bytes(policy=email_policy)
    header_block, separator, _payload = serialized.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("MIME-Header konnten nicht serialisiert werden.")
    handle.write(header_block)
    handle.write(b"\r\n\r\n")


def _write_base64_chunks(handle: Any, chunks: Iterable[bytes]) -> None:
    """Kodiert einen Bytestrom in RFC-konforme 76-Zeichen-Zeilen."""

    pending = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("MIME-Quelldaten müssen Bytes sein.")
        pending.extend(chunk)
        while len(pending) >= 57:
            handle.write(base64.b64encode(pending[:57]))
            handle.write(b"\r\n")
            del pending[:57]
    if pending:
        handle.write(base64.b64encode(pending))
        handle.write(b"\r\n")


def _iter_file_chunks(path: Path, *, chunk_size: int = 57 * 128) -> Iterator[bytes]:
    """Liest eine Anlage in kleinen Binaerpaketen statt per ``read_bytes``."""

    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
        raise ValueError("chunk_size muss eine positive Ganzzahl sein.")
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            yield chunk


def _write_complaint_email(
    path: Path,
    result: ScanResult,
    aggregate: _IpAggregate,
    config: ReportConfig,
    generated_at_utc: str,
    attachment_pdf: Path,
) -> None:
    """Schreibt eine versandfertige EML und streamt die PDF-Anlage."""

    email_policy = SMTP.clone(max_line_length=998)
    message = EmailMessage(policy=email_policy)
    project_hashes = _project_leak_hashes(aggregate)
    if project_hashes:
        subject = (
            "Strafanzeige gegen Unbekannt - Verdacht der Verbreitung von 281 GB "
            f"mutmaßlich unbefugt kopierter AfD-Daten - IP {aggregate.ip}"
        )
    else:
        subject = f"Strafanzeige gegen Unbekannt - BitTorrent-Endpunkt {aggregate.ip}"
    message["Subject"] = subject
    message["Date"] = format_datetime(_timestamp_as_datetime(generated_at_utc), usegmt=True)
    message["X-Unsent"] = "1"
    message["X-Report-Run-ID"] = _single_line(result.run_id, "run_id")

    if config.reporter_email:
        message["From"] = Address(
            display_name=config.reporter_name.strip(),
            addr_spec=config.reporter_email.strip(),
        )
    if config.recipient_email:
        message["To"] = Address(
            display_name=config.recipient_name.strip(),
            addr_spec=config.recipient_email.strip(),
        )

    row = _aggregate_row(aggregate)
    direct_check = _availability_overview(aggregate)
    additional_legal_text = ""
    if config.legal_notes:
        additional_legal_text = (
            "\n\nZusätzlich wird um Prüfung folgender angegebener Hinweise gebeten:\n"
            + "\n".join(f"- {note}" for note in config.legal_notes if note.strip())
        )

    if project_hashes:
        published_facts = "\n".join(f"- {fact}" for fact in PUBLISHED_DATASET_FACTS)
        legal_points = "\n".join(f"- {point}" for point in PROJECT_LEGAL_REVIEW_POINTS)
        original_magnets = "\n".join(f"- {magnet}" for magnet in PROJECT_ORIGINAL_MAGNET_LINKS)
        possible_act = (
            "Hiermit erstatte ich Strafanzeige gegen Unbekannt.\n\n"
            "Am 19. Oktober 2026 wurden auf der Internetseite "
            f"{PUBLISHED_SOURCE_URL} zwei BitTorrent-Links veröffentlicht:\n"
            f"{original_magnets}\n\n"
            "Nach der öffentlichen Beschreibung sollen die Daten ohne Berechtigung "
            "von Servern bzw. Postfächern der AfD kopiert worden sein und nun über "
            "BitTorrent verbreitet werden. BitTorrent ist ein Internet-Tauschsystem: "
            "Beteiligte Computer können Daten empfangen und vorhandene Teile "
            "gleichzeitig anderen Nutzern zum Abruf anbieten. Die veröffentlichende "
            "Seite beziffert das dort als sogenannten AfD-Datenleak beschriebene "
            "Material wie folgt:\n"
            f"{published_facts}\n\n"
            "Bitte prüfen Sie insbesondere folgende Straftatbestände:\n"
            f"{legal_points}"
        )
    else:
        possible_act = (
            "Hiermit erstatte ich Strafanzeige gegen Unbekannt. Der überwachte "
            "Infohash wurde individuell zur technischen Prüfung vorgegeben. Das "
            "Programm ordnet ihm keinen bestimmten Inhalt zu. Eine rechtliche "
            "Bewertung setzt deshalb die behördliche Klärung des tatsächlichen "
            "Inhalts voraus."
        )

    if project_hashes:
        ip_finding = (
            "Bei der gezielten Überprüfung wurde die öffentliche IP-Adresse "
            f"{aggregate.ip} als BitTorrent-Endpunkt ermittelt. Der Endpunkt "
            "bestätigte die überwachte eindeutige digitale Kennung (Infohash). "
            "Unter dieser IP wurden nach dem dokumentierten BitTorrent-Protokollbefund "
            "Teile des mutmaßlich rechtswidrig entwendeten Datenbestands \N{EN DASH} "
            "möglicherweise auch der vollständige Bestand \N{EN DASH} zum Download angeboten."
        )
    else:
        ip_finding = (
            "Bei der gezielten Überprüfung der dokumentierten Infohashes wurde die "
            f"öffentliche IP-Adresse {aggregate.ip} als BitTorrent-Endpunkt ermittelt. "
            "Der Endpunkt bestätigte die überwachte eindeutige digitale Kennung "
            "(Infohash)."
        )

    body = (
        "Sehr geehrte Damen und Herren,\n\n"
        "1. Gegenstand der Strafanzeige\n"
        f"{possible_act}"
        f"{additional_legal_text}\n\n"
        "2. Ermittlung der IP-Adresse\n"
        f"{ip_finding} Beobachtungszeitraum (UTC): "
        f"{row['erste_beobachtung_utc']} bis {row['letzte_beobachtung_utc']}.\n\n"
        "3. Direkte Überprüfung des BitTorrent-Clients\n"
        f"{direct_check}\n\n"
        "4. Technischer Beleg\n"
        "Die technischen Einzelheiten stehen in der angehängten PDF-Datei "
        f"{attachment_pdf.name}. Quellcode und Beschreibung der Messmethode sind "
        f"unter {PROJECT_REPOSITORY_URL} öffentlich einsehbar.\n\n"
        "Ich bitte um Aufnahme der Ermittlungen gegen Unbekannt, um zeitnahe "
        "Sicherung der zum genauen Beobachtungszeitpunkt verfügbaren Anschlussdaten "
        "und um Ermittlung der verantwortlichen Person. Bitte bestätigen Sie den "
        "Eingang und teilen Sie mir die Vorgangsnummer oder das Aktenzeichen mit.\n\n"
        "Mit freundlichen Grüßen"
        + (f"\n{config.reporter_name.strip()}" if config.reporter_name.strip() else "")
        + "\n"
    )

    boundary_seed = hashlib.sha256(
        f"{result.run_id}\0{aggregate.ip}\0{generated_at_utc}".encode()
    ).hexdigest()[:32]
    boundary = f"===============bittorrent-{boundary_seed}=="
    message["MIME-Version"] = "1.0"
    message["Content-Type"] = "multipart/mixed"
    message.set_boundary(boundary)

    text_headers = EmailMessage(policy=email_policy)
    text_headers["Content-Type"] = 'text/plain; charset="utf-8"'
    text_headers["Content-Transfer-Encoding"] = "base64"

    attachment_headers = EmailMessage(policy=email_policy)
    attachment_headers["Content-Type"] = "application/pdf"
    attachment_headers["Content-Transfer-Encoding"] = "base64"
    attachment_headers.add_header(
        "Content-Disposition",
        "attachment",
        filename=_single_line(attachment_pdf.name, "PDF-Dateiname"),
    )

    with path.open("xb") as handle:
        _set_private_mode(path, 0o600)
        _write_mime_headers(handle, message, email_policy)
        handle.write(f"--{boundary}\r\n".encode("ascii"))
        _write_mime_headers(handle, text_headers, email_policy)
        _write_base64_chunks(handle, (body.encode("utf-8"),))
        handle.write(f"\r\n--{boundary}\r\n".encode("ascii"))
        _write_mime_headers(handle, attachment_headers, email_policy)
        _write_base64_chunks(handle, _iter_file_chunks(attachment_pdf))
        handle.write(f"\r\n--{boundary}--\r\n".encode("ascii"))


def _timestamp_as_datetime(value: str) -> datetime:
    normalised = _normalise_utc_timestamp(value)
    return datetime.fromisoformat(normalised.replace("Z", "+00:00"))


def _single_line(value: str, label: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError(f"{label} darf keinen Zeilenumbruch enthalten")
    return value


def _start_manifest(
    path: Path,
    run_id: str,
    generated_at_utc: str,
) -> TextIO:
    """Öffnet ein privates Manifest und schreibt sofort den festen Kopf."""

    handle = path.open("x", encoding="utf-8", newline="\n")
    try:
        _set_private_mode(path, 0o600)
        handle.write("# SHA-256-Manifest der erzeugten Berichte\n")
        handle.write(f"# Lauf-ID: {run_id}\n")
        handle.write(f"# Erstellt (UTC): {generated_at_utc}\n")
        handle.write("# Die Manifestdatei selbst ist wegen des Zirkelschlusses nicht enthalten.\n")
    except Exception:
        handle.close()
        raise
    return handle


def _append_manifest_entry(handle: TextIO, file_path: Path) -> None:
    """Schreibt genau einen bereits erzeugten Bericht unmittelbar ins Manifest."""

    handle.write(f"{_sha256_file(file_path)} *{file_path.name}\n")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
