"""Erzeugt nachvollziehbare Anzeigen und Berichte aus bestaetigten Beobachtungen.

Das Modul versendet nichts. E-Mail-Ausgaben werden ausschliesslich als lokale
versandfertige ``.eml``-Dateien mit angehaengtem PDF erstellt. ReportLab wird erst beim
Erzeugen der PDFs importiert, damit alle anderen Programmteile auch ohne die
optionale PDF-Abhaengigkeit importierbar bleiben.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import ipaddress
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .models import EvidenceRecord, ScanResult

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
    "Der SHA-256-Wert der DHT-Antwort ist nur ein lokal berechneter "
    "Fingerabdruck. Das Rohpaket wird datensparsam nicht gespeichert; der Wert "
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
    "lokaler_dht_antwort_fingerabdruck_sha256",
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
    """Positive Gesamtbefunde für eine kanonische IP-Adresse."""

    ip: str
    records: tuple[EvidenceRecord, ...]

    @property
    def is_known_vpn(self) -> bool:
        """Wertet eine IP konservativ als VPN, sobald ein Datensatz so lautet."""

        return any(record.vpn.status == "known_vpn" for record in self.records)


def _project_leak_hashes(aggregate: _IpAggregate) -> tuple[str, ...]:
    """Liefert nur die fest im Projekt hinterlegten, fallbezogenen Infohashes."""

    return tuple(
        sorted(
            {
                record.handshake.candidate.info_hash_hex
                for record in aggregate.records
                if record.handshake.candidate.info_hash_hex in PROJECT_LEAK_INFO_HASHES
            }
        )
    )


def _availability_statements(aggregate: _IpAggregate) -> tuple[str, ...]:
    """Formuliert einen Angebotsbefund nur über das zentrale Gesamt-Gate."""

    statements: list[str] = []
    for record in aggregate.records:
        handshake = record.handshake
        observation = handshake.availability
        if observation is None:
            continue
        if not handshake.offering_observed:
            statements.append(
                "Die direkte Verfügbarkeitsprüfung ergab keinen vollständigen "
                "positiven Gesamtbefund. Daher wird nicht behauptet, dass der "
                "Peer Stückverfügbarkeit meldete oder ein UNCHOKE-Signal sendete. "
                "Es wurden keine Inhaltsblöcke angefordert oder heruntergeladen."
            )
            continue

        statements.append(
            "Das Prüfprogramm stellte eine direkte Verbindung zum BitTorrent-Client "
            "her. Der Client bestätigte die eindeutige digitale Kennung (Infohash). "
            "Er meldete, dass bei ihm Teile verfügbar seien; außerdem teilte er dem "
            "Prüfprogramm mit, dass es diese Teile nun anfordern dürfe (technische "
            "Nachricht: UNCHOKE). Der Client blieb während "
            "der vollständig durchgeführten Beobachtungszeit erreichbar. "
            "Beobachtet wurde von "
            f"{observation.started_at_utc} bis {observation.ended_at_utc} "
            f"({observation.duration_seconds:.1f} Sekunden; vorgesehen: "
            f"{observation.requested_duration_seconds:.1f} Sekunden). Das "
            "Prüfprogramm forderte diese Teile nicht an und lud keine Inhalte "
            "herunter."
        )
    return tuple(statements)


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
        ("Vollständige Beobachtungszeit erreicht", "ja"),
        ("Peer meldete Stückverfügbarkeit", "ja"),
        ("Peer sendete UNCHOKE", "ja"),
        ("Empfangene Protokollnachrichten", str(observation.messages_received)),
        ("Empfangene Bytes der Protokollprüfung", str(observation.bytes_received)),
        ("Gesendete REQUEST-Nachrichten", str(observation.request_messages_sent)),
        ("Empfangene Inhaltsbytes", str(observation.piece_payload_bytes_received)),
        ("Gesendete Metadatenanfragen", str(observation.metadata_requests_sent)),
        ("Beendigungsgrund", observation.termination_reason),
        ("Protokollierte Steuerereignisse", control_events),
        ("Fehler der Verfügbarkeitsprüfung", "keiner"),
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
    """Erzeugt den vollstaendigen Berichtssatz und gibt absolute Pfade zurueck.

    Ausschliesslich bestaetigte Eintraege aus ``result.records`` werden
    ausgewertet. Bekannte VPN-Endpunkte erscheinen ausschliesslich in einer
    datensparsamen VPN-Liste; fuer sie werden weder Einzelanlagen noch
    E-Mail-Dateien erzeugt. Das SHA-256-Manifest wird zuletzt erstellt und
    hasht alle anderen erzeugten Dateien.
    """

    _validate_report_config(config)
    _single_line(result.run_id, "run_id")
    aggregates = _aggregate_reportable_records(result.records)
    reportable = tuple(item for item in aggregates if not item.is_known_vpn)
    vpn_only = tuple(item for item in aggregates if item.is_known_vpn)
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
        generated_files: list[Path] = []

        summary_path = staging_dir / f"{run_slug}_laufbericht.pdf"
        _write_summary_pdf(
            summary_path,
            result,
            aggregates,
            reportable,
            vpn_only,
            config,
            generated_timestamp,
            toolkit,
        )
        generated_files.append(summary_path)

        csv_path = staging_dir / f"{run_slug}_beobachtungen.csv"
        _write_csv(csv_path, reportable)
        generated_files.append(csv_path)

        vpn_csv_path = staging_dir / f"{run_slug}_vpn_liste.csv"
        _write_vpn_csv(vpn_csv_path, vpn_only)
        generated_files.append(vpn_csv_path)

        vpn_pdf_path = staging_dir / f"{run_slug}_vpn_liste.pdf"
        _write_vpn_pdf(
            vpn_pdf_path,
            result,
            vpn_only,
            config,
            generated_timestamp,
            toolkit,
        )
        generated_files.append(vpn_pdf_path)

        for aggregate in reportable:
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
            generated_files.append(attachment_path)

            complaint_path = staging_dir / f"{run_slug}_strafanzeige_{ip_slug}.eml"
            _write_complaint_email(
                complaint_path,
                result,
                aggregate,
                config,
                generated_timestamp,
                attachment_path,
            )
            generated_files.append(complaint_path)

        manifest_path = staging_dir / f"{run_slug}_SHA256SUMS.txt"
        _write_manifest(
            manifest_path,
            generated_files,
            result.run_id,
            generated_timestamp,
        )
        generated_files.append(manifest_path)

        final_paths = _publish_staged_files(generated_files, output_dir)

    for path in final_paths:
        if path not in result.report_paths:
            result.report_paths.append(path)
    return final_paths


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


def _aggregate_reportable_records(
    records: Iterable[EvidenceRecord],
) -> tuple[_IpAggregate, ...]:
    """Gruppiert ausschließlich positive Gesamtbefunde nach kanonischer IP."""

    grouped: defaultdict[str, list[EvidenceRecord]] = defaultdict(list)
    for record in records:
        if not record.handshake.offering_observed:
            continue
        candidate_ip = _canonical_ip(record.handshake.candidate.ip)
        enrichment_ip = _canonical_ip(record.enrichment.ip)
        if candidate_ip != enrichment_ip:
            raise ValueError(
                "IP-Adresse der Netzregistrierung passt nicht zum Handshake: "
                f"{enrichment_ip} != {candidate_ip}"
            )
        grouped[candidate_ip].append(record)

    aggregates: list[_IpAggregate] = []
    for ip, ip_records in grouped.items():
        ordered_records = tuple(sorted(ip_records, key=_record_sort_key))
        aggregates.append(_IpAggregate(ip=ip, records=ordered_records))
    return tuple(sorted(aggregates, key=lambda item: _ip_sort_key(item.ip)))


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


def _publish_staged_files(files: Iterable[Path], output_dir: Path) -> list[Path]:
    final_paths: list[Path] = []
    for source in files:
        target = output_dir / source.name
        _set_private_mode(source, 0o600)
        os.replace(source, target)
        _set_private_mode(target, 0o600)
        final_paths.append(target)
    return final_paths


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


def _build_pdf(
    path: Path,
    title: str,
    story: list[Any],
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

    document.build(
        story,
        onFirstPage=decorate_page,
        onLaterPages=decorate_page,
        canvasmaker=canvas_maker,
    )


def _write_summary_pdf(
    path: Path,
    result: ScanResult,
    aggregates: tuple[_IpAggregate, ...],
    reportable: tuple[_IpAggregate, ...],
    vpn_only: tuple[_IpAggregate, ...],
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    styles = _styles(toolkit)
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
                ("Beginn (UTC)", result.started_at_utc),
                ("Abschluss (UTC)", result.completed_at_utc or "nicht abgeschlossen"),
                ("Bericht erstellt (UTC)", generated_at_utc),
                ("DHT-Kandidaten", str(len(result.candidates))),
                ("Handshake-Versuche", str(len(result.handshakes))),
                ("Bestätigte Handshakes", str(result.confirmed_count)),
                ("IP-Adressen mit positivem Gesamtbefund", str(len(aggregates))),
                ("Anlagen zu Strafanzeigen", str(len(reportable))),
                ("Bekannte VPN-IP-Adressen", str(len(vpn_only))),
            ),
            styles,
            toolkit,
        ),
        toolkit.Spacer(1, 6),
        _paragraph("Aussagegrenze", styles["Heading1"], toolkit),
        _limitations_paragraph(styles["EvidenceBox"], toolkit),
        _paragraph("Vorgehensweise", styles["Heading1"], toolkit),
        _paragraph(
            "Ein Kandidat wurde aus einer DHT-Antwort übernommen. Danach wurde "
            "eine TCP-Verbindung aufgebaut und der BitTorrent-Handshake für "
            "den konfigurierten Infohash geprüft. Nach bestätigtem Handshake wird "
            "eine inhaltsfreie Verfügbarkeitsprüfung durchgeführt. Sie beobachtet "
            "nur Bitfield-/Have- und Choke-/Unchoke-Signale; Piece-, Datei- oder "
            "Metadaten werden weder angefordert noch geladen. Die protokollierten Hashes "
            "dienen der Integritätsprüfung der lokal erfassten Ereignisse; sie "
            "sind keine digitale Signatur und kein vertrauenswürdiger externer "
            "Zeitstempel. Der lokale Fingerabdruck einer DHT-Antwort ist später "
            "nicht unabhängig reproduzierbar, weil das Rohpaket datensparsam "
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
        for aggregate in reportable:
            row = _aggregate_row(aggregate)
            table_rows.append(
                [
                    _paragraph(aggregate.ip, styles["SmallReportText"], toolkit),
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

    source_notes = _source_note_lines(
        record for aggregate in reportable for record in aggregate.records
    )
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
    styles = _styles(toolkit)
    row = _aggregate_row(aggregate)
    project_hashes = _project_leak_hashes(aggregate)
    availability_statements = _availability_statements(aggregate)

    story: list[Any] = [
        _paragraph(
            "Technische Anlage zur Strafanzeige gegen Unbekannt",
            styles["Title"],
            toolkit,
        ),
        _paragraph("1. Mögliche Tat", styles["Heading1"], toolkit),
    ]
    if project_hashes:
        story.extend(
            [
                _paragraph(
                    "Nach der öffentlichen Beschreibung sollen die Daten ohne Berechtigung "
                    "von Servern bzw. Postfächern der AfD kopiert worden sein "
                    "und nun über BitTorrent verbreitet werden. BitTorrent ist ein "
                    "Internet-Tauschsystem, bei dem beteiligte Computer vorhandene "
                    "Datenteile anderen Nutzern zum Abruf anbieten können. Die "
                    "veröffentlichende Seite beziffert das dort als sogenannten "
                    "AfD-Datenleak beschriebene Material wie folgt:",
                    styles["BodyText"],
                    toolkit,
                ),
                _paragraph(
                    "<br/>".join(f"- {_escape_text(fact)}" for fact in PUBLISHED_DATASET_FACTS),
                    styles["BodyText"],
                    toolkit,
                    already_escaped=True,
                ),
                _paragraph(
                    "Diese Angaben werden als zugrunde gelegter Sachverhalt "
                    "wiedergegeben. Das Programm hat die Inhalte nicht abgerufen "
                    "oder geprüft; die Angaben sind mit dieser Anlage nicht "
                    "gerichtlich bewiesen. Bitte prüfen Sie einen möglichen "
                    "Anfangsverdacht insbesondere hinsichtlich:",
                    styles["BodyText"],
                    toolkit,
                ),
                _paragraph(
                    "<br/>".join(
                        f"- {_escape_text(point)}" for point in PROJECT_LEGAL_REVIEW_POINTS
                    ),
                    styles["BodyText"],
                    toolkit,
                    already_escaped=True,
                ),
                _paragraph(
                    "Der technische Befund allein belegt keines der gesetzlichen "
                    "Tatbestandsmerkmale.",
                    styles["EvidenceBox"],
                    toolkit,
                ),
            ]
        )
    else:
        story.append(
            _paragraph(
                "Die dokumentierten Infohashes wurden individuell vorgegeben. "
                "Das Programm ordnet ihnen keinen bestimmten Inhalt zu. Eine "
                "rechtliche Bewertung setzt deshalb die behördliche Klärung des "
                "tatsächlichen Inhalts voraus.",
                styles["BodyText"],
                toolkit,
            )
        )

    story.extend(
        [
            _paragraph("2. Fund der IP-Adresse", styles["Heading1"], toolkit),
            _paragraph(
                "Bei der gezielten Überprüfung der dokumentierten Infohashes wurde "
                f"die öffentliche IP-Adresse {aggregate.ip} als BitTorrent-Endpunkt "
                "ermittelt. Der Endpunkt beantwortete den BitTorrent-Handshake für "
                "die überwachte eindeutige digitale Kennung (Infohash). Eine "
                "IP-Adresse identifiziert für sich "
                "allein keine Person.",
                styles["BodyText"],
                toolkit,
            ),
            _key_value_table(
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
            ),
            _paragraph("3. Direkte Verfügbarkeitsprüfung", styles["Heading1"], toolkit),
        ]
    )
    if availability_statements:
        story.append(
            _paragraph(
                "<br/><br/>".join(_escape_text(statement) for statement in availability_statements),
                styles["EvidenceBox"],
                toolkit,
                already_escaped=True,
            )
        )
    else:
        story.append(
            _paragraph(
                "Für diese ältere Beobachtung ist nur ein bestätigter "
                "BitTorrent-Handshake dokumentiert. Eine länger dauernde "
                "Verfügbarkeitsbeobachtung, gemeldete Stückverfügbarkeit oder "
                "ein UNCHOKE-Signal wurden nicht erfasst. Es wird daher "
                "keine solche Behauptung aufgestellt. Inhaltsblöcke wurden weder "
                "angefordert noch heruntergeladen.",
                styles["EvidenceBox"],
                toolkit,
            )
        )

    story.extend(
        [
            _paragraph(
                "4. Technischer Beleg und Nachprüfbarkeit",
                styles["Heading1"],
                toolkit,
            ),
            _paragraph(
                "Die nachfolgenden Tabellen enthalten den technischen Beleg der "
                "lokalen Beobachtung. Quellcode und Beschreibung der Messmethode "
                f"sind unter {PROJECT_REPOSITORY_URL} öffentlich einsehbar. Das "
                "Repository macht die Methode nachprüfbar; es belegt nicht für "
                "sich allein die konkrete Beobachtung.",
                styles["BodyText"],
                toolkit,
            ),
            _paragraph("Aussagegrenze", styles["Heading1"], toolkit),
            _limitations_paragraph(styles["EvidenceBox"], toolkit),
            _paragraph("Technische Zusammenfassung", styles["Heading1"], toolkit),
            _key_value_table(
                (
                    ("IP-Adresse", aggregate.ip),
                    ("Beobachtete Ports", row["ports"]),
                    ("Bestätigte Handshakes", row["bestaetigte_handshakes"]),
                    ("Zielbezeichnungen", row["zielbezeichnungen"]),
                    ("Infohashes", row["infohashes"]),
                    (
                        "Unbestätigte Sachverhaltsangaben",
                        row["quellen_sachverhaltshinweise"],
                    ),
                    ("VPN-Einordnung", row["vpn_status"]),
                ),
                styles,
                toolkit,
            ),
            _paragraph(
                "Öffentliche Routing-/Registry-Angaben",
                styles["Heading1"],
                toolkit,
            ),
            _paragraph(
                "Die folgenden Daten beschreiben den öffentlichen Adressbereich. "
                "Sie identifizieren keine Anschlussinhaberin, keinen "
                "Anschlussinhaber und keine handelnde Person.",
                styles["BodyText"],
                toolkit,
            ),
            _key_value_table(
                (
                    ("Präfix(e)", row["netzpraefixe"]),
                    ("ASN", row["asns"]),
                    (
                        "Öffentliche Routing-/Netzbetreiberangabe",
                        row["routing_netzbetreiberangaben"],
                    ),
                    ("RDAP-Name", row["rdap_namen"]),
                    ("RDAP-Handle", row["rdap_handles"]),
                    (
                        "Registrierungsland des Netzes (keine Standortbestimmung)",
                        row["laender"],
                    ),
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
            ),
            _paragraph("Technische Einzelbeobachtungen", styles["Heading1"], toolkit),
        ]
    )

    for index, record in enumerate(aggregate.records, start=1):
        candidate = record.handshake.candidate
        handshake = record.handshake
        story.extend(
            [
                _paragraph(
                    f"Beobachtung {index}",
                    styles["Heading2"],
                    toolkit,
                ),
                _key_value_table(
                    (
                        ("Zielbezeichnung", candidate.target_label),
                        ("Infohash", candidate.info_hash_hex),
                        (
                            "Unbestätigte Nutzerangabe",
                            candidate.source_note or "nicht angegeben",
                        ),
                        ("Endpunkt", _format_endpoint(aggregate.ip, candidate.port)),
                        ("Von DHT genannt (UTC)", candidate.discovered_at_utc),
                        (
                            "DHT-Antwort von",
                            _format_endpoint(
                                candidate.dht_node_ip,
                                candidate.dht_node_port,
                            ),
                        ),
                        ("DHT-Transaktions-ID", candidate.transaction_id_hex),
                        (
                            "Lokaler SHA-256-Fingerabdruck der DHT-Antwort",
                            candidate.response_sha256,
                        ),
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
                        ("SHA-256 des Evidenzereignisses", record.evidence_event_sha256),
                    ),
                    styles,
                    toolkit,
                ),
            ]
        )

    _append_legal_notes(story, config, styles, toolkit)
    _build_pdf(
        path,
        f"Technische Anlage zur Strafanzeige - {aggregate.ip}",
        story,
        config,
        generated_at_utc,
        toolkit,
    )


def _write_vpn_pdf(
    path: Path,
    result: ScanResult,
    vpn_only: tuple[_IpAggregate, ...],
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    styles = _styles(toolkit)
    story: list[Any] = [
        _paragraph("Liste bekannter VPN-Endpunkte", styles["Title"], toolkit),
        _paragraph(
            "Diese separate Liste enthält IP-Adressen, für die mindestens eine "
            "konservative Klassifikation als bekannter VPN-Endpunkt vorliegt. "
            "Für diese Einträge werden keine Einzelanlagen und keine "
            "E-Mail-Dateien erzeugt.",
            styles["BodyText"],
            toolkit,
        ),
        _key_value_table(
            (
                ("Lauf-ID", result.run_id),
                ("Bericht erstellt (UTC)", generated_at_utc),
                ("Anzahl IP-Adressen", str(len(vpn_only))),
            ),
            styles,
            toolkit,
        ),
        _paragraph("Aussagegrenze", styles["Heading1"], toolkit),
        _limitations_paragraph(styles["EvidenceBox"], toolkit),
    ]

    if vpn_only:
        rows: list[list[Any]] = [
            [
                _paragraph("IP-Adresse", styles["SmallReportText"], toolkit),
                _paragraph("Anbieter", styles["SmallReportText"], toolkit),
                _paragraph("Grund / Quelle", styles["SmallReportText"], toolkit),
            ]
        ]
        for aggregate in vpn_only:
            row = _aggregate_row(aggregate)
            reason_source = (
                " | ".join(
                    value
                    for value in (row["vpn_begruendung"], row["vpn_quellen"])
                    if value and value != "nicht angegeben"
                )
                or "nicht angegeben"
            )
            rows.append(
                [
                    _paragraph(aggregate.ip, styles["SmallReportText"], toolkit),
                    _paragraph(row["vpn_anbieter"], styles["SmallReportText"], toolkit),
                    _paragraph(reason_source, styles["SmallReportText"], toolkit),
                ]
            )
        story.append(_data_table(rows, (150, 130, 231), toolkit, repeat_rows=1))
    else:
        story.append(
            _paragraph(
                "Keine als bekannter VPN klassifizierte IP-Adresse vorhanden.",
                styles["BodyText"],
                toolkit,
            )
        )
    _append_legal_notes(story, config, styles, toolkit)
    _build_pdf(
        path,
        "Liste bekannter VPN-Endpunkte",
        story,
        config,
        generated_at_utc,
        toolkit,
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


def _source_note_lines(records: Iterable[EvidenceRecord]) -> tuple[str, ...]:
    """Bindet unbestätigte Nutzerangaben eindeutig an ihren Infohash."""

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
    return tuple(lines)


def _aggregate_row(aggregate: _IpAggregate) -> dict[str, str]:
    records = aggregate.records
    candidates = tuple(record.handshake.candidate for record in records)
    observations = tuple(
        timestamp
        for record in records
        for timestamp in (
            record.handshake.candidate.discovered_at_utc,
            record.handshake.attempted_at_utc,
            record.handshake.completed_at_utc,
        )
        if timestamp
    )
    ordered_observations = sorted(set(observations), key=_timestamp_as_datetime)

    def values(items: Iterable[object | None]) -> str:
        unique = sorted(
            {str(item).strip() for item in items if item is not None and str(item).strip()}
        )
        return " | ".join(unique) if unique else "nicht angegeben"

    ports = " | ".join(str(port) for port in sorted({candidate.port for candidate in candidates}))
    asns = " | ".join(
        str(asn) for asn in sorted({asn for record in records for asn in record.enrichment.asns})
    )
    row = {
        "ip": aggregate.ip,
        "ports": ports or "nicht angegeben",
        "zielbezeichnungen": values(candidate.target_label for candidate in candidates),
        "infohashes": values(candidate.info_hash_hex for candidate in candidates),
        "quellen_sachverhaltshinweise": (
            " | ".join(_source_note_lines(records)) or "nicht angegeben"
        ),
        "erste_beobachtung_utc": (
            ordered_observations[0] if ordered_observations else "nicht angegeben"
        ),
        "letzte_beobachtung_utc": (
            ordered_observations[-1] if ordered_observations else "nicht angegeben"
        ),
        "bestaetigte_handshakes": str(len(records)),
        "lokaler_dht_antwort_fingerabdruck_sha256": values(
            candidate.response_sha256 for candidate in candidates
        ),
        "beweisereignis_sha256": values(record.evidence_event_sha256 for record in records),
        "remote_peer_ids": values(record.handshake.remote_peer_id_hex for record in records),
        "bytes_gesendet_summe": str(sum(record.handshake.bytes_sent for record in records)),
        "bytes_empfangen_summe": str(sum(record.handshake.bytes_received for record in records)),
        "netzpraefixe": values(record.enrichment.prefix for record in records),
        "asns": asns or "nicht angegeben",
        "routing_netzbetreiberangaben": values(record.enrichment.holder for record in records),
        "rdap_namen": values(record.enrichment.rdap_name for record in records),
        "rdap_handles": values(record.enrichment.rdap_handle for record in records),
        "laender": values(record.enrichment.country for record in records),
        "abuse_kontakte": values(record.enrichment.abuse_email for record in records),
        "vpn_status": ("bekannter VPN" if aggregate.is_known_vpn else "kein bekannter VPN-Treffer"),
        "vpn_anbieter": values(record.vpn.provider for record in records),
        "vpn_begruendung": values(record.vpn.reason for record in records),
        "vpn_quellen": values(_vpn_source_text(record.vpn.source) for record in records),
        "angefragte_bzw_weitergeleitete_quellen": values(
            source for record in records for source in record.enrichment.source_urls
        ),
        "netzangaben_zusammengestellt_utc": values(
            record.enrichment.enriched_at_utc for record in records
        ),
        "netzregistrierung_quellen_abruf_utc": values(
            f"{source}: {timestamp}"
            for record in records
            for source, timestamp in record.enrichment.source_fetched_at_utc
        ),
        "netzregistrierung_cache_quellen": values(
            source for record in records for source in record.enrichment.cached_sources
        ),
        "netzregistrierungs_fehler": values(record.enrichment.error for record in records),
        "aussagegrenze": " ".join(EVIDENCE_LIMITATIONS),
    }
    return row


def _write_csv(path: Path, aggregates: Iterable[_IpAggregate]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=CSV_FIELDNAMES,
        delimiter=";",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    for aggregate in aggregates:
        row = _aggregate_row(aggregate)
        writer.writerow({key: _csv_safe(row[key]) for key in CSV_FIELDNAMES})
    path.write_text(buffer.getvalue(), encoding="utf-8", newline="")


def _write_vpn_csv(path: Path, aggregates: Iterable[_IpAggregate]) -> None:
    """Schreibe fuer bekannte VPNs bewusst nur die separate Minimalliste."""

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=VPN_CSV_FIELDNAMES,
        delimiter=";",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    for aggregate in aggregates:
        row = _aggregate_row(aggregate)
        writer.writerow({key: _csv_safe(row[key]) for key in VPN_CSV_FIELDNAMES})
    path.write_text(buffer.getvalue(), encoding="utf-8", newline="")


def _csv_safe(value: str) -> str:
    """Verhindert Formelausfuehrung beim Oeffnen externer Texte in Tabellenkalkulationen."""

    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _write_complaint_email(
    path: Path,
    result: ScanResult,
    aggregate: _IpAggregate,
    config: ReportConfig,
    generated_at_utc: str,
    attachment_pdf: Path,
) -> None:
    email_policy = SMTP.clone(max_line_length=998)
    message = EmailMessage(policy=email_policy)
    project_hashes = _project_leak_hashes(aggregate)
    if project_hashes:
        message["Subject"] = (
            "Strafanzeige gegen Unbekannt - Verdacht der Verbreitung von 281 GB "
            f"mutmaßlich unbefugt kopierter AfD-Daten - IP {aggregate.ip}"
        )
    else:
        message["Subject"] = f"Strafanzeige gegen Unbekannt - BitTorrent-Endpunkt {aggregate.ip}"
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
    availability_statements = _availability_statements(aggregate)
    if availability_statements:
        direct_check = "\n\n".join(availability_statements)
    else:
        direct_check = (
            "Für diesen älteren Datensatz ist nur ein erfolgreicher "
            "BitTorrent-Handshake dokumentiert. Eine 60-sekündige "
            "Verfügbarkeitsbeobachtung, gemeldete Stückverfügbarkeit oder "
            "ein UNCHOKE-Signal wurden nicht erfasst. Es wird daher keine "
            "solche Behauptung aufgestellt. Inhaltsblöcke wurden weder angefordert "
            "noch heruntergeladen."
        )

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
        f"Die technischen Einzelheiten stehen in der angehängten PDF-Datei "
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
    message.set_content(body, subtype="plain", charset="utf-8")
    message.add_attachment(
        attachment_pdf.read_bytes(),
        maintype="application",
        subtype="pdf",
        filename=attachment_pdf.name,
    )
    boundary_seed = hashlib.sha256(
        f"{result.run_id}\0{aggregate.ip}\0{generated_at_utc}".encode()
    ).hexdigest()[:32]
    message.set_boundary(f"===============bittorrent-{boundary_seed}==")
    path.write_bytes(message.as_bytes(policy=email_policy))


def _timestamp_as_datetime(value: str) -> datetime:
    normalised = _normalise_utc_timestamp(value)
    return datetime.fromisoformat(normalised.replace("Z", "+00:00"))


def _single_line(value: str, label: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError(f"{label} darf keinen Zeilenumbruch enthalten")
    return value


def _write_manifest(
    path: Path,
    files: Iterable[Path],
    run_id: str,
    generated_at_utc: str,
) -> None:
    entries = sorted(files, key=lambda item: item.name)
    lines = [
        "# SHA-256-Manifest der erzeugten Berichte",
        f"# Lauf-ID: {run_id}",
        f"# Erstellt (UTC): {generated_at_utc}",
        "# Die Manifestdatei selbst ist wegen des Zirkelschlusses nicht enthalten.",
    ]
    for file_path in entries:
        lines.append(f"{_sha256_file(file_path)} *{file_path.name}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
