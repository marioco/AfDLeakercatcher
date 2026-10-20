"""Erzeugt neutrale, nachvollziehbare Berichte aus bestaetigten Beobachtungen.

Das Modul versendet nichts. E-Mail-Ausgaben werden ausschliesslich als lokale
``.eml``-Entwuerfe mit angehaengtem PDF erstellt. ReportLab wird erst beim
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

EVIDENCE_LIMITATIONS = (
    "Es wurden keine Inhalte und keine Torrent-Metadaten heruntergeladen oder hochgeladen.",
    "Die behauptete Zuordnung des Infohashes zu einem bezeichneten Inhalt "
    "wurde deshalb nicht verifiziert; Magnetname, Zielbezeichnung und "
    "Infohash allein beweisen den Inhalt nicht.",
    "Die Beobachtung belegt ausschließlich, dass der öffentliche "
    "Netzwerkendpunkt den BitTorrent-Handshake für den genannten Infohash "
    "beantwortet hat.",
    "Sie belegt weder Eigentum am Anschluss oder Endgerät noch die Identität "
    "einer Person, deren Handeln oder deren Schuld.",
    "Öffentliche Routing-/Registry-Angaben beschreiben einen Netzbetreiber "
    "oder Adressbereich; sie sind keine Auskunft über die Anschlussinhaberin oder "
    "den Anschlussinhaber.",
    "Die lokalen SHA-256-Hashes und die lokale Hash-Kette unterstützen nur "
    "die Integritätsprüfung der lokalen Aufzeichnung; sie sind keine digitale "
    "Signatur und kein vertrauenswürdiger externer Zeitstempel.",
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
    "netzregistrierung_quellen_abruf_utc",
    "netzregistrierung_cache_quellen",
    "netzregistrierungs_fehler",
    "aussagegrenze",
)


@dataclass(frozen=True, slots=True)
class ReportConfig:
    """Konfigurierbare Absender-, Empfaenger- und Rechtshinweise.

    Leere Werte bleiben in den Berichten als nicht angegeben erkennbar. Das
    Modul erfindet insbesondere keine E-Mail- oder Postadresse.
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
    """Alle bestaetigten Evidenzdatensaetze fuer eine kanonische IP-Adresse."""

    ip: str
    records: tuple[EvidenceRecord, ...]

    @property
    def is_known_vpn(self) -> bool:
        """Wertet eine IP konservativ als VPN, sobald ein Datensatz so lautet."""

        return any(record.vpn.status == "known_vpn" for record in self.records)


def safe_ip_filename(ip: str) -> str:
    """Gibt eine kanonische, betriebssystemuebergreifend sichere IP-Kennung zurueck."""

    if "%" in ip:
        raise ValueError("IP-Adressen mit Zonenkennung sind nicht zulaessig")
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"Ungueltige IP-Adresse fuer Bericht: {ip!r}") from exc
    safe_address = re.sub(r"[^a-z0-9]+", "_", parsed.compressed.lower()).strip("_")
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
    ausgewertet. Bekannte VPN-Endpunkte erscheinen nur in der Gesamt- und
    VPN-Liste; fuer sie werden weder Einzelhinweise noch E-Mail-Entwuerfe
    erzeugt. Das SHA-256-Manifest wird zuletzt erstellt und hasht alle anderen
    erzeugten Dateien.
    """

    _validate_report_config(config)
    _single_line(result.run_id, "run_id")
    aggregates = _aggregate_confirmed_records(result.records)
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
        _write_csv(csv_path, aggregates)
        generated_files.append(csv_path)

        vpn_csv_path = staging_dir / f"{run_slug}_vpn_liste.csv"
        _write_csv(vpn_csv_path, vpn_only)
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
            notice_path = staging_dir / f"{run_slug}_hinweis_{ip_slug}.pdf"
            _write_notice_pdf(
                notice_path,
                result,
                aggregate,
                config,
                generated_timestamp,
                toolkit,
            )
            generated_files.append(notice_path)

            draft_path = staging_dir / f"{run_slug}_entwurf_{ip_slug}.eml"
            _write_email_draft(
                draft_path,
                result,
                aggregate,
                config,
                generated_timestamp,
                notice_path,
            )
            generated_files.append(draft_path)

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


def _aggregate_confirmed_records(
    records: Iterable[EvidenceRecord],
) -> tuple[_IpAggregate, ...]:
    """Gruppiert bestaetigte Records nach kanonischer IP-Adresse."""

    grouped: defaultdict[str, list[EvidenceRecord]] = defaultdict(list)
    for record in records:
        if not record.handshake.confirmed:
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
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
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
        if os.name != "nt":
            source.chmod(0o600)
        os.replace(source, target)
        target.chmod(0o600)
        final_paths.append(target)
    return final_paths


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
            "Zusammenfassung eines begrenzten BitTorrent-Netzwerktests. Dieser "
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
                ("Bestätigte IP-Adressen mit Evidenz", str(len(aggregates))),
                ("Einzelhinweise", str(len(reportable))),
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
            "eine TCP-Verbindung aufgebaut und genau der BitTorrent-Handshake "
            "für den konfigurierten Infohash geprüft. Es wurden keine Piece-, "
            "Datei- oder Metadatenanfragen gesendet. Die protokollierten Hashes "
            "dienen der Integritätsprüfung der lokal erfassten Ereignisse; sie "
            "sind keine digitale Signatur und kein vertrauenswürdiger externer "
            "Zeitstempel. Der lokale Fingerabdruck einer DHT-Antwort ist später "
            "nicht unabhängig reproduzierbar, weil das Rohpaket datensparsam "
            "nicht gespeichert wird.",
            styles["BodyText"],
            toolkit,
        ),
        _paragraph("Übersicht nach IP-Adresse", styles["Heading1"], toolkit),
    ]

    if aggregates:
        table_rows: list[list[Any]] = [
            [
                _paragraph("IP-Adresse", styles["SmallReportText"], toolkit),
                _paragraph("Einordnung", styles["SmallReportText"], toolkit),
                _paragraph("Anzahl", styles["SmallReportText"], toolkit),
                _paragraph("Infohashes", styles["SmallReportText"], toolkit),
                _paragraph("Zeitraum UTC", styles["SmallReportText"], toolkit),
            ]
        ]
        for aggregate in aggregates:
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
                "In diesem Lauf lagen keine bestätigten Evidenzdatensätze vor.",
                styles["BodyText"],
                toolkit,
            )
        )

    source_notes = _source_note_lines(
        record for aggregate in aggregates for record in aggregate.records
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


def _write_notice_pdf(
    path: Path,
    result: ScanResult,
    aggregate: _IpAggregate,
    config: ReportConfig,
    generated_at_utc: str,
    toolkit: SimpleNamespace,
) -> None:
    styles = _styles(toolkit)
    row = _aggregate_row(aggregate)
    story: list[Any] = [
        _paragraph(
            "Technischer Hinweis an eine Polizeidienststelle",
            styles["Title"],
            toolkit,
        ),
        _paragraph(
            "ENTWURF - nicht automatisch versandt",
            styles["EvidenceBox"],
            toolkit,
        ),
        _key_value_table(
            (
                ("Adressat", config.recipient_name.strip() or "nicht angegeben"),
                ("Anschrift", config.recipient_address.strip() or "nicht angegeben"),
                ("E-Mail", config.recipient_email or "nicht angegeben"),
                ("Meldende Person/Stelle", config.reporter_name.strip() or "nicht angegeben"),
                ("Kontakt", config.reporter_contact.strip() or "nicht angegeben"),
                ("Kontakt-E-Mail", config.reporter_email or "nicht angegeben"),
                ("Lauf-ID", result.run_id),
                ("Bericht erstellt (UTC)", generated_at_utc),
            ),
            styles,
            toolkit,
        ),
        _paragraph("Anlass des Hinweises", styles["Heading1"], toolkit),
        _paragraph(
            "Bei einem begrenzten technischen Netzwerktest antwortete der "
            f"öffentliche Endpunkt {aggregate.ip} auf mindestens einen "
            "BitTorrent-Handshake für einen der dokumentierten Infohashes. "
            "Es wird um eine eigenständige technische und rechtliche Prüfung "
            "durch die zuständige Behörde gebeten.",
            styles["BodyText"],
            toolkit,
        ),
        _paragraph("Aussagegrenze", styles["Heading1"], toolkit),
        _limitations_paragraph(styles["EvidenceBox"], toolkit),
        _paragraph("Zusammenfassung für diese IP-Adresse", styles["Heading1"], toolkit),
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
                ("Erste Beobachtung (UTC)", row["erste_beobachtung_utc"]),
                ("Letzte Beobachtung (UTC)", row["letzte_beobachtung_utc"]),
                ("VPN-Einordnung", row["vpn_status"]),
            ),
            styles,
            toolkit,
        ),
        _paragraph("Öffentliche Routing-/Registry-Angaben", styles["Heading1"], toolkit),
        _paragraph(
            "Die folgenden Daten sind öffentliche Routing-/Registry-Angaben "
            "zum Adressbereich. "
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
                ("Land", row["laender"]),
                ("Öffentlicher Abuse-Kontakt", row["abuse_kontakte"]),
                (
                    "Angefragte bzw. weitergeleitete Quellen",
                    row["angefragte_bzw_weitergeleitete_quellen"],
                ),
                (
                    "Quellenspezifischer Abrufzeitpunkt (UTC)",
                    row["netzregistrierung_quellen_abruf_utc"],
                ),
                (
                    "Aus lokalem Cache",
                    row["netzregistrierung_cache_quellen"],
                ),
                ("Abruffehler", row["netzregistrierungs_fehler"]),
            ),
            styles,
            toolkit,
        ),
        _paragraph("Technische Einzelbeobachtungen", styles["Heading1"], toolkit),
    ]

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
                        ("SHA-256 des Evidenzereignisses", record.evidence_event_sha256),
                    ),
                    styles,
                    toolkit,
                ),
            ]
        )

    _append_legal_notes(story, config, styles, toolkit)
    story.extend(
        [
            _paragraph("Bitte um Prüfung", styles["Heading1"], toolkit),
            _paragraph(
                "Es wird ausschließlich um behördliche Prüfung der technischen "
                "Beobachtung und ihrer rechtlichen Bedeutung gebeten. Für eine "
                "Zuordnung zu einem Anschluss oder einer Person sind eigenständige "
                "Ermittlungen, insbesondere unter Beachtung dynamischer Adressen, "
                "NAT, Proxies, VPNs und des genauen Zeitpunkts, erforderlich.",
                styles["BodyText"],
                toolkit,
            ),
        ]
    )
    _build_pdf(
        path,
        f"Technischer Hinweis - {aggregate.ip}",
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
            "Für diese Einträge werden keine Einzelhinweise und keine "
            "E-Mail-Entwürfe erzeugt.",
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
                _paragraph("Ports", styles["SmallReportText"], toolkit),
                _paragraph("Infohashes", styles["SmallReportText"], toolkit),
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
                    _paragraph(row["ports"], styles["SmallReportText"], toolkit),
                    _paragraph(row["infohashes"], styles["SmallReportText"], toolkit),
                    _paragraph(reason_source, styles["SmallReportText"], toolkit),
                ]
            )
        story.append(_data_table(rows, (82, 82, 48, 136, 163), toolkit, repeat_rows=1))
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
    table = toolkit.Table(rendered_rows, colWidths=(132, 379), hAlign="LEFT")
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
    table = toolkit.LongTable(rows, colWidths=widths, repeatRows=repeat_rows, hAlign="LEFT")
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
        "vpn_quellen": values(record.vpn.source for record in records),
        "angefragte_bzw_weitergeleitete_quellen": values(
            source for record in records for source in record.enrichment.source_urls
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


def _csv_safe(value: str) -> str:
    """Verhindert Formelausfuehrung beim Oeffnen externer Texte in Tabellenkalkulationen."""

    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _write_email_draft(
    path: Path,
    result: ScanResult,
    aggregate: _IpAggregate,
    config: ReportConfig,
    generated_at_utc: str,
    notice_pdf: Path,
) -> None:
    message = EmailMessage(policy=SMTP)
    message["Subject"] = f"Technischer Hinweis zu BitTorrent-Endpunkt {aggregate.ip}"
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

    legal_text = ""
    if config.legal_notes:
        legal_text = (
            "\n\nVom meldenden Nutzer angegebene Sachverhalts- und rechtliche Prüfhinweise "
            "(nicht durch das Programm bewertet):\n"
            + "\n".join(f"- {note}" for note in config.legal_notes if note.strip())
        )

    source_notes = _source_note_lines(aggregate.records)
    source_text = ""
    if source_notes:
        source_text = (
            "\n\nHashgebundene Sachverhaltshinweise (unbestätigte Nutzerangaben; "
            "der bezeichnete Inhalt wurde vom Programm nicht abgerufen oder verifiziert):\n"
            + "\n".join(f"- {note}" for note in source_notes)
        )

    row = _aggregate_row(aggregate)
    network_source_text = (
        "\n\nÖffentliche Routing-/Registry-Angaben zum Adressbereich:\n"
        "- Angefragte bzw. weitergeleitete Quellen: "
        f"{row['angefragte_bzw_weitergeleitete_quellen']}\n"
        "- Quellenspezifische Abrufzeitpunkte (UTC): "
        f"{row['netzregistrierung_quellen_abruf_utc']}\n"
        f"- Aus lokalem Cache: {row['netzregistrierung_cache_quellen']}\n"
        f"- Abruffehler: {row['netzregistrierungs_fehler']}"
    )

    body = (
        "Sehr geehrte Damen und Herren,\n\n"
        "anbei erhalten Sie einen neutralen technischen Hinweis zu einer "
        "BitTorrent-Netzwerkbeobachtung. Bitte prüfen Sie die technischen "
        "Angaben und ihre rechtliche Bedeutung eigenständig.\n\n"
        + "\n".join(f"- {text}" for text in EVIDENCE_LIMITATIONS)
        + source_text
        + legal_text
        + network_source_text
        + "\n\nDer angehängte Bericht enthält Zeitpunkte, Infohashes, "
        "Endpunkte, Integritätshashes und öffentliche Netzregistrierungsdaten.\n\n"
        "Mit freundlichen Grüßen\n"
        f"{config.reporter_name.strip() or '[Absender nicht angegeben]'}\n\n"
        "Hinweis: Dies ist ein lokal erzeugter Entwurf. Das Programm hat diese "
        "E-Mail nicht versandt.\n"
    )
    message.set_content(body, subtype="plain", charset="utf-8")
    message.add_attachment(
        notice_pdf.read_bytes(),
        maintype="application",
        subtype="pdf",
        filename=notice_pdf.name,
    )
    boundary_seed = hashlib.sha256(
        f"{result.run_id}\0{aggregate.ip}\0{generated_at_utc}".encode()
    ).hexdigest()[:32]
    message.set_boundary(f"===============bittorrent-{boundary_seed}==")
    path.write_bytes(message.as_bytes(policy=SMTP))


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
