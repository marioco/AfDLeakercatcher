"""Kommandozeile, Logging und robuste Programmeinstiege."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import APP_NAME, VERSION
from .config import (
    AppConfig,
    ConfigError,
    EnrichmentSettings,
    ReportingSettings,
    default_config_path,
    default_data_dir,
    load_config,
    parse_magnet,
    save_config,
)

MAX_LOG_BYTES = 25_000
LOG_BACKUPS = 1
LOG_FORMAT = "[%(asctime)sZ] %(levelname)s %(message)s"


class PrivateRotatingFileHandler(RotatingFileHandler):
    """Erzwingt private Rechte auch nach einer Logrotation."""

    def _open(self) -> object:
        stream = super()._open()
        if os.name != "nt":
            Path(self.baseFilename).chmod(0o600)
        return stream

    def doRollover(self) -> None:
        super().doRollover()
        if os.name == "nt":
            return
        rotated_path = Path(self.rotation_filename(f"{self.baseFilename}.1"))
        for path in (Path(self.baseFilename), rotated_path):
            if path.exists():
                path.chmod(0o600)


def default_log_file(data_dir: Path) -> Path:
    """Legt das Standardprotokoll in der jeweiligen App-Ablage ab."""
    return data_dir / "logs" / "monitor.log"


def setup_logging(log_file: Path) -> logging.Logger:
    """Konfiguriert UTC-Ausgabe und die vorgeschriebene kleine Rotation."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        log_file.parent.chmod(0o700)
    logger = logging.getLogger("bittorrent_beobachter")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger

    formatter = logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    formatter.converter = time.gmtime
    file_handler = PrivateRotatingFileHandler(
        log_file,
        maxBytes=MAX_LOG_BYTES,
        backupCount=LOG_BACKUPS,
        encoding="utf-8",
    )
    file_handler.namer = lambda _name: str(log_file.with_suffix(".old"))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if log_file.exists() and os.name != "nt":
        log_file.chmod(0o600)
    stream = sys.stdout
    if stream is not None and callable(getattr(stream, "write", None)):
        stream_handler = logging.StreamHandler(stream)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    return logger


def build_parser() -> argparse.ArgumentParser:
    """Erzeugt eine Oberfläche, die ohne Argumente direkt die GUI startet."""
    parser = argparse.ArgumentParser(
        prog="bittorrent-beobachter",
        description=(
            "Inhaltsfreie Beobachtung ausdrücklich konfigurierter BitTorrent-Infohashes. "
            "Ohne Unterbefehl wird die Desktop-Oberfläche geöffnet. Nicht anonym: "
            "DHT-Knoten und geprüfte Peer-Endpunkte sehen Quell-IP und Infohash; "
            "es erfolgen kein announce und kein Inhalts- oder Metadatentransfer."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--config", type=Path, help="Pfad zur JSON-Konfiguration")
    parser.add_argument("--data-dir", type=Path, help="Ablage für Evidenz und Berichte")
    parser.add_argument("--log-file", type=Path, help="Abweichender Logpfad")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("gui", help="Desktop-Oberfläche öffnen")
    acknowledgement_help = (
        "Pflichtbestätigung: DHT-Knoten und geprüfte Peer-Endpunkte sehen "
        "öffentliche Quell-IP und Infohash und können dies protokollieren"
    )
    scan_parser = subparsers.add_parser(
        "scan",
        help="Einen begrenzten Prüflauf ausführen",
    )
    scan_parser.add_argument(
        "--acknowledge-public-network",
        action="store_true",
        help=acknowledgement_help,
    )
    watch_parser = subparsers.add_parser(
        "watch",
        help="Fortlaufend im konfigurierten Intervall prüfen",
    )
    watch_parser.add_argument(
        "--acknowledge-public-network",
        action="store_true",
        help=acknowledgement_help,
    )
    subparsers.add_parser("verify-journal", help="Hash-Kette des Ereignisjournals prüfen")

    init_parser = subparsers.add_parser("init", help="Konfiguration ohne Editor anlegen")
    init_parser.add_argument("--magnet", action="append", required=True, help="Magnet-Link")
    init_parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Bezeichnung in derselben Reihenfolge wie --magnet",
    )
    init_parser.add_argument(
        "--source-note",
        action="append",
        default=[],
        help=(
            "Quellenhinweis zur behaupteten Zuordnung; wiederholbar in derselben "
            "Reihenfolge wie --magnet"
        ),
    )
    init_parser.add_argument("--reporter-name", default="", help="Name für Entwürfe")
    init_parser.add_argument("--reporter-email", default="", help="Absender für Entwürfe")
    init_parser.add_argument("--police-recipient", default="", help="Empfänger für .eml")
    init_parser.add_argument(
        "--enable-network-enrichment",
        action="store_true",
        help=(
            "Öffentliche Netzangaben aktivieren; bestätigte IP-Adressen werden "
            "an stat.ripe.net, rdap.org und das von rdap.org bestimmte "
            "autoritative Regionalregister übertragen"
        ),
    )
    init_parser.add_argument(
        "--legal-note",
        action="append",
        default=[],
        help="Nur als ungeprüfter rechtlicher Prüfhinweis aufnehmen",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Vorhandene Konfiguration ausdrücklich ersetzen",
    )
    return parser


def _resolve_paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    data_dir = (args.data_dir or default_data_dir()).expanduser().resolve()
    config_path = (args.config or default_config_path(data_dir)).expanduser().resolve()
    log_file = (args.log_file or default_log_file(data_dir)).expanduser().resolve()
    return data_dir, config_path, log_file


def _initialize_config(args: argparse.Namespace, config_path: Path) -> int:
    if config_path.exists() and not args.force:
        raise ConfigError(
            f"Konfiguration existiert bereits: {config_path}. Nur mit --force wird sie ersetzt."
        )
    labels: list[str] = args.label
    if len(labels) > len(args.magnet):
        raise ConfigError("Es wurden mehr --label- als --magnet-Angaben übergeben.")
    source_notes: list[str] = args.source_note
    if len(source_notes) > len(args.magnet):
        raise ConfigError("Es wurden mehr --source-note- als --magnet-Angaben übergeben.")

    targets = tuple(
        parse_magnet(
            magnet,
            label_override=labels[index] if index < len(labels) and labels[index].strip() else None,
            source_note=source_notes[index] if index < len(source_notes) else "",
        )
        for index, magnet in enumerate(args.magnet)
    )
    config = AppConfig(
        targets=targets,
        enrichment=EnrichmentSettings(enabled=args.enable_network_enrichment),
        reporting=ReportingSettings(
            reporter_name=args.reporter_name.strip(),
            reporter_email=args.reporter_email.strip(),
            police_recipient=args.police_recipient.strip(),
            legal_notes=tuple(note.strip() for note in args.legal_note if note.strip()),
        ),
    )
    save_config(config_path, config)
    print(f"Konfiguration gespeichert: {config_path}")
    print(
        "Magnet-Name und Tracker wurden verworfen; gespeichert sind nur eine "
        "neutrale oder ausdrücklich angegebene Bezeichnung und der Infohash."
    )
    print(
        "WICHTIG: Prüfläufe sind nicht anonym. DHT-Knoten und geprüfte "
        "Peer-Endpunkte sehen Ihre öffentliche Quell-IP und den abgefragten "
        "Infohash und können dies protokollieren. Es erfolgen kein announce "
        "und kein Inhalts- oder Metadatentransfer."
    )
    if config.enrichment.enabled:
        print(
            "Netzauskunft aktiviert: Bestätigte IP-Adressen werden an "
            "stat.ripe.net, rdap.org und das von rdap.org bestimmte autoritative "
            "Regionalregister (z. B. RIPE, ARIN, APNIC, LACNIC oder AFRINIC) "
            "übertragen; diese Stellen können die Abfragen protokollieren."
        )
    return 0


def _scan_once(config_path: Path, data_dir: Path, logger: logging.Logger) -> int:
    from .monitor import run_scan

    config = load_config(config_path)
    logger.info("Prüflauf für %d Ziel(e) gestartet", len(config.targets))
    result = run_scan(config, data_dir, progress=logger.info)
    logger.info(
        "Prüflauf beendet: %d DHT-Treffer, %d bestätigte Handshakes, %d VPN-Treffer",
        len(result.candidates),
        result.confirmed_count,
        result.known_vpn_count,
    )
    for path in result.report_paths:
        logger.info("Ausgabe: %s", path)
    for notice in result.notices:
        logger.info("Technischer Laufhinweis: %s", notice)
    for error in result.errors:
        logger.warning("Teilproblem: %s", error)
    return 0


def _watch(config_path: Path, data_dir: Path, logger: logging.Logger) -> int:
    stop_event = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        logger.info("Beendigungssignal %d empfangen", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    logger.info("Fortlaufende Überwachung gestartet")
    while not stop_event.is_set():
        try:
            exit_code = _scan_once(config_path, data_dir, logger)
        except (ConfigError, OSError):
            logger.exception("Prüflauf konnte nicht gestartet werden")
            exit_code = 1
        try:
            interval_minutes = load_config(config_path).interval_minutes
        except (ConfigError, OSError):
            logger.exception("Intervall konnte nicht neu geladen werden")
            return 1
        logger.info(
            "Nächster Prüflauf in %d Minuten (letzter Exitcode %d)",
            interval_minutes,
            exit_code,
        )
        stop_event.wait(interval_minutes * 60)
    logger.info("Fortlaufende Überwachung beendet")
    return 0


def _verify_journal(data_dir: Path) -> int:
    from .evidence import EvidenceJournal

    journal_path = data_dir / "evidence" / "events.jsonl"
    journal = EvidenceJournal(journal_path)
    result = journal.verify()
    if not result.valid:
        print(f"FEHLER: Hash-Kette ist ungültig: {journal_path}: {result.error}")
        return 1
    print(f"Hash-Kette ist gültig: {journal_path} ({result.entries_count} Ereignis(se))")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Steuert GUI, Einzellauf, Dauerbetrieb und Journalprüfung."""
    parser = build_parser()
    args = parser.parse_args(argv)
    data_dir, config_path, log_file = _resolve_paths(args)
    logger = setup_logging(log_file)
    command = args.command or "gui"
    logger.info("=== %s %s gestartet (%s) ===", APP_NAME, VERSION, command)

    try:
        if command == "gui":
            from .gui import launch_gui

            return launch_gui(config_path, data_dir)
        if command == "init":
            return _initialize_config(args, config_path)
        if command == "scan":
            if not args.acknowledge_public_network:
                raise ConfigError(
                    "scan benötigt --acknowledge-public-network als ausdrückliche "
                    "Bestätigung: DHT-Knoten und Peer-Endpunkte sehen Quell-IP und "
                    "Infohash und können dies protokollieren."
                )
            return _scan_once(config_path, data_dir, logger)
        if command == "watch":
            if not args.acknowledge_public_network:
                raise ConfigError(
                    "watch benötigt --acknowledge-public-network als ausdrückliche "
                    "Bestätigung: DHT-Knoten und Peer-Endpunkte sehen Quell-IP und "
                    "Infohash und können dies protokollieren."
                )
            return _watch(config_path, data_dir, logger)
        if command == "verify-journal":
            return _verify_journal(data_dir)
        parser.error(f"Unbekannter Unterbefehl: {command}")
    except (ConfigError, FileNotFoundError, PermissionError) as exc:
        logger.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        logger.info("Vom Benutzer abgebrochen")
        return 130
    except Exception:
        logger.exception("Unbehandelter Fehler")
        return 1
    finally:
        logger.info("=== %s beendet ===", APP_NAME)
    return 1
