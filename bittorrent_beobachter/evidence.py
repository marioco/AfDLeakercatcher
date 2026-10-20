"""Manipulationssichtbares, append-only JSONL-Journal fuer Beobachtungen.

Die SHA-256-Kette erkennt nachtraegliche Aenderungen, Einfuegungen und
Umordnungen innerhalb eines vorhandenen Journals. Sie ist keine digitale
Signatur, kein vertrauenswuerdiger Zeitstempel und kein kryptographischer
Nachweis der Urheberschaft, Nichtabstreitbarkeit oder sachlichen Richtigkeit.
Ohne einen separat gesicherten letzten Hash kann auch eine Verkuerzung am
Dateiende nicht sicher erkannt werden.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from .models import EvidenceRecord, HandshakeResult, NetworkEnrichment, VpnClassification

JOURNAL_FORMAT_VERSION = 1
GENESIS_SHA256 = "0" * 64
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_JOURNAL_LINE_BYTES = 4_000_000
MAX_JOURNAL_BYTES = 32 * 1024 * 1024

INTEGRITY_LIMITATION = (
    "Die SHA-256-Kette macht Aenderungen am vorhandenen Journal sichtbar, "
    "ist aber keine Signatur, kein vertrauenswuerdiger Zeitstempel und kein "
    "Beweis der Urheberschaft, Nichtabstreitbarkeit oder sachlichen Richtigkeit."
)

_JOURNAL_KEYS = {
    "format_version",
    "sequence",
    "recorded_at_utc",
    "previous_event_sha256",
    "event",
    "event_sha256",
}


class EvidenceJournalError(RuntimeError):
    """Fehler beim Lesen, Pruefen oder Erweitern eines Beweisjournals."""


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """Ein vollstaendiger, gehashter Datensatz des JSONL-Journals."""

    format_version: int
    sequence: int
    recorded_at_utc: str
    previous_event_sha256: str
    event: dict[str, Any]
    event_sha256: str

    def as_dict(self) -> dict[str, Any]:
        """Gib den Datensatz in seiner kanonisch serialisierbaren Form zurueck."""

        return {
            "format_version": self.format_version,
            "sequence": self.sequence,
            "recorded_at_utc": self.recorded_at_utc,
            "previous_event_sha256": self.previous_event_sha256,
            "event": self.event,
            "event_sha256": self.event_sha256,
        }


@dataclass(frozen=True, slots=True)
class JournalVerification:
    """Ergebnis einer vollstaendigen Pruefung der lokalen Hash-Kette."""

    valid: bool
    entries_count: int
    last_event_sha256: str | None
    error: str | None = None


def _utc_now() -> str:
    """Erzeuge einen eindeutigen UTC-Zeitwert ohne lokale Zeitzonenannahme."""

    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _json_value(value: Any) -> Any:
    """Normalisiere erlaubte Werte, ohne unbekannte Objekte still umzudeuten."""

    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value))
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON-Ereignisse duerfen keine NaN- oder Infinity-Werte enthalten")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON-Objektschluessel muessen Zeichenketten sein")
            result[key] = _json_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    raise TypeError(f"Nicht unterstuetzter JSON-Wert: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialisiere einen Wert deterministisch als UTF-8-JSON."""

    normalized = _json_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _set_private_mode(path: Path, mode: int) -> None:
    """Setze private Rechte; Windows darf fehlende chmod-Unterstuetzung melden."""

    try:
        os.chmod(path, mode)
    except OSError:
        if os.name != "nt":
            raise


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _set_private_mode(path, 0o700)


def _open_private_append(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        _set_private_mode(path, 0o600)
        return os.fdopen(descriptor, "a+b", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(file_descriptor: int, data: bytes) -> None:
    """Schreibe auch dann vollstaendig, wenn das Betriebssystem partiell schreibt."""

    view = memoryview(data)
    while view:
        written = os.write(file_descriptor, view)
        if written <= 0:
            raise OSError("Dateischreibvorgang wurde unerwartet abgebrochen")
        view = view[written:]


def _fsync_directory(directory: Path) -> None:
    """Synchronisiere einen Verzeichniseintrag auf Plattformen mit O_DIRECTORY."""

    directory_flag = getattr(os, "O_DIRECTORY", None)
    if directory_flag is None:
        return
    descriptor = os.open(directory, os.O_RDONLY | directory_flag)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, value: Any) -> None:
    """Ersetze eine kleine JSON-Status- oder Cachedatei atomar und synchron."""

    destination = Path(path)
    _ensure_private_directory(destination.parent)
    payload = canonical_json_bytes(value) + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        _set_private_mode(temporary_path, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_path, destination)
        _fsync_directory(destination.parent)
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError as cleanup_error:
            exc.add_note(f"Temporaere Datei konnte nicht entfernt werden: {cleanup_error}")
        raise


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Verhindere mehrdeutige JSON-Objekte mit doppelten Schluesseln."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Doppelter JSON-Schluessel: {key}")
        result[key] = value
    return result


def _parse_canonical_line(line: bytes, line_number: int) -> dict[str, Any]:
    """Lese und validiere genau eine kanonische Journalzeile."""

    try:
        decoded = line.decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(parsed, dict):
            raise TypeError("Journalzeile ist kein JSON-Objekt")
        if canonical_json_bytes(parsed) != line:
            raise ValueError("Journalzeile ist nicht kanonisch serialisiert")
    except (RecursionError, TypeError, ValueError) as exc:
        raise EvidenceJournalError(
            f"Zeile {line_number} enthaelt kein eindeutiges UTF-8-JSON: {exc}"
        ) from exc
    return parsed


def _validate_timestamp(value: Any, line_number: int) -> str:
    """Validiere einen UTC-Zeitstempel aus dem Journal."""

    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceJournalError(f"Zeile {line_number} enthaelt keinen gueltigen UTC-Zeitstempel")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise EvidenceJournalError(
            f"Zeile {line_number} enthaelt keinen gueltigen UTC-Zeitstempel"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EvidenceJournalError(f"Zeile {line_number} enthaelt keinen UTC-Zeitstempel")
    return value


def _entry_from_mapping(
    raw_entry: Mapping[str, Any],
    *,
    expected_sequence: int,
    expected_previous_hash: str,
) -> JournalEntry:
    """Pruefe Struktur, Sequenz, Vorganger und Hash eines Datensatzes."""

    line_number = expected_sequence
    if set(raw_entry) != _JOURNAL_KEYS:
        raise EvidenceJournalError(f"Zeile {line_number} hat unerwartete oder fehlende Felder")
    if type(raw_entry["format_version"]) is not int or (
        raw_entry["format_version"] != JOURNAL_FORMAT_VERSION
    ):
        raise EvidenceJournalError(f"Zeile {line_number} hat eine unbekannte Formatversion")
    if type(raw_entry["sequence"]) is not int or raw_entry["sequence"] != expected_sequence:
        raise EvidenceJournalError(f"Zeile {line_number} hat eine ungueltige Sequenznummer")

    previous_hash = raw_entry["previous_event_sha256"]
    if not isinstance(previous_hash, str) or not hmac.compare_digest(
        previous_hash, expected_previous_hash
    ):
        raise EvidenceJournalError(f"Zeile {line_number} unterbricht die Hash-Kette")

    event = raw_entry["event"]
    if not isinstance(event, dict):
        raise EvidenceJournalError(f"Zeile {line_number} enthaelt kein Ereignisobjekt")
    timestamp = _validate_timestamp(raw_entry["recorded_at_utc"], line_number)
    event_hash = raw_entry["event_sha256"]
    if not isinstance(event_hash, str) or SHA256_PATTERN.fullmatch(event_hash) is None:
        raise EvidenceJournalError(f"Zeile {line_number} enthaelt keinen gueltigen SHA-256-Wert")

    hash_material = {key: value for key, value in raw_entry.items() if key != "event_sha256"}
    calculated_hash = hashlib.sha256(canonical_json_bytes(hash_material)).hexdigest()
    if not hmac.compare_digest(event_hash, calculated_hash):
        raise EvidenceJournalError(f"Zeile {line_number} hat einen unpassenden Ereignis-Hash")

    return JournalEntry(
        format_version=JOURNAL_FORMAT_VERSION,
        sequence=expected_sequence,
        recorded_at_utc=timestamp,
        previous_event_sha256=previous_hash,
        event=event,
        event_sha256=event_hash,
    )


def _read_entries(file_handle: BinaryIO) -> tuple[int, JournalEntry | None]:
    """Pruefe das Journal speicherschonend und liefere Zaehler sowie Kettenkopf."""

    file_handle.seek(0)
    entries_count = 0
    last_entry = None
    previous_hash = GENESIS_SHA256
    while True:
        raw_line = file_handle.readline(MAX_JOURNAL_LINE_BYTES + 1)
        if not raw_line:
            break
        line_number = entries_count + 1
        if len(raw_line) > MAX_JOURNAL_LINE_BYTES:
            raise EvidenceJournalError(f"Zeile {line_number} ueberschreitet das Groessenlimit")
        if not raw_line.endswith(b"\n"):
            raise EvidenceJournalError("Das Journal endet mit einer unvollstaendigen Zeile")
        line = raw_line[:-1]
        if not line:
            raise EvidenceJournalError(f"Zeile {line_number} ist leer")
        parsed = _parse_canonical_line(line, line_number)
        last_entry = _entry_from_mapping(
            parsed,
            expected_sequence=line_number,
            expected_previous_hash=previous_hash,
        )
        entries_count += 1
        previous_hash = last_entry.event_sha256
    return entries_count, last_entry


@contextmanager
def _windows_region_lock(file_handle: BinaryIO, locking_module: Any) -> Iterator[None]:
    """Sperre unter Windows eindeutig das erste Byte einer separaten Lockdatei."""

    file_handle.seek(0, os.SEEK_END)
    if file_handle.tell() == 0:
        file_handle.write(b"\0")
        file_handle.flush()
        os.fsync(file_handle.fileno())
    file_handle.seek(0)
    locking_module.locking(file_handle.fileno(), locking_module.LK_LOCK, 1)
    try:
        yield
    finally:
        file_handle.seek(0)
        locking_module.locking(file_handle.fileno(), locking_module.LK_UNLCK, 1)


@contextmanager
def _journal_process_lock(path: Path, *, exclusive: bool) -> Iterator[None]:
    """Sperre eine Sidecar-Datei plattformgerecht fuer den gesamten Journalzugriff."""

    lock_path = path.with_name(f".{path.name}.lock")
    _ensure_private_directory(path.parent)
    with _open_private_append(lock_path) as lock_handle:
        if os.name == "nt":  # pragma: no cover - Backend separat getestet
            import msvcrt

            # msvcrt bietet hier keinen Shared-Lock; Verifikation sperrt daher exklusiv.
            with _windows_region_lock(lock_handle, msvcrt):
                yield
            return

        import fcntl

        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(lock_handle.fileno(), operation)
        try:
            yield
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _locked_file(path: Path, *, exclusive: bool) -> Iterator[BinaryIO]:
    """Oeffne und sperre das Journal fuer einen konsistenten Prozesszugriff."""

    _ensure_private_directory(path.parent)
    with (
        _journal_process_lock(path, exclusive=exclusive),
        _open_private_append(path) as file_handle,
    ):
        yield file_handle


class EvidenceJournal:
    """Verwalte eine lokale kanonische JSONL-Hash-Kette im Append-only-Modus."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def append(
        self,
        event: Mapping[str, Any],
        *,
        recorded_at_utc: str | None = None,
    ) -> JournalEntry:
        """Fuege ein Ereignis ueber denselben atomaren Batch-Pfad an."""

        return self.append_many((event,), recorded_at_utc=recorded_at_utc)[0]

    def append_many(
        self,
        events: Iterable[Mapping[str, Any]],
        *,
        recorded_at_utc: str | None = None,
    ) -> tuple[JournalEntry, ...]:
        """Pruefe einmal und fuege einen vollstaendig vorgebauten Batch an."""

        normalized_events: list[dict[str, Any]] = []
        for event in events:
            normalized_event = _json_value(event)
            if not isinstance(normalized_event, dict):
                raise TypeError("Ein Journalereignis muss ein JSON-Objekt sein")
            normalized_events.append(normalized_event)
        if not normalized_events:
            return ()

        timestamp = _validate_timestamp(recorded_at_utc or _utc_now(), 0)
        existed_before = self.path.exists()
        journal_entries: list[JournalEntry] = []

        try:
            with _locked_file(self.path, exclusive=True) as file_handle:
                entries_count, last_entry = _read_entries(file_handle)
                previous_hash = (
                    last_entry.event_sha256 if last_entry is not None else GENESIS_SHA256
                )
                lines: list[bytes] = []
                for offset, normalized_event in enumerate(normalized_events, start=1):
                    sequence = entries_count + offset
                    hash_material: dict[str, Any] = {
                        "format_version": JOURNAL_FORMAT_VERSION,
                        "sequence": sequence,
                        "recorded_at_utc": timestamp,
                        "previous_event_sha256": previous_hash,
                        "event": normalized_event,
                    }
                    event_hash = hashlib.sha256(canonical_json_bytes(hash_material)).hexdigest()
                    complete_entry = {**hash_material, "event_sha256": event_hash}
                    line = canonical_json_bytes(complete_entry) + b"\n"
                    if len(line) > MAX_JOURNAL_LINE_BYTES:
                        raise EvidenceJournalError(
                            "Evidenzereignis ueberschreitet das Journal-Groessenlimit"
                        )
                    lines.append(line)
                    journal_entries.append(
                        JournalEntry(
                            format_version=JOURNAL_FORMAT_VERSION,
                            sequence=sequence,
                            recorded_at_utc=timestamp,
                            previous_event_sha256=previous_hash,
                            event=normalized_event,
                            event_sha256=event_hash,
                        )
                    )
                    previous_hash = event_hash

                payload = b"".join(lines)
                file_handle.seek(0, os.SEEK_END)
                if file_handle.tell() > MAX_JOURNAL_BYTES - len(payload):
                    raise EvidenceJournalError(
                        "Beweisjournal wuerde das feste Limit von 32 MiB "
                        "ueberschreiten. Archivieren Sie das bestehende Journal "
                        "unveraendert und starten Sie danach ein neues Journal."
                    )
                _write_all(file_handle.fileno(), payload)
                os.fsync(file_handle.fileno())
        except OSError as exc:
            raise EvidenceJournalError(
                f"Beweisjournal konnte nicht erweitert werden: {self.path}"
            ) from exc

        if not existed_before:
            _fsync_directory(self.path.parent)
        return tuple(journal_entries)

    def append_evidence(
        self,
        handshake: HandshakeResult,
        enrichment: NetworkEnrichment,
        vpn: VpnClassification,
    ) -> EvidenceRecord:
        """Speichere eine bestaetigte Handshake-Beobachtung und liefere ihr Modell."""

        if not handshake.confirmed:
            raise ValueError("Nur bestaetigte Handshakes duerfen als Evidenz gespeichert werden")
        try:
            candidate_ip = ipaddress.ip_address(handshake.candidate.ip)
            enrichment_ip = ipaddress.ip_address(enrichment.ip)
        except ValueError as exc:
            raise ValueError("Evidenz enthaelt eine ungueltige IP-Adresse") from exc
        if candidate_ip != enrichment_ip:
            raise ValueError("Handshake und Netzauskunft beziehen sich nicht auf dieselbe IP")
        if not candidate_ip.is_global or candidate_ip.is_multicast:
            raise ValueError("Evidenz-IP ist nicht global routbar")
        entry = self.append(
            {
                "event_type": "confirmed_bittorrent_handshake",
                "handshake": handshake,
                "enrichment": enrichment,
                "vpn": vpn,
            }
        )
        return EvidenceRecord(
            handshake=handshake,
            enrichment=enrichment,
            vpn=vpn,
            evidence_event_sha256=entry.event_sha256,
        )

    def verify(self) -> JournalVerification:
        """Pruefe Format und Hash-Kette des gesamten Journals ohne Netzaufrufe."""

        if not self.path.exists():
            return JournalVerification(
                valid=True,
                entries_count=0,
                last_event_sha256=None,
            )
        try:
            with _locked_file(self.path, exclusive=False) as file_handle:
                entries_count, last_entry = _read_entries(file_handle)
        except (EvidenceJournalError, OSError, TypeError, ValueError) as exc:
            return JournalVerification(
                valid=False,
                entries_count=0,
                last_event_sha256=None,
                error=str(exc),
            )
        return JournalVerification(
            valid=True,
            entries_count=entries_count,
            last_event_sha256=(last_entry.event_sha256 if last_entry is not None else None),
        )


def verify_journal(path: Path) -> JournalVerification:
    """Pruefe ein Journal ueber eine kleine funktionale Schnittstelle."""

    return EvidenceJournal(path).verify()
