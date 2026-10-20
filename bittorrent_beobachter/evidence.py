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
import stat
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from .models import EvidenceRecord, HandshakeResult, NetworkEnrichment, VpnClassification

JOURNAL_FORMAT_VERSION = 1
JOURNAL_TRANSACTION_FORMAT_VERSION = 1
GENESIS_SHA256 = "0" * 64
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_JOURNAL_LINE_BYTES = 4_000_000
MAX_TRANSACTION_HEADER_BYTES = 4_096
MAX_VERIFIED_BATCH_ENTRIES = 5

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


@dataclass(frozen=True, slots=True)
class _JournalHead:
    """Verifizierter Kettenkopf samt Dateisignatur fuer inkrementelle Appends."""

    entries_count: int
    last_event_sha256: str
    signature: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _PendingTransaction:
    """Dauerhaft vorbereiteter Append, der nach einem Absturz fortgesetzt wird."""

    base_size: int
    base_entries_count: int
    base_last_event_sha256: str
    final_entries_count: int
    final_event_sha256: str
    payload: bytes
    payload_sha256: str


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

    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) == mode:
        return

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


def _file_signature(file_handle: BinaryIO) -> tuple[int, int, int, int, int]:
    """Erkennt Aenderungen zwischen zwei Appends derselben Journalinstanz."""

    metadata = os.fstat(file_handle.fileno())
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


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


def _read_entries(
    file_handle: BinaryIO,
    *,
    end_offset: int | None = None,
) -> tuple[int, JournalEntry | None]:
    """Pruefe das Journal speicherschonend und liefere Zaehler sowie Kettenkopf."""

    entries_count = 0
    last_entry = None
    for entry in _iter_entries(file_handle, end_offset=end_offset):
        entries_count += 1
        last_entry = entry
    return entries_count, last_entry


def _iter_entries(
    file_handle: BinaryIO,
    *,
    end_offset: int | None = None,
) -> Iterator[JournalEntry]:
    """Validiere und durchlaufe Journalzeilen ohne anwachsende Ergebnisliste."""

    if end_offset is not None and (
        isinstance(end_offset, bool) or not isinstance(end_offset, int) or end_offset < 0
    ):
        raise ValueError("end_offset muss eine nichtnegative Ganzzahl sein")

    file_handle.seek(0)
    entries_count = 0
    previous_hash = GENESIS_SHA256
    while True:
        if end_offset is not None:
            position = file_handle.tell()
            if position == end_offset:
                break
            if position > end_offset:
                raise EvidenceJournalError("Der verifizierte Journalabschnitt ist ungueltig")
            read_size = min(MAX_JOURNAL_LINE_BYTES + 1, end_offset - position)
        else:
            read_size = MAX_JOURNAL_LINE_BYTES + 1
        raw_line = file_handle.readline(read_size)
        if not raw_line:
            if end_offset is not None:
                raise EvidenceJournalError("Der vorbereitete Journalabschnitt endet unerwartet")
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
        entry = _entry_from_mapping(
            parsed,
            expected_sequence=line_number,
            expected_previous_hash=previous_hash,
        )
        entries_count += 1
        previous_hash = entry.event_sha256
        yield entry


def _pending_transaction_path(journal_path: Path) -> Path:
    return journal_path.with_name(f".{journal_path.name}.pending")


def _write_pending_transaction(
    journal_path: Path,
    transaction: _PendingTransaction,
) -> Path:
    """Schreibt den vorbereiteten Append vor der Journalveraenderung dauerhaft."""

    pending_path = _pending_transaction_path(journal_path)
    if pending_path.exists():
        raise EvidenceJournalError(
            "Eine fruehere Journaltransaktion muss zuerst wiederhergestellt werden"
        )
    header = {
        "transaction_format_version": JOURNAL_TRANSACTION_FORMAT_VERSION,
        "base_size": transaction.base_size,
        "base_entries_count": transaction.base_entries_count,
        "base_last_event_sha256": transaction.base_last_event_sha256,
        "final_entries_count": transaction.final_entries_count,
        "final_event_sha256": transaction.final_event_sha256,
        "payload_length": len(transaction.payload),
        "payload_sha256": transaction.payload_sha256,
    }
    encoded_header = canonical_json_bytes(header) + b"\n"
    if len(encoded_header) > MAX_TRANSACTION_HEADER_BYTES:
        raise EvidenceJournalError("Journaltransaktions-Kopf ist unerwartet gross")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{pending_path.name}.",
        suffix=".tmp",
        dir=journal_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        _set_private_mode(temporary_path, 0o600)
        _write_all(descriptor, encoded_header)
        _write_all(descriptor, transaction.payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if pending_path.exists():
            raise EvidenceJournalError(
                "Eine fruehere Journaltransaktion wurde gleichzeitig angelegt"
            )
        os.replace(temporary_path, pending_path)
        _set_private_mode(pending_path, 0o600)
        _fsync_directory(journal_path.parent)
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError as cleanup_error:
            exc.add_note(
                f"Temporaere Journaltransaktion konnte nicht entfernt werden: {cleanup_error}"
            )
        raise
    return pending_path


def _read_pending_transaction(pending_path: Path) -> _PendingTransaction | None:
    """Liest eine vollstaendige vorbereitete Transaktion ohne Symlink-Folgen."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(pending_path, flags)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise EvidenceJournalError("Journaltransaktion ist keine regulaere Datei")
        with os.fdopen(descriptor, "rb", buffering=0) as file_handle:
            descriptor = -1
            raw_header = file_handle.readline(MAX_TRANSACTION_HEADER_BYTES + 1)
            if (
                not raw_header
                or len(raw_header) > MAX_TRANSACTION_HEADER_BYTES
                or not raw_header.endswith(b"\n")
            ):
                raise EvidenceJournalError("Journaltransaktion hat keinen gueltigen Kopf")
            encoded_header = raw_header[:-1]
            try:
                header = json.loads(
                    encoded_header.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                )
            except (UnicodeError, TypeError, ValueError) as exc:
                raise EvidenceJournalError(
                    "Journaltransaktion enthaelt keinen eindeutigen JSON-Kopf"
                ) from exc
            expected_keys = {
                "transaction_format_version",
                "base_size",
                "base_entries_count",
                "base_last_event_sha256",
                "final_entries_count",
                "final_event_sha256",
                "payload_length",
                "payload_sha256",
            }
            if not isinstance(header, dict) or set(header) != expected_keys:
                raise EvidenceJournalError("Journaltransaktion hat unerwartete Felder")
            if canonical_json_bytes(header) != encoded_header:
                raise EvidenceJournalError(
                    "Journaltransaktions-Kopf ist nicht kanonisch serialisiert"
                )

            integer_fields = (
                "transaction_format_version",
                "base_size",
                "base_entries_count",
                "final_entries_count",
                "payload_length",
            )
            if any(type(header[field]) is not int for field in integer_fields):
                raise EvidenceJournalError("Journaltransaktion enthaelt ungueltige Ganzzahlfelder")
            if header["transaction_format_version"] != JOURNAL_TRANSACTION_FORMAT_VERSION:
                raise EvidenceJournalError("Journaltransaktion hat eine unbekannte Formatversion")
            if (
                header["base_size"] < 0
                or header["base_entries_count"] < 0
                or header["payload_length"] <= 0
                or header["final_entries_count"] <= header["base_entries_count"]
            ):
                raise EvidenceJournalError(
                    "Journaltransaktion enthaelt ungueltige Groessen- oder Sequenzwerte"
                )
            for field in (
                "base_last_event_sha256",
                "final_event_sha256",
                "payload_sha256",
            ):
                value = header[field]
                if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
                    raise EvidenceJournalError(
                        f"Journaltransaktion enthaelt keinen gueltigen Wert fuer {field}"
                    )

            payload = file_handle.read(header["payload_length"] + 1)
            if len(payload) != header["payload_length"]:
                raise EvidenceJournalError(
                    "Journaltransaktion ist unvollstaendig oder enthaelt Zusatzdaten"
                )
            if not payload.endswith(b"\n"):
                raise EvidenceJournalError(
                    "Journaltransaktion endet mit einer unvollstaendigen Zeile"
                )
            if payload.count(b"\n") != (
                header["final_entries_count"] - header["base_entries_count"]
            ):
                raise EvidenceJournalError(
                    "Journaltransaktion enthaelt nicht die erwartete Ereigniszahl"
                )
            calculated_payload_hash = hashlib.sha256(payload).hexdigest()
            if not hmac.compare_digest(
                calculated_payload_hash,
                header["payload_sha256"],
            ):
                raise EvidenceJournalError("Journaltransaktion hat einen unpassenden Nutzlast-Hash")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    return _PendingTransaction(
        base_size=header["base_size"],
        base_entries_count=header["base_entries_count"],
        base_last_event_sha256=header["base_last_event_sha256"],
        final_entries_count=header["final_entries_count"],
        final_event_sha256=header["final_event_sha256"],
        payload=payload,
        payload_sha256=header["payload_sha256"],
    )


def _recover_pending_transaction(
    journal_path: Path,
    file_handle: BinaryIO,
) -> tuple[int, JournalEntry | None] | None:
    """Rollt einen nachweisbar vorbereiteten, teilweise geschriebenen Batch vor."""

    pending_path = _pending_transaction_path(journal_path)
    transaction = _read_pending_transaction(pending_path)
    if transaction is None:
        return None

    base_count, base_last_entry = _read_entries(
        file_handle,
        end_offset=transaction.base_size,
    )
    base_hash = base_last_entry.event_sha256 if base_last_entry is not None else GENESIS_SHA256
    if base_count != transaction.base_entries_count or not hmac.compare_digest(
        base_hash,
        transaction.base_last_event_sha256,
    ):
        raise EvidenceJournalError("Journalbasis passt nicht zur vorbereiteten Transaktion")

    current_size = os.fstat(file_handle.fileno()).st_size
    final_size = transaction.base_size + len(transaction.payload)
    if current_size < transaction.base_size or current_size > final_size:
        raise EvidenceJournalError("Journalgroesse passt nicht zur vorbereiteten Transaktion")
    file_handle.seek(transaction.base_size)
    existing_tail = file_handle.read(current_size - transaction.base_size)
    if existing_tail != transaction.payload[: len(existing_tail)]:
        raise EvidenceJournalError("Journalende passt nicht zur vorbereiteten Transaktion")
    if existing_tail != transaction.payload:
        file_handle.truncate(transaction.base_size)
        file_handle.seek(transaction.base_size)
        _write_all(file_handle.fileno(), transaction.payload)
        os.fsync(file_handle.fileno())

    entries_count, last_entry = _read_entries(file_handle)
    last_hash = last_entry.event_sha256 if last_entry is not None else GENESIS_SHA256
    if entries_count != transaction.final_entries_count or not hmac.compare_digest(
        last_hash,
        transaction.final_event_sha256,
    ):
        raise EvidenceJournalError(
            "Wiederhergestellte Journaltransaktion stimmt nicht mit ihrem Kettenkopf ueberein"
        )
    pending_path.unlink()
    _fsync_directory(journal_path.parent)
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
        self._head: _JournalHead | None = None

    def _remember_head(
        self,
        file_handle: BinaryIO,
        entries_count: int,
        last_event_sha256: str,
    ) -> None:
        self._head = _JournalHead(
            entries_count=entries_count,
            last_event_sha256=last_event_sha256,
            signature=_file_signature(file_handle),
        )

    def _current_head(self, file_handle: BinaryIO) -> tuple[int, str]:
        """Verifiziert einmal und nutzt danach nur einen unveraenderten Dateikopf."""

        recovered = _recover_pending_transaction(self.path, file_handle)
        if recovered is not None:
            entries_count, last_entry = recovered
            last_hash = last_entry.event_sha256 if last_entry is not None else GENESIS_SHA256
            self._remember_head(file_handle, entries_count, last_hash)
            return entries_count, last_hash

        signature = _file_signature(file_handle)
        if self._head is not None and self._head.signature == signature:
            return self._head.entries_count, self._head.last_event_sha256

        entries_count, last_entry = _read_entries(file_handle)
        last_hash = last_entry.event_sha256 if last_entry is not None else GENESIS_SHA256
        self._remember_head(file_handle, entries_count, last_hash)
        return entries_count, last_hash

    def iter_verified_batches(
        self,
        *,
        batch_size: int = MAX_VERIFIED_BATCH_ENTRIES,
    ) -> Iterator[tuple[JournalEntry, ...]]:
        """Liefere ein vollstaendig validiertes Journal in kleinen Batches.

        Vor der ersten Ausgabe wird ein eventuell vorbereiteter Crash-Append unter
        exklusiver Prozesssperre wiederhergestellt und der gesamte bis dahin
        vorhandene Journalabschnitt validiert. Danach liest der Iterator genau
        diesen bereits geoeffneten, unveraenderlichen Praefix erneut; spaetere
        kooperative Appends sind nicht Teil dieses Snapshots. Im Speicher liegt
        dabei nie mehr als ein Batch mit hoechstens fuenf Eintraegen.
        """

        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or not 1 <= batch_size <= MAX_VERIFIED_BATCH_ENTRIES
        ):
            raise ValueError(f"batch_size muss zwischen 1 und {MAX_VERIFIED_BATCH_ENTRIES} liegen")

        pending_path = _pending_transaction_path(self.path)
        file_handle: BinaryIO | None = None
        try:
            # Die exklusive Sperre ist fuer eine moegliche Recovery erforderlich.
            # Der danach offen gehaltene Deskriptor bildet zusammen mit end_offset
            # einen append-stabilen Snapshot, ohne Schreiber waehrend der Ausgabe
            # aller Batches zu blockieren.
            with _journal_process_lock(self.path, exclusive=True):
                if not self.path.exists() and not pending_path.exists():
                    self._head = None
                    return
                file_handle = _open_private_append(self.path)
                recovered = _recover_pending_transaction(self.path, file_handle)
                if recovered is None:
                    entries_count, last_entry = _read_entries(file_handle)
                else:
                    entries_count, last_entry = recovered
                last_hash = last_entry.event_sha256 if last_entry is not None else GENESIS_SHA256
                snapshot_end_offset = os.fstat(file_handle.fileno()).st_size
                self._remember_head(file_handle, entries_count, last_hash)

            batch: list[JournalEntry] = []
            for entry in _iter_entries(file_handle, end_offset=snapshot_end_offset):
                batch.append(entry)
                if len(batch) == batch_size:
                    yield tuple(batch)
                    batch.clear()
            if batch:
                yield tuple(batch)
        except EvidenceJournalError:
            self._head = None
            raise
        except OSError as exc:
            self._head = None
            raise EvidenceJournalError(
                f"Beweisjournal konnte nicht gelesen werden: {self.path}"
            ) from exc
        finally:
            if file_handle is not None:
                file_handle.close()

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
                entries_count, previous_hash = self._current_head(file_handle)
                base_size = os.fstat(file_handle.fileno()).st_size
                base_last_hash = previous_hash
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
                transaction = _PendingTransaction(
                    base_size=base_size,
                    base_entries_count=entries_count,
                    base_last_event_sha256=base_last_hash,
                    final_entries_count=entries_count + len(journal_entries),
                    final_event_sha256=previous_hash,
                    payload=payload,
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                )
                pending_path = _write_pending_transaction(self.path, transaction)
                if os.fstat(file_handle.fileno()).st_size != base_size:
                    raise EvidenceJournalError(
                        "Journal wurde waehrend des vorbereiteten Appends veraendert"
                    )
                file_handle.seek(0, os.SEEK_END)
                _write_all(file_handle.fileno(), payload)
                os.fsync(file_handle.fileno())
                pending_path.unlink()
                _fsync_directory(self.path.parent)
                self._remember_head(
                    file_handle,
                    transaction.final_entries_count,
                    transaction.final_event_sha256,
                )
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
        """Pruefe die ganze Hash-Kette und beende vorbereitete Crash-Appends."""

        pending_path = _pending_transaction_path(self.path)
        if not self.path.exists() and not pending_path.exists():
            self._head = None
            return JournalVerification(
                valid=True,
                entries_count=0,
                last_event_sha256=None,
            )
        try:
            # Die exklusive Sperre ist erforderlich, weil eine gueltige, vor dem
            # Absturz vorbereitete Transaktion hier zu Ende geschrieben werden kann.
            with _locked_file(self.path, exclusive=True) as file_handle:
                recovered = _recover_pending_transaction(self.path, file_handle)
                if recovered is None:
                    entries_count, last_entry = _read_entries(file_handle)
                else:
                    entries_count, last_entry = recovered
                last_hash = last_entry.event_sha256 if last_entry is not None else GENESIS_SHA256
                self._remember_head(file_handle, entries_count, last_hash)
        except (EvidenceJournalError, OSError, TypeError, ValueError) as exc:
            self._head = None
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
