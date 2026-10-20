"""Stelle journalisierte Evidenz nach einem abgebrochenen Lauf wieder her."""

from __future__ import annotations

import hmac
import json
import os
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import EvidenceJournal, canonical_json_bytes
from .models import EvidenceRecord
from .run_store import RunStore, RunStoreError, decode_evidence_journal_event

MAX_RECOVERY_BATCH_SIZE = 5
RECOVERY_MIN_FREE_SPACE_BYTES = 100_000_000
_PUBLISH_STATE_FILENAME = ".recovery-publish-state.sqlite3"
_LEGACY_SCAN_STARTED_KEYS = frozenset(
    {
        "event_type",
        "run_id",
        "config_sha256",
        "software_sha256",
        "targets",
        "network_enrichment_enabled",
    }
)
_CURRENT_SCAN_STARTED_KEYS = _LEGACY_SCAN_STARTED_KEYS | {
    "config_snapshot",
    "config_snapshot_file_sha256",
}
_LEGACY_OFFERING_ERROR = "Evidenz benoetigt einen positiven Verfuegbarkeitsbefund."


class EvidenceRecoveryError(RuntimeError):
    """Das verifizierte Journal passt nicht eindeutig zu seinen Laufdatenbanken."""


@dataclass(frozen=True, slots=True)
class RecoveredEvidenceBatch:
    """Kleiner Evidenzbatch samt seiner validierten Laufbindung."""

    run_id: str
    config_sha256: str
    software_sha256: str
    config_snapshot: str | None
    config_snapshot_file_sha256: str | None
    records: tuple[EvidenceRecord, ...]


@dataclass(frozen=True, slots=True)
class RecoverySummary:
    """Kompakte Bilanz einer vollstaendig abgeschlossenen Recovery."""

    scanned_entries: int = 0
    evidence_events: int = 0
    inserted_records: int = 0
    skipped_legacy_runs: int = 0


@dataclass(frozen=True, slots=True)
class RecoveredRunContext:
    """Gebundener Lauf, dessen Datenbank noch positive Handshakes enthaelt."""

    run_id: str
    config_sha256: str
    software_sha256: str
    config_snapshot: str | None
    config_snapshot_file_sha256: str | None
    store_path: Path
    terminal_event: str | None


@dataclass(frozen=True, slots=True)
class LegacyRecoveryNotice:
    """Begruendeter Hinweis zu einem nicht automatisch migrierbaren Altlauf."""

    run_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class _StartedRun:
    run_id: str
    config_sha256: str
    software_sha256: str
    config_snapshot: str | None
    config_snapshot_file_sha256: str | None
    legacy_schema: bool
    terminal_event: str | None = None
    report_manifest_bound: bool = False
    legacy_skip_reason: str | None = None


@dataclass(slots=True)
class _PendingRunBatch:
    binding: _StartedRun
    records: list[EvidenceRecord]


RecoveryCallback = Callable[[RecoveredEvidenceBatch], None]
IncompleteRunCallback = Callable[[RecoveredRunContext], None]
LegacyNoticeCallback = Callable[[LegacyRecoveryNotice], None]


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise EvidenceRecoveryError(f"{label} ist kein gueltiges JSON-Objekt.")
    return value


def _require_safe_run_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or value.strip() != value
        or any(
            not (character.isascii() and (character.isalnum() or character in "._-"))
            for character in value
        )
    ):
        raise EvidenceRecoveryError(
            "run_id muss eine nichtleere ASCII-Kennung aus Buchstaben, Ziffern, Punkt, "
            "Unterstrich oder Bindestrich sein."
        )
    return value


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceRecoveryError(f"{label} muss ein kleingeschriebener SHA-256-Hexwert sein.")
    return value


def _require_safe_basename(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise EvidenceRecoveryError(f"{label} muss ein sicherer Dateiname ohne Pfadanteil sein.")
    return value


def _validate_started_targets(value: object) -> None:
    if not isinstance(value, list):
        raise EvidenceRecoveryError("scan_started.targets muss eine Liste sein.")
    for index, target_value in enumerate(value):
        target = _require_mapping(target_value, f"scan_started.targets[{index}]")
        if set(target) != {"label", "info_hash"}:
            raise EvidenceRecoveryError(f"scan_started.targets[{index}] hat unerwartete Felder.")
        label = target["label"]
        info_hash = target["info_hash"]
        if not isinstance(label, str) or not label.strip():
            raise EvidenceRecoveryError(
                f"scan_started.targets[{index}].label muss nichtleerer Text sein."
            )
        if (
            not isinstance(info_hash, str)
            or len(info_hash) != 40
            or any(character not in "0123456789abcdef" for character in info_hash)
        ):
            raise EvidenceRecoveryError(f"scan_started.targets[{index}].info_hash ist ungueltig.")


def _decode_scan_started(event: object) -> _StartedRun:
    data = _require_mapping(event, "scan_started-Ereignis")
    event_keys = frozenset(data)
    if event_keys not in {_LEGACY_SCAN_STARTED_KEYS, _CURRENT_SCAN_STARTED_KEYS}:
        raise EvidenceRecoveryError("scan_started-Ereignis hat fehlende oder unerwartete Felder.")
    if data["event_type"] != "scan_started":
        raise EvidenceRecoveryError("Interner Fehler beim Dekodieren von scan_started.")

    run_id = _require_safe_run_id(data["run_id"])
    config_sha256 = _require_sha256(data["config_sha256"], "config_sha256")
    software_sha256 = _require_sha256(data["software_sha256"], "software_sha256")
    legacy_schema = event_keys == _LEGACY_SCAN_STARTED_KEYS
    config_snapshot: str | None = None
    config_snapshot_file_sha256: str | None = None
    if not legacy_schema:
        config_snapshot_file_sha256 = _require_sha256(
            data["config_snapshot_file_sha256"],
            "config_snapshot_file_sha256",
        )
        raw_config_snapshot = data["config_snapshot"]
        expected_snapshot = f"{run_id}.config.json"
        if not isinstance(raw_config_snapshot, str) or not hmac.compare_digest(
            raw_config_snapshot,
            expected_snapshot,
        ):
            raise EvidenceRecoveryError(
                "scan_started.config_snapshot ist keine sichere, zum Lauf gehoerende "
                "Basename-Kennung."
            )
        config_snapshot = raw_config_snapshot
    _validate_started_targets(data["targets"])
    if not isinstance(data["network_enrichment_enabled"], bool):
        raise EvidenceRecoveryError(
            "scan_started.network_enrichment_enabled muss ein Wahrheitswert sein."
        )
    return _StartedRun(
        run_id=run_id,
        config_sha256=config_sha256,
        software_sha256=software_sha256,
        config_snapshot=config_snapshot,
        config_snapshot_file_sha256=config_snapshot_file_sha256,
        legacy_schema=legacy_schema,
    )


def _create_binding_index(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE run_bindings (
            run_id TEXT PRIMARY KEY,
            config_sha256 TEXT NOT NULL,
            software_sha256 TEXT NOT NULL,
            config_snapshot TEXT,
            config_snapshot_file_sha256 TEXT,
            terminal_event TEXT,
            report_manifest_bound INTEGER NOT NULL DEFAULT 0
                CHECK (report_manifest_bound IN (0, 1)),
            legacy_schema INTEGER NOT NULL CHECK (legacy_schema IN (0, 1)),
            legacy_skip_reason TEXT,
            evidence_indexed INTEGER NOT NULL DEFAULT 0
                CHECK (evidence_indexed IN (0, 1))
        );
        CREATE TABLE known_evidence (
            run_id TEXT NOT NULL,
            info_hash TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            PRIMARY KEY (run_id, info_hash, ip, port),
            FOREIGN KEY (run_id) REFERENCES run_bindings(run_id) ON DELETE CASCADE
        );
        CREATE TABLE journal_evidence (
            sequence INTEGER PRIMARY KEY,
            run_id TEXT NOT NULL,
            event_json BLOB NOT NULL,
            event_sha256 TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES run_bindings(run_id) ON DELETE CASCADE
        )
        """
    )
    connection.commit()


def _store_started_run(connection: sqlite3.Connection, binding: _StartedRun) -> None:
    try:
        connection.execute(
            """
            INSERT INTO run_bindings (
                run_id,
                config_sha256,
                software_sha256,
                config_snapshot,
                config_snapshot_file_sha256,
                legacy_schema
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                binding.run_id,
                binding.config_sha256,
                binding.software_sha256,
                binding.config_snapshot,
                binding.config_snapshot_file_sha256,
                int(binding.legacy_schema),
            ),
        )
        connection.commit()
    except sqlite3.IntegrityError as exc:
        connection.rollback()
        raise EvidenceRecoveryError(
            f"Lauf {binding.run_id!r} besitzt ein doppeltes scan_started-Ereignis."
        ) from exc


def _load_started_run(connection: sqlite3.Connection, run_id: str) -> _StartedRun:
    row = connection.execute(
        """
        SELECT
            run_id,
            config_sha256,
            software_sha256,
            config_snapshot,
            config_snapshot_file_sha256,
            legacy_schema,
            terminal_event,
            report_manifest_bound,
            legacy_skip_reason
        FROM run_bindings
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        raise EvidenceRecoveryError(
            f"Evidenz fuer Lauf {run_id!r} steht vor dem zugehoerigen scan_started-Ereignis."
        )
    return _StartedRun(
        run_id=str(row[0]),
        config_sha256=str(row[1]),
        software_sha256=str(row[2]),
        config_snapshot=str(row[3]) if row[3] is not None else None,
        config_snapshot_file_sha256=str(row[4]) if row[4] is not None else None,
        legacy_schema=bool(row[5]),
        terminal_event=str(row[6]) if row[6] is not None else None,
        report_manifest_bound=bool(row[7]),
        legacy_skip_reason=str(row[8]) if row[8] is not None else None,
    )


def _mark_legacy_skip(
    connection: sqlite3.Connection,
    binding: _StartedRun,
    reason: str,
) -> None:
    if not binding.legacy_schema:
        raise EvidenceRecoveryError("Nur ein Legacy-Lauf darf gezielt uebersprungen werden.")
    if not reason.strip():
        raise ValueError("Legacy-Skip benoetigt eine Begruendung.")
    connection.execute(
        """
        UPDATE run_bindings
        SET legacy_skip_reason = COALESCE(legacy_skip_reason, ?)
        WHERE run_id = ? AND legacy_schema = 1
        """,
        (reason, binding.run_id),
    )
    connection.commit()


def _mark_terminal_event(connection: sqlite3.Connection, event: object) -> None:
    data = _require_mapping(event, "terminales Laufereignis")
    terminal_event = data.get("event_type")
    if terminal_event not in {"scan_completed", "scan_cancelled", "scan_failed"}:
        raise EvidenceRecoveryError("Unbekanntes terminales Laufereignis.")
    run_id = _require_safe_run_id(data.get("run_id"))
    binding = _load_started_run(connection, run_id)
    config_sha256 = _require_sha256(data.get("config_sha256"), "config_sha256")
    software_sha256 = _require_sha256(data.get("software_sha256"), "software_sha256")
    if not hmac.compare_digest(config_sha256, binding.config_sha256):
        raise EvidenceRecoveryError(
            f"Terminales Laufereignis fuer {run_id!r} hat eine abweichende Konfiguration."
        )
    if not hmac.compare_digest(software_sha256, binding.software_sha256):
        raise EvidenceRecoveryError(
            f"Terminales Laufereignis fuer {run_id!r} hat einen abweichenden Softwarestand."
        )

    config_snapshot = data.get("config_snapshot")
    snapshot_sha256 = data.get("config_snapshot_file_sha256")
    if (config_snapshot is None) != (snapshot_sha256 is None):
        raise EvidenceRecoveryError(
            f"Terminales Laufereignis fuer {run_id!r} hat eine unvollstaendige Snapshot-Bindung."
        )
    if config_snapshot is not None:
        validated_snapshot_sha256 = _require_sha256(
            snapshot_sha256,
            "config_snapshot_file_sha256",
        )
        if (
            binding.config_snapshot is None
            or binding.config_snapshot_file_sha256 is None
            or not isinstance(config_snapshot, str)
            or not hmac.compare_digest(
                config_snapshot,
                binding.config_snapshot,
            )
        ):
            raise EvidenceRecoveryError(
                f"Terminales Laufereignis fuer {run_id!r} verweist auf einen anderen Snapshot."
            )
        if not hmac.compare_digest(
            validated_snapshot_sha256,
            binding.config_snapshot_file_sha256,
        ):
            raise EvidenceRecoveryError(
                f"Terminales Laufereignis fuer {run_id!r} hat einen anderen Snapshot-Hash."
            )

    report_manifest = data.get("report_manifest")
    report_manifest_sha256 = data.get("report_manifest_sha256")
    if (report_manifest is None) != (report_manifest_sha256 is None):
        raise EvidenceRecoveryError(
            f"Terminales Laufereignis fuer {run_id!r} hat eine unvollstaendige Manifest-Bindung."
        )
    report_manifest_bound = report_manifest is not None
    if report_manifest_bound:
        _require_safe_basename(report_manifest, "report_manifest")
        _require_sha256(report_manifest_sha256, "report_manifest_sha256")
        report_file_count = data.get("report_file_count")
        if (
            isinstance(report_file_count, bool)
            or not isinstance(report_file_count, int)
            or report_file_count < 1
        ):
            raise EvidenceRecoveryError(
                f"Terminales Laufereignis fuer {run_id!r} hat keine gueltige Berichtsanzahl."
            )
    elif data.get("report_file_count") is not None:
        raise EvidenceRecoveryError(
            f"Terminales Laufereignis fuer {run_id!r} nennt Berichte ohne Manifest-Bindung."
        )

    updated = connection.execute(
        """
        UPDATE run_bindings
        SET terminal_event = ?, report_manifest_bound = ?
        WHERE run_id = ? AND terminal_event IS NULL
        """,
        (terminal_event, int(report_manifest_bound), run_id),
    )
    if updated.rowcount != 1:
        connection.rollback()
        raise EvidenceRecoveryError(f"Lauf {run_id!r} besitzt mehrere terminale Journalereignisse.")
    connection.commit()


def _safe_run_store_path(evidence_dir: Path, run_id: str) -> Path:
    runs_dir = evidence_dir / "runs"
    if runs_dir.is_symlink() or not runs_dir.is_dir():
        raise EvidenceRecoveryError(
            f"Laufdatenbank-Verzeichnis fehlt oder ist unsicher: {runs_dir}"
        )
    database_path = runs_dir / f"{run_id}.sqlite3"
    if database_path.is_symlink() or not database_path.is_file():
        raise EvidenceRecoveryError(
            f"Laufdatenbank fuer {run_id!r} fehlt oder ist unsicher: {database_path}"
        )
    try:
        resolved_runs_dir = runs_dir.resolve(strict=True)
        resolved_database = database_path.resolve(strict=True)
    except OSError as exc:
        raise EvidenceRecoveryError(
            f"Laufdatenbankpfad fuer {run_id!r} konnte nicht sicher aufgeloest werden."
        ) from exc
    if resolved_database.parent != resolved_runs_dir:
        raise EvidenceRecoveryError(
            f"Laufdatenbank fuer {run_id!r} liegt ausserhalb des privaten Run-Verzeichnisses."
        )
    return database_path


def _enforce_recovery_capacity(path: Path) -> None:
    try:
        free_bytes = shutil.disk_usage(path).free
    except OSError as exc:
        raise EvidenceRecoveryError(
            "Freier Speicherplatz fuer den Recovery-Index konnte nicht bestimmt werden."
        ) from exc
    if free_bytes < RECOVERY_MIN_FREE_SPACE_BYTES:
        raise EvidenceRecoveryError(
            "Weniger als 100 MB freier Speicherplatz fuer den temporaeren Recovery-Index."
        )


def _open_publish_state(evidence_dir: Path) -> sqlite3.Connection:
    state_path = evidence_dir / _PUBLISH_STATE_FILENAME
    if state_path.is_symlink() or (state_path.exists() and not state_path.is_file()):
        raise EvidenceRecoveryError(
            f"Recovery-Publikationsstatus fehlt oder ist unsicher: {state_path}"
        )
    if not state_path.exists():
        try:
            state_path.touch(mode=0o600, exist_ok=False)
        except OSError as exc:
            raise EvidenceRecoveryError(
                "Recovery-Publikationsstatus konnte nicht sicher angelegt werden."
            ) from exc
    if os.name != "nt":
        try:
            state_path.chmod(0o600)
        except OSError as exc:
            raise EvidenceRecoveryError(
                "Recovery-Publikationsstatus konnte nicht privat gesetzt werden."
            ) from exc
    try:
        if state_path.resolve(strict=True).parent != evidence_dir.resolve(strict=True):
            raise EvidenceRecoveryError(
                "Recovery-Publikationsstatus liegt ausserhalb des Evidenzverzeichnisses."
            )
        connection = sqlite3.connect(state_path)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_reconciled_reports (
                event_sha256 TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                config_sha256 TEXT NOT NULL,
                software_sha256 TEXT NOT NULL,
                config_snapshot TEXT,
                config_snapshot_file_sha256 TEXT
            )
            """
        )
        connection.commit()
    except EvidenceRecoveryError:
        raise
    except (OSError, sqlite3.Error) as exc:
        if "connection" in locals():
            connection.close()
        raise EvidenceRecoveryError(
            "Recovery-Publikationsstatus konnte nicht geoeffnet werden."
        ) from exc
    return connection


def _publish_binding_values(
    binding: _StartedRun,
    event_sha256: str,
) -> tuple[str, str, str, str, str | None, str | None]:
    return (
        event_sha256,
        binding.run_id,
        binding.config_sha256,
        binding.software_sha256,
        binding.config_snapshot,
        binding.config_snapshot_file_sha256,
    )


def _validate_publish_binding(
    row: tuple[object, ...],
    binding: _StartedRun,
    event_sha256: str,
) -> None:
    actual = tuple(str(value) if value is not None else None for value in row)
    if actual != _publish_binding_values(binding, event_sha256):
        raise EvidenceRecoveryError(
            f"Recovery-Publikationsstatus fuer Lauf {binding.run_id!r} ist widerspruechlich."
        )


def _mark_publish_pending(
    publish_state: sqlite3.Connection,
    binding: _StartedRun,
    records: list[EvidenceRecord],
) -> None:
    try:
        for record in records:
            event_sha256 = _require_sha256(
                record.evidence_event_sha256,
                "evidence_event_sha256",
            )
            row = publish_state.execute(
                """
                SELECT
                    event_sha256,
                    run_id,
                    config_sha256,
                    software_sha256,
                    config_snapshot,
                    config_snapshot_file_sha256
                FROM pending_reconciled_reports
                WHERE event_sha256 = ?
                """,
                (event_sha256,),
            ).fetchone()
            if row is not None:
                _validate_publish_binding(row, binding, event_sha256)
                continue
            publish_state.execute(
                """
                INSERT INTO pending_reconciled_reports (
                    event_sha256,
                    run_id,
                    config_sha256,
                    software_sha256,
                    config_snapshot,
                    config_snapshot_file_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                _publish_binding_values(binding, event_sha256),
            )
        publish_state.commit()
    except sqlite3.Error as exc:
        publish_state.rollback()
        raise EvidenceRecoveryError(
            "Ausstehende Recovery-Berichte konnten nicht dauerhaft vorgemerkt werden."
        ) from exc


def _has_publish_pending(
    publish_state: sqlite3.Connection,
    binding: _StartedRun,
    records: list[EvidenceRecord],
) -> bool:
    has_pending = False
    try:
        for record in records:
            event_sha256 = _require_sha256(
                record.evidence_event_sha256,
                "evidence_event_sha256",
            )
            row = publish_state.execute(
                """
                SELECT
                    event_sha256,
                    run_id,
                    config_sha256,
                    software_sha256,
                    config_snapshot,
                    config_snapshot_file_sha256
                FROM pending_reconciled_reports
                WHERE event_sha256 = ?
                """,
                (event_sha256,),
            ).fetchone()
            if row is not None:
                _validate_publish_binding(row, binding, event_sha256)
                has_pending = True
    except sqlite3.Error as exc:
        raise EvidenceRecoveryError(
            "Ausstehende Recovery-Berichte konnten nicht gelesen werden."
        ) from exc
    return has_pending


def _acknowledge_publish_pending(
    publish_state: sqlite3.Connection,
    binding: _StartedRun,
    records: list[EvidenceRecord],
) -> None:
    try:
        for record in records:
            publish_state.execute(
                """
                DELETE FROM pending_reconciled_reports
                WHERE event_sha256 = ? AND run_id = ?
                """,
                (record.evidence_event_sha256, binding.run_id),
            )
        publish_state.commit()
    except sqlite3.Error as exc:
        publish_state.rollback()
        raise EvidenceRecoveryError(
            "Fertiggestellte Recovery-Berichte konnten nicht quittiert werden."
        ) from exc


def _evidence_key(record: EvidenceRecord) -> tuple[str, str, int]:
    candidate = record.handshake.candidate
    return candidate.info_hash_hex, candidate.ip, candidate.port


def _ensure_known_evidence_index(
    connection: sqlite3.Connection,
    run_id: str,
    store: RunStore,
    evidence_dir: Path,
) -> None:
    row = connection.execute(
        "SELECT evidence_indexed FROM run_bindings WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise EvidenceRecoveryError(f"Recovery-Index kennt Lauf {run_id!r} nicht.")
    if int(row[0]) == 1:
        return

    indexed_since_capacity_check = 0
    try:
        connection.execute("BEGIN IMMEDIATE")
        for existing_record in store.iter_evidence_records(batch_size=MAX_RECOVERY_BATCH_SIZE):
            info_hash, ip, port = _evidence_key(existing_record)
            connection.execute(
                """
                INSERT INTO known_evidence (run_id, info_hash, ip, port)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, info_hash, ip, port),
            )
            indexed_since_capacity_check += 1
            if indexed_since_capacity_check == MAX_RECOVERY_BATCH_SIZE:
                _enforce_recovery_capacity(evidence_dir)
                indexed_since_capacity_check = 0
        connection.execute(
            "UPDATE run_bindings SET evidence_indexed = 1 WHERE run_id = ?",
            (run_id,),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _known_evidence_keys(
    connection: sqlite3.Connection,
    run_id: str,
    records: list[EvidenceRecord],
) -> set[tuple[str, str, int]]:
    known: set[tuple[str, str, int]] = set()
    for record in records:
        key = _evidence_key(record)
        row = connection.execute(
            """
            SELECT 1
            FROM known_evidence
            WHERE run_id = ? AND info_hash = ? AND ip = ? AND port = ?
            """,
            (run_id, *key),
        ).fetchone()
        if row is not None:
            known.add(key)
    return known


def _decode_evidence_for_started_run(
    event: object,
    event_sha256: str,
    connection: sqlite3.Connection,
) -> tuple[_StartedRun, EvidenceRecord | None]:
    event_data = _require_mapping(event, "Evidenzereignis")
    run_id = _require_safe_run_id(event_data.get("run_id"))
    binding = _load_started_run(connection, run_id)
    if binding.legacy_skip_reason is not None:
        return binding, None
    try:
        decoded = decode_evidence_journal_event(
            event_data,
            event_sha256,
            expected_run_id=binding.run_id,
            expected_config_sha256=binding.config_sha256,
            expected_software_sha256=binding.software_sha256,
        )
    except RunStoreError as exc:
        if binding.legacy_schema and str(exc) == _LEGACY_OFFERING_ERROR:
            _mark_legacy_skip(
                connection,
                binding,
                "Legacy-Evidenz verwendet die fruehere Positivsemantik ohne "
                "zeitgleiche Stueckverfuegbarkeit und UNCHOKE; automatische "
                "Migration wurde ausgelassen.",
            )
            return binding, None
        raise EvidenceRecoveryError(
            f"Evidenzereignis fuer Lauf {run_id!r} ist nicht an scan_started gebunden: {exc}"
        ) from exc
    return binding, decoded.record


def _reconcile_run_batch(
    evidence_dir: Path,
    pending: _PendingRunBatch,
    binding_index: sqlite3.Connection,
    publish_state: sqlite3.Connection,
) -> tuple[EvidenceRecord, ...] | None:
    try:
        database_path = _safe_run_store_path(evidence_dir, pending.binding.run_id)
    except EvidenceRecoveryError as exc:
        if not pending.binding.legacy_schema:
            raise
        _mark_legacy_skip(
            binding_index,
            pending.binding,
            f"Legacy-Laufdatenbank ist nicht mehr verfuegbar: {exc}",
        )
        return None
    try:
        store = RunStore(database_path)
        _ensure_known_evidence_index(
            binding_index,
            pending.binding.run_id,
            store,
            evidence_dir,
        )
        known_keys = _known_evidence_keys(
            binding_index,
            pending.binding.run_id,
            pending.records,
        )
        inserted_records = [
            record for record in pending.records if _evidence_key(record) not in known_keys
        ]
        if inserted_records and pending.binding.report_manifest_bound:
            _mark_publish_pending(
                publish_state,
                pending.binding,
                inserted_records,
            )
        inserted_count = store.reconcile_evidence_batch(pending.records)
        if inserted_count != len(inserted_records):
            raise EvidenceRecoveryError(
                "Die Laufdatenbank wurde waehrend der Recovery konkurrierend veraendert."
            )
        for record in inserted_records:
            info_hash, ip, port = _evidence_key(record)
            binding_index.execute(
                """
                INSERT INTO known_evidence (run_id, info_hash, ip, port)
                VALUES (?, ?, ?, ?)
                """,
                (pending.binding.run_id, info_hash, ip, port),
            )
        binding_index.commit()
    except (OSError, sqlite3.Error, RunStoreError, ValueError, TypeError) as exc:
        binding_index.rollback()
        if (
            pending.binding.legacy_schema
            and isinstance(exc, RunStoreError)
            and str(exc) == _LEGACY_OFFERING_ERROR
        ):
            _mark_legacy_skip(
                binding_index,
                pending.binding,
                "Die Legacy-Laufdatenbank enthaelt Evidenz nach der frueheren "
                "Positivsemantik; automatische Migration wurde ausgelassen.",
            )
            return None
        raise EvidenceRecoveryError(
            f"Journal und Laufdatenbank fuer {pending.binding.run_id!r} weichen ab: {exc}"
        ) from exc
    return tuple(inserted_records)


def _index_verified_journal(
    journal_path: Path,
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
) -> tuple[int, int]:
    """Indexiere Laufbindungen, Abschlussstatus und Evidenz ohne RAM-Wachstum."""

    scanned_entries = 0
    evidence_events = 0
    for journal_batch in EvidenceJournal(journal_path).iter_verified_batches(
        batch_size=MAX_RECOVERY_BATCH_SIZE
    ):
        _enforce_recovery_capacity(evidence_dir)
        try:
            for entry in journal_batch:
                scanned_entries += 1
                event_type = entry.event.get("event_type")
                if event_type == "scan_started":
                    _store_started_run(binding_index, _decode_scan_started(entry.event))
                    continue
                if event_type in {"scan_completed", "scan_cancelled", "scan_failed"}:
                    _mark_terminal_event(binding_index, entry.event)
                    continue
                if event_type != "observed_bittorrent_piece_availability":
                    continue

                evidence_events += 1
                event_data = _require_mapping(entry.event, "Evidenzereignis")
                run_id = _require_safe_run_id(event_data.get("run_id"))
                _decode_evidence_for_started_run(
                    event_data,
                    entry.event_sha256,
                    binding_index,
                )
                binding_index.execute(
                    """
                    INSERT INTO journal_evidence (
                        sequence,
                        run_id,
                        event_json,
                        event_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        entry.sequence,
                        run_id,
                        canonical_json_bytes(event_data),
                        entry.event_sha256,
                    ),
                )
            binding_index.commit()
        except sqlite3.Error as exc:
            binding_index.rollback()
            raise EvidenceRecoveryError(
                "Der temporaere Recovery-Index konnte nicht aufgebaut werden."
            ) from exc
        except Exception:
            binding_index.rollback()
            raise
    return scanned_entries, evidence_events


def _recovered_batch(
    pending: _PendingRunBatch,
    records: tuple[EvidenceRecord, ...],
) -> RecoveredEvidenceBatch:
    binding = pending.binding
    return RecoveredEvidenceBatch(
        run_id=binding.run_id,
        config_sha256=binding.config_sha256,
        software_sha256=binding.software_sha256,
        config_snapshot=binding.config_snapshot,
        config_snapshot_file_sha256=binding.config_snapshot_file_sha256,
        records=records,
    )


def _decode_indexed_event(raw_event: object) -> Mapping[str, Any]:
    if not isinstance(raw_event, (bytes, str)):
        raise EvidenceRecoveryError("Der temporaere Recovery-Index enthaelt ungueltiges JSON.")
    try:
        event = json.loads(raw_event)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise EvidenceRecoveryError(
            "Der temporaere Recovery-Index enthaelt ungueltiges JSON."
        ) from exc
    return _require_mapping(event, "indexiertes Evidenzereignis")


def _reconcile_indexed_evidence(
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
    publish_state: sqlite3.Connection,
    *,
    on_recovered: RecoveryCallback | None,
    on_reconciled: RecoveryCallback | None,
) -> int:
    """Rekonziliiere indexierte Evidenz erst nach bekanntem Laufabschluss."""

    inserted_records = 0
    last_sequence = 0
    while True:
        rows = binding_index.execute(
            """
            SELECT sequence, event_json, event_sha256
            FROM journal_evidence
            WHERE sequence > ?
            ORDER BY sequence
            LIMIT ?
            """,
            (last_sequence, MAX_RECOVERY_BATCH_SIZE),
        ).fetchall()
        if not rows:
            return inserted_records
        last_sequence = int(rows[-1][0])

        pending_by_run: dict[str, _PendingRunBatch] = {}
        for row in rows:
            event = _decode_indexed_event(row[1])
            event_sha256 = _require_sha256(row[2], "event_sha256")
            binding, record = _decode_evidence_for_started_run(
                event,
                event_sha256,
                binding_index,
            )
            if record is None:
                pending_by_run.pop(binding.run_id, None)
                continue
            pending = pending_by_run.get(binding.run_id)
            if pending is None:
                pending = _PendingRunBatch(binding=binding, records=[])
                pending_by_run[binding.run_id] = pending
            pending.records.append(record)

        for pending in pending_by_run.values():
            recovered_records = _reconcile_run_batch(
                evidence_dir,
                pending,
                binding_index,
                publish_state,
            )
            if recovered_records is None:
                continue
            if recovered_records:
                inserted_records += len(recovered_records)
                if on_recovered is not None:
                    on_recovered(_recovered_batch(pending, recovered_records))
            publish_pending = _has_publish_pending(
                publish_state,
                pending.binding,
                pending.records,
            )
            if on_reconciled is not None and (
                recovered_records or not pending.binding.report_manifest_bound or publish_pending
            ):
                on_reconciled(_recovered_batch(pending, tuple(pending.records)))
                if publish_pending:
                    _acknowledge_publish_pending(
                        publish_state,
                        pending.binding,
                        pending.records,
                    )


def _notify_incomplete_runs(
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
    on_incomplete_run: IncompleteRunCallback | None,
) -> None:
    cursor = binding_index.execute(
        """
        SELECT
            run_id,
            config_sha256,
            software_sha256,
            config_snapshot,
            config_snapshot_file_sha256,
            terminal_event,
            legacy_schema,
            legacy_skip_reason
        FROM run_bindings
        ORDER BY rowid
        """
    )
    while rows := cursor.fetchmany(MAX_RECOVERY_BATCH_SIZE):
        for row in rows:
            run_id = str(row[0])
            binding = _load_started_run(binding_index, run_id)
            if binding.legacy_skip_reason is not None:
                continue
            try:
                database_path = _safe_run_store_path(evidence_dir, run_id)
            except EvidenceRecoveryError as exc:
                if not binding.legacy_schema:
                    raise
                _mark_legacy_skip(
                    binding_index,
                    binding,
                    f"Legacy-Laufdatenbank ist nicht mehr verfuegbar: {exc}",
                )
                continue
            try:
                store = RunStore(database_path)
                unpersisted = store.iter_unpersisted_offering_handshakes(batch_size=1)
                try:
                    has_unpersisted_offering = next(unpersisted, None) is not None
                finally:
                    unpersisted.close()
            except (OSError, sqlite3.Error, RunStoreError, ValueError, TypeError) as exc:
                if (
                    binding.legacy_schema
                    and isinstance(exc, RunStoreError)
                    and str(exc) == _LEGACY_OFFERING_ERROR
                ):
                    _mark_legacy_skip(
                        binding_index,
                        binding,
                        "Die Legacy-Laufdatenbank enthaelt Evidenz nach der frueheren "
                        "Positivsemantik; automatische Migration wurde ausgelassen.",
                    )
                    continue
                raise EvidenceRecoveryError(
                    f"Unvollstaendiger Lauf {run_id!r} konnte nicht geprueft werden: {exc}"
                ) from exc
            if not has_unpersisted_offering:
                continue
            if binding.legacy_schema:
                _mark_legacy_skip(
                    binding_index,
                    binding,
                    "Legacy-Lauf hat positive Handshakes ohne Evidenz, aber keinen "
                    "gebundenen Konfigurationssnapshot; automatische Nachpersistenz "
                    "wurde ausgelassen.",
                )
                continue
            if on_incomplete_run is None:
                continue
            on_incomplete_run(
                RecoveredRunContext(
                    run_id=run_id,
                    config_sha256=str(row[1]),
                    software_sha256=str(row[2]),
                    config_snapshot=str(row[3]) if row[3] is not None else None,
                    config_snapshot_file_sha256=str(row[4]) if row[4] is not None else None,
                    store_path=database_path,
                    terminal_event=str(row[5]) if row[5] is not None else None,
                )
            )


def _notify_legacy_skips(
    binding_index: sqlite3.Connection,
    on_legacy_skipped: LegacyNoticeCallback | None,
) -> int:
    skipped_runs = 0
    cursor = binding_index.execute(
        """
        SELECT run_id, legacy_skip_reason
        FROM run_bindings
        WHERE legacy_skip_reason IS NOT NULL
        ORDER BY rowid
        """
    )
    while rows := cursor.fetchmany(MAX_RECOVERY_BATCH_SIZE):
        for row in rows:
            skipped_runs += 1
            if on_legacy_skipped is not None:
                on_legacy_skipped(
                    LegacyRecoveryNotice(
                        run_id=str(row[0]),
                        reason=str(row[1]),
                    )
                )
    return skipped_runs


def recover_evidence_journal(
    evidence_dir: Path,
    *,
    on_recovered: RecoveryCallback | None = None,
    on_reconciled: RecoveryCallback | None = None,
    on_incomplete_run: IncompleteRunCallback | None = None,
    on_legacy_skipped: LegacyNoticeCallback | None = None,
) -> RecoverySummary:
    """Ziehe fehlende Journal-Evidenz in ihre vorhandenen Laufdatenbanken nach.

    Das globale Journal wird zuerst von :class:`EvidenceJournal` vollstaendig
    kryptografisch geprueft und danach ausschliesslich in Batches von hoechstens
    fuenf Eintraegen verarbeitet. Ein temporaerer SQLite-Index bindet beliebig
    viele Lauf-IDs speicherbegrenzt an ihr vorangegangenes ``scan_started``.
    """

    root = Path(evidence_dir)
    if on_recovered is not None and not callable(on_recovered):
        raise TypeError("on_recovered muss aufrufbar sein.")
    if on_reconciled is not None and not callable(on_reconciled):
        raise TypeError("on_reconciled muss aufrufbar sein.")
    if on_incomplete_run is not None and not callable(on_incomplete_run):
        raise TypeError("on_incomplete_run muss aufrufbar sein.")
    if on_legacy_skipped is not None and not callable(on_legacy_skipped):
        raise TypeError("on_legacy_skipped muss aufrufbar sein.")
    if root.is_symlink():
        raise EvidenceRecoveryError(f"Evidenzverzeichnis darf kein Symlink sein: {root}")
    journal_path = root / "events.jsonl"
    if journal_path.is_symlink():
        raise EvidenceRecoveryError(f"Evidenzjournal darf kein Symlink sein: {journal_path}")
    pending_journal_path = root / f".{journal_path.name}.pending"
    if not journal_path.exists() and not pending_journal_path.exists():
        return RecoverySummary()
    if not root.is_dir():
        raise EvidenceRecoveryError(f"Evidenzverzeichnis fehlt oder ist ungueltig: {root}")

    _enforce_recovery_capacity(root)
    with tempfile.TemporaryDirectory(
        prefix=".afdleakercatcher-recovery-",
        dir=root,
    ) as index_directory:
        index_directory_path = Path(index_directory)
        if os.name != "nt":
            index_directory_path.chmod(0o700)
        index_path = Path(index_directory) / "run-bindings.sqlite3"
        index_path.touch(mode=0o600, exist_ok=False)
        if os.name != "nt":
            index_path.chmod(0o600)
        with (
            closing(sqlite3.connect(index_path)) as binding_index,
            closing(_open_publish_state(root)) as publish_state,
        ):
            binding_index.execute("PRAGMA foreign_keys = ON")
            _create_binding_index(binding_index)
            scanned_entries, evidence_events = _index_verified_journal(
                journal_path,
                root,
                binding_index,
            )
            inserted_records = _reconcile_indexed_evidence(
                root,
                binding_index,
                publish_state,
                on_recovered=on_recovered,
                on_reconciled=on_reconciled,
            )
            _notify_incomplete_runs(root, binding_index, on_incomplete_run)
            skipped_legacy_runs = _notify_legacy_skips(
                binding_index,
                on_legacy_skipped,
            )

    return RecoverySummary(
        scanned_entries=scanned_entries,
        evidence_events=evidence_events,
        inserted_records=inserted_records,
        skipped_legacy_runs=skipped_legacy_runs,
    )


__all__ = [
    "EvidenceRecoveryError",
    "LegacyRecoveryNotice",
    "RecoveredEvidenceBatch",
    "RecoveredRunContext",
    "RecoverySummary",
    "recover_evidence_journal",
]
