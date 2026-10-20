"""Stelle journalisierte Evidenz nach einem abgebrochenen Lauf wieder her."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .evidence import EvidenceJournal, canonical_json_bytes
from .models import EvidenceRecord, HandshakeResult
from .run_store import RunStore, RunStoreError, decode_evidence_journal_event

MAX_RECOVERY_BATCH_SIZE = 5
RECOVERY_MIN_FREE_SPACE_BYTES = 100_000_000
_PUBLISH_STATE_FILENAME = ".recovery-publish-state.sqlite3"
_MAX_REPORT_MANIFEST_BYTES = 4_000_000
_MAX_REPORT_MANIFEST_LINE_LENGTH = 4_096
_REQUIRED_REPORT_SUFFIXES = (
    "_laufbericht.pdf",
    "_beobachtungen.csv",
    "_vpn_liste.csv",
    "_vpn_liste.pdf",
)
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
_V033_SCAN_STARTED_KEYS = _LEGACY_SCAN_STARTED_KEYS | {
    "config_snapshot",
    "config_snapshot_file_sha256",
}
_CURRENT_SCAN_STARTED_KEYS = _V033_SCAN_STARTED_KEYS | {"evidence_semantics_version"}
_SUPPORTED_EVIDENCE_SEMANTICS_VERSIONS = frozenset({1, 2})
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
    evidence_semantics_version: int = 1
    report_manifest: str | None = None
    report_manifest_sha256: str | None = None
    report_file_count: int | None = None


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
    evidence_semantics_version: int = 1
    report_manifest: str | None = None
    report_manifest_sha256: str | None = None
    report_file_count: int | None = None


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
    evidence_semantics_version: int
    legacy_schema: bool
    targets: tuple[tuple[str, str], ...] = ()
    terminal_event: str | None = None
    terminal_sequence: int | None = None
    report_manifest: str | None = None
    report_manifest_sha256: str | None = None
    report_file_count: int | None = None
    legacy_skip_reason: str | None = None

    @property
    def report_manifest_bound(self) -> bool:
        """Meldet eine vollstaendige, bereits validierte Manifestbindung."""

        return (
            self.report_manifest is not None
            and self.report_manifest_sha256 is not None
            and self.report_file_count is not None
        )


@dataclass(frozen=True, slots=True)
class _ReportPackageBinding:
    manifest_name: str
    manifest_sha256: str
    file_count: int


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


def _decode_started_targets(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise EvidenceRecoveryError("scan_started.targets muss eine Liste sein.")
    decoded_targets: list[tuple[str, str]] = []
    seen_targets: set[tuple[str, str]] = set()
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
        target_binding = (label, info_hash)
        if target_binding in seen_targets:
            raise EvidenceRecoveryError(
                f"scan_started.targets[{index}] ist eine doppelte Zielbindung."
            )
        seen_targets.add(target_binding)
        decoded_targets.append(target_binding)
    return tuple(decoded_targets)


def _decode_scan_started(event: object) -> _StartedRun:
    data = _require_mapping(event, "scan_started-Ereignis")
    event_keys = frozenset(data)
    if event_keys not in {
        _LEGACY_SCAN_STARTED_KEYS,
        _V033_SCAN_STARTED_KEYS,
        _CURRENT_SCAN_STARTED_KEYS,
    }:
        raise EvidenceRecoveryError("scan_started-Ereignis hat fehlende oder unerwartete Felder.")
    if data["event_type"] != "scan_started":
        raise EvidenceRecoveryError("Interner Fehler beim Dekodieren von scan_started.")

    run_id = _require_safe_run_id(data["run_id"])
    config_sha256 = _require_sha256(data["config_sha256"], "config_sha256")
    software_sha256 = _require_sha256(data["software_sha256"], "software_sha256")
    legacy_schema = event_keys == _LEGACY_SCAN_STARTED_KEYS
    evidence_semantics_version = 1
    if event_keys == _CURRENT_SCAN_STARTED_KEYS:
        raw_semantics_version = data["evidence_semantics_version"]
        if (
            isinstance(raw_semantics_version, bool)
            or not isinstance(raw_semantics_version, int)
            or raw_semantics_version not in _SUPPORTED_EVIDENCE_SEMANTICS_VERSIONS
        ):
            raise EvidenceRecoveryError(
                "scan_started.evidence_semantics_version wird von dieser "
                "Programmversion nicht unterstuetzt."
            )
        evidence_semantics_version = raw_semantics_version
    config_snapshot: str | None = None
    config_snapshot_file_sha256: str | None = None
    if event_keys != _LEGACY_SCAN_STARTED_KEYS:
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
    targets = _decode_started_targets(data["targets"])
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
        evidence_semantics_version=evidence_semantics_version,
        legacy_schema=legacy_schema,
        targets=targets,
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
            evidence_semantics_version INTEGER NOT NULL,
            terminal_event TEXT,
            terminal_sequence INTEGER,
            report_manifest TEXT,
            report_manifest_sha256 TEXT,
            report_file_count INTEGER,
            original_report_checked INTEGER NOT NULL DEFAULT 0
                CHECK (original_report_checked IN (0, 1)),
            original_report_complete INTEGER NOT NULL DEFAULT 0
                CHECK (original_report_complete IN (0, 1)),
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
        CREATE TABLE run_targets (
            run_id TEXT NOT NULL,
            target_label TEXT NOT NULL,
            info_hash TEXT NOT NULL,
            PRIMARY KEY (run_id, target_label, info_hash),
            FOREIGN KEY (run_id) REFERENCES run_bindings(run_id) ON DELETE CASCADE
        );
        CREATE TABLE journal_evidence (
            sequence INTEGER PRIMARY KEY,
            run_id TEXT NOT NULL,
            event_json BLOB NOT NULL,
            event_sha256 TEXT NOT NULL,
            FOREIGN KEY (run_id) REFERENCES run_bindings(run_id) ON DELETE CASCADE
        );
        CREATE TABLE verified_report_files (
            package_key TEXT NOT NULL,
            file_name TEXT NOT NULL,
            PRIMARY KEY (package_key, file_name)
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
                evidence_semantics_version,
                legacy_schema
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                binding.run_id,
                binding.config_sha256,
                binding.software_sha256,
                binding.config_snapshot,
                binding.config_snapshot_file_sha256,
                binding.evidence_semantics_version,
                int(binding.legacy_schema),
            ),
        )
        connection.executemany(
            """
            INSERT INTO run_targets (run_id, target_label, info_hash)
            VALUES (?, ?, ?)
            """,
            (
                (binding.run_id, target_label, info_hash)
                for target_label, info_hash in binding.targets
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
            evidence_semantics_version,
            legacy_schema,
            terminal_event,
            terminal_sequence,
            report_manifest,
            report_manifest_sha256,
            report_file_count,
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
        evidence_semantics_version=int(row[5]),
        legacy_schema=bool(row[6]),
        terminal_event=str(row[7]) if row[7] is not None else None,
        terminal_sequence=int(row[8]) if row[8] is not None else None,
        report_manifest=str(row[9]) if row[9] is not None else None,
        report_manifest_sha256=str(row[10]) if row[10] is not None else None,
        report_file_count=int(row[11]) if row[11] is not None else None,
        legacy_skip_reason=str(row[12]) if row[12] is not None else None,
    )


def _mark_legacy_skip(
    connection: sqlite3.Connection,
    binding: _StartedRun,
    reason: str,
) -> None:
    if not reason.strip():
        raise ValueError("Legacy-Skip benoetigt eine Begruendung.")
    updated = connection.execute(
        """
        UPDATE run_bindings
        SET legacy_skip_reason = COALESCE(legacy_skip_reason, ?)
        WHERE run_id = ?
        """,
        (reason, binding.run_id),
    )
    if updated.rowcount != 1:
        connection.rollback()
        raise EvidenceRecoveryError(f"Recovery-Index kennt Lauf {binding.run_id!r} nicht.")
    connection.commit()


def _mark_terminal_event(
    connection: sqlite3.Connection,
    event: object,
    sequence: int,
) -> None:
    data = _require_mapping(event, "terminales Laufereignis")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise EvidenceRecoveryError("Terminales Laufereignis hat keine gueltige Sequenz.")
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
    validated_report_manifest: str | None = None
    validated_report_manifest_sha256: str | None = None
    validated_report_file_count: int | None = None
    if report_manifest_bound:
        validated_report_manifest = _require_safe_basename(report_manifest, "report_manifest")
        validated_report_manifest_sha256 = _require_sha256(
            report_manifest_sha256,
            "report_manifest_sha256",
        )
        report_file_count = data.get("report_file_count")
        if (
            isinstance(report_file_count, bool)
            or not isinstance(report_file_count, int)
            or report_file_count < 1
        ):
            raise EvidenceRecoveryError(
                f"Terminales Laufereignis fuer {run_id!r} hat keine gueltige Berichtsanzahl."
            )
        validated_report_file_count = report_file_count
    elif data.get("report_file_count") is not None:
        raise EvidenceRecoveryError(
            f"Terminales Laufereignis fuer {run_id!r} nennt Berichte ohne Manifest-Bindung."
        )

    updated = connection.execute(
        """
        UPDATE run_bindings
        SET
            terminal_event = ?,
            terminal_sequence = ?,
            report_manifest = ?,
            report_manifest_sha256 = ?,
            report_file_count = ?
        WHERE run_id = ? AND terminal_event IS NULL
        """,
        (
            terminal_event,
            sequence,
            validated_report_manifest,
            validated_report_manifest_sha256,
            validated_report_file_count,
            run_id,
        ),
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
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS pending_reconciled_reports (
                event_sha256 TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                config_sha256 TEXT NOT NULL,
                software_sha256 TEXT NOT NULL,
                config_snapshot TEXT,
                config_snapshot_file_sha256 TEXT,
                evidence_semantics_version INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS completed_reconciled_reports (
                event_sha256 TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                config_sha256 TEXT NOT NULL,
                software_sha256 TEXT NOT NULL,
                config_snapshot TEXT,
                config_snapshot_file_sha256 TEXT,
                evidence_semantics_version INTEGER NOT NULL DEFAULT 1,
                report_manifest TEXT NOT NULL,
                report_manifest_sha256 TEXT NOT NULL,
                report_file_count INTEGER NOT NULL CHECK (report_file_count > 0)
            );
            """
        )
        for table_name in (
            "pending_reconciled_reports",
            "completed_reconciled_reports",
        ):
            columns = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
            }
            if "evidence_semantics_version" not in columns:
                connection.execute(
                    f"ALTER TABLE {table_name} "
                    "ADD COLUMN evidence_semantics_version INTEGER NOT NULL DEFAULT 1"
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
) -> tuple[str, str, str, str, str | None, str | None, int]:
    return (
        event_sha256,
        binding.run_id,
        binding.config_sha256,
        binding.software_sha256,
        binding.config_snapshot,
        binding.config_snapshot_file_sha256,
        binding.evidence_semantics_version,
    )


def _validate_publish_binding(
    row: tuple[object, ...],
    binding: _StartedRun,
    event_sha256: str,
) -> None:
    try:
        actual = (
            *(str(value) if value is not None else None for value in row[:6]),
            int(row[6]),
        )
    except (IndexError, TypeError, ValueError) as exc:
        raise EvidenceRecoveryError(
            f"Recovery-Publikationsstatus fuer Lauf {binding.run_id!r} ist ungueltig."
        ) from exc
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
            publish_state.execute(
                "DELETE FROM completed_reconciled_reports WHERE event_sha256 = ?",
                (event_sha256,),
            )
            row = publish_state.execute(
                """
                SELECT
                    event_sha256,
                    run_id,
                    config_sha256,
                    software_sha256,
                    config_snapshot,
                    config_snapshot_file_sha256,
                    evidence_semantics_version
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
                    config_snapshot_file_sha256,
                    evidence_semantics_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                _publish_binding_values(binding, event_sha256),
            )
        publish_state.commit()
    except EvidenceRecoveryError:
        publish_state.rollback()
        raise
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
                    config_snapshot_file_sha256,
                    evidence_semantics_version
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


def _load_completed_publish_binding(
    publish_state: sqlite3.Connection,
    binding: _StartedRun,
    records: list[EvidenceRecord],
) -> _ReportPackageBinding | None:
    completed_binding: _ReportPackageBinding | None = None
    completed_rows = 0
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
                    config_snapshot_file_sha256,
                    evidence_semantics_version,
                    report_manifest,
                    report_manifest_sha256,
                    report_file_count
                FROM completed_reconciled_reports
                WHERE event_sha256 = ?
                """,
                (event_sha256,),
            ).fetchone()
            if row is None:
                continue
            completed_rows += 1
            _validate_publish_binding(row[:7], binding, event_sha256)
            package_binding = _ReportPackageBinding(
                manifest_name=_require_safe_basename(row[7], "report_manifest"),
                manifest_sha256=_require_sha256(
                    row[8],
                    "report_manifest_sha256",
                ),
                file_count=int(row[9]),
            )
            if package_binding.file_count < 1:
                raise EvidenceRecoveryError(
                    "Recovery-Publikationsstatus enthaelt keine gueltige Berichtsanzahl."
                )
            if completed_binding is None:
                completed_binding = package_binding
            elif completed_binding != package_binding:
                raise EvidenceRecoveryError(
                    f"Recovery-Publikationsstatus fuer Lauf {binding.run_id!r} "
                    "verweist auf verschiedene Berichtspakete."
                )
    except EvidenceRecoveryError:
        raise
    except (TypeError, ValueError) as exc:
        raise EvidenceRecoveryError(
            "Fertiggestellte Recovery-Berichte enthalten eine ungueltige Berichtsanzahl."
        ) from exc
    except sqlite3.Error as exc:
        raise EvidenceRecoveryError(
            "Fertiggestellte Recovery-Berichte konnten nicht gelesen werden."
        ) from exc
    if completed_rows not in {0, len(records)}:
        raise EvidenceRecoveryError(
            f"Recovery-Publikationsstatus fuer Lauf {binding.run_id!r} ist unvollstaendig."
        )
    return completed_binding


def _mark_publish_completed(
    publish_state: sqlite3.Connection,
    binding: _StartedRun,
    records: list[EvidenceRecord],
    package_binding: _ReportPackageBinding,
) -> None:
    manifest_name = _require_safe_basename(package_binding.manifest_name, "report_manifest")
    manifest_sha256 = _require_sha256(
        package_binding.manifest_sha256,
        "report_manifest_sha256",
    )
    if package_binding.file_count < 1:
        raise EvidenceRecoveryError("Recovery-Berichtspaket enthaelt keine Berichtsdateien.")
    try:
        for record in records:
            event_sha256 = _require_sha256(
                record.evidence_event_sha256,
                "evidence_event_sha256",
            )
            publish_state.execute(
                """
                INSERT INTO completed_reconciled_reports (
                    event_sha256,
                    run_id,
                    config_sha256,
                    software_sha256,
                    config_snapshot,
                    config_snapshot_file_sha256,
                    evidence_semantics_version,
                    report_manifest,
                    report_manifest_sha256,
                    report_file_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    *_publish_binding_values(binding, event_sha256),
                    manifest_name,
                    manifest_sha256,
                    package_binding.file_count,
                ),
            )
            publish_state.execute(
                """
                DELETE FROM pending_reconciled_reports
                WHERE event_sha256 = ? AND run_id = ?
                """,
                (event_sha256, binding.run_id),
            )
        publish_state.commit()
    except sqlite3.IntegrityError as exc:
        publish_state.rollback()
        raise EvidenceRecoveryError(
            "Fertiggestellte Recovery-Berichte sind bereits widerspruechlich quittiert."
        ) from exc
    except sqlite3.Error as exc:
        publish_state.rollback()
        raise EvidenceRecoveryError(
            "Fertiggestellte Recovery-Berichte konnten nicht quittiert werden."
        ) from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_existing_report_directory(
    evidence_dir: Path,
    components: tuple[str, ...],
) -> Path | None:
    reports_root = evidence_dir.parent / "reports"
    if reports_root.is_symlink() or not reports_root.is_dir():
        return None
    try:
        resolved_parent = evidence_dir.parent.resolve(strict=True)
        resolved_directory = reports_root.resolve(strict=True)
    except OSError:
        return None
    if resolved_directory.parent != resolved_parent:
        return None

    directory = reports_root
    for component in components:
        try:
            _require_safe_basename(component, "Berichtsverzeichnis")
        except EvidenceRecoveryError:
            return None
        candidate = directory / component
        if candidate.is_symlink() or not candidate.is_dir():
            return None
        try:
            resolved_candidate = candidate.resolve(strict=True)
            resolved_directory = directory.resolve(strict=True)
        except OSError:
            return None
        if resolved_candidate.parent != resolved_directory:
            return None
        directory = candidate
    return directory


def _manifest_entry_is_valid(
    digest: str,
    file_name: str,
) -> bool:
    try:
        _require_sha256(digest, "Manifest-SHA-256")
        _require_safe_basename(file_name, "Manifest-Dateiname")
    except EvidenceRecoveryError:
        return False
    return True


def _inspect_report_package(
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
    *,
    directory_components: tuple[str, ...],
    report_run_id: str,
    manifest_name: str,
    expected_manifest_sha256: str | None = None,
    expected_file_count: int | None = None,
) -> _ReportPackageBinding | None:
    """Prueft ein Berichtspaket vollstaendig und speicherbegrenzt."""

    try:
        _require_safe_run_id(report_run_id)
        validated_manifest_name = _require_safe_basename(manifest_name, "report_manifest")
        if expected_manifest_sha256 is not None:
            expected_manifest_sha256 = _require_sha256(
                expected_manifest_sha256,
                "report_manifest_sha256",
            )
    except EvidenceRecoveryError:
        return None
    manifest_suffix = "_SHA256SUMS.txt"
    if not validated_manifest_name.endswith(manifest_suffix):
        return None
    required_file_prefix = validated_manifest_name.removesuffix(manifest_suffix)
    if not required_file_prefix:
        return None
    if expected_file_count is not None and expected_file_count < 1:
        return None

    output_dir = _safe_existing_report_directory(evidence_dir, directory_components)
    if output_dir is None:
        return None
    manifest_path = output_dir / validated_manifest_name
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return None
        if manifest_path.resolve(strict=True).parent != output_dir.resolve(strict=True):
            return None
        if manifest_path.stat().st_size > _MAX_REPORT_MANIFEST_BYTES:
            return None
        manifest_sha256 = _file_sha256(manifest_path)
    except OSError:
        return None
    if expected_manifest_sha256 is not None and not hmac.compare_digest(
        manifest_sha256,
        expected_manifest_sha256,
    ):
        return None

    package_key = hashlib.sha256(
        "\0".join((*directory_components, validated_manifest_name)).encode("utf-8")
    ).hexdigest()
    entry_count = 0
    run_id_header_count = 0
    try:
        binding_index.execute(
            "DELETE FROM verified_report_files WHERE package_key = ?",
            (package_key,),
        )
        with manifest_path.open("r", encoding="utf-8", newline=None) as handle:
            while raw_line := handle.readline(_MAX_REPORT_MANIFEST_LINE_LENGTH + 1):
                if len(raw_line) > _MAX_REPORT_MANIFEST_LINE_LENGTH:
                    return None
                line = raw_line.rstrip("\r\n")
                if not line:
                    continue
                if line.startswith("#"):
                    if line.startswith("# Lauf-ID: "):
                        run_id_header_count += 1
                        if not hmac.compare_digest(line.removeprefix("# Lauf-ID: "), report_run_id):
                            return None
                    continue
                digest, separator, file_name = line.partition(" *")
                if not separator or not _manifest_entry_is_valid(digest, file_name):
                    return None
                report_path = output_dir / file_name
                try:
                    if report_path.is_symlink() or not report_path.is_file():
                        return None
                    if report_path.resolve(strict=True).parent != output_dir.resolve(strict=True):
                        return None
                    report_sha256 = _file_sha256(report_path)
                except OSError:
                    return None
                if not hmac.compare_digest(report_sha256, digest):
                    return None
                inserted = binding_index.execute(
                    """
                    INSERT OR IGNORE INTO verified_report_files (package_key, file_name)
                    VALUES (?, ?)
                    """,
                    (package_key, file_name),
                )
                if inserted.rowcount != 1:
                    return None
                entry_count += 1

        if run_id_header_count != 1:
            return None
        actual_file_count = 0
        with os.scandir(output_dir) as directory_entries:
            for entry in directory_entries:
                if entry.is_symlink():
                    return None
                if entry.is_dir(follow_symlinks=False):
                    return None
                if not entry.is_file(follow_symlinks=False):
                    return None
                actual_file_count += 1
                if entry.name == validated_manifest_name:
                    continue
                indexed = binding_index.execute(
                    """
                    SELECT 1
                    FROM verified_report_files
                    WHERE package_key = ? AND file_name = ?
                    """,
                    (package_key, entry.name),
                ).fetchone()
                if indexed is None:
                    return None

        if actual_file_count != entry_count + 1:
            return None
        if expected_file_count is not None and actual_file_count != expected_file_count:
            return None
        for suffix in _REQUIRED_REPORT_SUFFIXES:
            required_name = f"{required_file_prefix}{suffix}"
            present = binding_index.execute(
                """
                SELECT 1
                FROM verified_report_files
                WHERE package_key = ? AND file_name = ?
                """,
                (package_key, required_name),
            ).fetchone()
            if present is None:
                return None
        return _ReportPackageBinding(
            manifest_name=validated_manifest_name,
            manifest_sha256=manifest_sha256,
            file_count=actual_file_count,
        )
    except (OSError, UnicodeError):
        return None
    except sqlite3.Error as exc:
        raise EvidenceRecoveryError(
            "Berichtsmanifest konnte im temporaeren Recovery-Index nicht geprueft werden."
        ) from exc
    finally:
        try:
            binding_index.execute(
                "DELETE FROM verified_report_files WHERE package_key = ?",
                (package_key,),
            )
            binding_index.commit()
        except sqlite3.Error as exc:
            binding_index.rollback()
            raise EvidenceRecoveryError(
                "Temporaere Manifestpruefung konnte nicht bereinigt werden."
            ) from exc


def _original_report_is_complete(
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
    binding: _StartedRun,
) -> bool:
    status = binding_index.execute(
        """
        SELECT original_report_checked, original_report_complete
        FROM run_bindings
        WHERE run_id = ?
        """,
        (binding.run_id,),
    ).fetchone()
    if status is None:
        raise EvidenceRecoveryError(f"Recovery-Index kennt Lauf {binding.run_id!r} nicht.")
    if bool(status[0]):
        return bool(status[1])

    complete = False
    if binding.report_manifest_bound:
        evidence_after_terminal = (
            binding.terminal_sequence is None
            or binding_index.execute(
                """
                SELECT 1
                FROM journal_evidence
                WHERE run_id = ? AND sequence > ?
                LIMIT 1
                """,
                (binding.run_id, binding.terminal_sequence),
            ).fetchone()
            is not None
        )
        if not evidence_after_terminal:
            package = _inspect_report_package(
                evidence_dir,
                binding_index,
                directory_components=(binding.run_id,),
                report_run_id=binding.run_id,
                manifest_name=binding.report_manifest or "",
                expected_manifest_sha256=binding.report_manifest_sha256,
                expected_file_count=binding.report_file_count,
            )
            complete = package is not None
    binding_index.execute(
        """
        UPDATE run_bindings
        SET original_report_checked = 1, original_report_complete = ?
        WHERE run_id = ?
        """,
        (int(complete), binding.run_id),
    )
    binding_index.commit()
    return complete


def _recovery_report_identity(
    binding: _StartedRun,
    records: list[EvidenceRecord],
) -> tuple[str, str, str]:
    digest = hashlib.sha256(
        "\n".join(record.evidence_event_sha256 for record in records).encode("ascii")
    ).hexdigest()[:16]
    report_run_id = f"recovery-{binding.run_id[-32:]}-{digest}"
    directory_name = f"wiederhergestellt-{digest}"
    manifest_name = f"{report_run_id}_SHA256SUMS.txt"
    return report_run_id, directory_name, manifest_name


def _inspect_recovery_report(
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
    binding: _StartedRun,
    records: list[EvidenceRecord],
    expected_binding: _ReportPackageBinding | None,
) -> _ReportPackageBinding | None:
    report_run_id, directory_name, manifest_name = _recovery_report_identity(binding, records)
    if expected_binding is not None and not hmac.compare_digest(
        expected_binding.manifest_name,
        manifest_name,
    ):
        return None
    return _inspect_report_package(
        evidence_dir,
        binding_index,
        directory_components=(binding.run_id, directory_name),
        report_run_id=report_run_id,
        manifest_name=manifest_name,
        expected_manifest_sha256=(
            expected_binding.manifest_sha256 if expected_binding is not None else None
        ),
        expected_file_count=(expected_binding.file_count if expected_binding is not None else None),
    )


def _evidence_key(record: EvidenceRecord) -> tuple[str, str, int]:
    candidate = record.handshake.candidate
    return candidate.info_hash_hex, candidate.ip, candidate.port


def _require_handshake_target_binding(
    connection: sqlite3.Connection,
    binding: _StartedRun,
    handshake: HandshakeResult,
) -> None:
    candidate = handshake.candidate
    row = connection.execute(
        """
        SELECT 1
        FROM run_targets
        WHERE run_id = ? AND target_label = ? AND info_hash = ?
        """,
        (binding.run_id, candidate.target_label, candidate.info_hash_hex),
    ).fetchone()
    if row is None:
        raise EvidenceRecoveryError(
            f"BitTorrent-Ziel {candidate.target_label!r} mit Infohash "
            f"{candidate.info_hash_hex!r} ist fuer Lauf {binding.run_id!r} "
            "nicht an scan_started gebunden."
        )


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


def _event_with_current_availability_gates(event: Mapping[str, Any]) -> dict[str, Any] | None:
    handshake_value = event.get("handshake")
    if not isinstance(handshake_value, dict):
        return None
    availability_value = handshake_value.get("availability")
    if not isinstance(availability_value, dict):
        return None
    completed_full_window = availability_value.get("completed_full_window")
    availability_error = availability_value.get("error")
    if not isinstance(completed_full_window, bool) or (
        availability_error is not None and not isinstance(availability_error, str)
    ):
        return None
    if completed_full_window and availability_error is None:
        return None

    patched_availability = dict(availability_value)
    patched_availability["completed_full_window"] = True
    patched_availability["error"] = None
    patched_handshake = dict(handshake_value)
    patched_handshake["availability"] = patched_availability
    patched_event = dict(event)
    patched_event["handshake"] = patched_handshake
    return patched_event


def _is_v1_availability_gate_only_record(
    event: Mapping[str, Any],
    event_sha256: str,
    binding: _StartedRun,
) -> bool:
    patched_event = _event_with_current_availability_gates(event)
    if patched_event is None:
        return False
    try:
        decode_evidence_journal_event(
            patched_event,
            event_sha256,
            expected_run_id=binding.run_id,
            expected_config_sha256=binding.config_sha256,
            expected_software_sha256=binding.software_sha256,
        )
    except RunStoreError:
        return False
    return True


def _handshake_with_current_availability_gates(
    handshake: HandshakeResult,
) -> HandshakeResult | None:
    observation = handshake.availability
    if observation is None or (observation.completed_full_window and observation.error is None):
        return None
    return replace(
        handshake,
        availability=replace(
            observation,
            completed_full_window=True,
            error=None,
        ),
    )


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
    patched_gate_event = _event_with_current_availability_gates(event_data)
    if binding.evidence_semantics_version == 1 and _is_v1_availability_gate_only_record(
        event_data,
        event_sha256,
        binding,
    ):
        _mark_legacy_skip(
            connection,
            binding,
            "Lauf verwendet eine bis Version 0.3.3 gueltige Positivsemantik: "
            "Stueckverfuegbarkeit und UNCHOKE wurden gemeldet, die Beobachtung "
            "endete jedoch vor dem vollstaendigen Zeitfenster oder mit einem "
            "Verbindungsfehler; der Lauf wird nicht erneut veroeffentlicht.",
        )
        return binding, None
    if binding.evidence_semantics_version >= 2 and patched_gate_event is not None:
        raise EvidenceRecoveryError(
            f"Evidenzereignis fuer Lauf {run_id!r} verletzt die gebundene "
            "Positivsemantik Version 2."
        )
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
    _require_handshake_target_binding(connection, binding, decoded.record.handshake)
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
        if inserted_records:
            _mark_publish_pending(
                publish_state,
                pending.binding,
                pending.records,
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
                    _mark_terminal_event(binding_index, entry.event, entry.sequence)
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
        evidence_semantics_version=binding.evidence_semantics_version,
        report_manifest=binding.report_manifest,
        report_manifest_sha256=binding.report_manifest_sha256,
        report_file_count=binding.report_file_count,
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
            original_report_complete = _original_report_is_complete(
                evidence_dir,
                binding_index,
                pending.binding,
            )
            completed_binding = _load_completed_publish_binding(
                publish_state,
                pending.binding,
                pending.records,
            )
            recovery_report_complete = completed_binding is not None and (
                _inspect_recovery_report(
                    evidence_dir,
                    binding_index,
                    pending.binding,
                    pending.records,
                    completed_binding,
                )
                is not None
            )
            if completed_binding is not None and not recovery_report_complete:
                _mark_publish_pending(
                    publish_state,
                    pending.binding,
                    pending.records,
                )
            publish_pending = _has_publish_pending(
                publish_state,
                pending.binding,
                pending.records,
            )
            publish_required = (
                bool(recovered_records)
                or publish_pending
                or (not original_report_complete and not recovery_report_complete)
            )
            if publish_required and not publish_pending:
                _mark_publish_pending(
                    publish_state,
                    pending.binding,
                    pending.records,
                )
            if on_reconciled is not None and publish_required:
                on_reconciled(_recovered_batch(pending, tuple(pending.records)))
                recovered_package = _inspect_recovery_report(
                    evidence_dir,
                    binding_index,
                    pending.binding,
                    pending.records,
                    None,
                )
                if recovered_package is not None:
                    _mark_publish_completed(
                        publish_state,
                        pending.binding,
                        pending.records,
                        recovered_package,
                    )


def _notify_incomplete_runs(
    evidence_dir: Path,
    binding_index: sqlite3.Connection,
    on_incomplete_run: IncompleteRunCallback | None,
) -> None:
    cursor = binding_index.execute(
        """
        SELECT run_id
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
                unpersisted = store.iter_unpersisted_offering_handshakes(
                    batch_size=MAX_RECOVERY_BATCH_SIZE
                )
                has_unpersisted_offering = False
                legacy_gate_only_handshake = False
                try:
                    for handshake in unpersisted:
                        has_unpersisted_offering = True
                        _require_handshake_target_binding(
                            binding_index,
                            binding,
                            handshake,
                        )
                        if handshake.offering_observed:
                            continue
                        patched_handshake = _handshake_with_current_availability_gates(handshake)
                        if patched_handshake is None or not patched_handshake.offering_observed:
                            raise EvidenceRecoveryError(
                                f"Laufdatenbank fuer {run_id!r} enthaelt einen als positiv "
                                "markierten, fachlich aber nicht positiven Verfuegbarkeitsbefund."
                            )
                        if binding.evidence_semantics_version >= 2:
                            raise EvidenceRecoveryError(
                                f"Laufdatenbank fuer {run_id!r} verletzt die gebundene "
                                "Positivsemantik Version 2."
                            )
                        legacy_gate_only_handshake = True
                        break
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
            if legacy_gate_only_handshake:
                _mark_legacy_skip(
                    binding_index,
                    binding,
                    "Laufdatenbank verwendet eine bis Version 0.3.3 gueltige "
                    "Positivsemantik mit vorzeitigem Ende oder Verbindungsfehler; "
                    "der Lauf wird nicht nachtraeglich veroeffentlicht.",
                )
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
                    config_sha256=binding.config_sha256,
                    software_sha256=binding.software_sha256,
                    config_snapshot=binding.config_snapshot,
                    config_snapshot_file_sha256=binding.config_snapshot_file_sha256,
                    store_path=database_path,
                    terminal_event=binding.terminal_event,
                    evidence_semantics_version=binding.evidence_semantics_version,
                    report_manifest=binding.report_manifest,
                    report_manifest_sha256=binding.report_manifest_sha256,
                    report_file_count=binding.report_file_count,
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
