"""Private, streaming-faehige SQLite-Ablage fuer einen Prueflauf."""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    PeerControlEvent,
    VpnClassification,
)

SCHEMA_VERSION = 1
VALID_CANDIDATE_STATUSES = frozenset({"pending", "in_progress", "done"})


class RunStoreError(RuntimeError):
    """Die Laufdatenbank enthaelt inkonsistente oder ungueltige Daten."""


@dataclass(frozen=True, slots=True)
class RunStoreMetrics:
    """Kleine, per SQL aggregierte Zaehler fuer genau einen Infohash."""

    info_hash: str
    candidates: int = 0
    pending: int = 0
    in_progress: int = 0
    done: int = 0
    handshake_results: int = 0
    confirmed: int = 0
    piece_availability: int = 0
    unchoked: int = 0
    offering_observed: int = 0
    terminal_failures: int = 0
    evidence_records: int = 0


@dataclass(frozen=True, slots=True)
class RunStoreIpGroup:
    """Kleine Bilanz einer positiven IP-Gruppe ohne Evidenzobjekte im Speicher."""

    ip: str
    record_count: int
    is_known_vpn: bool


def _utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RunStoreError(f"{label} ist kein gueltiges JSON-Objekt.")
    return value


def _require_exact_keys(
    value: Mapping[str, Any],
    expected: Sequence[str],
    label: str,
) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise RunStoreError(
            f"{label} hat unerwartete Felder: "
            f"fehlend={sorted(wanted - actual)}, zusaetzlich={sorted(actual - wanted)}."
        )


def _require_string(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise RunStoreError(f"{label} muss Text sein.")
    return value


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise RunStoreError(f"{label} muss ein Wahrheitswert sein.")
    return value


def _require_int(value: object, label: str, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RunStoreError(f"{label} muss eine Ganzzahl sein.")
    return value


def _require_float(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RunStoreError(f"{label} muss eine Zahl sein.")
    return float(value)


def _require_string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise RunStoreError(f"{label} muss eine Textliste sein.")
    return tuple(value)


def _validate_info_hash(info_hash: str) -> str:
    if not isinstance(info_hash, str):
        raise RunStoreError("Der Infohash muss Text sein.")
    if len(info_hash) != 40:
        raise RunStoreError("Der Infohash muss genau 40 Hexadezimalzeichen enthalten.")
    try:
        bytes.fromhex(info_hash)
    except ValueError as exc:
        raise RunStoreError("Der Infohash ist nicht hexadezimal.") from exc
    return info_hash.casefold()


def _candidate_from_mapping(value: object) -> PeerCandidate:
    data = _require_mapping(value, "PeerCandidate")
    field_names = (
        "target_label",
        "info_hash_hex",
        "ip",
        "port",
        "discovered_at_utc",
        "dht_node_ip",
        "dht_node_port",
        "transaction_id_hex",
        "response_sha256",
        "source_note",
        "discovery_source",
    )
    _require_exact_keys(data, field_names, "PeerCandidate")
    info_hash = _validate_info_hash(str(_require_string(data["info_hash_hex"], "info_hash_hex")))
    ip = str(_require_string(data["ip"], "ip"))
    dht_node_ip = str(_require_string(data["dht_node_ip"], "dht_node_ip"))
    try:
        ip = ipaddress.ip_address(ip).compressed
        dht_node_ip = ipaddress.ip_address(dht_node_ip).compressed
    except ValueError as exc:
        raise RunStoreError("PeerCandidate enthaelt eine ungueltige IP-Adresse.") from exc
    port = _require_int(data["port"], "port")
    dht_node_port = _require_int(data["dht_node_port"], "dht_node_port")
    if port is None or not 1 <= port <= 65_535:
        raise RunStoreError("PeerCandidate enthaelt einen ungueltigen Port.")
    if dht_node_port is None or not 1 <= dht_node_port <= 65_535:
        raise RunStoreError("PeerCandidate enthaelt einen ungueltigen DHT-Port.")
    discovery_source = str(_require_string(data["discovery_source"], "discovery_source"))
    if discovery_source not in {"dht", "tracker"}:
        raise RunStoreError("PeerCandidate enthaelt eine ungueltige Fundquelle.")
    return PeerCandidate(
        target_label=str(_require_string(data["target_label"], "target_label")),
        info_hash_hex=info_hash,
        ip=ip,
        port=port,
        discovered_at_utc=str(_require_string(data["discovered_at_utc"], "discovered_at_utc")),
        dht_node_ip=dht_node_ip,
        dht_node_port=dht_node_port,
        transaction_id_hex=str(_require_string(data["transaction_id_hex"], "transaction_id_hex")),
        response_sha256=str(_require_string(data["response_sha256"], "response_sha256")),
        source_note=str(_require_string(data["source_note"], "source_note")),
        discovery_source=discovery_source,
    )


def _control_event_from_mapping(value: object) -> PeerControlEvent:
    data = _require_mapping(value, "PeerControlEvent")
    field_names = (
        "observed_at_utc",
        "elapsed_seconds",
        "kind",
        "payload_length",
        "piece_index",
        "non_empty",
        "payload_sha256",
        "set_bits",
    )
    _require_exact_keys(data, field_names, "PeerControlEvent")
    non_empty = data["non_empty"]
    if non_empty is not None and not isinstance(non_empty, bool):
        raise RunStoreError("PeerControlEvent.non_empty ist ungueltig.")
    return PeerControlEvent(
        observed_at_utc=str(
            _require_string(data["observed_at_utc"], "control_event.observed_at_utc")
        ),
        elapsed_seconds=_require_float(data["elapsed_seconds"], "control_event.elapsed_seconds"),
        kind=str(_require_string(data["kind"], "control_event.kind")),
        payload_length=int(_require_int(data["payload_length"], "control_event.payload_length")),
        piece_index=_require_int(data["piece_index"], "control_event.piece_index", optional=True),
        non_empty=non_empty,
        payload_sha256=_require_string(
            data["payload_sha256"], "control_event.payload_sha256", optional=True
        ),
        set_bits=_require_int(data["set_bits"], "control_event.set_bits", optional=True),
    )


def _availability_from_mapping(value: object) -> PeerAvailabilityObservation:
    data = _require_mapping(value, "PeerAvailabilityObservation")
    field_names = (
        "started_at_utc",
        "ended_at_utc",
        "requested_duration_seconds",
        "duration_seconds",
        "completed_full_window",
        "interested_sent",
        "non_empty_bitfield",
        "have_announced",
        "piece_availability_announced",
        "unchoked",
        "peer_choking_at_end",
        "unchoked_duration_seconds",
        "messages_received",
        "bytes_received",
        "request_messages_sent",
        "piece_payload_bytes_received",
        "metadata_requests_sent",
        "termination_reason",
        "control_events",
        "error",
    )
    _require_exact_keys(data, field_names, "PeerAvailabilityObservation")
    raw_events = data["control_events"]
    if not isinstance(raw_events, (list, tuple)):
        raise RunStoreError("control_events muss eine Liste sein.")
    return PeerAvailabilityObservation(
        started_at_utc=str(_require_string(data["started_at_utc"], "started_at_utc")),
        ended_at_utc=str(_require_string(data["ended_at_utc"], "ended_at_utc")),
        requested_duration_seconds=_require_float(
            data["requested_duration_seconds"], "requested_duration_seconds"
        ),
        duration_seconds=_require_float(data["duration_seconds"], "duration_seconds"),
        completed_full_window=_require_bool(data["completed_full_window"], "completed_full_window"),
        interested_sent=_require_bool(data["interested_sent"], "interested_sent"),
        non_empty_bitfield=_require_bool(data["non_empty_bitfield"], "non_empty_bitfield"),
        have_announced=_require_bool(data["have_announced"], "have_announced"),
        piece_availability_announced=_require_bool(
            data["piece_availability_announced"], "piece_availability_announced"
        ),
        unchoked=_require_bool(data["unchoked"], "unchoked"),
        peer_choking_at_end=_require_bool(data["peer_choking_at_end"], "peer_choking_at_end"),
        unchoked_duration_seconds=_require_float(
            data["unchoked_duration_seconds"], "unchoked_duration_seconds"
        ),
        messages_received=int(_require_int(data["messages_received"], "messages_received")),
        bytes_received=int(_require_int(data["bytes_received"], "bytes_received")),
        request_messages_sent=int(
            _require_int(data["request_messages_sent"], "request_messages_sent")
        ),
        piece_payload_bytes_received=int(
            _require_int(data["piece_payload_bytes_received"], "piece_payload_bytes_received")
        ),
        metadata_requests_sent=int(
            _require_int(data["metadata_requests_sent"], "metadata_requests_sent")
        ),
        termination_reason=str(_require_string(data["termination_reason"], "termination_reason")),
        control_events=tuple(_control_event_from_mapping(item) for item in raw_events),
        error=_require_string(data["error"], "availability.error", optional=True),
    )


def _handshake_from_mapping(value: object) -> HandshakeResult:
    data = _require_mapping(value, "HandshakeResult")
    field_names = (
        "candidate",
        "attempted_at_utc",
        "completed_at_utc",
        "confirmed",
        "remote_peer_id_hex",
        "reserved_bits_hex",
        "local_ip",
        "local_port",
        "bytes_sent",
        "bytes_received",
        "error",
        "availability",
    )
    _require_exact_keys(data, field_names, "HandshakeResult")
    raw_availability = data["availability"]
    availability = (
        None if raw_availability is None else _availability_from_mapping(raw_availability)
    )
    local_ip = _require_string(data["local_ip"], "local_ip", optional=True)
    if local_ip is not None:
        try:
            ipaddress.ip_address(local_ip)
        except ValueError as exc:
            raise RunStoreError("HandshakeResult.local_ip ist ungueltig.") from exc
    return HandshakeResult(
        candidate=_candidate_from_mapping(data["candidate"]),
        attempted_at_utc=str(_require_string(data["attempted_at_utc"], "attempted_at_utc")),
        completed_at_utc=_require_string(
            data["completed_at_utc"], "completed_at_utc", optional=True
        ),
        confirmed=_require_bool(data["confirmed"], "confirmed"),
        remote_peer_id_hex=_require_string(
            data["remote_peer_id_hex"], "remote_peer_id_hex", optional=True
        ),
        reserved_bits_hex=_require_string(
            data["reserved_bits_hex"], "reserved_bits_hex", optional=True
        ),
        local_ip=local_ip,
        local_port=_require_int(data["local_port"], "local_port", optional=True),
        bytes_sent=int(_require_int(data["bytes_sent"], "bytes_sent")),
        bytes_received=int(_require_int(data["bytes_received"], "bytes_received")),
        error=_require_string(data["error"], "handshake.error", optional=True),
        availability=availability,
    )


def _network_enrichment_from_mapping(value: object) -> NetworkEnrichment:
    data = _require_mapping(value, "NetworkEnrichment")
    field_names = (
        "ip",
        "enriched_at_utc",
        "prefix",
        "asns",
        "holder",
        "rdap_name",
        "rdap_handle",
        "country",
        "abuse_email",
        "source_urls",
        "source_fetched_at_utc",
        "cached_sources",
        "error",
    )
    _require_exact_keys(data, field_names, "NetworkEnrichment")
    asns = data["asns"]
    source_fetched = data["source_fetched_at_utc"]
    if not isinstance(asns, (list, tuple)) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in asns
    ):
        raise RunStoreError("NetworkEnrichment.asns ist ungueltig.")
    if not isinstance(source_fetched, (list, tuple)):
        raise RunStoreError("NetworkEnrichment.source_fetched_at_utc ist ungueltig.")
    fetched_items: list[tuple[str, str]] = []
    for item in source_fetched:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or not all(isinstance(part, str) for part in item)
        ):
            raise RunStoreError("NetworkEnrichment enthaelt eine ungueltige Quellenzeit.")
        fetched_items.append((item[0], item[1]))
    return NetworkEnrichment(
        ip=str(_require_string(data["ip"], "enrichment.ip")),
        enriched_at_utc=str(_require_string(data["enriched_at_utc"], "enrichment.enriched_at_utc")),
        prefix=_require_string(data["prefix"], "enrichment.prefix", optional=True),
        asns=tuple(asns),
        holder=_require_string(data["holder"], "enrichment.holder", optional=True),
        rdap_name=_require_string(data["rdap_name"], "enrichment.rdap_name", optional=True),
        rdap_handle=_require_string(data["rdap_handle"], "enrichment.rdap_handle", optional=True),
        country=_require_string(data["country"], "enrichment.country", optional=True),
        abuse_email=_require_string(data["abuse_email"], "enrichment.abuse_email", optional=True),
        source_urls=_require_string_tuple(data["source_urls"], "enrichment.source_urls"),
        source_fetched_at_utc=tuple(fetched_items),
        cached_sources=_require_string_tuple(data["cached_sources"], "enrichment.cached_sources"),
        error=_require_string(data["error"], "enrichment.error", optional=True),
    )


def _vpn_from_mapping(value: object) -> VpnClassification:
    data = _require_mapping(value, "VpnClassification")
    field_names = ("status", "provider", "reason", "source")
    _require_exact_keys(data, field_names, "VpnClassification")
    return VpnClassification(
        status=str(_require_string(data["status"], "vpn.status")),
        provider=_require_string(data["provider"], "vpn.provider", optional=True),
        reason=_require_string(data["reason"], "vpn.reason", optional=True),
        source=_require_string(data["source"], "vpn.source", optional=True),
    )


def _evidence_from_mapping(value: object) -> EvidenceRecord:
    data = _require_mapping(value, "EvidenceRecord")
    field_names = ("handshake", "enrichment", "vpn", "evidence_event_sha256")
    _require_exact_keys(data, field_names, "EvidenceRecord")
    return EvidenceRecord(
        handshake=_handshake_from_mapping(data["handshake"]),
        enrichment=_network_enrichment_from_mapping(data["enrichment"]),
        vpn=_vpn_from_mapping(data["vpn"]),
        evidence_event_sha256=str(
            _require_string(data["evidence_event_sha256"], "evidence_event_sha256")
        ),
    )


def _decode_json(raw: str, label: str) -> object:
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RunStoreError(f"{label} enthaelt ungueltiges JSON.") from exc


def _result_error_category(result: HandshakeResult) -> str | None:
    if result.error:
        return "handshake"
    observation = result.availability
    if observation is not None and observation.error:
        return "availability"
    return None


class RunStore:
    """Persistiert Laufdaten atomar und liest grosse Mengen nur in Batches."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._prepare_private_database_file()
        with closing(self._connect()) as connection:
            self._initialize_schema(connection)

    def _prepare_private_database_file(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.parent.chmod(0o700)
        if self.path.exists():
            if self.path.is_symlink() or not self.path.is_file():
                raise RunStoreError("Die Laufdatenbank muss eine regulaere Datei sein.")
        else:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            os.close(descriptor)
        if os.name != "nt":
            self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, SCHEMA_VERSION}:
            raise RunStoreError(
                f"Nicht unterstuetzte Laufdatenbank-Version {version}; erwartet {SCHEMA_VERSION}."
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS candidates (
                id INTEGER PRIMARY KEY,
                info_hash TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                candidate_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'in_progress', 'done')),
                claimed_at_utc TEXT,
                completed_at_utc TEXT,
                UNIQUE (info_hash, ip, port)
            );
            CREATE INDEX IF NOT EXISTS candidates_claim_idx
                ON candidates (status, info_hash, id);
            CREATE INDEX IF NOT EXISTS candidates_ip_id_idx
                ON candidates (ip, id);

            CREATE TABLE IF NOT EXISTS handshake_results (
                candidate_id INTEGER PRIMARY KEY
                    REFERENCES candidates(id) ON DELETE CASCADE,
                result_json TEXT NOT NULL,
                confirmed INTEGER NOT NULL CHECK (confirmed IN (0, 1)),
                availability_present INTEGER NOT NULL
                    CHECK (availability_present IN (0, 1)),
                piece_availability INTEGER NOT NULL CHECK (piece_availability IN (0, 1)),
                unchoked INTEGER NOT NULL CHECK (unchoked IN (0, 1)),
                offering_observed INTEGER NOT NULL CHECK (offering_observed IN (0, 1)),
                termination_reason TEXT,
                error_category TEXT,
                stored_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence_records (
                candidate_id INTEGER PRIMARY KEY
                    REFERENCES handshake_results(candidate_id) ON DELETE CASCADE,
                evidence_json TEXT NOT NULL,
                stored_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()

    @staticmethod
    def _begin_immediate(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def add_candidates(self, candidates: Iterable[PeerCandidate]) -> int:
        """Fuegt genau den uebergebenen Batch atomar ein und ignoriert Duplikate."""

        rows: list[tuple[str, str, int, str]] = []
        for candidate in candidates:
            if not isinstance(candidate, PeerCandidate):
                raise TypeError("add_candidates erwartet PeerCandidate-Objekte.")
            reconstructed = _candidate_from_mapping(asdict(candidate))
            rows.append(
                (
                    reconstructed.info_hash_hex,
                    reconstructed.ip,
                    reconstructed.port,
                    _canonical_json(asdict(reconstructed)),
                )
            )
        if not rows:
            return 0

        with closing(self._connect()) as connection:
            try:
                self._begin_immediate(connection)
                before = connection.total_changes
                connection.executemany(
                    """
                    INSERT INTO candidates (info_hash, ip, port, candidate_json)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT (info_hash, ip, port) DO NOTHING
                    """,
                    rows,
                )
                inserted = connection.total_changes - before
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return inserted

    def claim_candidate_batch(
        self,
        target_hashes: Iterable[str],
        size: int = 5,
    ) -> list[PeerCandidate]:
        """Reserviert bis zu ``size`` Kandidaten fair reihum ueber alle Ziele."""

        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise ValueError("size muss eine positive Ganzzahl sein.")
        hashes = tuple(dict.fromkeys(_validate_info_hash(item) for item in target_hashes))
        if not hashes:
            return []

        with closing(self._connect()) as connection:
            try:
                self._begin_immediate(connection)
                cursor_row = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'claim_next_hash'"
                ).fetchone()
                next_hash = str(cursor_row["value"]) if cursor_row is not None else hashes[0]
                start = hashes.index(next_hash) if next_hash in hashes else 0
                selected: list[PeerCandidate] = []
                last_hash_index: int | None = None

                while len(selected) < size:
                    added_in_cycle = False
                    for offset in range(len(hashes)):
                        hash_index = (start + offset) % len(hashes)
                        info_hash = hashes[hash_index]
                        row = connection.execute(
                            """
                            SELECT id, candidate_json
                            FROM candidates
                            WHERE status = 'pending' AND info_hash = ?
                            ORDER BY id
                            LIMIT 1
                            """,
                            (info_hash,),
                        ).fetchone()
                        if row is None:
                            continue
                        candidate = _candidate_from_mapping(
                            _decode_json(str(row["candidate_json"]), "candidate_json")
                        )
                        connection.execute(
                            """
                            UPDATE candidates
                            SET status = 'in_progress', claimed_at_utc = ?
                            WHERE id = ? AND status = 'pending'
                            """,
                            (_utc_now_text(), int(row["id"])),
                        )
                        selected.append(candidate)
                        last_hash_index = hash_index
                        added_in_cycle = True
                        if len(selected) >= size:
                            break
                    if not added_in_cycle:
                        break
                    if last_hash_index is not None:
                        start = (last_hash_index + 1) % len(hashes)

                if last_hash_index is not None:
                    following_hash = hashes[(last_hash_index + 1) % len(hashes)]
                    connection.execute(
                        """
                        INSERT INTO metadata (key, value)
                        VALUES ('claim_next_hash', ?)
                        ON CONFLICT (key) DO UPDATE SET value = excluded.value
                        """,
                        (following_hash,),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        return selected

    def store_handshake_batch(self, results: Iterable[HandshakeResult]) -> int:
        """Speichert einen Ergebnisbatch und setzt seine Kandidaten atomar auf ``done``."""

        prepared: list[tuple[HandshakeResult, str]] = []
        seen: set[tuple[str, str, int]] = set()
        for result in results:
            if not isinstance(result, HandshakeResult):
                raise TypeError("store_handshake_batch erwartet HandshakeResult-Objekte.")
            reconstructed = _handshake_from_mapping(asdict(result))
            key = (
                reconstructed.candidate.info_hash_hex,
                reconstructed.candidate.ip,
                reconstructed.candidate.port,
            )
            if key in seen:
                raise RunStoreError("Ein Handshake-Batch enthaelt denselben Kandidaten mehrfach.")
            seen.add(key)
            prepared.append((reconstructed, _canonical_json(asdict(reconstructed))))
        if not prepared:
            return 0

        with closing(self._connect()) as connection:
            try:
                self._begin_immediate(connection)
                for result, payload in prepared:
                    candidate = result.candidate
                    row = connection.execute(
                        """
                        SELECT id, candidate_json, status
                        FROM candidates
                        WHERE info_hash = ? AND ip = ? AND port = ?
                        """,
                        (candidate.info_hash_hex, candidate.ip, candidate.port),
                    ).fetchone()
                    if row is None:
                        raise RunStoreError("Handshake-Ergebnis gehoert zu keinem Kandidaten.")
                    stored_candidate = _candidate_from_mapping(
                        _decode_json(str(row["candidate_json"]), "candidate_json")
                    )
                    if stored_candidate != candidate:
                        raise RunStoreError(
                            "Handshake-Ergebnis enthaelt abweichende Kandidatendaten."
                        )
                    if str(row["status"]) != "in_progress":
                        raise RunStoreError(
                            "Handshake-Ergebnis gehoert nicht zu einem reservierten Kandidaten."
                        )
                    candidate_id = int(row["id"])
                    observation = result.availability
                    connection.execute(
                        """
                        INSERT INTO handshake_results (
                            candidate_id,
                            result_json,
                            confirmed,
                            availability_present,
                            piece_availability,
                            unchoked,
                            offering_observed,
                            termination_reason,
                            error_category,
                            stored_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            candidate_id,
                            payload,
                            int(result.confirmed),
                            int(observation is not None),
                            int(
                                observation is not None and observation.piece_availability_announced
                            ),
                            int(observation is not None and observation.unchoked),
                            int(result.offering_observed),
                            observation.termination_reason if observation is not None else None,
                            _result_error_category(result),
                            _utc_now_text(),
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE candidates
                        SET status = 'done', completed_at_utc = ?
                        WHERE id = ?
                        """,
                        (_utc_now_text(), candidate_id),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return len(prepared)

    def store_evidence_batch(self, records: Iterable[EvidenceRecord]) -> int:
        """Speichert einen vollstaendigen EvidenceRecord-Batch atomar."""

        prepared: list[tuple[EvidenceRecord, str]] = []
        seen: set[tuple[str, str, int]] = set()
        for record in records:
            if not isinstance(record, EvidenceRecord):
                raise TypeError("store_evidence_batch erwartet EvidenceRecord-Objekte.")
            reconstructed = _evidence_from_mapping(asdict(record))
            candidate = reconstructed.handshake.candidate
            key = (candidate.info_hash_hex, candidate.ip, candidate.port)
            if key in seen:
                raise RunStoreError("Ein Evidenz-Batch enthaelt denselben Kandidaten mehrfach.")
            seen.add(key)
            prepared.append((reconstructed, _canonical_json(asdict(reconstructed))))
        if not prepared:
            return 0

        with closing(self._connect()) as connection:
            try:
                self._begin_immediate(connection)
                for record, payload in prepared:
                    candidate = record.handshake.candidate
                    row = connection.execute(
                        """
                        SELECT c.id, h.result_json
                        FROM candidates AS c
                        JOIN handshake_results AS h ON h.candidate_id = c.id
                        WHERE c.info_hash = ? AND c.ip = ? AND c.port = ?
                        """,
                        (candidate.info_hash_hex, candidate.ip, candidate.port),
                    ).fetchone()
                    if row is None:
                        raise RunStoreError("Evidenz gehoert zu keinem Handshake-Ergebnis.")
                    stored_handshake = _handshake_from_mapping(
                        _decode_json(str(row["result_json"]), "result_json")
                    )
                    if stored_handshake != record.handshake:
                        raise RunStoreError("Evidenz enthaelt abweichende Handshake-Daten.")
                    connection.execute(
                        """
                        INSERT INTO evidence_records (candidate_id, evidence_json, stored_at_utc)
                        VALUES (?, ?, ?)
                        """,
                        (int(row["id"]), payload, _utc_now_text()),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return len(prepared)

    def requeue_in_progress(self) -> int:
        """Stellt nach einem Absturz alle nicht abgeschlossenen Reservierungen zurueck."""

        with closing(self._connect()) as connection:
            try:
                self._begin_immediate(connection)
                cursor = connection.execute(
                    """
                    UPDATE candidates
                    SET status = 'pending', claimed_at_utc = NULL
                    WHERE status = 'in_progress'
                    """
                )
                changed = int(cursor.rowcount)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return changed

    def iter_candidates(
        self,
        *,
        status: str | None = None,
        batch_size: int = 100,
    ) -> Iterator[PeerCandidate]:
        """Liest Kandidaten geordnet mit ``fetchmany`` statt als Gesamtliste."""

        self._validate_batch_size(batch_size)
        if status is not None and status not in VALID_CANDIDATE_STATUSES:
            raise ValueError(f"Unbekannter Kandidatenstatus: {status}")
        connection = self._connect()
        try:
            if status is None:
                cursor = connection.execute("SELECT candidate_json FROM candidates ORDER BY id")
            else:
                cursor = connection.execute(
                    "SELECT candidate_json FROM candidates WHERE status = ? ORDER BY id",
                    (status,),
                )
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    yield _candidate_from_mapping(
                        _decode_json(str(row["candidate_json"]), "candidate_json")
                    )
        finally:
            connection.close()

    def iter_handshake_results(self, *, batch_size: int = 5) -> Iterator[HandshakeResult]:
        """Liest Handshake-Ergebnisse geordnet in kleinen Batches."""

        self._validate_batch_size(batch_size)
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT result_json FROM handshake_results ORDER BY candidate_id"
            )
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    yield _handshake_from_mapping(
                        _decode_json(str(row["result_json"]), "result_json")
                    )
        finally:
            connection.close()

    def iter_evidence_records(self, *, batch_size: int = 5) -> Iterator[EvidenceRecord]:
        """Liest Evidenzdatensaetze geordnet in kleinen Batches."""

        self._validate_batch_size(batch_size)
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT evidence_json FROM evidence_records ORDER BY candidate_id"
            )
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    yield _evidence_from_mapping(
                        _decode_json(str(row["evidence_json"]), "evidence_json")
                    )
        finally:
            connection.close()

    def iter_positive_ip_groups(
        self,
        *,
        batch_size: int = 5,
    ) -> Iterator[RunStoreIpGroup]:
        """Zaehlt positive Evidenz IP-weise mit konstantem Python-Speicher."""

        self._validate_batch_size(batch_size)
        connection = self._connect()
        current_ip: str | None = None
        current_count = 0
        current_is_known_vpn = False
        try:
            cursor = connection.execute(
                """
                SELECT c.ip, e.evidence_json
                FROM evidence_records AS e
                JOIN candidates AS c ON c.id = e.candidate_id
                JOIN handshake_results AS h ON h.candidate_id = e.candidate_id
                WHERE h.offering_observed = 1
                ORDER BY c.ip, c.id
                """
            )
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    stored_ip = str(row["ip"])
                    record = _evidence_from_mapping(
                        _decode_json(str(row["evidence_json"]), "evidence_json")
                    )
                    record_ip = record.handshake.candidate.ip
                    if record_ip != stored_ip:
                        raise RunStoreError(
                            "Evidenz-IP stimmt nicht mit dem Kandidatenindex ueberein."
                        )
                    if not record.handshake.offering_observed:
                        raise RunStoreError(
                            "Als positiv indexierte Evidenz hat keinen positiven Gesamtbefund."
                        )
                    if current_ip is not None and stored_ip != current_ip:
                        yield RunStoreIpGroup(
                            ip=current_ip,
                            record_count=current_count,
                            is_known_vpn=current_is_known_vpn,
                        )
                        current_count = 0
                        current_is_known_vpn = False
                    current_ip = stored_ip
                    current_count += 1
                    current_is_known_vpn = current_is_known_vpn or record.vpn.status == "known_vpn"
            if current_ip is not None:
                yield RunStoreIpGroup(
                    ip=current_ip,
                    record_count=current_count,
                    is_known_vpn=current_is_known_vpn,
                )
        finally:
            connection.close()

    def iter_positive_evidence_for_ip(
        self,
        ip: str,
        *,
        batch_size: int = 5,
    ) -> Iterator[EvidenceRecord]:
        """Liest alle positiven Befunde einer kanonischen IP in kleinen Batches."""

        self._validate_batch_size(batch_size)
        if not isinstance(ip, str) or "%" in ip:
            raise ValueError("ip muss eine numerische IP-Adresse ohne Zonenkennung sein.")
        try:
            canonical_ip = ipaddress.ip_address(ip).compressed
        except ValueError as exc:
            raise ValueError("ip muss eine gueltige numerische IP-Adresse sein.") from exc

        connection = self._connect()
        try:
            cursor = connection.execute(
                """
                SELECT e.evidence_json
                FROM evidence_records AS e
                JOIN candidates AS c ON c.id = e.candidate_id
                JOIN handshake_results AS h ON h.candidate_id = e.candidate_id
                WHERE c.ip = ? AND h.offering_observed = 1
                ORDER BY c.id
                """,
                (canonical_ip,),
            )
            while rows := cursor.fetchmany(batch_size):
                for row in rows:
                    record = _evidence_from_mapping(
                        _decode_json(str(row["evidence_json"]), "evidence_json")
                    )
                    if record.handshake.candidate.ip != canonical_ip:
                        raise RunStoreError(
                            "Evidenz-IP stimmt nicht mit der abgefragten IP ueberein."
                        )
                    if not record.handshake.offering_observed:
                        raise RunStoreError(
                            "Als positiv indexierte Evidenz hat keinen positiven Gesamtbefund."
                        )
                    yield record
        finally:
            connection.close()

    def evidence_count(self) -> int:
        """Liefert die Anzahl persistierter Evidenzdatensaetze ohne Materialisierung."""

        with closing(self._connect()) as connection:
            row = connection.execute("SELECT COUNT(*) FROM evidence_records").fetchone()
        return int(row[0])

    def failure_reasons_by_hash(
        self,
        target_hashes: Iterable[str] = (),
    ) -> dict[str, dict[str, int]]:
        """Aggregiert diagnostische Fehlschlagkategorien direkt in SQLite."""

        requested = tuple(dict.fromkeys(_validate_info_hash(item) for item in target_hashes))
        reasons: dict[str, dict[str, int]] = {info_hash: {} for info_hash in requested}
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                WITH failure_reasons AS (
                    SELECT c.info_hash, 'confirmation:not_confirmed' AS reason
                    FROM candidates AS c
                    JOIN handshake_results AS h ON h.candidate_id = c.id
                    WHERE h.confirmed = 0

                    UNION ALL
                    SELECT c.info_hash, 'availability:missing'
                    FROM candidates AS c
                    JOIN handshake_results AS h ON h.candidate_id = c.id
                    WHERE h.confirmed = 1 AND h.availability_present = 0

                    UNION ALL
                    SELECT c.info_hash, 'availability:no_piece'
                    FROM candidates AS c
                    JOIN handshake_results AS h ON h.candidate_id = c.id
                    WHERE h.availability_present = 1 AND h.piece_availability = 0

                    UNION ALL
                    SELECT c.info_hash, 'availability:no_unchoke'
                    FROM candidates AS c
                    JOIN handshake_results AS h ON h.candidate_id = c.id
                    WHERE h.availability_present = 1 AND h.unchoked = 0

                    UNION ALL
                    SELECT c.info_hash, 'termination:' || h.termination_reason
                    FROM candidates AS c
                    JOIN handshake_results AS h ON h.candidate_id = c.id
                    WHERE h.offering_observed = 0 AND h.termination_reason IS NOT NULL

                    UNION ALL
                    SELECT c.info_hash, 'error:' || h.error_category
                    FROM candidates AS c
                    JOIN handshake_results AS h ON h.candidate_id = c.id
                    WHERE h.offering_observed = 0 AND h.error_category IS NOT NULL
                )
                SELECT info_hash, reason, COUNT(*) AS occurrences
                FROM failure_reasons
                GROUP BY info_hash, reason
                ORDER BY info_hash, reason
                """
            )
            for row in cursor:
                info_hash = str(row["info_hash"])
                reasons.setdefault(info_hash, {})[str(row["reason"])] = int(row["occurrences"])
        return reasons

    def metrics_by_hash(
        self,
        target_hashes: Iterable[str] = (),
    ) -> dict[str, RunStoreMetrics]:
        """Aggregiert Status-, Handshake- und Evidenzzaehler vollstaendig in SQL."""

        requested = tuple(dict.fromkeys(_validate_info_hash(item) for item in target_hashes))
        metrics: dict[str, RunStoreMetrics] = {
            info_hash: RunStoreMetrics(info_hash=info_hash) for info_hash in requested
        }
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                SELECT
                    c.info_hash,
                    COUNT(*) AS candidates,
                    SUM(CASE WHEN c.status = 'pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN c.status = 'in_progress' THEN 1 ELSE 0 END) AS in_progress,
                    SUM(CASE WHEN c.status = 'done' THEN 1 ELSE 0 END) AS done,
                    COUNT(h.candidate_id) AS handshake_results,
                    COALESCE(SUM(h.confirmed), 0) AS confirmed,
                    COALESCE(SUM(h.piece_availability), 0) AS piece_availability,
                    COALESCE(SUM(h.unchoked), 0) AS unchoked,
                    COALESCE(SUM(h.offering_observed), 0) AS offering_observed,
                    SUM(
                        CASE
                            WHEN h.candidate_id IS NOT NULL AND h.offering_observed = 0 THEN 1
                            ELSE 0
                        END
                    ) AS terminal_failures,
                    COUNT(e.candidate_id) AS evidence_records
                FROM candidates AS c
                LEFT JOIN handshake_results AS h ON h.candidate_id = c.id
                LEFT JOIN evidence_records AS e ON e.candidate_id = c.id
                GROUP BY c.info_hash
                ORDER BY MIN(c.id)
                """
            )
            for row in cursor:
                info_hash = str(row["info_hash"])
                metrics[info_hash] = RunStoreMetrics(
                    info_hash=info_hash,
                    candidates=int(row["candidates"]),
                    pending=int(row["pending"]),
                    in_progress=int(row["in_progress"]),
                    done=int(row["done"]),
                    handshake_results=int(row["handshake_results"]),
                    confirmed=int(row["confirmed"]),
                    piece_availability=int(row["piece_availability"]),
                    unchoked=int(row["unchoked"]),
                    offering_observed=int(row["offering_observed"]),
                    terminal_failures=int(row["terminal_failures"]),
                    evidence_records=int(row["evidence_records"]),
                )
        return metrics

    @staticmethod
    def _validate_batch_size(batch_size: int) -> None:
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
            raise ValueError("batch_size muss eine positive Ganzzahl sein.")
