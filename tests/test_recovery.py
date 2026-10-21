"""Offline-Tests fuer die speicherbegrenzte Journal-Recovery."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import bittorrent_beobachter.monitor as monitor_module
import bittorrent_beobachter.recovery as recovery_module
from bittorrent_beobachter.config import default_app_config
from bittorrent_beobachter.evidence import EvidenceJournal, EvidenceJournalError
from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    PeerControlEvent,
    ScanResult,
    VpnClassification,
)
from bittorrent_beobachter.recovery import (
    EvidenceRecoveryError,
    LegacyRecoveryNotice,
    RecoveredEvidenceBatch,
    RecoveredRunContext,
    RecoverySummary,
    recover_evidence_journal,
)
from bittorrent_beobachter.run_store import RunStore

HASH_A = "11" * 20
HASH_B = "22" * 20
CONFIG_A = "a" * 64
CONFIG_B = "c" * 64
SOFTWARE_A = "b" * 64
SOFTWARE_B = "d" * 64
SNAPSHOT_HASH_A = "e" * 64
SNAPSHOT_HASH_B = "f" * 64


def _candidate(info_hash: str, index: int) -> PeerCandidate:
    return PeerCandidate(
        target_label="Ziel A" if info_hash == HASH_A else "Ziel B",
        info_hash_hex=info_hash,
        ip=f"8.8.{index // 250}.{index % 250 + 1}",
        port=10_000 + index,
        discovered_at_utc="2026-10-20T10:00:00.000Z",
        dht_node_ip="9.9.9.9",
        dht_node_port=6881,
        transaction_id_hex=f"{index:08x}",
        response_sha256=f"{index + 1:064x}",
        source_note="Recovery-Test",
    )


def _handshake(candidate: PeerCandidate) -> HandshakeResult:
    bitfield_event = PeerControlEvent(
        observed_at_utc="2026-10-20T10:00:01.500Z",
        elapsed_seconds=0.5,
        kind="bitfield",
        payload_length=1,
        non_empty=True,
        payload_sha256="12" * 32,
        set_bits=1,
    )
    unchoke_event = PeerControlEvent(
        observed_at_utc="2026-10-20T10:00:02.000Z",
        elapsed_seconds=1.0,
        kind="unchoke",
        payload_length=0,
    )
    availability = PeerAvailabilityObservation(
        started_at_utc="2026-10-20T10:00:01.000Z",
        ended_at_utc="2026-10-20T10:01:01.000Z",
        requested_duration_seconds=60.0,
        duration_seconds=60.0,
        completed_full_window=True,
        interested_sent=True,
        non_empty_bitfield=True,
        have_announced=False,
        piece_availability_announced=True,
        unchoked=True,
        peer_choking_at_end=False,
        unchoked_duration_seconds=59.0,
        messages_received=2,
        bytes_received=11,
        request_messages_sent=0,
        piece_payload_bytes_received=0,
        metadata_requests_sent=0,
        termination_reason="duration_elapsed",
        control_events=(bitfield_event, unchoke_event),
    )
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc="2026-10-20T10:00:00.500Z",
        completed_at_utc="2026-10-20T10:00:00.750Z",
        confirmed=True,
        remote_peer_id_hex="ab" * 20,
        reserved_bits_hex="00" * 8,
        local_ip="192.0.2.20",
        local_port=50_000,
        bytes_sent=73,
        bytes_received=79,
        error=None,
        availability=availability,
    )


def _record(info_hash: str, index: int) -> EvidenceRecord:
    handshake = _handshake(_candidate(info_hash, index))
    ip = handshake.candidate.ip
    return EvidenceRecord(
        handshake=handshake,
        enrichment=NetworkEnrichment(
            ip=ip,
            enriched_at_utc="2026-10-20T10:01:02.000Z",
            prefix=f"{ip}/32",
            asns=(64_496 + index,),
            holder="Testnetz",
            country="DE",
            source_urls=("https://example.invalid/rdap",),
            source_fetched_at_utc=(("https://example.invalid/rdap", "2026-10-20T10:01:02.000Z"),),
        ),
        vpn=VpnClassification(status="not_known_vpn"),
        evidence_event_sha256="0" * 64,
    )


def _record_with_legacy_gate_difference(
    index: int,
    *,
    completed_full_window: bool,
    availability_error: str | None,
    interested_sent: bool = True,
) -> EvidenceRecord:
    record = _record(HASH_A, index)
    availability = record.handshake.availability
    assert availability is not None
    return replace(
        record,
        handshake=replace(
            record.handshake,
            availability=replace(
                availability,
                completed_full_window=completed_full_window,
                interested_sent=interested_sent,
                termination_reason=(
                    "duration_elapsed"
                    if completed_full_window and availability_error is None
                    else "peer_closed"
                ),
                error=availability_error,
            ),
        ),
    )


def _record_with_v1_proof_difference(index: int, case: str) -> EvidenceRecord:
    record = _record(HASH_A, index)
    availability = record.handshake.availability
    assert availability is not None
    bitfield, unchoke = availability.control_events
    if case == "duplicate_bitfield":
        middle = replace(
            bitfield,
            observed_at_utc="2026-10-20T10:00:01.750Z",
            elapsed_seconds=0.75,
        )
    elif case == "have_none":
        middle = PeerControlEvent(
            observed_at_utc="2026-10-20T10:00:01.750Z",
            elapsed_seconds=0.75,
            kind="have_none",
            payload_length=0,
        )
    else:
        raise AssertionError(f"Unbekannter v1-Prooffall: {case}")
    events = (bitfield, middle, unchoke)
    availability_bytes = 17 if case == "duplicate_bitfield" else 16
    return replace(
        record,
        handshake=replace(
            record.handshake,
            bytes_received=68 + availability_bytes,
            availability=replace(
                availability,
                messages_received=3,
                bytes_received=availability_bytes,
                control_events=events,
            ),
        ),
    )


def _start_event(
    run_id: str,
    *,
    info_hash: str = HASH_A,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
    snapshot_sha256: str = SNAPSHOT_HASH_A,
    evidence_semantics_version: int = 2,
) -> dict[str, object]:
    return {
        "event_type": "scan_started",
        "run_id": run_id,
        "config_sha256": config_sha256,
        "config_snapshot": f"{run_id}.config.json",
        "config_snapshot_file_sha256": snapshot_sha256,
        "evidence_semantics_version": evidence_semantics_version,
        "software_sha256": software_sha256,
        "targets": [
            {"label": "Ziel A" if info_hash == HASH_A else "Ziel B", "info_hash": info_hash}
        ],
        "network_enrichment_enabled": False,
    }


def _legacy_start_event(
    run_id: str,
    *,
    info_hash: str = HASH_A,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
) -> dict[str, object]:
    event = _start_event(
        run_id,
        info_hash=info_hash,
        config_sha256=config_sha256,
        software_sha256=software_sha256,
    )
    del event["evidence_semantics_version"]
    del event["config_snapshot"]
    del event["config_snapshot_file_sha256"]
    return event


def _v033_start_event(
    run_id: str,
    *,
    info_hash: str = HASH_A,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
    snapshot_sha256: str = SNAPSHOT_HASH_A,
) -> dict[str, object]:
    event = _start_event(
        run_id,
        info_hash=info_hash,
        config_sha256=config_sha256,
        software_sha256=software_sha256,
        snapshot_sha256=snapshot_sha256,
    )
    del event["evidence_semantics_version"]
    return event


def _evidence_event(
    run_id: str,
    record: EvidenceRecord,
    *,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
) -> dict[str, object]:
    return {
        "event_type": "observed_bittorrent_piece_availability",
        "run_id": run_id,
        "config_sha256": config_sha256,
        "software_sha256": software_sha256,
        "handshake": asdict(record.handshake),
        "enrichment": asdict(record.enrichment),
        "vpn": asdict(record.vpn),
    }


def _terminal_event(
    run_id: str,
    event_type: str = "scan_failed",
    *,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
) -> dict[str, object]:
    return {
        "event_type": event_type,
        "run_id": run_id,
        "config_sha256": config_sha256,
        "software_sha256": software_sha256,
        "failed_at_utc": "2026-10-20T10:02:00.000Z",
        "error_type": "RuntimeError",
        "error": "simulierter Abbruch",
    }


def _published_terminal_event(
    run_id: str,
    event_type: str = "scan_completed",
    *,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
    report_binding: dict[str, object] | None = None,
) -> dict[str, object]:
    event = _terminal_event(
        run_id,
        event_type,
        config_sha256=config_sha256,
        software_sha256=software_sha256,
    )
    event.update(
        report_binding
        or {
            "report_file_count": 1,
            "report_manifest": "manifest.json",
            "report_manifest_sha256": "9" * 64,
        }
    )
    return event


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_report_package(
    output_dir: Path,
    report_run_id: str,
    *,
    file_prefix: str | None = None,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_prefix = file_prefix or report_run_id
    report_paths: list[Path] = []
    for suffix in (
        "_laufbericht.pdf",
        "_beobachtungen.csv",
        "_vpn_liste.csv",
        "_vpn_liste.pdf",
    ):
        path = output_dir / f"{report_prefix}{suffix}"
        path.write_bytes(f"Testbericht {suffix}\n".encode())
        report_paths.append(path)

    manifest_path = output_dir / f"{report_prefix}_SHA256SUMS.txt"
    manifest_lines = [
        "# SHA-256-Manifest der erzeugten Berichte",
        f"# Lauf-ID: {report_run_id}",
        "# Erstellt (UTC): 2026-10-20T10:02:00.000Z",
        "# Die Manifestdatei selbst ist wegen des Zirkelschlusses nicht enthalten.",
        *(f"{_sha256_file(path)} *{path.name}" for path in report_paths),
    ]
    manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    return {
        "report_file_count": len(report_paths) + 1,
        "report_manifest": manifest_path.name,
        "report_manifest_sha256": _sha256_file(manifest_path),
    }


def _recovery_report_directory(evidence_dir: Path, batch: RecoveredEvidenceBatch) -> Path:
    digest = hashlib.sha256(
        "\n".join(record.evidence_event_sha256 for record in batch.records).encode("ascii")
    ).hexdigest()[:16]
    return evidence_dir.parent / "reports" / batch.run_id / f"wiederhergestellt-{digest}"


def _write_recovery_report_package(
    evidence_dir: Path,
    batch: RecoveredEvidenceBatch,
) -> dict[str, object]:
    digest = hashlib.sha256(
        "\n".join(record.evidence_event_sha256 for record in batch.records).encode("ascii")
    ).hexdigest()[:16]
    report_run_id = f"recovery-{batch.run_id[-32:]}-{digest}"
    return _write_report_package(
        _recovery_report_directory(evidence_dir, batch),
        report_run_id,
    )


def _prepare_store(evidence_dir: Path, run_id: str, records: list[EvidenceRecord]) -> RunStore:
    store = RunStore(evidence_dir / "runs" / f"{run_id}.sqlite3")
    candidates = [record.handshake.candidate for record in records]
    if candidates:
        assert store.add_candidates(candidates) == len(candidates)
        target_hashes = tuple(dict.fromkeys(candidate.info_hash_hex for candidate in candidates))
        assert len(store.claim_candidate_batch(target_hashes, size=len(candidates))) == len(
            candidates
        )
        assert store.store_handshake_batch(record.handshake for record in records) == len(records)
    return store


def test_empty_journal_returns_zero_summary(tmp_path: Path) -> None:
    callbacks: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(
        tmp_path / "evidence",
        on_recovered=callbacks.append,
    )

    assert summary == RecoverySummary()
    assert callbacks == []


def test_mixed_journal_recovers_only_evidence_event(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-mixed"
    source_record = _record(HASH_A, 1)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    journal = EvidenceJournal(evidence_dir / "events.jsonl")
    entries = journal.append_many(
        (
            _start_event(run_id),
            {"event_type": "diagnostic", "message": "wird ignoriert"},
            _evidence_event(run_id, source_record),
        )
    )
    callbacks: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_recovered=callbacks.append)

    expected = replace(source_record, evidence_event_sha256=entries[2].event_sha256)
    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1, inserted_records=1)
    assert list(store.iter_evidence_records()) == [expected]
    assert callbacks == [
        RecoveredEvidenceBatch(
            run_id=run_id,
            config_sha256=CONFIG_A,
            software_sha256=SOFTWARE_A,
            config_snapshot=f"{run_id}.config.json",
            config_snapshot_file_sha256=SNAPSHOT_HASH_A,
            records=(expected,),
            evidence_semantics_version=2,
        )
    ]


def test_repeated_recovery_is_noop_and_does_not_call_callback(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-idempotent"
    source_record = _record(HASH_A, 2)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    assert recover_evidence_journal(evidence_dir).inserted_records == 1
    callbacks: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_recovered=callbacks.append)

    assert summary == RecoverySummary(scanned_entries=2, evidence_events=1, inserted_records=0)
    assert callbacks == []
    assert store.evidence_count() == 1


def test_multiple_runs_in_one_journal_batch_lose_no_records(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    record_a = _record(HASH_A, 3)
    record_b = _record(HASH_B, 4)
    store_a = _prepare_store(evidence_dir, "run-a", [record_a])
    store_b = _prepare_store(evidence_dir, "run-b", [record_b])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event("run-a"),
            _start_event(
                "run-b",
                info_hash=HASH_B,
                config_sha256=CONFIG_B,
                software_sha256=SOFTWARE_B,
                snapshot_sha256=SNAPSHOT_HASH_B,
            ),
            _evidence_event("run-a", record_a),
            _evidence_event(
                "run-b",
                record_b,
                config_sha256=CONFIG_B,
                software_sha256=SOFTWARE_B,
            ),
            {"event_type": "diagnostic"},
        )
    )
    callbacks: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_recovered=callbacks.append)

    assert summary == RecoverySummary(scanned_entries=5, evidence_events=2, inserted_records=2)
    assert list(store_a.iter_evidence_records()) == [
        replace(record_a, evidence_event_sha256=entries[2].event_sha256)
    ]
    assert list(store_b.iter_evidence_records()) == [
        replace(record_b, evidence_event_sha256=entries[3].event_sha256)
    ]
    assert [batch.run_id for batch in callbacks] == ["run-a", "run-b"]


def test_journal_evidence_must_match_started_infohash(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-wrong-infohash"
    source_record = _record(HASH_B, 62)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id, info_hash=HASH_A), _evidence_event(run_id, source_record))
    )

    with pytest.raises(EvidenceRecoveryError, match="nicht an scan_started gebunden"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_db_only_evidence_must_match_started_target_label(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-wrong-target-label"
    source_record = _record(HASH_A, 63)
    candidate = replace(source_record.handshake.candidate, target_label="Anderes Ziel")
    source_record = replace(
        source_record,
        handshake=replace(source_record.handshake, candidate=candidate),
    )
    _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append(_start_event(run_id))
    callbacks: list[RecoveredRunContext] = []

    with pytest.raises(EvidenceRecoveryError, match="nicht an scan_started gebunden"):
        recover_evidence_journal(evidence_dir, on_incomplete_run=callbacks.append)

    assert callbacks == []


def test_missing_run_database_fails_without_creating_one(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-missing"
    source_record = _record(HASH_A, 5)
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    database_path = evidence_dir / "runs" / f"{run_id}.sqlite3"

    with pytest.raises(EvidenceRecoveryError, match=r"Laufdatenbank.*fehlt oder ist unsicher"):
        recover_evidence_journal(evidence_dir)

    assert not database_path.exists()


@pytest.mark.parametrize(
    ("config_sha256", "software_sha256", "expected"),
    [
        (CONFIG_B, SOFTWARE_A, "anderen Konfiguration"),
        (CONFIG_A, SOFTWARE_B, "anderen Softwarestand"),
    ],
)
def test_evidence_must_match_scan_started_binding(
    tmp_path: Path,
    config_sha256: str,
    software_sha256: str,
    expected: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-binding"
    source_record = _record(HASH_A, 6)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(
                run_id,
                source_record,
                config_sha256=config_sha256,
                software_sha256=software_sha256,
            ),
        )
    )

    with pytest.raises(EvidenceRecoveryError, match=expected):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_evidence_without_prior_start_is_rejected(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-no-start"
    source_record = _record(HASH_A, 7)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append(_evidence_event(run_id, source_record))

    with pytest.raises(EvidenceRecoveryError, match="vor dem zugehoerigen scan_started"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


@pytest.mark.parametrize("divergent", (False, True))
def test_duplicate_scan_started_is_rejected(tmp_path: Path, divergent: bool) -> None:
    evidence_dir = tmp_path / "evidence"
    first = _start_event("run-duplicate")
    second = _start_event(
        "run-duplicate",
        config_sha256=CONFIG_B if divergent else CONFIG_A,
    )
    EvidenceJournal(evidence_dir / "events.jsonl").append_many((first, second))

    with pytest.raises(EvidenceRecoveryError, match="doppeltes scan_started"):
        recover_evidence_journal(evidence_dir)


def test_callback_contains_only_records_inserted_by_this_recovery(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-partial"
    source_records = [_record(HASH_A, 8), _record(HASH_A, 9)]
    store = _prepare_store(evidence_dir, run_id, source_records)
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_records[0]),
            _evidence_event(run_id, source_records[1]),
        )
    )
    existing = replace(source_records[0], evidence_event_sha256=entries[1].event_sha256)
    expected_new = replace(source_records[1], evidence_event_sha256=entries[2].event_sha256)
    assert store.store_evidence_batch([existing]) == 1
    callbacks: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_recovered=callbacks.append)

    assert summary.inserted_records == 1
    assert [batch.records for batch in callbacks] == [(expected_new,)]
    assert list(store.iter_evidence_records()) == [existing, expected_new]


def test_recovery_callback_batch_never_exceeds_five_records(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-five"
    source_records = [_record(HASH_A, 20 + index) for index in range(5)]
    _prepare_store(evidence_dir, run_id, source_records)
    events: list[dict[str, object]] = [_start_event(run_id)]
    events.extend({"event_type": "diagnostic", "index": index} for index in range(4))
    events.extend(_evidence_event(run_id, record) for record in source_records)
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(events)
    callbacks: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_recovered=callbacks.append)

    assert summary == RecoverySummary(scanned_entries=10, evidence_events=5, inserted_records=5)
    assert [len(batch.records) for batch in callbacks] == [5]


def test_journal_tampering_propagates_without_database_change(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-tamper"
    source_record = _record(HASH_A, 30)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    journal_path = evidence_dir / "events.jsonl"
    EvidenceJournal(journal_path).append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    tampered = journal_path.read_bytes().replace(
        b'"run_id":"run-tamper"',
        b'"run_id":"run-hacker"',
        1,
    )
    journal_path.write_bytes(tampered)

    with pytest.raises(EvidenceJournalError, match="Ereignis-Hash"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_divergent_existing_database_record_is_rejected(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-divergent"
    source_record = _record(HASH_A, 31)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    assert store.store_evidence_batch([source_record]) == 1

    with pytest.raises(EvidenceRecoveryError, match="weichen ab"):
        recover_evidence_journal(evidence_dir)

    assert list(store.iter_evidence_records()) == [source_record]


def test_unsafe_config_snapshot_name_is_rejected(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    event = _start_event("run-unsafe")
    event["config_snapshot"] = "../run-unsafe.config.json"
    EvidenceJournal(evidence_dir / "events.jsonl").append(event)

    with pytest.raises(EvidenceRecoveryError, match=r"sichere.*Basename"):
        recover_evidence_journal(evidence_dir)


def test_db_only_offering_handshake_is_reported_as_incomplete_run(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-incomplete"
    source_record = _record(HASH_A, 32)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _terminal_event(run_id))
    )
    contexts: list[RecoveredRunContext] = []

    summary = recover_evidence_journal(
        evidence_dir,
        on_incomplete_run=contexts.append,
    )

    assert summary == RecoverySummary(scanned_entries=2)
    assert contexts == [
        RecoveredRunContext(
            run_id=run_id,
            config_sha256=CONFIG_A,
            software_sha256=SOFTWARE_A,
            config_snapshot=f"{run_id}.config.json",
            config_snapshot_file_sha256=SNAPSHOT_HASH_A,
            store_path=store.path,
            terminal_event="scan_failed",
            evidence_semantics_version=2,
        )
    ]


def test_incomplete_run_context_keeps_terminal_manifest_binding(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-incomplete-manifest"
    source_record = _record(HASH_A, 34)
    _prepare_store(evidence_dir, run_id, [source_record])
    report_binding = _write_report_package(
        evidence_dir.parent / "reports" / run_id,
        run_id,
    )
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _published_terminal_event(run_id, report_binding=report_binding),
        )
    )
    contexts: list[RecoveredRunContext] = []

    recover_evidence_journal(evidence_dir, on_incomplete_run=contexts.append)

    assert len(contexts) == 1
    assert contexts[0].report_manifest == report_binding["report_manifest"]
    assert contexts[0].report_manifest_sha256 == report_binding["report_manifest_sha256"]
    assert contexts[0].report_file_count == report_binding["report_file_count"]


def test_completed_store_without_unpersisted_offering_is_not_reported(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-complete"
    source_record = _record(HASH_A, 33)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    contexts: list[RecoveredRunContext] = []

    recover_evidence_journal(evidence_dir, on_incomplete_run=contexts.append)

    assert contexts == []


def test_terminal_event_must_match_started_binding(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-terminal-binding"
    _prepare_store(evidence_dir, run_id, [])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _terminal_event(run_id, config_sha256=CONFIG_B),
        )
    )

    with pytest.raises(EvidenceRecoveryError, match="abweichende Konfiguration"):
        recover_evidence_journal(evidence_dir)


def test_reconcile_is_atomic_when_second_record_diverges(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-atomic"
    source_records = [_record(HASH_A, 40), _record(HASH_A, 41)]
    store = _prepare_store(evidence_dir, run_id, source_records)
    divergent_second = replace(
        source_records[1],
        handshake=replace(
            source_records[1].handshake,
            candidate=replace(
                source_records[1].handshake.candidate,
                source_note="Abweichende Journalquelle",
            ),
        ),
    )
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_records[0]),
            _evidence_event(run_id, divergent_second),
        )
    )

    with pytest.raises(EvidenceRecoveryError, match="abweichende Kandidatendaten"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_reconciled_callback_is_retried_after_callback_failure(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-report-retry"
    source_record = _record(HASH_A, 42)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )

    def failing_callback(_batch: RecoveredEvidenceBatch) -> None:
        raise RuntimeError("simulierter Berichtsausfall")

    with pytest.raises(RuntimeError, match="Berichtsausfall"):
        recover_evidence_journal(evidence_dir, on_reconciled=failing_callback)

    assert store.evidence_count() == 1
    retried: list[RecoveredEvidenceBatch] = []
    summary = recover_evidence_journal(evidence_dir, on_reconciled=retried.append)

    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert summary.inserted_records == 0
    assert [batch.records for batch in retried] == [(expected,)]


def test_v033_pending_publish_state_is_migrated_as_semantics_v1(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-pending-state"
    source_record = _record(HASH_A, 57)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_v033_start_event(run_id), _evidence_event(run_id, source_record))
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    state_path = evidence_dir / recovery_module._PUBLISH_STATE_FILENAME
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            """
            CREATE TABLE pending_reconciled_reports (
                event_sha256 TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                config_sha256 TEXT NOT NULL,
                software_sha256 TEXT NOT NULL,
                config_snapshot TEXT,
                config_snapshot_file_sha256 TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO pending_reconciled_reports VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entries[1].event_sha256,
                run_id,
                CONFIG_A,
                SOFTWARE_A,
                f"{run_id}.config.json",
                SNAPSHOT_HASH_A,
            ),
        )
        connection.commit()
    reconciled: list[RecoveredEvidenceBatch] = []

    recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert [batch.evidence_semantics_version for batch in reconciled] == [1]
    with sqlite3.connect(state_path) as connection:
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(pending_reconciled_reports)"
            ).fetchall()
        }
        semantics_version = connection.execute(
            """
            SELECT evidence_semantics_version
            FROM pending_reconciled_reports
            WHERE event_sha256 = ?
            """,
            (entries[1].event_sha256,),
        ).fetchone()
    assert "evidence_semantics_version" in columns
    assert semantics_version == (1,)


@pytest.mark.parametrize("terminal_event", ("scan_completed", "scan_cancelled", "scan_failed"))
def test_clean_terminal_run_does_not_repeat_reconciled_callback(
    tmp_path: Path,
    terminal_event: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"run-clean-{terminal_event}"
    source_record = _record(HASH_A, 43)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    report_binding = _write_report_package(
        evidence_dir.parent / "reports" / run_id,
        run_id,
    )
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            {"event_type": "diagnostic", "index": 1},
            {"event_type": "diagnostic", "index": 2},
            {"event_type": "diagnostic", "index": 3},
            _published_terminal_event(
                run_id,
                terminal_event,
                report_binding=report_binding,
            ),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert summary == RecoverySummary(scanned_entries=6, evidence_events=1)
    assert reconciled == []
    assert list(store.iter_evidence_records()) == [expected]


def test_clean_terminal_accepts_report_slug_for_long_run_id(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "long-run-" + "x" * 100
    source_record = _record(HASH_A, 49)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    report_binding = _write_report_package(
        evidence_dir.parent / "reports" / run_id,
        run_id,
        file_prefix=run_id[:80],
    )
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _published_terminal_event(run_id, report_binding=report_binding),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert reconciled == []


def test_clean_terminal_accepts_complete_intermediate_report_packages(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-clean-with-intermediate"
    source_record = _record(HASH_A, 61)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    output_dir = evidence_dir.parent / "reports" / run_id
    report_binding = _write_report_package(output_dir, run_id)
    _write_report_package(
        output_dir / "zwischenstand-000001",
        f"{run_id}-zwischenstand-000001",
    )
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _published_terminal_event(run_id, report_binding=report_binding),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1)
    assert reconciled == []


@pytest.mark.parametrize(
    ("directory_name", "damage"),
    (
        ("zwischenstand-1", None),
        ("zwischenstand-000001", "missing_file"),
    ),
)
def test_terminal_rejects_nonstrict_or_incomplete_intermediate_package(
    tmp_path: Path,
    directory_name: str,
    damage: str | None,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"run-invalid-intermediate-{damage or 'name'}"
    source_record = _record(HASH_A, 62)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    output_dir = evidence_dir.parent / "reports" / run_id
    report_binding = _write_report_package(output_dir, run_id)
    intermediate_run_id = f"{run_id}-{directory_name}"
    intermediate_dir = output_dir / directory_name
    _write_report_package(intermediate_dir, intermediate_run_id)
    if damage == "missing_file":
        (intermediate_dir / f"{intermediate_run_id}_laufbericht.pdf").unlink()
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _published_terminal_event(run_id, report_binding=report_binding),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert [batch.records for batch in reconciled] == [(expected,)]


@pytest.mark.skipif(os.name == "nt", reason="Symlink-Rechte unterscheiden sich unter Windows")
def test_terminal_rejects_symlinked_intermediate_package_without_touching_target(
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-symlinked-intermediate"
    source_record = _record(HASH_A, 63)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    output_dir = evidence_dir.parent / "reports" / run_id
    report_binding = _write_report_package(output_dir, run_id)
    external_dir = tmp_path / "preserved-intermediate"
    _write_report_package(external_dir, f"{run_id}-zwischenstand-000001")
    preserved = {path.name: path.read_bytes() for path in external_dir.iterdir() if path.is_file()}
    (output_dir / "zwischenstand-000001").symlink_to(
        external_dir,
        target_is_directory=True,
    )
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _published_terminal_event(run_id, report_binding=report_binding),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert [batch.records for batch in reconciled] == [(expected,)]
    assert {
        path.name: path.read_bytes() for path in external_dir.iterdir() if path.is_file()
    } == preserved


@pytest.mark.parametrize(
    "damage",
    (
        "manifest_name",
        "manifest_sha256",
        "file_count",
        "listed_file",
        "unlisted_file",
        "unlisted_directory",
    ),
)
def test_terminal_report_package_must_match_complete_manifest_binding(
    tmp_path: Path,
    damage: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"run-invalid-package-{damage}"
    source_record = _record(HASH_A, 48)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    output_dir = evidence_dir.parent / "reports" / run_id
    report_binding = _write_report_package(output_dir, run_id)
    terminal_binding = dict(report_binding)
    if damage == "manifest_name":
        terminal_binding["report_manifest"] = "anderes_SHA256SUMS.txt"
    elif damage == "manifest_sha256":
        terminal_binding["report_manifest_sha256"] = "0" * 64
    elif damage == "file_count":
        terminal_binding["report_file_count"] = int(report_binding["report_file_count"]) + 1
    elif damage == "listed_file":
        (output_dir / f"{run_id}_laufbericht.pdf").write_bytes(b"nachtraeglich beschaedigt")
    elif damage == "unlisted_file":
        (output_dir / "nicht-im-manifest.txt").write_text("unerwartet", encoding="utf-8")
    else:
        unlisted_directory = output_dir / "nicht-im-manifest"
        unlisted_directory.mkdir()
        (unlisted_directory / "payload.txt").write_text("unerwartet", encoding="utf-8")

    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _published_terminal_event(run_id, report_binding=terminal_binding),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1)
    assert [batch.records for batch in reconciled] == [(expected,)]
    assert reconciled[0].report_manifest == terminal_binding["report_manifest"]
    assert reconciled[0].report_manifest_sha256 == terminal_binding["report_manifest_sha256"]
    assert reconciled[0].report_file_count == terminal_binding["report_file_count"]


def test_terminal_run_with_missing_record_calls_reconciled_callback(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-terminal-insert"
    source_record = _record(HASH_A, 44)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            {"event_type": "diagnostic", "index": 1},
            {"event_type": "diagnostic", "index": 2},
            {"event_type": "diagnostic", "index": 3},
            _published_terminal_event(run_id, "scan_completed"),
        )
    )
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert summary == RecoverySummary(scanned_entries=6, evidence_events=1, inserted_records=1)
    assert [batch.records for batch in reconciled] == [(expected,)]
    assert list(store.iter_evidence_records()) == [expected]


def test_published_terminal_repair_retries_callback_until_acknowledged(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-published-retry"
    source_record = _record(HASH_A, 46)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _published_terminal_event(run_id),
        )
    )
    first_callbacks: list[RecoveredEvidenceBatch] = []

    def failing_callback(batch: RecoveredEvidenceBatch) -> None:
        first_callbacks.append(batch)
        raise RuntimeError("simulierter terminaler Berichtsausfall")

    with pytest.raises(RuntimeError, match="terminaler Berichtsausfall"):
        recover_evidence_journal(evidence_dir, on_reconciled=failing_callback)

    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert [batch.records for batch in first_callbacks] == [(expected,)]
    assert list(store.iter_evidence_records()) == [expected]

    retried: list[RecoveredEvidenceBatch] = []

    def successful_callback(batch: RecoveredEvidenceBatch) -> None:
        retried.append(batch)
        _write_recovery_report_package(evidence_dir, batch)

    summary = recover_evidence_journal(evidence_dir, on_reconciled=successful_callback)

    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1)
    assert [batch.records for batch in retried] == [(expected,)]

    after_acknowledgement: list[RecoveredEvidenceBatch] = []
    recover_evidence_journal(
        evidence_dir,
        on_reconciled=after_acknowledgement.append,
    )
    assert after_acknowledgement == []

    recovery_dir = _recovery_report_directory(evidence_dir, retried[0])
    (recovery_dir / next(path.name for path in recovery_dir.glob("*_laufbericht.pdf"))).write_bytes(
        b"beschaedigt"
    )
    retried_after_damage: list[RecoveredEvidenceBatch] = []

    def repair_callback(batch: RecoveredEvidenceBatch) -> None:
        retried_after_damage.append(batch)
        _write_recovery_report_package(evidence_dir, batch)

    recover_evidence_journal(evidence_dir, on_reconciled=repair_callback)

    assert [batch.records for batch in retried_after_damage] == [(expected,)]
    final_callbacks: list[RecoveredEvidenceBatch] = []
    recover_evidence_journal(evidence_dir, on_reconciled=final_callbacks.append)
    assert final_callbacks == []

    next(recovery_dir.glob("*_SHA256SUMS.txt")).unlink()
    retried_after_missing: list[RecoveredEvidenceBatch] = []

    def restore_missing_callback(batch: RecoveredEvidenceBatch) -> None:
        retried_after_missing.append(batch)
        _write_recovery_report_package(evidence_dir, batch)

    recover_evidence_journal(evidence_dir, on_reconciled=restore_missing_callback)

    assert [batch.records for batch in retried_after_missing] == [(expected,)]
    callbacks_after_restore: list[RecoveredEvidenceBatch] = []
    recover_evidence_journal(evidence_dir, on_reconciled=callbacks_after_restore.append)
    assert callbacks_after_restore == []


@pytest.mark.parametrize(
    "residue_kind",
    ("previous_manifest", "unlisted_file", "unlisted_directory"),
)
def test_monitor_repairs_recovery_package_with_unlisted_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    residue_kind: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"run-recovery-residue-{residue_kind}"
    source_record = _record(HASH_A, 64)
    _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    generated_packages = 0

    def fake_generate_reports(
        result: ScanResult,
        output_dir: Path,
        _config: object,
        **_kwargs: object,
    ) -> list[Path]:
        nonlocal generated_packages
        generated_packages += 1
        report_run_id = result.run_id
        _write_report_package(output_dir, report_run_id)
        return list(output_dir.iterdir())

    monkeypatch.setattr(monitor_module, "generate_reports", fake_generate_reports)
    callbacks = 0

    def publish(batch: RecoveredEvidenceBatch) -> None:
        nonlocal callbacks
        callbacks += 1
        monitor_module._publish_recovered_batch(
            batch,
            default_app_config(),
            tmp_path,
            lambda _message: None,
            None,
        )

    recover_evidence_journal(evidence_dir, on_reconciled=publish)
    assert callbacks == 1
    recovery_dir = next(
        path
        for path in (tmp_path / "reports" / run_id).iterdir()
        if path.name.startswith("wiederhergestellt-")
    )
    manifest = next(recovery_dir.glob("*_SHA256SUMS.txt"))
    residue_name = (
        f".{manifest.name}.previous"
        if residue_kind == "previous_manifest"
        else "unerwartete-restdatei.tmp"
    )
    residue_path = recovery_dir / residue_name
    if residue_kind == "unlisted_directory":
        residue_path.mkdir()
        (residue_path / "payload.bin").write_bytes(b"aufbewahrter Testrest")
    else:
        residue_path.write_bytes(b"aufbewahrter Testrest")

    recover_evidence_journal(evidence_dir, on_reconciled=publish)

    assert callbacks == 2
    assert generated_packages == 2
    assert monitor_module._recovery_report_is_complete(
        recovery_dir,
        manifest.name.removesuffix("_SHA256SUMS.txt"),
    )
    quarantines = tuple(recovery_dir.parent.glob(f".{recovery_dir.name}.defekt-*"))
    assert len(quarantines) == 1
    preserved_residue = quarantines[0] / residue_name
    if residue_kind == "unlisted_directory":
        preserved_residue = preserved_residue / "payload.bin"
    assert preserved_residue.read_bytes() == b"aufbewahrter Testrest"

    recover_evidence_journal(evidence_dir, on_reconciled=publish)

    assert callbacks == 2
    assert generated_packages == 2


def test_monitor_repairs_symlinked_recovery_batch_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "run-symlinked-recovery-batch"
    record = replace(_record(HASH_A, 65), evidence_event_sha256="7" * 64)
    batch = RecoveredEvidenceBatch(
        run_id=run_id,
        config_sha256=CONFIG_A,
        software_sha256=SOFTWARE_A,
        config_snapshot=None,
        config_snapshot_file_sha256=None,
        records=(record,),
        evidence_semantics_version=2,
    )
    digest = hashlib.sha256(record.evidence_event_sha256.encode("ascii")).hexdigest()[:16]
    run_output_dir = tmp_path / "reports" / run_id
    run_output_dir.mkdir(parents=True)
    batch_output_dir = run_output_dir / f"wiederhergestellt-{digest}"
    preserved_target = tmp_path / "preserved-symlink-target"
    preserved_target.mkdir()
    (preserved_target / "payload.bin").write_bytes(b"nicht folgen")
    try:
        batch_output_dir.symlink_to(preserved_target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Verzeichnis-Symlinks sind nicht verfuegbar: {exc}")

    def fake_generate_reports(
        result: ScanResult,
        output_dir: Path,
        _config: object,
        **_kwargs: object,
    ) -> list[Path]:
        _write_report_package(output_dir, result.run_id)
        return list(output_dir.iterdir())

    monkeypatch.setattr(monitor_module, "generate_reports", fake_generate_reports)

    monitor_module._publish_recovered_batch(
        batch,
        default_app_config(),
        tmp_path,
        lambda _message: None,
        None,
    )

    assert batch_output_dir.is_dir()
    assert not batch_output_dir.is_symlink()
    assert (preserved_target / "payload.bin").read_bytes() == b"nicht folgen"
    quarantines = tuple(run_output_dir.glob(f".{batch_output_dir.name}.defekt-*"))
    assert len(quarantines) == 1
    assert quarantines[0].is_symlink()
    assert monitor_module._recovery_report_is_complete(
        batch_output_dir,
        f"recovery-{run_id[-32:]}-{digest}",
    )


def test_manifestless_failed_run_is_acknowledged_after_valid_recovery_package(
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-manifestless-failure"
    source_record = _record(HASH_A, 47)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            _terminal_event(run_id, "scan_failed"),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    def publish_callback(batch: RecoveredEvidenceBatch) -> None:
        reconciled.append(batch)
        _write_recovery_report_package(evidence_dir, batch)

    summary = recover_evidence_journal(evidence_dir, on_reconciled=publish_callback)

    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1)
    assert [batch.records for batch in reconciled] == [(expected,)]
    repeated: list[RecoveredEvidenceBatch] = []

    recover_evidence_journal(evidence_dir, on_reconciled=repeated.append)

    assert repeated == []


def test_evidence_after_terminal_retries_publication_until_acknowledged(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-late-recovered-evidence"
    source_record = _record(HASH_A, 61)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    report_binding = _write_report_package(
        evidence_dir.parent / "reports" / run_id,
        run_id,
    )
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _published_terminal_event(run_id, report_binding=report_binding),
            _evidence_event(run_id, source_record),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[2].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    failed_callbacks: list[RecoveredEvidenceBatch] = []

    def failing_callback(batch: RecoveredEvidenceBatch) -> None:
        failed_callbacks.append(batch)
        raise RuntimeError("simulierter Ausfall fuer spaete Evidenz")

    with pytest.raises(RuntimeError, match="Ausfall fuer spaete Evidenz"):
        recover_evidence_journal(evidence_dir, on_reconciled=failing_callback)

    assert [batch.records for batch in failed_callbacks] == [(expected,)]
    retried: list[RecoveredEvidenceBatch] = []

    def successful_callback(batch: RecoveredEvidenceBatch) -> None:
        retried.append(batch)
        _write_recovery_report_package(evidence_dir, batch)

    recover_evidence_journal(evidence_dir, on_reconciled=successful_callback)

    assert [batch.records for batch in retried] == [(expected,)]
    after_acknowledgement: list[RecoveredEvidenceBatch] = []
    recover_evidence_journal(evidence_dir, on_reconciled=after_acknowledgement.append)
    assert after_acknowledgement == []


def test_interrupted_consistent_run_retries_reconciled_callback(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-interrupted-consistent"
    source_record = _record(HASH_A, 45)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert summary == RecoverySummary(scanned_entries=2, evidence_events=1)
    assert [batch.records for batch in reconciled] == [(expected,)]


def test_low_disk_aborts_and_cleans_private_same_volume_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "run-low-disk"
    _prepare_store(evidence_dir, run_id, [])
    EvidenceJournal(evidence_dir / "events.jsonl").append(_start_event(run_id))
    checked_paths: list[Path] = []
    observed_modes: list[tuple[int, int]] = []

    def disk_usage(path: os.PathLike[str] | str) -> SimpleNamespace:
        checked_paths.append(Path(path))
        temporary_directories = tuple(evidence_dir.glob(".afdleakercatcher-recovery-*"))
        if temporary_directories:
            if os.name != "nt":
                index_directory = temporary_directories[0]
                index_file = index_directory / "run-bindings.sqlite3"
                observed_modes.append(
                    (
                        stat.S_IMODE(index_directory.stat().st_mode),
                        stat.S_IMODE(index_file.stat().st_mode),
                    )
                )
            return SimpleNamespace(free=recovery_module.RECOVERY_MIN_FREE_SPACE_BYTES - 1)
        return SimpleNamespace(free=recovery_module.RECOVERY_MIN_FREE_SPACE_BYTES)

    monkeypatch.setattr(recovery_module.shutil, "disk_usage", disk_usage)

    with pytest.raises(EvidenceRecoveryError, match="Weniger als 100 MB"):
        recover_evidence_journal(evidence_dir)

    assert checked_paths
    assert all(path == evidence_dir for path in checked_paths)
    if os.name != "nt":
        assert observed_modes == [(0o700, 0o600)]
    assert tuple(evidence_dir.glob(".afdleakercatcher-recovery-*")) == ()


@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    (
        ("short_full_window", "unterschreitet"),
        ("nonmonotonic_events", "nicht monoton"),
        ("event_after_duration", "hinter der protokollierten"),
    ),
)
def test_recovery_rejects_invalid_availability_timeline(
    tmp_path: Path,
    corruption: str,
    expected_error: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"invalid-availability-{corruption}"
    source_record = _record(HASH_A, 64)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    event = _evidence_event(run_id, source_record)
    handshake = event["handshake"]
    assert isinstance(handshake, dict)
    availability = handshake["availability"]
    assert isinstance(availability, dict)
    control_events = availability["control_events"]
    assert isinstance(control_events, tuple)
    first_event = dict(control_events[0])
    if corruption == "short_full_window":
        availability["duration_seconds"] = 0.1
    elif corruption == "nonmonotonic_events":
        second_event = {
            **first_event,
            "observed_at_utc": "2026-10-20T10:00:03.000Z",
            "elapsed_seconds": 0.25,
            "kind": "have",
            "payload_length": 4,
            "piece_index": 1,
            "non_empty": None,
            "payload_sha256": None,
            "set_bits": None,
        }
        availability["control_events"] = (first_event, second_event)
        availability["bytes_received"] = 15
        handshake["bytes_received"] = 83
    elif corruption == "event_after_duration":
        availability["messages_received"] = 1
        availability["bytes_received"] = 6
        availability["control_events"] = ({**first_event, "elapsed_seconds": 60.000002},)
        handshake["bytes_received"] = 74
    else:
        raise AssertionError(f"Unbekannter Testfall: {corruption}")
    EvidenceJournal(evidence_dir / "events.jsonl").append_many((_start_event(run_id), event))

    with pytest.raises(EvidenceRecoveryError, match=expected_error):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


@pytest.mark.parametrize(
    ("completed_full_window", "availability_error"),
    (
        (False, None),
        (True, "Peer schloss die Verbindung vorzeitig."),
        (False, "Peer schloss die Verbindung vorzeitig."),
    ),
)
def test_v033_gate_only_evidence_is_skipped_runwise_without_publication(
    tmp_path: Path,
    completed_full_window: bool,
    availability_error: str | None,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-early-end"
    source_record = _record_with_legacy_gate_difference(
        53,
        completed_full_window=completed_full_window,
        availability_error=availability_error,
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _v033_start_event(run_id, software_sha256=SOFTWARE_A),
            _evidence_event(run_id, source_record, software_sha256=SOFTWARE_A),
        )
    )
    recovered: list[RecoveredEvidenceBatch] = []
    reconciled: list[RecoveredEvidenceBatch] = []
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(
        evidence_dir,
        on_recovered=recovered.append,
        on_reconciled=reconciled.append,
        on_legacy_skipped=notices.append,
    )

    assert summary == RecoverySummary(
        scanned_entries=2,
        evidence_events=1,
        skipped_legacy_runs=1,
    )
    assert store.evidence_count() == 0
    assert recovered == []
    assert reconciled == []
    assert len(notices) == 1
    assert notices[0].run_id == run_id
    assert "Version 0.3.3" in notices[0].reason


def test_v033_short_early_eof_record_does_not_block_recovery(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-realistic-short-eof"
    base_record = _record(HASH_A, 57)
    source_record = _record_with_legacy_gate_difference(
        57,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
    )
    availability = source_record.handshake.availability
    assert availability is not None
    source_record = replace(
        source_record,
        handshake=replace(
            source_record.handshake,
            availability=replace(
                availability,
                ended_at_utc="2026-10-20T10:00:03.000Z",
                duration_seconds=2.0,
                unchoked_duration_seconds=2.0,
            ),
        ),
    )
    store = _prepare_store(evidence_dir, run_id, [base_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _v033_start_event(run_id, software_sha256=SOFTWARE_A),
            _evidence_event(run_id, source_record, software_sha256=SOFTWARE_A),
        )
    )
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(evidence_dir, on_legacy_skipped=notices.append)

    assert summary.skipped_legacy_runs == 1
    assert store.evidence_count() == 0
    assert [notice.run_id for notice in notices] == [run_id]


def test_explicit_semantics_v1_gate_only_evidence_is_skipped(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "explicit-v1-early-end"
    source_record = _record_with_legacy_gate_difference(
        54,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id, evidence_semantics_version=1),
            _evidence_event(run_id, source_record),
        )
    )
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(evidence_dir, on_legacy_skipped=notices.append)

    assert summary.skipped_legacy_runs == 1
    assert store.evidence_count() == 0
    assert [notice.run_id for notice in notices] == [run_id]


@pytest.mark.parametrize("case", ("duplicate_bitfield", "have_none"))
def test_v033_historical_proof_semantics_are_skipped_runwise(
    tmp_path: Path,
    case: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"v033-proof-{case}"
    source_record = _record_with_v1_proof_difference(62, case)
    store = _prepare_store(evidence_dir, run_id, [_record(HASH_A, 62)])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_v033_start_event(run_id), _evidence_event(run_id, source_record))
    )
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(evidence_dir, on_legacy_skipped=notices.append)

    assert summary == RecoverySummary(
        scanned_entries=2,
        evidence_events=1,
        skipped_legacy_runs=1,
    )
    assert store.evidence_count() == 0
    assert [notice.run_id for notice in notices] == [run_id]


@pytest.mark.parametrize("case", ("duplicate_bitfield", "have_none"))
def test_semantics_v2_historical_proof_difference_is_fatal(
    tmp_path: Path,
    case: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"v2-proof-{case}"
    source_record = _record_with_v1_proof_difference(63, case)
    store = _prepare_store(evidence_dir, run_id, [_record(HASH_A, 63)])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )

    with pytest.raises(EvidenceRecoveryError, match="nicht an scan_started gebunden"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_v033_db_only_historical_proof_semantics_are_skipped(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-db-only-duplicate-bitfield"
    source_record = _record_with_v1_proof_difference(64, "duplicate_bitfield")
    store = _prepare_store(evidence_dir, run_id, [_record(HASH_A, 64)])
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE handshake_results SET result_json = ?, offering_observed = 1",
            (
                json.dumps(
                    asdict(source_record.handshake),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        connection.commit()
    EvidenceJournal(evidence_dir / "events.jsonl").append(_v033_start_event(run_id))
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(evidence_dir, on_legacy_skipped=notices.append)

    assert summary == RecoverySummary(scanned_entries=1, skipped_legacy_runs=1)
    assert store.evidence_count() == 0
    assert [notice.run_id for notice in notices] == [run_id]


def test_v033_db_only_gate_record_is_skipped_before_incomplete_callback(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-db-only-early-end"
    source_record = _record_with_legacy_gate_difference(
        58,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE handshake_results SET offering_observed = 1")
        connection.commit()
    EvidenceJournal(evidence_dir / "events.jsonl").append(_v033_start_event(run_id))
    incomplete: list[RecoveredRunContext] = []
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(
        evidence_dir,
        on_incomplete_run=incomplete.append,
        on_legacy_skipped=notices.append,
    )

    assert summary == RecoverySummary(scanned_entries=1, skipped_legacy_runs=1)
    assert incomplete == []
    assert [notice.run_id for notice in notices] == [run_id]


def test_unknown_future_evidence_semantics_version_is_rejected(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    EvidenceJournal(evidence_dir / "events.jsonl").append(
        _start_event("future-semantics", evidence_semantics_version=3)
    )

    with pytest.raises(EvidenceRecoveryError, match="nicht unterstuetzt"):
        recover_evidence_journal(evidence_dir)


def test_semantics_v2_gate_failure_is_fatal(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v2-early-end"
    source_record = _record_with_legacy_gate_difference(
        55,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_start_event(run_id), _evidence_event(run_id, source_record))
    )

    with pytest.raises(EvidenceRecoveryError, match="Positivsemantik Version 2"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_semantics_v2_db_only_gate_failure_is_fatal(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v2-db-only-early-end"
    source_record = _record_with_legacy_gate_difference(
        59,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE handshake_results SET offering_observed = 1")
        connection.commit()
    EvidenceJournal(evidence_dir / "events.jsonl").append(_start_event(run_id))

    with pytest.raises(EvidenceRecoveryError, match="Positivsemantik Version 2"):
        recover_evidence_journal(evidence_dir)


def test_v033_db_only_other_negative_condition_is_fatal(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-db-only-not-old-positive"
    source_record = _record_with_legacy_gate_difference(
        60,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
        interested_sent=False,
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE handshake_results SET offering_observed = 1")
        connection.commit()
    EvidenceJournal(evidence_dir / "events.jsonl").append(_v033_start_event(run_id))

    with pytest.raises(EvidenceRecoveryError, match="fachlich aber nicht positiven"):
        recover_evidence_journal(evidence_dir)


def test_v033_gate_difference_with_other_negative_condition_is_fatal(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "v033-not-old-positive"
    source_record = _record_with_legacy_gate_difference(
        56,
        completed_full_window=False,
        availability_error="Fruehes EOF.",
        interested_sent=False,
    )
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_v033_start_event(run_id), _evidence_event(run_id, source_record))
    )

    with pytest.raises(EvidenceRecoveryError, match="nicht an scan_started gebunden"):
        recover_evidence_journal(evidence_dir)

    assert store.evidence_count() == 0


def test_legacy_start_and_schema_v1_database_reconcile_on_upgrade(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "legacy-compatible"
    source_record = _record(HASH_A, 50)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    with sqlite3.connect(store.path) as connection:
        connection.execute("ALTER TABLE evidence_records DROP COLUMN evidence_json_sha256")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (_legacy_start_event(run_id), _evidence_event(run_id, source_record))
    )
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert summary == RecoverySummary(scanned_entries=2, evidence_events=1, inserted_records=1)
    assert list(RunStore(store.path).iter_evidence_records()) == [expected]
    assert reconciled == [
        RecoveredEvidenceBatch(
            run_id=run_id,
            config_sha256=CONFIG_A,
            software_sha256=SOFTWARE_A,
            config_snapshot=None,
            config_snapshot_file_sha256=None,
            records=(expected,),
        )
    ]
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_incompatible_v031_legacy_record_does_not_block_new_run(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    legacy_run_id = "legacy-old-offer"
    legacy_source = _record(HASH_A, 51)
    legacy_store = _prepare_store(evidence_dir, legacy_run_id, [legacy_source])
    availability = legacy_source.handshake.availability
    assert availability is not None
    old_control_events = (
        PeerControlEvent(
            observed_at_utc="2026-10-20T10:00:02.000Z",
            elapsed_seconds=1.0,
            kind="unchoke",
            payload_length=0,
        ),
        PeerControlEvent(
            observed_at_utc="2026-10-20T10:00:03.000Z",
            elapsed_seconds=2.0,
            kind="choke",
            payload_length=0,
        ),
        PeerControlEvent(
            observed_at_utc="2026-10-20T10:00:04.000Z",
            elapsed_seconds=3.0,
            kind="bitfield",
            payload_length=1,
            non_empty=True,
            payload_sha256="12" * 32,
            set_bits=1,
        ),
    )
    old_handshake = replace(
        legacy_source.handshake,
        bytes_received=84,
        availability=replace(
            availability,
            peer_choking_at_end=True,
            messages_received=3,
            bytes_received=16,
            control_events=old_control_events,
        ),
    )
    assert old_handshake.confirmed
    assert old_handshake.availability is not None
    assert old_handshake.availability.unchoked
    assert old_handshake.availability.piece_availability_announced
    assert not old_handshake.offering_observed
    old_record = replace(legacy_source, handshake=old_handshake)
    with sqlite3.connect(legacy_store.path) as connection:
        connection.execute(
            """
            UPDATE handshake_results
            SET result_json = ?, offering_observed = 1
            """,
            (
                json.dumps(
                    asdict(old_handshake),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        connection.execute("ALTER TABLE evidence_records DROP COLUMN evidence_json_sha256")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()

    new_run_id = "new-after-legacy"
    new_source = _record(HASH_B, 52)
    new_store = _prepare_store(evidence_dir, new_run_id, [new_source])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _legacy_start_event(legacy_run_id),
            _evidence_event(legacy_run_id, old_record),
            _start_event(new_run_id, info_hash=HASH_B),
            _evidence_event(new_run_id, new_source),
        )
    )
    notices: list[LegacyRecoveryNotice] = []
    incomplete: list[RecoveredRunContext] = []

    summary = recover_evidence_journal(
        evidence_dir,
        on_incomplete_run=incomplete.append,
        on_legacy_skipped=notices.append,
    )

    assert summary == RecoverySummary(
        scanned_entries=4,
        evidence_events=2,
        inserted_records=1,
        skipped_legacy_runs=1,
    )
    assert legacy_store.evidence_count() == 0
    assert list(new_store.iter_evidence_records()) == [
        replace(new_source, evidence_event_sha256=entries[3].event_sha256)
    ]
    assert incomplete == []
    assert len(notices) == 1
    assert notices[0].run_id == legacy_run_id
    assert "fruehere Positivsemantik" in notices[0].reason


def test_scan_started_rejects_incomplete_snapshot_pair(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    event = _start_event("run-partial-snapshot")
    del event["config_snapshot_file_sha256"]
    EvidenceJournal(evidence_dir / "events.jsonl").append(event)

    with pytest.raises(EvidenceRecoveryError, match="fehlende oder unerwartete Felder"):
        recover_evidence_journal(evidence_dir)


def test_legacy_db_only_positive_is_not_sent_to_incomplete_callback(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "legacy-no-snapshot"
    source_record = _record(HASH_A, 53)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    EvidenceJournal(evidence_dir / "events.jsonl").append(_legacy_start_event(run_id))
    incomplete: list[RecoveredRunContext] = []
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(
        evidence_dir,
        on_incomplete_run=incomplete.append,
        on_legacy_skipped=notices.append,
    )

    assert summary == RecoverySummary(scanned_entries=1, skipped_legacy_runs=1)
    assert store.evidence_count() == 0
    assert incomplete == []
    assert len(notices) == 1
    assert notices[0].run_id == run_id
    assert "keinen gebundenen Konfigurationssnapshot" in notices[0].reason


def test_v031_db_only_old_offer_semantics_does_not_block_new_run(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = "legacy-db-only-old-offer"
    source_record = _record(HASH_A, 61)
    availability = source_record.handshake.availability
    assert availability is not None
    old_handshake = replace(
        source_record.handshake,
        bytes_received=84,
        availability=replace(
            availability,
            peer_choking_at_end=True,
            messages_received=3,
            bytes_received=16,
            control_events=(
                PeerControlEvent(
                    observed_at_utc="2026-10-20T10:00:02.000Z",
                    elapsed_seconds=1.0,
                    kind="unchoke",
                    payload_length=0,
                ),
                PeerControlEvent(
                    observed_at_utc="2026-10-20T10:00:03.000Z",
                    elapsed_seconds=2.0,
                    kind="choke",
                    payload_length=0,
                ),
                PeerControlEvent(
                    observed_at_utc="2026-10-20T10:00:04.000Z",
                    elapsed_seconds=3.0,
                    kind="bitfield",
                    payload_length=1,
                    non_empty=True,
                    payload_sha256="12" * 32,
                    set_bits=1,
                ),
            ),
        ),
    )
    assert not old_handshake.offering_observed
    store = _prepare_store(evidence_dir, run_id, [source_record])
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            UPDATE handshake_results
            SET result_json = ?, offering_observed = 1
            """,
            (
                json.dumps(
                    asdict(old_handshake),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        connection.commit()
    EvidenceJournal(evidence_dir / "events.jsonl").append(_legacy_start_event(run_id))
    notices: list[LegacyRecoveryNotice] = []

    summary = recover_evidence_journal(
        evidence_dir,
        on_legacy_skipped=notices.append,
    )

    assert summary == RecoverySummary(scanned_entries=1, skipped_legacy_runs=1)
    assert store.evidence_count() == 0
    assert [notice.run_id for notice in notices] == [run_id]
    assert "frueherer Positivsemantik" in notices[0].reason
