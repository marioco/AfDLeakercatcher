"""Offline-Tests fuer die speicherbegrenzte Journal-Recovery."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import bittorrent_beobachter.recovery as recovery_module
from bittorrent_beobachter.evidence import EvidenceJournal, EvidenceJournalError
from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    PeerControlEvent,
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
    control_event = PeerControlEvent(
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
        bytes_received=9,
        request_messages_sent=0,
        piece_payload_bytes_received=0,
        metadata_requests_sent=0,
        termination_reason="duration_elapsed",
        control_events=(control_event,),
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
        bytes_received=77,
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


def _start_event(
    run_id: str,
    *,
    info_hash: str = HASH_A,
    config_sha256: str = CONFIG_A,
    software_sha256: str = SOFTWARE_A,
    snapshot_sha256: str = SNAPSHOT_HASH_A,
) -> dict[str, object]:
    return {
        "event_type": "scan_started",
        "run_id": run_id,
        "config_sha256": config_sha256,
        "config_snapshot": f"{run_id}.config.json",
        "config_snapshot_file_sha256": snapshot_sha256,
        "software_sha256": software_sha256,
        "targets": [{"label": "Recovery-Ziel", "info_hash": info_hash}],
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
    del event["config_snapshot"]
    del event["config_snapshot_file_sha256"]
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
) -> dict[str, object]:
    event = _terminal_event(
        run_id,
        event_type,
        config_sha256=config_sha256,
        software_sha256=software_sha256,
    )
    event.update(
        {
            "report_file_count": 1,
            "report_manifest": "manifest.json",
            "report_manifest_sha256": "9" * 64,
        }
    )
    return event


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
        )
    ]


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


@pytest.mark.parametrize("terminal_event", ("scan_completed", "scan_cancelled", "scan_failed"))
def test_clean_terminal_run_does_not_repeat_reconciled_callback(
    tmp_path: Path,
    terminal_event: str,
) -> None:
    evidence_dir = tmp_path / "evidence"
    run_id = f"run-clean-{terminal_event}"
    source_record = _record(HASH_A, 43)
    store = _prepare_store(evidence_dir, run_id, [source_record])
    entries = EvidenceJournal(evidence_dir / "events.jsonl").append_many(
        (
            _start_event(run_id),
            _evidence_event(run_id, source_record),
            {"event_type": "diagnostic", "index": 1},
            {"event_type": "diagnostic", "index": 2},
            {"event_type": "diagnostic", "index": 3},
            _published_terminal_event(run_id, terminal_event),
        )
    )
    expected = replace(source_record, evidence_event_sha256=entries[1].event_sha256)
    assert store.store_evidence_batch([expected]) == 1
    reconciled: list[RecoveredEvidenceBatch] = []

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert summary == RecoverySummary(scanned_entries=6, evidence_events=1)
    assert reconciled == []
    assert list(store.iter_evidence_records()) == [expected]


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
    summary = recover_evidence_journal(evidence_dir, on_reconciled=retried.append)

    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1)
    assert [batch.records for batch in retried] == [(expected,)]

    after_acknowledgement: list[RecoveredEvidenceBatch] = []
    recover_evidence_journal(
        evidence_dir,
        on_reconciled=after_acknowledgement.append,
    )
    assert after_acknowledgement == []


def test_manifestless_failed_run_remains_reconciled_callback_retryable(tmp_path: Path) -> None:
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

    summary = recover_evidence_journal(evidence_dir, on_reconciled=reconciled.append)

    assert summary == RecoverySummary(scanned_entries=3, evidence_events=1)
    assert [batch.records for batch in reconciled] == [(expected,)]


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
        if temporary_directories and os.name != "nt":
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
            set_bits=1,
        ),
    )
    old_handshake = replace(
        legacy_source.handshake,
        availability=replace(
            availability,
            peer_choking_at_end=True,
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
