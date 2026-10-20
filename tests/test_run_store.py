"""Offline-Tests fuer die persistente, batchweise Laufablage."""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    PeerControlEvent,
    VpnClassification,
)
from bittorrent_beobachter.run_store import RunStore, RunStoreError

HASH_A = "11" * 20
HASH_B = "22" * 20


def _candidate(info_hash: str, index: int) -> PeerCandidate:
    second_octet = (index // (254 * 254)) % 250
    third_octet = (index // 254) % 254
    fourth_octet = (index % 254) + 1
    return PeerCandidate(
        target_label="Ziel A" if info_hash == HASH_A else "Ziel B",
        info_hash_hex=info_hash,
        ip=f"8.{second_octet}.{third_octet}.{fourth_octet}",
        port=10_000 + index,
        discovered_at_utc="2026-10-20T10:00:00.000Z",
        dht_node_ip="9.9.9.9",
        dht_node_port=6881,
        transaction_id_hex=f"{index:08x}",
        response_sha256=f"{index:064x}",
        source_note="Testquelle",
    )


def _handshake(candidate: PeerCandidate) -> HandshakeResult:
    event = PeerControlEvent(
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
        control_events=(event,),
    )
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc="2026-10-20T10:00:00.500Z",
        completed_at_utc="2026-10-20T10:01:01.000Z",
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


def _evidence(handshake: HandshakeResult, index: int) -> EvidenceRecord:
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
            cached_sources=(),
        ),
        vpn=VpnClassification(status="not_known_vpn"),
        evidence_event_sha256=f"{index + 1:064x}",
    )


def test_four_candidate_batch_is_atomic_streamed_and_private(tmp_path: Path) -> None:
    database_path = tmp_path / "private" / "run.sqlite3"
    store = RunStore(database_path)
    candidates = [_candidate(HASH_A, index) for index in range(4)]

    assert store.add_candidates(candidates) == 4
    if os.name != "nt":
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(database_path.parent.stat().st_mode) == 0o700

    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    finally:
        connection.close()

    invalid = replace(_candidate(HASH_A, 5), port=0)
    with pytest.raises(RunStoreError, match="Port"):
        store.add_candidates([_candidate(HASH_A, 4), invalid])

    assert list(store.iter_candidates(batch_size=2)) == candidates
    metrics = store.metrics_by_hash([HASH_A, HASH_B])
    assert metrics[HASH_A].candidates == 4
    assert metrics[HASH_A].pending == 4
    assert metrics[HASH_B].candidates == 0

    claimed = store.claim_candidate_batch([HASH_A], size=5)
    base_results = [_handshake(candidate) for candidate in claimed]
    unconfirmed = replace(
        base_results[0],
        confirmed=False,
        remote_peer_id_hex=None,
        reserved_bits_hex=None,
        availability=None,
        error="ConnectionRefusedError: abgelehnt",
    )
    missing_availability = replace(base_results[1], availability=None)
    assert base_results[2].availability is not None
    no_piece = replace(
        base_results[2],
        availability=replace(
            base_results[2].availability,
            non_empty_bitfield=False,
            piece_availability_announced=False,
            termination_reason="peer_closed",
        ),
    )
    assert base_results[3].availability is not None
    no_unchoke = replace(
        base_results[3],
        availability=replace(
            base_results[3].availability,
            unchoked=False,
            termination_reason="protocol_or_network_error",
            error="PeerProtocolError: ungueltige Nachricht",
        ),
    )
    assert (
        store.store_handshake_batch([unconfirmed, missing_availability, no_piece, no_unchoke]) == 4
    )
    metrics = store.metrics_by_hash()[HASH_A]
    assert metrics.confirmed == 3
    assert metrics.piece_availability == 1
    assert metrics.unchoked == 1
    assert metrics.offering_observed == 0
    assert metrics.terminal_failures == 4
    assert store.failure_reasons_by_hash([HASH_A, HASH_B]) == {
        HASH_A: {
            "availability:missing": 1,
            "availability:no_piece": 1,
            "availability:no_unchoke": 1,
            "confirmation:not_confirmed": 1,
            "error:availability": 1,
            "error:handshake": 1,
            "termination:peer_closed": 1,
            "termination:protocol_or_network_error": 1,
        },
        HASH_B: {},
    }


def test_five_candidates_are_deduplicated_claimed_and_stored(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates = [_candidate(HASH_A, index) for index in range(5)]

    assert store.add_candidates(candidates) == 5
    duplicates = [replace(candidate, source_note="Andere Fundstelle") for candidate in candidates]
    assert store.add_candidates(duplicates) == 0

    claimed = store.claim_candidate_batch([HASH_A], size=5)
    assert claimed == candidates
    handshakes = [_handshake(candidate) for candidate in claimed]
    assert store.store_handshake_batch(handshakes) == 5
    assert list(store.iter_handshake_results(batch_size=2)) == handshakes

    metrics = store.metrics_by_hash()[HASH_A]
    assert metrics.candidates == 5
    assert metrics.pending == 0
    assert metrics.in_progress == 0
    assert metrics.done == 5
    assert metrics.handshake_results == 5
    assert metrics.confirmed == 5
    assert metrics.piece_availability == 5
    assert metrics.unchoked == 5
    assert metrics.offering_observed == 5
    assert metrics.terminal_failures == 0
    assert store.failure_reasons_by_hash([HASH_A]) == {HASH_A: {}}


def test_six_candidates_survive_crash_and_evidence_is_stored_five_plus_one(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    candidates = [_candidate(HASH_B, 100 + index) for index in range(6)]
    assert store.add_candidates(candidates) == 6
    assert len(store.claim_candidate_batch([HASH_B], size=5)) == 5

    restarted = RunStore(database_path)
    before = restarted.metrics_by_hash()[HASH_B]
    assert before.in_progress == 5
    assert before.pending == 1
    assert restarted.requeue_in_progress() == 5

    first = restarted.claim_candidate_batch([HASH_B], size=5)
    first_handshakes = [_handshake(candidate) for candidate in first]
    assert restarted.store_handshake_batch(first_handshakes) == 5
    second = restarted.claim_candidate_batch([HASH_B], size=5)
    second_handshakes = [_handshake(candidate) for candidate in second]
    assert len(second) == 1
    assert restarted.store_handshake_batch(second_handshakes) == 1
    assert restarted.claim_candidate_batch([HASH_B], size=5) == []

    handshakes = first_handshakes + second_handshakes
    evidence = [_evidence(handshake, index) for index, handshake in enumerate(handshakes)]
    assert restarted.store_evidence_batch(evidence[:5]) == 5
    assert restarted.store_evidence_batch(evidence[5:]) == 1
    assert list(restarted.iter_evidence_records(batch_size=5)) == evidence
    assert restarted.evidence_count() == 6

    metrics = restarted.metrics_by_hash()[HASH_B]
    assert metrics.candidates == 6
    assert metrics.done == 6
    assert metrics.handshake_results == 6
    assert metrics.evidence_records == 6


def test_positive_ip_handles_and_records_use_bounded_five_row_fetches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates = [
        replace(
            _candidate(HASH_A, index),
            ip="8.8.8.8" if index < 41 else "9.9.9.9",
            port=20_000 + index,
        )
        for index in range(47)
    ]
    assert store.add_candidates(candidates) == 47

    handshakes: list[HandshakeResult] = []
    while claimed := store.claim_candidate_batch([HASH_A], size=5):
        batch = [_handshake(candidate) for candidate in claimed]
        assert store.store_handshake_batch(batch) == len(batch)
        handshakes.extend(batch)

    evidence = [_evidence(handshake, index) for index, handshake in enumerate(handshakes)]
    for start_index in range(0, len(evidence), 5):
        batch = evidence[start_index : start_index + 5]
        assert store.store_evidence_batch(batch) == len(batch)

    fetch_sizes: list[int] = []
    largest_fetch = 0
    real_connect = store._connect

    class CursorProxy:
        def __init__(self, cursor: sqlite3.Cursor) -> None:
            self.cursor = cursor

        def fetchmany(self, size: int) -> list[sqlite3.Row]:
            nonlocal largest_fetch
            fetch_sizes.append(size)
            rows = self.cursor.fetchmany(size)
            largest_fetch = max(largest_fetch, len(rows))
            return rows

        def __getattr__(self, name: str) -> object:
            return getattr(self.cursor, name)

    class ConnectionProxy:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, *args: object, **kwargs: object) -> CursorProxy:
            return CursorProxy(self.connection.execute(*args, **kwargs))

        def close(self) -> None:
            self.connection.close()

    monkeypatch.setattr(store, "_connect", lambda: ConnectionProxy(real_connect()))

    groups = list(store.iter_positive_ip_groups(batch_size=5))

    assert [(group.ip, group.record_count) for group in groups] == [
        ("8.8.8.8", 41),
        ("9.9.9.9", 6),
    ]
    assert all(not hasattr(group, "records") for group in groups)
    assert sum(1 for _ in store.iter_positive_evidence_for_ip("8.8.8.8", batch_size=5)) == 41
    assert sum(1 for _ in store.iter_positive_evidence_for_ip("9.9.9.9", batch_size=5)) == 6
    assert fetch_sizes
    assert set(fetch_sizes) == {5}
    assert largest_fetch <= 5


def test_equivalent_ipv6_spellings_share_one_positive_ip_handle(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates = [
        replace(
            _candidate(HASH_A, 50),
            ip="2001:4860:4860:0:0:0:0:8888",
            port=30_000,
        ),
        replace(
            _candidate(HASH_A, 51),
            ip="2001:4860:4860::8888",
            port=30_001,
        ),
    ]
    assert store.add_candidates(candidates) == 2
    claimed = store.claim_candidate_batch([HASH_A], size=5)
    assert {candidate.ip for candidate in claimed} == {"2001:4860:4860::8888"}

    handshakes = [_handshake(candidate) for candidate in claimed]
    assert store.store_handshake_batch(handshakes) == 2
    evidence = [_evidence(handshake, index) for index, handshake in enumerate(handshakes)]
    assert store.store_evidence_batch(evidence) == 2

    groups = list(store.iter_positive_ip_groups(batch_size=5))

    assert len(groups) == 1
    assert groups[0].ip == "2001:4860:4860::8888"
    assert groups[0].record_count == 2
    assert (
        list(store.iter_positive_evidence_for_ip("2001:4860:4860:0:0:0:0:8888", batch_size=5))
        == evidence
    )


def test_305_candidates_are_claimed_fairly_in_five_item_batches(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates_a = [_candidate(HASH_A, index) for index in range(153)]
    candidates_b = [_candidate(HASH_B, 10_000 + index) for index in range(152)]
    assert store.add_candidates(candidates_a + candidates_b) == 305

    batches: list[list[PeerCandidate]] = []
    while batch := store.claim_candidate_batch([HASH_A, HASH_B], size=5):
        batches.append(batch)

    assert len(batches) == 61
    assert all(len(batch) == 5 for batch in batches)
    claimed = [candidate for batch in batches for candidate in batch]
    assert len(claimed) == 305
    assert len({(*candidate.endpoint, candidate.info_hash_hex) for candidate in claimed}) == 305
    assert [candidate.info_hash_hex for candidate in claimed] == [
        HASH_A if index % 2 == 0 else HASH_B for index in range(305)
    ]
    assert sum(candidate.info_hash_hex == HASH_A for candidate in claimed) == 153
    assert sum(candidate.info_hash_hex == HASH_B for candidate in claimed) == 152
    assert len(list(store.iter_candidates(status="in_progress", batch_size=5))) == 305

    metrics = store.metrics_by_hash([HASH_A, HASH_B])
    assert metrics[HASH_A].in_progress == 153
    assert metrics[HASH_B].in_progress == 152
    assert store.claim_candidate_batch([HASH_A, HASH_B], size=5) == []
