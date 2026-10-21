"""Offline-Tests fuer die persistente, batchweise Laufablage."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import asdict, replace
from datetime import datetime, timedelta
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
from bittorrent_beobachter.run_store import (
    RunStore,
    RunStoreError,
    decode_evidence_journal_event,
)

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
            "termination:duration_elapsed": 1,
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


def test_handshake_result_count_reports_unique_stored_progress(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates_a = [_candidate(HASH_A, index) for index in range(3)]
    candidates_b = [_candidate(HASH_B, 10 + index) for index in range(2)]
    assert store.add_candidates([*candidates_a, *candidates_b]) == 5
    assert store.handshake_result_count() == 0

    claimed_a = store.claim_candidate_batch([HASH_A], size=2)
    assert store.store_handshake_batch(_handshake(candidate) for candidate in claimed_a) == 2
    claimed_b = store.claim_candidate_batch([HASH_B], size=1)
    assert store.store_handshake_batch(_handshake(candidate) for candidate in claimed_b) == 1

    assert store.handshake_result_count() == 3
    assert store.handshake_result_count([HASH_A]) == 2
    assert store.handshake_result_count([HASH_B, HASH_B]) == 1
    with pytest.raises(RunStoreError, match="Infohash"):
        store.handshake_result_count(["kein-infohash"])


@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    (
        ("short_full_window", "unterschreitet"),
        ("wrong_full_window_reason", "Abschlussgrund"),
        ("wall_clock_duration_mismatch", "UTC-Zeitfenster"),
        ("event_wall_clock_mismatch", "UTC-Zeitpunkt"),
        ("impossible_have", "HAVE-Kontrollereignis"),
        ("oversized_piece_index", "vier Byte breite Wire-Feld"),
        ("oversized_payload", "Peer-Wire-Limit"),
        ("impossible_bitfield", "BITFIELD-Kontrollereignis"),
        ("duplicate_bitfield", "nur ein BITFIELD"),
        ("nonmonotonic_events", "nicht monoton"),
        ("event_after_duration", "hinter der protokollierten"),
    ),
)
def test_store_handshake_batch_rejects_invalid_availability_timeline(
    tmp_path: Path,
    corruption: str,
    expected_error: str,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 20)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    first_event = availability.control_events[0]
    if corruption == "short_full_window":
        availability = replace(availability, duration_seconds=59.0)
    elif corruption == "wrong_full_window_reason":
        availability = replace(availability, termination_reason="peer_closed")
    elif corruption == "wall_clock_duration_mismatch":
        availability = replace(
            availability,
            ended_at_utc=availability.started_at_utc,
            control_events=tuple(
                replace(event, observed_at_utc=availability.started_at_utc)
                for event in availability.control_events
            ),
        )
    elif corruption == "event_wall_clock_mismatch":
        availability = replace(
            availability,
            control_events=(
                replace(first_event, observed_at_utc="2026-10-20T10:01:00.000Z"),
                replace(
                    availability.control_events[1],
                    observed_at_utc="2026-10-20T10:00:02.000Z",
                ),
            ),
        )
    elif corruption == "impossible_have":
        handshake = replace(handshake, bytes_received=73)
        availability = replace(
            availability,
            messages_received=1,
            bytes_received=5,
            control_events=(
                replace(
                    first_event,
                    kind="have",
                    payload_length=0,
                    piece_index=None,
                    non_empty=None,
                    payload_sha256=None,
                    set_bits=None,
                ),
            ),
        )
    elif corruption == "oversized_piece_index":
        handshake = replace(handshake, bytes_received=82)
        availability = replace(
            availability,
            bytes_received=14,
            control_events=(
                replace(
                    first_event,
                    kind="have",
                    payload_length=4,
                    piece_index=1 << 32,
                    non_empty=None,
                    payload_sha256=None,
                    set_bits=None,
                ),
                availability.control_events[1],
            ),
        )
    elif corruption == "oversized_payload":
        oversized_length = 1_048_576
        availability = replace(
            availability,
            bytes_received=oversized_length + 10,
            control_events=(
                replace(first_event, payload_length=oversized_length),
                availability.control_events[1],
            ),
        )
        handshake = replace(
            handshake,
            bytes_received=68 + availability.bytes_received,
        )
    elif corruption == "impossible_bitfield":
        handshake = replace(handshake, bytes_received=73)
        availability = replace(
            availability,
            messages_received=1,
            bytes_received=5,
            control_events=(replace(first_event, payload_length=0),),
        )
    elif corruption == "duplicate_bitfield":
        handshake = replace(handshake, bytes_received=85)
        availability = replace(
            availability,
            messages_received=3,
            bytes_received=17,
            control_events=(
                first_event,
                replace(
                    first_event,
                    observed_at_utc="2026-10-20T10:00:01.750Z",
                    elapsed_seconds=0.75,
                    non_empty=False,
                    set_bits=0,
                    payload_sha256="34" * 32,
                ),
                availability.control_events[1],
            ),
        )
    elif corruption == "nonmonotonic_events":
        handshake = replace(handshake, bytes_received=83)
        availability = replace(
            availability,
            bytes_received=15,
            control_events=(
                first_event,
                replace(
                    first_event,
                    observed_at_utc="2026-10-20T10:00:03.000Z",
                    elapsed_seconds=0.25,
                    kind="have",
                    payload_length=4,
                    piece_index=1,
                    non_empty=None,
                    payload_sha256=None,
                    set_bits=None,
                ),
            ),
        )
    elif corruption == "event_after_duration":
        handshake = replace(handshake, bytes_received=74)
        availability = replace(
            availability,
            messages_received=1,
            bytes_received=6,
            control_events=(replace(first_event, elapsed_seconds=60.000002),),
        )
    else:
        raise AssertionError(f"Unbekannter Testfall: {corruption}")

    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match=expected_error):
        store.store_handshake_batch([replace(handshake, availability=availability)])
    assert store.handshake_result_count() == 0


def test_summary_flags_without_control_event_proof_are_not_an_offer(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 22)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    without_proof = replace(
        availability,
        messages_received=0,
        bytes_received=0,
        control_events=(),
    )
    result = replace(handshake, bytes_received=68, availability=without_proof)

    assert not result.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    assert store.store_handshake_batch([result]) == 1
    assert store.metrics_by_hash()[HASH_A].offering_observed == 0

    unchoke = availability.control_events[1]
    impossible_have = replace(
        availability.control_events[0],
        kind="have",
        payload_length=0,
        piece_index=None,
        non_empty=None,
        payload_sha256=None,
        set_bits=None,
    )
    assert not replace(
        handshake,
        availability=replace(
            availability,
            control_events=(impossible_have, unchoke),
        ),
    ).offering_observed
    assert not replace(
        handshake,
        bytes_received=82,
        availability=replace(
            availability,
            bytes_received=14,
            control_events=(
                replace(
                    availability.control_events[0],
                    kind="have",
                    payload_length=4,
                    piece_index=1 << 32,
                    non_empty=None,
                    payload_sha256=None,
                    set_bits=None,
                ),
                unchoke,
            ),
        ),
    ).offering_observed

    duplicate_bitfield = replace(
        availability.control_events[0],
        observed_at_utc="2026-10-20T10:00:01.750Z",
        elapsed_seconds=0.75,
        non_empty=False,
        set_bits=0,
        payload_sha256="34" * 32,
    )
    assert not replace(
        handshake,
        bytes_received=85,
        availability=replace(
            availability,
            messages_received=3,
            bytes_received=17,
            control_events=(
                availability.control_events[0],
                duplicate_bitfield,
                unchoke,
            ),
        ),
    ).offering_observed

    have_none = replace(
        unchoke,
        observed_at_utc="2026-10-20T10:00:01.750Z",
        elapsed_seconds=0.75,
        kind="have_none",
    )
    assert not replace(
        handshake,
        bytes_received=84,
        availability=replace(
            availability,
            messages_received=3,
            bytes_received=16,
            control_events=(availability.control_events[0], have_none, unchoke),
        ),
    ).offering_observed


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    (
        ({"bytes_sent": 0}, "mindestens 68"),
        ({"bytes_received": 0}, "mindestens 68"),
        ({"bytes_sent": 74}, "genau 73"),
    ),
)
def test_confirmed_handshake_rejects_impossible_wire_counters(
    tmp_path: Path,
    mutation: dict[str, int],
    expected_error: str,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 25)
    result = replace(_handshake(candidate), **mutation)

    assert not result.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match=expected_error):
        store.store_handshake_batch([result])


def test_positive_handshake_rejects_impossible_observation_counters(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 26)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    impossible = replace(
        handshake,
        bytes_received=68,
        availability=replace(
            availability,
            messages_received=0,
            bytes_received=0,
        ),
    )

    assert not impossible.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match="Kontrollnachrichten"):
        store.store_handshake_batch([impossible])


def test_positive_handshake_rejects_message_count_without_wire_bytes(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 27)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    impossible = replace(
        handshake,
        availability=replace(availability, messages_received=1_000_000),
    )

    assert not impossible.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match="gespeicherte Ereigniszahl"):
        store.store_handshake_batch([impossible])


@pytest.mark.parametrize(
    ("messages_received", "bytes_received", "expected_error"),
    (
        (3, 15, "gespeicherte Ereigniszahl"),
        (2, 12, "passen nicht exakt"),
    ),
)
def test_positive_handshake_rejects_omitted_or_surplus_control_bytes(
    tmp_path: Path,
    messages_received: int,
    bytes_received: int,
    expected_error: str,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 28)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    impossible = replace(
        handshake,
        bytes_received=68 + bytes_received,
        availability=replace(
            availability,
            messages_received=messages_received,
            bytes_received=bytes_received,
        ),
    )

    assert not impossible.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match=expected_error):
        store.store_handshake_batch([impossible])


def test_offer_property_rejects_counters_beyond_live_observation_limits() -> None:
    handshake = _handshake(_candidate(HASH_A, 29))
    availability = handshake.availability
    assert availability is not None

    too_many_messages = replace(
        handshake,
        bytes_received=80_071,
        availability=replace(
            availability,
            messages_received=20_000,
            bytes_received=80_003,
        ),
    )
    too_many_bytes = replace(
        handshake,
        bytes_received=68 + 4_194_305,
        availability=replace(
            availability,
            bytes_received=4_194_305,
        ),
    )

    assert not too_many_messages.offering_observed
    assert not too_many_bytes.offering_observed


@pytest.mark.parametrize(
    ("kind", "payload_length", "availability_bytes"),
    (
        ("unknown_message_rejected", 0, 16),
        ("request_rejected", 12, 16),
        ("piece_rejected", 12, 16),
        ("extension_payload_rejected", 1, 17),
    ),
)
def test_positive_handshake_rejects_terminal_diagnostic_event(
    tmp_path: Path,
    kind: str,
    payload_length: int,
    availability_bytes: int,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 30)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    diagnostic = PeerControlEvent(
        observed_at_utc="2026-10-20T10:00:02.500Z",
        elapsed_seconds=1.5,
        kind=kind,
        payload_length=payload_length,
    )
    impossible = replace(
        handshake,
        bytes_received=68 + availability_bytes,
        availability=replace(
            availability,
            messages_received=3,
            bytes_received=availability_bytes,
            control_events=(*availability.control_events, diagnostic),
        ),
    )

    assert not impossible.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match="terminales Diagnoseereignis"):
        store.store_handshake_batch([impossible])


def test_offer_property_rejects_short_or_wrongly_terminated_window() -> None:
    result = _handshake(_candidate(HASH_A, 24))
    availability = result.availability
    assert availability is not None

    assert not replace(
        result,
        availability=replace(availability, duration_seconds=1.0),
    ).offering_observed
    assert not replace(
        result,
        availability=replace(
            availability,
            control_events=(
                replace(
                    availability.control_events[0],
                    observed_at_utc="2026-10-20T10:01:00.000Z",
                ),
                replace(
                    availability.control_events[1],
                    observed_at_utc="2026-10-20T10:00:02.000Z",
                ),
            ),
        ),
    ).offering_observed
    assert not replace(
        result,
        availability=replace(availability, termination_reason="peer_closed"),
    ).offering_observed
    assert not replace(
        result,
        availability=replace(
            availability,
            ended_at_utc=availability.started_at_utc,
            control_events=tuple(
                replace(event, observed_at_utc=availability.started_at_utc)
                for event in availability.control_events
            ),
        ),
    ).offering_observed


def test_offer_property_requires_configured_sixty_second_window(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 31)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    one_second = replace(
        handshake,
        availability=replace(
            availability,
            ended_at_utc="2026-10-20T10:00:02.000Z",
            requested_duration_seconds=1.0,
            duration_seconds=1.0,
            unchoked_duration_seconds=0.5,
        ),
    )

    assert not one_second.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    assert store.store_handshake_batch([one_second]) == 1
    assert store.metrics_by_hash()[HASH_A].offering_observed == 0


def test_confirmed_handshake_with_top_level_error_is_rejected(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 23)
    result = replace(_handshake(candidate), error="PeerProtocolError: widerspruechlich")

    assert not result.offering_observed
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    with pytest.raises(RunStoreError, match="keinen Handshake-Fehler"):
        store.store_handshake_batch([result])
    assert store.handshake_result_count() == 0


def test_full_window_accepts_only_microsecond_rounding_difference(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 21)
    handshake = _handshake(candidate)
    availability = handshake.availability
    assert availability is not None
    rounded = replace(availability, duration_seconds=59.9999995)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]

    assert store.store_handshake_batch([replace(handshake, availability=rounded)]) == 1


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


def _offset_utc(timestamp: str, *, seconds: float) -> str:
    parsed = datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    return (
        (parsed + timedelta(seconds=seconds))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _stored_completion(database_path: Path) -> str:
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT completed_at_utc FROM candidates WHERE status = 'done'"
        ).fetchone()
    assert row is not None
    assert isinstance(row[0], str)
    return row[0]


def test_late_sighting_requeues_only_completed_negative_candidate(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    candidate = _candidate(HASH_A, 70)
    assert store.add_candidates([candidate]) == 1
    claimed = store.claim_candidate_batch([HASH_A])
    assert claimed == [candidate]
    negative = replace(_handshake(candidate), availability=None)
    assert store.store_handshake_batch([negative]) == 1
    completed_at = _stored_completion(database_path)

    too_early = replace(
        candidate,
        discovered_at_utc=_offset_utc(completed_at, seconds=9.999),
        source_note="Zu fruehe neue Sichtung",
    )
    ignored = store.ingest_candidates(
        [candidate, too_early],
        negative_recheck_cooldown_seconds=10.0,
    )
    assert ignored.new_candidates == 0
    assert ignored.requeued_negative_candidates == 0
    assert ignored.ignored_sightings == 2
    assert ignored.scheduled_candidates == 0
    assert store.claim_candidate_batch([HASH_A]) == []

    late = replace(
        candidate,
        discovered_at_utc=_offset_utc(completed_at, seconds=10.0),
        transaction_id_hex="deadbeef",
        response_sha256="fe" * 32,
        source_note="Spaetere neue Sichtung",
    )
    scheduled = store.ingest_candidates(
        [late],
        negative_recheck_cooldown_seconds=10.0,
    )
    assert scheduled.new_candidates == 0
    assert scheduled.requeued_negative_candidates == 1
    assert scheduled.ignored_sightings == 0
    assert scheduled.scheduled_candidates == 1
    metrics = store.metrics_by_hash()[HASH_A]
    assert metrics.pending == 1
    assert metrics.handshake_results == 1
    assert list(store.iter_handshake_results()) == [negative]

    duplicate = store.ingest_candidates(
        [late],
        negative_recheck_cooldown_seconds=10.0,
    )
    assert duplicate.requeued_negative_candidates == 0
    assert duplicate.ignored_sightings == 1
    assert store.claim_candidate_batch([HASH_A]) == [late]
    late_result = replace(
        _handshake(late),
        attempted_at_utc=_offset_utc(late.discovered_at_utc, seconds=0.5),
        completed_at_utc=_offset_utc(late.discovered_at_utc, seconds=0.75),
        availability=None,
    )
    assert store.store_handshake_batch([late_result]) == 1
    assert list(store.iter_handshake_results()) == [late_result]

    repeated = store.ingest_candidates(
        [late],
        negative_recheck_cooldown_seconds=10.0,
    )
    assert repeated.scheduled_candidates == 0
    assert repeated.ignored_sightings == 1
    assert store.claim_candidate_batch([HASH_A]) == []


def test_positive_candidate_is_never_requeued(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    candidate = _candidate(HASH_A, 71)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    assert store.store_handshake_batch([_handshake(candidate)]) == 1
    completed_at = _stored_completion(database_path)

    much_later = replace(
        candidate,
        discovered_at_utc=_offset_utc(completed_at, seconds=3_600),
        source_note="Viel spaetere Sichtung",
    )
    result = store.ingest_candidates(
        [much_later],
        negative_recheck_cooldown_seconds=0,
    )

    assert result.scheduled_candidates == 0
    assert result.ignored_sightings == 1
    assert store.claim_candidate_batch([HASH_A]) == []
    metrics = store.metrics_by_hash()[HASH_A]
    assert metrics.done == 1
    assert metrics.offering_observed == 1


@pytest.mark.parametrize("cooldown", [-1, float("inf"), float("nan"), True])
def test_candidate_recheck_cooldown_must_be_finite_and_nonnegative(
    tmp_path: Path,
    cooldown: float,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    with pytest.raises(ValueError, match="negative_recheck_cooldown_seconds"):
        store.ingest_candidates([], negative_recheck_cooldown_seconds=cooldown)


def _persist_one_evidence(database_path: Path) -> RunStore:
    store = RunStore(database_path)
    candidate = _candidate(HASH_A, 72)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    handshake = _handshake(candidate)
    assert store.store_handshake_batch([handshake]) == 1
    assert store.store_evidence_batch([_evidence(handshake, 0)]) == 1
    return store


@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    [
        ("event_hash", "evidence_event_sha256"),
        ("vpn_status", "VPN-Status"),
        ("known_vpn_without_provider", "benoetigt einen Anbieter"),
        ("provider_without_known_vpn", "Nur ein bekannter VPN-Treffer"),
        ("enrichment_ip", "nicht auf dieselbe IP"),
        ("negative_counter", "nichtnegative Ganzzahl"),
        ("invalid_timestamp", "UTC-Zeitstempel"),
        ("invalid_asn", "ungueltigen Wert"),
    ],
)
def test_corrupt_evidence_json_is_rejected_during_deserialization(
    tmp_path: Path,
    corruption: str,
    expected_error: str,
) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = _persist_one_evidence(database_path)
    with sqlite3.connect(database_path) as connection:
        row = connection.execute("SELECT evidence_json FROM evidence_records").fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        if corruption == "event_hash":
            payload["evidence_event_sha256"] = "z" * 64
        elif corruption == "vpn_status":
            payload["vpn"]["status"] = "maybe_vpn"
        elif corruption == "known_vpn_without_provider":
            payload["vpn"]["status"] = "known_vpn"
            payload["vpn"]["provider"] = None
        elif corruption == "provider_without_known_vpn":
            payload["vpn"]["provider"] = "Unerwarteter Anbieter"
        elif corruption == "enrichment_ip":
            payload["enrichment"]["ip"] = "9.9.9.9"
        elif corruption == "negative_counter":
            payload["handshake"]["bytes_received"] = -1
        elif corruption == "invalid_timestamp":
            payload["handshake"]["availability"]["ended_at_utc"] = "2026-10-20 10:01:01"
        elif corruption == "invalid_asn":
            payload["enrichment"]["asns"] = [0]
        else:
            raise AssertionError(f"Unbekannter Testfall: {corruption}")
        serialized = json.dumps(payload)
        connection.execute(
            "UPDATE evidence_records SET evidence_json = ?, evidence_json_sha256 = ?",
            (serialized, hashlib.sha256(serialized.encode("utf-8")).hexdigest()),
        )
        connection.commit()

    with pytest.raises(RunStoreError, match=expected_error):
        list(store.iter_evidence_records())


def test_canonical_equivalent_enrichment_ip_is_accepted(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = replace(
        _candidate(HASH_A, 73),
        ip="2001:4860:4860::8888",
        port=30_073,
    )
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    handshake = _handshake(candidate)
    assert store.store_handshake_batch([handshake]) == 1
    evidence = _evidence(handshake, 0)
    evidence = replace(
        evidence,
        enrichment=replace(
            evidence.enrichment,
            ip="2001:4860:4860:0:0:0:0:8888",
        ),
    )

    assert store.store_evidence_batch([evidence]) == 1
    stored = list(store.iter_evidence_records())
    assert len(stored) == 1
    assert stored[0].enrichment.ip == "2001:4860:4860::8888"


@pytest.mark.parametrize("read_path", ["all_records", "ip_groups", "records_for_ip"])
def test_semantically_valid_vpn_tampering_is_rejected_on_every_read_path(
    tmp_path: Path,
    read_path: str,
) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = _persist_one_evidence(database_path)
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT e.evidence_json, c.ip
            FROM evidence_records AS e
            JOIN candidates AS c ON c.id = e.candidate_id
            """
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        ip = str(row[1])
        payload["vpn"]["status"] = "known_vpn"
        payload["vpn"]["provider"] = "Manipulierter Anbieter"
        connection.execute(
            "UPDATE evidence_records SET evidence_json = ?",
            (json.dumps(payload),),
        )
        connection.commit()

    with pytest.raises(RunStoreError, match="Integritaetspruefung"):
        if read_path == "all_records":
            list(store.iter_evidence_records())
        elif read_path == "ip_groups":
            list(store.iter_positive_ip_groups())
        elif read_path == "records_for_ip":
            list(store.iter_positive_evidence_for_ip(ip))
        else:
            raise AssertionError(f"Unbekannter Lesepfad: {read_path}")


def test_schema_v1_migration_backfills_exact_evidence_json_digest(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    _persist_one_evidence(database_path)
    with sqlite3.connect(database_path) as connection:
        raw = connection.execute("SELECT evidence_json FROM evidence_records").fetchone()[0]
        assert isinstance(raw, str)
        connection.execute("ALTER TABLE evidence_records DROP COLUMN evidence_json_sha256")
        connection.execute("PRAGMA user_version = 1")
        connection.commit()

    migrated = RunStore(database_path)

    with sqlite3.connect(database_path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        row = connection.execute(
            "SELECT evidence_json, evidence_json_sha256 FROM evidence_records"
        ).fetchone()
    assert version == 3
    assert row is not None
    assert row[0] == raw
    assert row[1] == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert len(list(migrated.iter_evidence_records())) == 1


def _journal_event(record: EvidenceRecord) -> dict[str, object]:
    return {
        "event_type": "observed_bittorrent_piece_availability",
        "run_id": "run-1",
        "config_sha256": "a" * 64,
        "software_sha256": "b" * 64,
        "handshake": asdict(record.handshake),
        "enrichment": asdict(record.enrichment),
        "vpn": asdict(record.vpn),
    }


def test_decode_evidence_journal_event_binds_run_hashes_and_record() -> None:
    evidence = _evidence(_handshake(_candidate(HASH_A, 80)), 0)
    event_sha256 = "c" * 64

    decoded = decode_evidence_journal_event(
        _journal_event(evidence),
        event_sha256,
        expected_run_id="run-1",
        expected_config_sha256="a" * 64,
        expected_software_sha256="b" * 64,
    )

    assert decoded.run_id == "run-1"
    assert decoded.config_sha256 == "a" * 64
    assert decoded.software_sha256 == "b" * 64
    assert decoded.record == replace(evidence, evidence_event_sha256=event_sha256)


def test_decode_evidence_journal_event_rejects_short_completed_window() -> None:
    evidence = _evidence(_handshake(_candidate(HASH_A, 81)), 0)
    event = _journal_event(evidence)
    event["handshake"]["availability"]["duration_seconds"] = 0.1  # type: ignore[index]

    with pytest.raises(RunStoreError, match="unterschreitet"):
        decode_evidence_journal_event(event, "c" * 64)


@pytest.mark.parametrize(
    ("corruption", "expected_error"),
    [
        ("run", "anderen Lauf"),
        ("config", "anderen Konfiguration"),
        ("software", "anderen Softwarestand"),
        ("event_hash", "event_sha256"),
        ("event_type", "Ereignistyp"),
        ("extra_key", "unerwartete Felder"),
    ],
)
def test_decode_evidence_journal_event_rejects_wrong_binding_or_shape(
    corruption: str,
    expected_error: str,
) -> None:
    evidence = _evidence(_handshake(_candidate(HASH_A, 81)), 0)
    event = _journal_event(evidence)
    event_sha256 = "c" * 64
    expected_run_id = "run-1"
    expected_config_sha256 = "a" * 64
    expected_software_sha256 = "b" * 64
    if corruption == "run":
        expected_run_id = "run-2"
    elif corruption == "config":
        expected_config_sha256 = "d" * 64
    elif corruption == "software":
        expected_software_sha256 = "e" * 64
    elif corruption == "event_hash":
        event_sha256 = "z" * 64
    elif corruption == "event_type":
        event["event_type"] = "scan_completed"
    elif corruption == "extra_key":
        event["unexpected"] = True
    else:
        raise AssertionError(f"Unbekannter Testfall: {corruption}")

    with pytest.raises(RunStoreError, match=expected_error):
        decode_evidence_journal_event(
            event,
            event_sha256,
            expected_run_id=expected_run_id,
            expected_config_sha256=expected_config_sha256,
            expected_software_sha256=expected_software_sha256,
        )


def test_reconcile_evidence_batch_inserts_five_and_is_idempotent(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates = [_candidate(HASH_A, 82 + index) for index in range(5)]
    assert store.add_candidates(candidates) == 5
    assert store.claim_candidate_batch([HASH_A], size=5) == candidates
    handshakes = [_handshake(candidate) for candidate in candidates]
    assert store.store_handshake_batch(handshakes) == 5
    records = [_evidence(handshake, index) for index, handshake in enumerate(handshakes)]

    assert store.reconcile_evidence_batch(records) == 5
    assert store.reconcile_evidence_batch(records) == 0
    assert list(store.iter_evidence_records()) == records
    with sqlite3.connect(store.path) as connection:
        stored = connection.execute(
            "SELECT evidence_json, evidence_json_sha256 FROM evidence_records ORDER BY candidate_id"
        ).fetchall()
    assert len(stored) == 5
    assert all(
        digest == hashlib.sha256(payload.encode("utf-8")).hexdigest() for payload, digest in stored
    )


def test_reconcile_evidence_batch_rolls_back_on_divergent_existing_record(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidates = [_candidate(HASH_A, 90 + index) for index in range(2)]
    assert store.add_candidates(candidates) == 2
    assert store.claim_candidate_batch([HASH_A], size=2) == candidates
    handshakes = [_handshake(candidate) for candidate in candidates]
    assert store.store_handshake_batch(handshakes) == 2
    missing = _evidence(handshakes[0], 0)
    existing = _evidence(handshakes[1], 1)
    assert store.store_evidence_batch([existing]) == 1
    divergent = replace(
        existing,
        vpn=VpnClassification(status="unknown", reason="Abweichender Datensatz"),
    )

    with pytest.raises(RunStoreError, match="weicht vom gespeicherten Datensatz ab"):
        store.reconcile_evidence_batch([missing, divergent])

    assert store.evidence_count() == 1
    assert list(store.iter_evidence_records()) == [existing]
    assert store.reconcile_evidence_batch([missing]) == 1


def test_reconcile_evidence_batch_requires_exact_stored_candidate(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    candidate = _candidate(HASH_A, 94)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    handshake = _handshake(candidate)
    assert store.store_handshake_batch([handshake]) == 1
    changed_handshake = replace(
        handshake,
        candidate=replace(candidate, source_note="Abweichende Kandidatendaten"),
    )

    with pytest.raises(RunStoreError, match="abweichende Kandidatendaten"):
        store.reconcile_evidence_batch([_evidence(changed_handshake, 0)])

    assert store.evidence_count() == 0


def test_reconcile_evidence_batch_rejects_more_than_five_records(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run.sqlite3")
    evidence = [_evidence(_handshake(_candidate(HASH_A, 95 + index)), index) for index in range(6)]

    with pytest.raises(ValueError, match="hoechstens 5"):
        store.reconcile_evidence_batch(evidence)

    assert store.evidence_count() == 0


def _claimed_at(database_path: Path) -> str:
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT claimed_at_utc FROM candidates WHERE status = 'in_progress'"
        ).fetchone()
    assert row is not None
    assert isinstance(row[0], str)
    return row[0]


def test_new_sighting_during_negative_check_is_requeued_after_completion(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    candidate = _candidate(HASH_A, 100)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    rediscovered = replace(
        candidate,
        discovered_at_utc=_offset_utc(_claimed_at(database_path), seconds=20),
        transaction_id_hex="feedbeef",
        response_sha256="cd" * 32,
        source_note="Sichtung waehrend laufender Pruefung",
    )

    ingest = store.ingest_candidates(
        [rediscovered],
        negative_recheck_cooldown_seconds=10,
    )
    assert ingest.deferred_negative_rechecks == 1
    assert ingest.scheduled_candidates == 0
    assert store.store_handshake_batch([replace(_handshake(candidate), availability=None)]) == 1

    metrics = store.metrics_by_hash()[HASH_A]
    assert metrics.pending == 1
    assert metrics.done == 0
    assert metrics.handshake_results == 1
    assert list(store.iter_handshake_results()) == [
        replace(_handshake(candidate), availability=None)
    ]
    assert store.claim_candidate_batch([HASH_A]) == [rediscovered]


def test_new_candidates_are_checked_before_hot_negative_rechecks(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    hot = _candidate(HASH_A, 110)
    assert store.add_candidates([hot]) == 1
    assert store.claim_candidate_batch([HASH_A, HASH_B]) == [hot]
    first_negative = replace(_handshake(hot), availability=None)
    assert store.store_handshake_batch([first_negative], count_new_only=True) == 1

    first_completion = _stored_completion(database_path)
    first_rediscovery = replace(
        hot,
        discovered_at_utc=_offset_utc(first_completion, seconds=10),
        transaction_id_hex="feed0001",
        response_sha256="a1" * 32,
        source_note="Erste erneute Sichtung",
    )
    assert (
        store.ingest_candidates(
            [first_rediscovery],
            negative_recheck_cooldown_seconds=10,
        ).requeued_negative_candidates
        == 1
    )

    fresh = [
        *(_candidate(HASH_A, 200 + index) for index in range(7)),
        *(_candidate(HASH_B, 300 + index) for index in range(8)),
    ]
    assert store.add_candidates(fresh) == 15
    first_checks: list[PeerCandidate] = []
    while len(first_checks) < len(fresh):
        batch = store.claim_candidate_batch([HASH_A, HASH_B], size=5)
        assert batch
        assert first_rediscovery not in batch
        first_checks.extend(batch)
        store.store_handshake_batch(
            replace(_handshake(candidate), availability=None) for candidate in batch
        )

    assert {(*candidate.endpoint, candidate.info_hash_hex) for candidate in first_checks} == {
        (*candidate.endpoint, candidate.info_hash_hex) for candidate in fresh
    }
    assert store.claim_candidate_batch([HASH_A, HASH_B], size=5) == [first_rediscovery]

    second_rediscovery = replace(
        first_rediscovery,
        discovered_at_utc=_offset_utc(_claimed_at(database_path), seconds=20),
        transaction_id_hex="feed0002",
        response_sha256="a2" * 32,
        source_note="Sichtung waehrend der Wiederholungspruefung",
    )
    assert (
        store.ingest_candidates(
            [second_rediscovery],
            negative_recheck_cooldown_seconds=10,
        ).deferred_negative_rechecks
        == 1
    )
    second_negative = replace(
        _handshake(first_rediscovery),
        attempted_at_utc=_offset_utc(first_rediscovery.discovered_at_utc, seconds=0.5),
        completed_at_utc=_offset_utc(first_rediscovery.discovered_at_utc, seconds=0.75),
        availability=None,
    )
    assert store.store_handshake_batch([second_negative], count_new_only=True) == 0

    later_fresh = [_candidate(HASH_B, 400 + index) for index in range(3)]
    assert store.add_candidates(later_fresh) == 3
    assert store.claim_candidate_batch([HASH_A, HASH_B], size=5) == later_fresh
    store.store_handshake_batch(
        replace(_handshake(candidate), availability=None) for candidate in later_fresh
    )
    assert store.claim_candidate_batch([HASH_A, HASH_B], size=5) == [second_rediscovery]

    metrics = store.metrics_by_hash([HASH_A, HASH_B])
    assert sum(metric.candidates for metric in metrics.values()) == 19
    assert sum(metric.handshake_results for metric in metrics.values()) == 19


def test_new_sighting_during_positive_check_remains_terminal(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    candidate = _candidate(HASH_A, 101)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    rediscovered = replace(
        candidate,
        discovered_at_utc=_offset_utc(_claimed_at(database_path), seconds=20),
        source_note="Spaetere Sichtung desselben positiven Endpunkts",
    )
    assert (
        store.ingest_candidates(
            [rediscovered],
            negative_recheck_cooldown_seconds=10,
        ).deferred_negative_rechecks
        == 1
    )

    assert store.store_handshake_batch([_handshake(candidate)]) == 1

    metrics = store.metrics_by_hash()[HASH_A]
    assert metrics.pending == 0
    assert metrics.done == 1
    assert metrics.offering_observed == 1
    assert store.claim_candidate_batch([HASH_A]) == []


def test_crash_requeue_promotes_latest_deferred_sighting(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    store = RunStore(database_path)
    candidate = _candidate(HASH_A, 102)
    assert store.add_candidates([candidate]) == 1
    assert store.claim_candidate_batch([HASH_A]) == [candidate]
    rediscovered = replace(
        candidate,
        discovered_at_utc=_offset_utc(_claimed_at(database_path), seconds=20),
        source_note="Vor Absturz vorgemerkte Sichtung",
    )
    assert (
        store.ingest_candidates(
            [rediscovered],
            negative_recheck_cooldown_seconds=10,
        ).deferred_negative_rechecks
        == 1
    )

    restarted = RunStore(database_path)
    assert restarted.requeue_in_progress() == 1
    assert restarted.claim_candidate_batch([HASH_A]) == [rediscovered]


def test_schema_v2_migration_adds_rediscovery_columns(tmp_path: Path) -> None:
    database_path = tmp_path / "run.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE candidates (
                id INTEGER PRIMARY KEY,
                info_hash TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                candidate_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                claimed_at_utc TEXT,
                completed_at_utc TEXT,
                UNIQUE (info_hash, ip, port)
            )
            """
        )
        connection.execute("PRAGMA user_version = 2")
        connection.commit()

    RunStore(database_path)

    with sqlite3.connect(database_path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(candidates)").fetchall()}
    assert version == 3
    assert {"rediscovery_candidate_json", "rediscovered_at_utc"} <= columns
