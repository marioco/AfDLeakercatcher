"""Offline-Tests fuer die datensparsame UDP-Tracker-Ermittlung."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import struct
from collections.abc import AsyncIterator, Iterator
from unittest.mock import patch

import pytest

import bittorrent_beobachter.tracker as tracker_module
from bittorrent_beobachter.config import MAX_TRACKERS_PER_TARGET
from bittorrent_beobachter.models import PeerCandidate, Target
from bittorrent_beobachter.tracker import (
    ANNOUNCE_REQUEST_BYTES,
    TRACKER_ACTION_ANNOUNCE,
    TRACKER_ACTION_CONNECT,
    TRACKER_EVENT_STARTED,
    TRACKER_EVENT_STOPPED,
    TRACKER_LEFT_UNKNOWN,
    TRACKER_NUM_WANT_DEFAULT,
    TRACKER_NUM_WANT_NONE,
    UDP_TRACKER_PROTOCOL_ID,
    TrackerAnnounceResponse,
    TrackerDiscoveryStats,
    TrackerProtocolError,
    TrackerURL,
    _announce_to_endpoint,
    build_announce_request,
    build_connect_request,
    discover_tracker_peers,
    parse_announce_response,
    parse_connect_response,
    parse_tracker_url,
    resolve_tracker,
)

INFO_HASH = b"h" * 20
PEER_ID = b"p" * 20
TARGET = Target("Testziel", INFO_HASH, "Quellenhinweis")


def _compact_ipv4(ip: str, port: int) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip) + port.to_bytes(2, "big")


def _compact_ipv6(ip: str, port: int) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip) + port.to_bytes(2, "big")


def test_connect_request_and_response_follow_bep15_minimum_length() -> None:
    request = build_connect_request(0x01020304)

    assert len(request) == 16
    assert struct.unpack("!QII", request) == (
        UDP_TRACKER_PROTOCOL_ID,
        TRACKER_ACTION_CONNECT,
        0x01020304,
    )
    response = struct.pack("!IIQ", TRACKER_ACTION_CONNECT, 0x01020304, 0x1122334455667788)
    assert (
        parse_connect_response(response, expected_transaction_id=0x01020304) == 0x1122334455667788
    )
    assert (
        parse_connect_response(
            response + b"future extension",
            expected_transaction_id=0x01020304,
        )
        == 0x1122334455667788
    )
    with pytest.raises(TrackerProtocolError, match="ungueltig"):
        parse_connect_response(response[:-1], expected_transaction_id=0x01020304)

    with pytest.raises(TrackerProtocolError):
        parse_connect_response(response, expected_transaction_id=7)
    error_response = struct.pack("!II", 3, 0x01020304) + b"untrusted message"
    with pytest.raises(TrackerProtocolError, match="meldete einen Fehler"):
        parse_connect_response(error_response, expected_transaction_id=0x01020304)


def test_announce_requests_are_wire_exact_without_transfer_claims() -> None:
    assert TRACKER_NUM_WANT_DEFAULT == 0x7FFF_FFFF
    started_request = build_announce_request(
        0x1122334455667788,
        0x01020304,
        INFO_HASH,
        PEER_ID,
        0x55667788,
        event=TRACKER_EVENT_STARTED,
        port=51413,
    )
    stopped_request = build_announce_request(
        0x1122334455667788,
        0x01020305,
        INFO_HASH,
        PEER_ID,
        0x55667788,
        event=TRACKER_EVENT_STOPPED,
        port=51413,
        num_want=TRACKER_NUM_WANT_NONE,
    )

    assert len(started_request) == ANNOUNCE_REQUEST_BYTES
    assert len(stopped_request) == ANNOUNCE_REQUEST_BYTES
    assert struct.unpack("!QII20s20sQQQIIIiH", started_request) == (
        0x1122334455667788,
        TRACKER_ACTION_ANNOUNCE,
        0x01020304,
        INFO_HASH,
        PEER_ID,
        0,
        TRACKER_LEFT_UNKNOWN,
        0,
        TRACKER_EVENT_STARTED,
        0,
        0x55667788,
        TRACKER_NUM_WANT_DEFAULT,
        51413,
    )
    assert struct.unpack("!QII20s20sQQQIIIiH", stopped_request) == (
        0x1122334455667788,
        TRACKER_ACTION_ANNOUNCE,
        0x01020305,
        INFO_HASH,
        PEER_ID,
        0,
        TRACKER_LEFT_UNKNOWN,
        0,
        TRACKER_EVENT_STOPPED,
        0,
        0x55667788,
        TRACKER_NUM_WANT_NONE,
        51413,
    )

    with pytest.raises(ValueError, match="Port"):
        build_announce_request(
            1,
            2,
            INFO_HASH,
            PEER_ID,
            3,
            event=TRACKER_EVENT_STARTED,
            port=0,
        )


def test_announce_parser_supports_ipv4_and_filters_non_global_peers() -> None:
    packet = (
        struct.pack("!IIIII", TRACKER_ACTION_ANNOUNCE, 7, 60, 1, 2)
        + _compact_ipv4("8.8.8.8", 6881)
        + _compact_ipv4("192.168.1.5", 6881)
        + _compact_ipv4("1.1.1.1", 0)
    )

    assert parse_announce_response(
        packet,
        expected_transaction_id=7,
        family=socket.AF_INET,
    ) == (("8.8.8.8", 6881),)

    with pytest.raises(TrackerProtocolError):
        parse_announce_response(packet + b"x", expected_transaction_id=7, family=socket.AF_INET)


def test_announce_parser_supports_ipv6() -> None:
    packet = (
        struct.pack("!IIIII", TRACKER_ACTION_ANNOUNCE, 9, 60, 1, 2)
        + _compact_ipv6("2606:4700:4700::1111", 51413)
        + _compact_ipv6("::1", 6881)
    )

    assert parse_announce_response(
        packet,
        expected_transaction_id=9,
        family=socket.AF_INET6,
    ) == (("2606:4700:4700::1111", 51413),)


@pytest.mark.parametrize(
    "value",
    [
        "http://tracker.example:80/announce",
        "udp://user:password@tracker.example:80/announce",
        "udp://tracker.example/announce",
        "udp://tracker.example:70000/announce",
        "udp://tracker.example:80/announce#fragment",
    ],
)
def test_only_plain_udp_tracker_urls_with_explicit_port_are_accepted(value: str) -> None:
    with pytest.raises(ValueError):
        parse_tracker_url(value)


def test_tracker_url_parser_accepts_ipv4_ipv6_and_dns() -> None:
    assert parse_tracker_url("udp://tracker.example:1337/announce") == TrackerURL(
        "tracker.example", 1337
    )
    assert parse_tracker_url("udp://[2606:4700:4700::1111]:6969/announce") == TrackerURL(
        "2606:4700:4700::1111", 6969
    )


def test_resolver_keeps_every_unique_global_udp_address_without_result_cap() -> None:
    async def scenario() -> None:
        addresses = [
            (
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                "",
                ("127.0.0.1", 1337),
            )
        ]
        addresses.extend(
            (
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                "",
                ("8.8.8.8", 10_000 + index),
            )
            for index in range(73)
        )
        addresses.append(addresses[-1])

        async def fake_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple]:
            return addresses

        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", new=fake_getaddrinfo):
            resolved = await resolve_tracker(TrackerURL("tracker.example", 1337), timeout=1.0)

        assert len(resolved) == 73
        assert all(ip == "8.8.8.8" for ip, _port in resolved)

    asyncio.run(scenario())


def test_resolver_has_an_explicit_timeout_and_cancels_the_await() -> None:
    async def scenario() -> None:
        cancelled = asyncio.Event()

        async def hanging_getaddrinfo(*_args: object, **_kwargs: object) -> list[tuple]:
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        loop = asyncio.get_running_loop()
        with (
            patch.object(loop, "getaddrinfo", new=hanging_getaddrinfo),
            pytest.raises(TimeoutError),
        ):
            await resolve_tracker(TrackerURL("tracker.example", 1337), timeout=0.1)

        assert cancelled.is_set()

    asyncio.run(scenario())


def test_connect_and_announce_use_wire_safe_values_and_same_endpoint() -> None:
    async def scenario() -> None:
        requests: list[tuple[tuple[str, int], bytes]] = []
        transactions = iter((11, 22, 44))

        async def exchange(endpoint: tuple[str, int], packet: bytes) -> bytes:
            requests.append((endpoint, packet))
            action = struct.unpack_from("!I", packet, 8)[0]
            transaction = struct.unpack_from("!I", packet, 12)[0]
            if action == TRACKER_ACTION_CONNECT:
                return struct.pack("!IIQ", TRACKER_ACTION_CONNECT, transaction, 1234)
            event = struct.unpack_from("!I", packet, 80)[0]
            response = struct.pack("!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1)
            if event == TRACKER_EVENT_STARTED:
                return response + _compact_ipv4("8.8.4.4", 51413)
            assert event == TRACKER_EVENT_STOPPED
            return response

        response = await _announce_to_endpoint(
            TARGET,
            ("1.1.1.1", 6969),
            timeout=1.0,
            peer_id=PEER_ID,
            exchange_hook=exchange,
            transaction_id_factory=lambda: next(transactions),
            key_factory=lambda: 33,
            announce_port_factory=lambda: 51413,
        )

        assert [endpoint for endpoint, _packet in requests] == [
            ("1.1.1.1", 6969),
            ("1.1.1.1", 6969),
            ("1.1.1.1", 6969),
        ]
        started = struct.unpack("!QII20s20sQQQIIIiH", requests[1][1])
        stopped = struct.unpack("!QII20s20sQQQIIIiH", requests[2][1])
        assert started[1] == stopped[1] == TRACKER_ACTION_ANNOUNCE
        assert started[0] == stopped[0] == 1234
        assert (
            started[3:8]
            == stopped[3:8]
            == (
                INFO_HASH,
                PEER_ID,
                0,
                TRACKER_LEFT_UNKNOWN,
                0,
            )
        )
        assert started[8] == TRACKER_EVENT_STARTED
        assert stopped[8] == TRACKER_EVENT_STOPPED
        assert started[10] == stopped[10] == 33
        assert started[11:] == (TRACKER_NUM_WANT_DEFAULT, 51413)
        assert stopped[11:] == (TRACKER_NUM_WANT_NONE, 51413)
        assert response.peers == (("8.8.4.4", 51413),)
        assert response.transaction_id == 22
        assert response.cleanup_failed is False

    asyncio.run(scenario())


def test_stopped_failure_preserves_started_peer_response() -> None:
    async def scenario() -> None:
        transactions = iter((11, 22, 44))

        async def exchange(_endpoint: tuple[str, int], packet: bytes) -> bytes:
            action = struct.unpack_from("!I", packet, 8)[0]
            transaction = struct.unpack_from("!I", packet, 12)[0]
            if action == TRACKER_ACTION_CONNECT:
                return struct.pack("!IIQ", TRACKER_ACTION_CONNECT, transaction, 1234)
            event = struct.unpack_from("!I", packet, 80)[0]
            if event == TRACKER_EVENT_STOPPED:
                raise TimeoutError
            return struct.pack(
                "!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1
            ) + _compact_ipv4("8.8.4.4", 51413)

        response = await _announce_to_endpoint(
            TARGET,
            ("1.1.1.1", 6969),
            timeout=1.0,
            peer_id=PEER_ID,
            exchange_hook=exchange,
            transaction_id_factory=lambda: next(transactions),
            key_factory=lambda: 33,
            announce_port_factory=lambda: 51413,
        )

        assert response.peers == (("8.8.4.4", 51413),)
        assert response.transaction_id == 22
        assert response.cleanup_failed is True

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("mode", "error_type"),
    [
        ("timeout", TimeoutError),
        ("invalid", TrackerProtocolError),
    ],
)
def test_started_failure_still_attempts_stopped_and_raises_original(
    mode: str,
    error_type: type[BaseException],
) -> None:
    async def scenario() -> None:
        transactions = iter((11, 22, 44))
        observed_events: list[int] = []

        async def exchange(_endpoint: tuple[str, int], packet: bytes) -> bytes:
            action = struct.unpack_from("!I", packet, 8)[0]
            transaction = struct.unpack_from("!I", packet, 12)[0]
            if action == TRACKER_ACTION_CONNECT:
                return struct.pack("!IIQ", TRACKER_ACTION_CONNECT, transaction, 1234)
            event = struct.unpack_from("!I", packet, 80)[0]
            observed_events.append(event)
            if event == TRACKER_EVENT_STARTED:
                if mode == "timeout":
                    raise TimeoutError("started failed")
                return b"invalid"
            assert event == TRACKER_EVENT_STOPPED
            return struct.pack("!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1)

        with pytest.raises(error_type):
            await _announce_to_endpoint(
                TARGET,
                ("1.1.1.1", 6969),
                timeout=1.0,
                peer_id=PEER_ID,
                exchange_hook=exchange,
                transaction_id_factory=lambda: next(transactions),
                key_factory=lambda: 33,
                announce_port_factory=lambda: 51413,
                retry_backoff_seconds=0.0,
            )

        assert observed_events == [
            *([TRACKER_EVENT_STARTED] * 3),
            TRACKER_EVENT_STOPPED,
        ]

    asyncio.run(scenario())


def test_stale_connect_response_during_announce_is_ignored_by_retry() -> None:
    async def scenario() -> None:
        transactions = iter((11, 22, 44))
        started_calls = 0

        async def exchange(_endpoint: tuple[str, int], packet: bytes) -> bytes:
            nonlocal started_calls
            action = struct.unpack_from("!I", packet, 8)[0]
            transaction = struct.unpack_from("!I", packet, 12)[0]
            if action == TRACKER_ACTION_CONNECT:
                return struct.pack("!IIQ", TRACKER_ACTION_CONNECT, transaction, 1234)
            event = struct.unpack_from("!I", packet, 80)[0]
            if event == TRACKER_EVENT_STARTED:
                started_calls += 1
                if started_calls == 1:
                    return struct.pack("!IIQ", TRACKER_ACTION_CONNECT, 11, 1234)
                return struct.pack(
                    "!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1
                ) + _compact_ipv4("8.8.4.4", 51413)
            return struct.pack("!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1)

        response = await _announce_to_endpoint(
            TARGET,
            ("1.1.1.1", 6969),
            timeout=1.0,
            peer_id=PEER_ID,
            exchange_hook=exchange,
            transaction_id_factory=lambda: next(transactions),
            key_factory=lambda: 33,
            announce_port_factory=lambda: 51413,
            retry_backoff_seconds=0.0,
        )

        assert started_calls == 2
        assert response.peers == (("8.8.4.4", 51413),)

    asyncio.run(scenario())


def test_connect_and_started_are_retransmitted_after_transient_network_errors() -> None:
    async def scenario() -> None:
        transactions = iter((11, 22, 44))
        connect_calls = 0
        started_calls = 0
        stopped_calls = 0

        async def exchange(_endpoint: tuple[str, int], packet: bytes) -> bytes:
            nonlocal connect_calls, started_calls, stopped_calls
            action = struct.unpack_from("!I", packet, 8)[0]
            transaction = struct.unpack_from("!I", packet, 12)[0]
            if action == TRACKER_ACTION_CONNECT:
                connect_calls += 1
                if connect_calls == 1:
                    raise TimeoutError("first connect packet lost")
                return struct.pack("!IIQ", TRACKER_ACTION_CONNECT, transaction, 1234)
            event = struct.unpack_from("!I", packet, 80)[0]
            if event == TRACKER_EVENT_STARTED:
                started_calls += 1
                if started_calls == 1:
                    raise ConnectionResetError("transient UDP error")
                return struct.pack(
                    "!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1
                ) + _compact_ipv4("8.8.4.4", 51413)
            stopped_calls += 1
            return struct.pack("!IIIII", TRACKER_ACTION_ANNOUNCE, transaction, 60, 1, 1)

        response = await _announce_to_endpoint(
            TARGET,
            ("1.1.1.1", 6969),
            timeout=1.0,
            peer_id=PEER_ID,
            exchange_hook=exchange,
            transaction_id_factory=lambda: next(transactions),
            key_factory=lambda: 33,
            announce_port_factory=lambda: 51413,
            retry_backoff_seconds=0.0,
        )

        assert response.peers == (("8.8.4.4", 51413),)
        assert (connect_calls, started_calls, stopped_calls) == (2, 2, 1)

    asyncio.run(scenario())


def test_streaming_mode_batches_five_without_cross_tracker_peer_set() -> None:
    async def scenario() -> None:
        peer_groups = (
            tuple(("8.8.8.8", 10_000 + index) for index in range(7)),
            tuple(("8.8.4.4", 20_000 + index) for index in range(4)),
        )
        responses = iter(peer_groups)
        batches: list[tuple[PeerCandidate, ...]] = []
        stats = TrackerDiscoveryStats()

        async def fake_resolve(
            tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            yield ("1.1.1.1", tracker.port)

        async def fake_announce(
            target: Target,
            tracker: tuple[str, int],
            **_kwargs: object,
        ) -> TrackerAnnounceResponse:
            peers = next(responses)
            packet = repr(peers).encode()
            return TrackerAnnounceResponse(
                tracker=tracker,
                transaction_id=tracker[1],
                peers=peers,
                response_sha256=hashlib.sha256(packet).hexdigest(),
                cleanup_failed=tracker[1] == 1002,
            )

        async def receive(batch: tuple[PeerCandidate, ...]) -> None:
            batches.append(batch)

        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module, "_announce_to_endpoint", new=fake_announce),
        ):
            candidates = await discover_tracker_peers(
                TARGET,
                (
                    "udp://tracker-one.example:1001/announce",
                    "udp://tracker-two.example:1002/announce",
                ),
                timeout=1.0,
                candidate_callback=receive,
                collect=False,
                stats=stats,
            )

        assert candidates == []
        assert [len(batch) for batch in batches] == [5, 5, 1]
        flattened = [candidate for batch in batches for candidate in batch]
        assert len(flattened) == 11
        assert flattened[0].target_label == TARGET.label
        assert flattened[0].source_note == TARGET.source_note
        assert {candidate.dht_node_port for candidate in flattened} == {1001, 1002}
        assert stats.trackers_configured == 2
        assert stats.endpoints_attempted == 2
        assert stats.queries_completed == 2
        assert stats.queries_failed == 0
        assert stats.stop_queries_failed == 1

    asyncio.run(scenario())


def test_streaming_tracker_discovery_has_no_candidate_count_cap() -> None:
    async def scenario() -> None:
        peers = tuple(("8.8.8.8", 10_000 + index) for index in range(607))
        batch_sizes: list[int] = []

        async def fake_resolve(
            _tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            yield ("1.1.1.1", 6969)

        async def fake_announce(
            _target: Target,
            tracker: tuple[str, int],
            **_kwargs: object,
        ) -> TrackerAnnounceResponse:
            return TrackerAnnounceResponse(
                tracker=tracker,
                transaction_id=1,
                peers=peers,
                response_sha256="a" * 64,
            )

        async def receive(batch: tuple[PeerCandidate, ...]) -> None:
            batch_sizes.append(len(batch))

        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module, "_announce_to_endpoint", new=fake_announce),
        ):
            await discover_tracker_peers(
                TARGET,
                ("udp://tracker.example:6969/announce",),
                timeout=1.0,
                candidate_callback=receive,
            )

        assert sum(batch_sizes) == 607
        assert batch_sizes[-1] == 2
        assert all(size == 5 for size in batch_sizes[:-1])

    asyncio.run(scenario())


def test_endpoint_queries_are_parallel_but_candidate_callback_is_serial() -> None:
    async def scenario() -> None:
        both_queries_started = asyncio.Event()
        active_queries = 0
        peak_queries = 0
        active_callbacks = 0
        peak_callbacks = 0
        batches: list[tuple[PeerCandidate, ...]] = []

        async def fake_resolve(
            _tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            yield ("1.1.1.1", 1001)
            yield ("1.1.1.1", 1002)

        async def fake_announce(
            _target: Target,
            tracker: tuple[str, int],
            **_kwargs: object,
        ) -> TrackerAnnounceResponse:
            nonlocal active_queries, peak_queries
            active_queries += 1
            peak_queries = max(peak_queries, active_queries)
            if active_queries == 2:
                both_queries_started.set()
            await asyncio.wait_for(both_queries_started.wait(), timeout=1.0)
            await asyncio.sleep(0)
            active_queries -= 1
            peers = tuple(("8.8.8.8", tracker[1] * 10 + index) for index in range(3))
            return TrackerAnnounceResponse(
                tracker=tracker,
                transaction_id=tracker[1],
                peers=peers,
                response_sha256=f"{tracker[1]:064x}",
            )

        async def receive(batch: tuple[PeerCandidate, ...]) -> None:
            nonlocal active_callbacks, peak_callbacks
            active_callbacks += 1
            peak_callbacks = max(peak_callbacks, active_callbacks)
            await asyncio.sleep(0)
            batches.append(batch)
            active_callbacks -= 1

        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module, "_announce_to_endpoint", new=fake_announce),
        ):
            await discover_tracker_peers(
                TARGET,
                ("udp://tracker.example:6969/announce",),
                timeout=1.0,
                candidate_callback=receive,
            )

        assert peak_queries == 2
        assert peak_callbacks == 1
        assert [len(batch) for batch in batches] == [5, 1]

    asyncio.run(scenario())


def test_cancellation_flushes_partial_batch_and_propagates() -> None:
    async def scenario() -> None:
        peers_consumed = asyncio.Event()
        persisted: list[tuple[PeerCandidate, ...]] = []

        class ObservedPeers(tuple):
            def __iter__(self) -> Iterator[tuple[str, int]]:
                yield from super().__iter__()
                peers_consumed.set()

        async def fake_resolve(
            _tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            yield ("1.1.1.1", 1001)
            yield ("1.1.1.1", 1002)

        async def fake_announce(
            _target: Target,
            tracker: tuple[str, int],
            **_kwargs: object,
        ) -> TrackerAnnounceResponse:
            if tracker[1] == 1002:
                await asyncio.Event().wait()
            peers = ObservedPeers(("8.8.8.8", 10_000 + index) for index in range(3))
            return TrackerAnnounceResponse(
                tracker=tracker,
                transaction_id=1,
                peers=peers,
                response_sha256="a" * 64,
            )

        async def persist(batch: tuple[PeerCandidate, ...]) -> None:
            persisted.append(batch)

        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module, "_announce_to_endpoint", new=fake_announce),
        ):
            task = asyncio.create_task(
                discover_tracker_peers(
                    TARGET,
                    ("udp://tracker.example:6969/announce",),
                    timeout=1.0,
                    candidate_callback=persist,
                )
            )
            await asyncio.wait_for(peers_consumed.wait(), timeout=1.0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert [len(batch) for batch in persisted] == [3]

    asyncio.run(scenario())


def test_unexpected_endpoint_error_flushes_partial_batch_before_propagation() -> None:
    async def scenario() -> None:
        peers_consumed = asyncio.Event()
        persisted: list[tuple[PeerCandidate, ...]] = []

        class ObservedPeers(tuple):
            def __iter__(self) -> Iterator[tuple[str, int]]:
                yield from super().__iter__()
                peers_consumed.set()

        async def fake_resolve(
            _tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            yield ("1.1.1.1", 1001)
            yield ("1.1.1.1", 1002)

        async def fake_announce(
            _target: Target,
            tracker: tuple[str, int],
            **_kwargs: object,
        ) -> TrackerAnnounceResponse:
            if tracker[1] == 1002:
                await peers_consumed.wait()
                raise AssertionError("programming bug")
            peers = ObservedPeers(("8.8.8.8", 20_000 + index) for index in range(3))
            return TrackerAnnounceResponse(
                tracker=tracker,
                transaction_id=1,
                peers=peers,
                response_sha256="b" * 64,
            )

        async def persist(batch: tuple[PeerCandidate, ...]) -> None:
            persisted.append(batch)

        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module, "_announce_to_endpoint", new=fake_announce),
            pytest.raises(AssertionError, match="programming bug"),
        ):
            await discover_tracker_peers(
                TARGET,
                ("udp://tracker.example:6969/announce",),
                timeout=1.0,
                candidate_callback=persist,
            )

        assert [len(batch) for batch in persisted] == [3]

    asyncio.run(scenario())


def test_collect_mode_deduplicates_and_returns_candidates() -> None:
    async def scenario() -> None:
        async def fake_resolve(
            _tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            yield ("1.1.1.1", 6969)

        async def fake_announce(
            _target: Target,
            tracker: tuple[str, int],
            **_kwargs: object,
        ) -> TrackerAnnounceResponse:
            return TrackerAnnounceResponse(
                tracker=tracker,
                transaction_id=7,
                peers=(("8.8.8.8", 6881), ("8.8.8.8", 6881)),
                response_sha256="a" * 64,
            )

        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module, "_announce_to_endpoint", new=fake_announce),
        ):
            candidates = await discover_tracker_peers(
                TARGET,
                ("udp://tracker.example:6969/announce",),
                timeout=1.0,
                candidate_callback=None,
                collect=True,
            )

        assert [(candidate.ip, candidate.port) for candidate in candidates] == [("8.8.8.8", 6881)]

    asyncio.run(scenario())


def test_streaming_mode_requires_callback_and_rejects_non_udp_before_network() -> None:
    async def scenario() -> None:
        with pytest.raises(ValueError, match="candidate_callback"):
            await discover_tracker_peers(
                TARGET,
                ("udp://tracker.example:6969/announce",),
                timeout=1.0,
                candidate_callback=None,
            )
        with pytest.raises(ValueError, match="udp://"):
            await discover_tracker_peers(
                TARGET,
                ("https://tracker.example/announce",),
                timeout=1.0,
                candidate_callback=lambda _batch: asyncio.sleep(0),
            )

    asyncio.run(scenario())


def test_tracker_sources_use_constant_bounded_worker_tasks() -> None:
    async def scenario() -> None:
        resolved_ports: list[int] = []
        real_create_task = asyncio.create_task
        created_tasks = 0

        async def fake_resolve(
            tracker: TrackerURL,
            *,
            timeout: float,
        ) -> AsyncIterator[tuple[str, int]]:
            assert timeout == 1.0
            resolved_ports.append(tracker.port)
            await asyncio.sleep(0)
            if tracker.port < 0:  # pragma: no cover - macht die Funktion zum Async-Generator
                yield ("1.1.1.1", tracker.port)

        def counting_create_task(coroutine: object, *args: object, **kwargs: object) -> object:
            nonlocal created_tasks
            created_tasks += 1
            return real_create_task(coroutine, *args, **kwargs)

        tracker_urls = tuple(
            f"udp://tracker-{index}.example:{10_000 + index}/announce"
            for index in range(MAX_TRACKERS_PER_TARGET)
        )
        with (
            patch.object(tracker_module, "iter_resolved_tracker_endpoints", new=fake_resolve),
            patch.object(tracker_module.asyncio, "create_task", new=counting_create_task),
        ):
            await discover_tracker_peers(
                TARGET,
                tracker_urls,
                timeout=1.0,
                candidate_callback=lambda _batch: asyncio.sleep(0),
            )

        assert len(resolved_ports) == MAX_TRACKERS_PER_TARGET
        assert created_tasks <= tracker_module.TRACKER_DISCOVERY_CONCURRENCY + 1

    asyncio.run(scenario())


def test_tracker_discovery_rejects_more_than_configured_source_limit() -> None:
    async def scenario() -> None:
        tracker_urls = tuple(
            f"udp://tracker-{index}.example:{10_000 + index}/announce"
            for index in range(MAX_TRACKERS_PER_TARGET + 1)
        )
        with pytest.raises(ValueError, match=rf"Höchstens {MAX_TRACKERS_PER_TARGET} Tracker"):
            await discover_tracker_peers(
                TARGET,
                tracker_urls,
                timeout=1.0,
                candidate_callback=lambda _batch: asyncio.sleep(0),
            )

    asyncio.run(scenario())
