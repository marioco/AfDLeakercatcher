"""Zusätzliche Offline-Regressionstests für Netzwerk-Härtungen."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

import bittorrent_beobachter.dht as dht_module
import bittorrent_beobachter.monitor as monitor_module
import bittorrent_beobachter.peer as peer_module
from bittorrent_beobachter.config import AppConfig, DhtSettings, EnrichmentSettings
from bittorrent_beobachter.dht import (
    BOOTSTRAP_ISSUE_DNS,
    BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS,
    BOOTSTRAP_ISSUE_RESOLVER,
    BOOTSTRAP_ISSUE_TIMEOUT,
    DHT_ISSUE_DEADLINE,
    DHT_ISSUE_NETWORK,
    DHTConfig,
    DHTCrawler,
    DHTNode,
    DHTQueryError,
    DHTResponse,
    resolve_bootstrap_nodes,
)
from bittorrent_beobachter.models import (
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    ScanResult,
    Target,
)
from bittorrent_beobachter.monitor import MonitorError
from bittorrent_beobachter.peer import PeerVerifier

INFO_HASH = b"h" * 20
PEER_ID = b"-TEST00-123456789012"


def _candidate(
    target: Target,
    *,
    ip: str = "8.8.8.8",
    port: int = 6881,
    response_sha256: str = "a" * 64,
) -> PeerCandidate:
    return PeerCandidate(
        target_label=target.label,
        info_hash_hex=target.info_hash_hex,
        ip=ip,
        port=port,
        discovered_at_utc="2026-10-20T12:00:00.000Z",
        dht_node_ip="1.1.1.1",
        dht_node_port=6881,
        transaction_id_hex="0102",
        response_sha256=response_sha256,
    )


def _confirmed(candidate: PeerCandidate) -> HandshakeResult:
    availability = PeerAvailabilityObservation(
        started_at_utc="2026-10-20T12:00:01.100Z",
        ended_at_utc="2026-10-20T12:01:01.100Z",
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
        bytes_received=8,
        request_messages_sent=0,
        piece_payload_bytes_received=0,
        metadata_requests_sent=0,
        termination_reason="duration_elapsed",
        control_events=(),
    )
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc="2026-10-20T12:00:01.000Z",
        completed_at_utc="2026-10-20T12:00:01.100Z",
        confirmed=True,
        remote_peer_id_hex="b" * 40,
        reserved_bits_hex="0" * 16,
        local_ip="192.0.2.10",
        local_port=40_000,
        bytes_sent=68,
        bytes_received=68,
        error=None,
        availability=availability,
    )


def test_bootstrap_partial_failures_are_categorized_without_endpoint_text() -> None:
    async def scenario() -> None:
        cancelled = asyncio.Event()

        async def fake_getaddrinfo(
            host: str,
            port: int,
            **_kwargs: object,
        ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            if host == "good.example":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_DGRAM,
                        socket.IPPROTO_UDP,
                        "",
                        ("8.8.8.8", port),
                    )
                ]
            if host == "dns.example":
                raise socket.gaierror("sensitive dns.example 203.0.113.10")
            if host == "private.example":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_DGRAM,
                        socket.IPPROTO_UDP,
                        "",
                        ("127.0.0.1", port),
                    )
                ]
            if host == "resolver.example":
                raise OSError("sensitive resolver.example 203.0.113.11")
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        issues: list[str] = []
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", new=fake_getaddrinfo):
            resolved = await resolve_bootstrap_nodes(
                [
                    ("good.example", 6881),
                    ("dns.example", 6881),
                    ("private.example", 6881),
                    ("resolver.example", 6881),
                    ("slow.example", 6881),
                ],
                timeout=0.1,
                issue_hook=issues.append,
            )

        assert resolved == [("8.8.8.8", 6881)]
        assert sorted(issues) == sorted(
            [
                BOOTSTRAP_ISSUE_DNS,
                BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS,
                BOOTSTRAP_ISSUE_RESOLVER,
                BOOTSTRAP_ISSUE_TIMEOUT,
            ]
        )
        assert cancelled.is_set()
        assert " ".join(issues).find("203.0.113") == -1

    asyncio.run(scenario())


def test_dht_socket_is_closed_when_nonblocking_setup_fails() -> None:
    async def scenario() -> None:
        class FailingSocket:
            def __init__(self) -> None:
                self.closed = False

            def setblocking(self, _value: bool) -> None:
                raise OSError("sensitive 203.0.113.12")

            def close(self) -> None:
                self.closed = True

        failing_socket = FailingSocket()
        crawler = DHTCrawler([("8.8.8.8", 6881)])
        with (
            patch.object(dht_module.socket, "socket", return_value=failing_socket),
            pytest.raises(DHTQueryError) as caught,
        ):
            await crawler._query_node(("8.8.8.8", 6881), INFO_HASH, b"tx")

        assert failing_socket.closed
        assert caught.value.category == DHT_ISSUE_NETWORK
        assert "203.0.113" not in str(caught.value)

    asyncio.run(scenario())


def test_dht_issue_count_is_not_truncated_and_errors_do_not_leak_ips() -> None:
    async def scenario() -> None:
        bootstrap = ("8.8.8.8", 6881)
        returned_nodes = tuple(
            DHTNode(index.to_bytes(20, "big"), "1.1.1.1", 10_000 + index) for index in range(110)
        )

        async def query(
            endpoint: tuple[str, int],
            _info_hash: bytes,
            transaction_id: bytes,
        ) -> DHTResponse:
            if endpoint == bootstrap:
                return DHTResponse(
                    source=endpoint,
                    transaction_id=transaction_id,
                    nodes=returned_nodes,
                    peers=(),
                    response_sha256="a" * 64,
                )
            raise OSError("sensitive endpoint 203.0.113.13:6881")

        crawler = DHTCrawler(
            [bootstrap],
            config=DHTConfig(
                overall_timeout_seconds=5.0,
                max_queries=111,
                concurrency=32,
                max_nodes=200,
            ),
            query_hook=query,
        )
        candidates = await crawler.discover(Target("Test", INFO_HASH))

        assert candidates == []
        assert crawler.queries_completed == 1
        assert crawler.queries_failed == 110
        assert crawler.issue_count == 110
        assert crawler.issue_counts == {DHT_ISSUE_NETWORK: 110}
        assert len(crawler.errors) == 100
        assert all("203.0.113" not in error for error in crawler.errors)

    asyncio.run(scenario())


def test_dht_deadline_cancels_active_query() -> None:
    async def scenario() -> None:
        cancelled = asyncio.Event()

        async def query(
            _endpoint: tuple[str, int],
            _info_hash: bytes,
            _transaction_id: bytes,
        ) -> DHTResponse:
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        crawler = DHTCrawler(
            [("8.8.8.8", 6881)],
            config=DHTConfig(
                timeout_seconds=30.0,
                overall_timeout_seconds=0.1,
                max_queries=1,
            ),
            query_hook=query,
        )
        assert await crawler.discover(Target("Test", INFO_HASH)) == []
        assert cancelled.is_set()
        assert crawler.queries_failed == 0
        assert crawler.issue_counts == {DHT_ISSUE_DEADLINE: 1}

    asyncio.run(scenario())


def test_peer_socket_is_closed_when_nonblocking_setup_fails() -> None:
    async def scenario() -> None:
        class FailingSocket:
            def __init__(self) -> None:
                self.closed = False

            def setblocking(self, _value: bool) -> None:
                raise OSError("setup failed")

            def close(self) -> None:
                self.closed = True

        target = Target("Test", INFO_HASH)
        failing_socket = FailingSocket()
        verifier = PeerVerifier(peer_id=PEER_ID, timeout=1.0)
        with patch.object(peer_module.socket, "socket", return_value=failing_socket):
            result = await verifier.verify(_candidate(target), INFO_HASH)

        assert not result.confirmed
        assert result.bytes_sent == 0
        assert failing_socket.closed

    asyncio.run(scenario())


def test_handshake_selection_deduplicates_same_target_endpoint() -> None:
    target = Target("Test", INFO_HASH)
    first = _candidate(target, response_sha256="a" * 64)
    duplicate = _candidate(target, response_sha256="b" * 64)

    selected = monitor_module._fair_handshake_candidates(
        (target,),
        (first, duplicate),
        2,
    )

    assert selected == [first]


def test_monitor_caps_candidates_fairly_and_anonymizes_bootstrap_notices() -> None:
    async def scenario() -> None:
        targets = tuple(
            Target(f"Ziel {index}", index.to_bytes(20, "big")) for index in range(1, 21)
        )
        config = AppConfig(
            targets=targets,
            dht=DhtSettings(
                timeout_seconds=0.25,
                max_queries=1,
                alpha=1,
                max_nodes=1_000,
                max_candidates=5_000,
                bootstrap_nodes=(("secret-bootstrap.example", 6881),),
            ),
        )
        crawler_limits: list[int] = []

        async def fake_resolve(*_args: object, **kwargs: object) -> list[tuple[str, int]]:
            issue_hook = kwargs["issue_hook"]
            assert callable(issue_hook)
            issue_hook(BOOTSTRAP_ISSUE_DNS)
            issue_hook(BOOTSTRAP_ISSUE_TIMEOUT)
            return [("9.9.9.9", 6881)]

        class FakeCrawler:
            def __init__(self, _bootstrap: object, *, config: DHTConfig) -> None:
                crawler_limits.append(config.max_candidates)
                self.queries_completed = 1
                self.errors: tuple[str, ...] = ()
                self.issue_count = 0

            async def discover(self, _target: Target) -> list[PeerCandidate]:
                return []

        with (
            patch.object(monitor_module, "resolve_bootstrap_nodes", new=fake_resolve),
            patch.object(monitor_module, "DHTCrawler", new=FakeCrawler),
        ):
            candidates, notices = await monitor_module._discover_candidates(
                config,
                lambda _message: None,
            )

        assert candidates == []
        assert crawler_limits == [500] * 20
        assert len(notices) == 2
        joined = " ".join(notices)
        assert "Sicherheitslimit" in joined
        assert "DNS-Fehler" in joined
        assert "Zeitlimit" in joined
        assert "secret-bootstrap" not in joined
        assert "9.9.9.9" not in joined

    asyncio.run(scenario())


def test_inner_timeout_is_generic_and_journaled_as_failed_scan(
    tmp_path: Path,
) -> None:
    target = Target("Test", INFO_HASH)
    config = AppConfig(targets=(target,))

    async def inner_timeout(
        _config: AppConfig,
        _progress: object,
    ) -> tuple[list[PeerCandidate], list[HandshakeResult], list[str]]:
        raise TimeoutError("sensitive endpoint 203.0.113.14:6881")

    with (
        patch.object(monitor_module, "_network_phase", new=inner_timeout),
        patch.object(monitor_module, "_software_sha256", return_value="f" * 64),
        pytest.raises(MonitorError) as caught,
    ):
        monitor_module.run_scan(config, tmp_path)

    assert "einzelne Operation" in str(caught.value)
    assert "203.0.113" not in str(caught.value)
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert [event["event_type"] for event in events] == ["scan_started", "scan_failed"]
    assert events[-1]["error_type"] == "MonitorError"
    assert "203.0.113" not in json.dumps(events[-1])


def test_expected_enrichment_failure_is_notice_not_popup_error(tmp_path: Path) -> None:
    target = Target("Test", INFO_HASH)
    handshake = _confirmed(_candidate(target))
    config = AppConfig(
        targets=(target,),
        enrichment=EnrichmentSettings(enabled=True),
    )

    class FailingEnricher:
        def __init__(self, _cache_dir: Path, **_kwargs: object) -> None:
            pass

        def enrich(self, _ip: str) -> NetworkEnrichment:
            raise OSError("sensitive endpoint 203.0.113.15")

    result = ScanResult(run_id="test-run", started_at_utc="2026-10-20T12:00:00Z")
    with patch.object(monitor_module, "NetworkEnricher", new=FailingEnricher):
        enrichment = monitor_module._enrich_confirmed_handshakes(
            config,
            tmp_path,
            (handshake,),
            result,
            lambda _message: None,
        )

    assert enrichment["8.8.8.8"][0].error is not None
    assert result.errors == []
    assert len(result.notices) == 1
    assert "Netzauskunft" in result.notices[0]
    assert "203.0.113" not in result.notices[0]
