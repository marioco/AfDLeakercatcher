"""Zusätzliche Offline-Regressionstests für Netzwerk-Härtungen."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

import bittorrent_beobachter.dht as dht_module
import bittorrent_beobachter.monitor as monitor_module
import bittorrent_beobachter.peer as peer_module
from bittorrent_beobachter.config import (
    AppConfig,
    DhtSettings,
    EnrichmentSettings,
    PeerSettings,
)
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
                concurrency=32,
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


def test_discovery_streams_more_than_six_hundred_for_both_hashes_without_caps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alle eindeutigen Treffer landen direkt in SQLite; Wiederholungen enden per Ruhephase."""

    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        first = Target("Ziel A", b"a" * 20)
        second = Target("Ziel B", b"b" * 20)
        config = AppConfig(
            targets=(first, second),
            dht=DhtSettings(
                timeout_seconds=0.25,
                overall_timeout_seconds=1.0,
                concurrency=4,
                quiet_seconds=1.0,
                refresh_interval_seconds=0.1,
                bootstrap_nodes=(("secret-bootstrap.example", 6881),),
            ),
            peer=PeerSettings(retry_attempts=1, retry_backoff_seconds=0.0),
        )
        store = RunStore(tmp_path / "run.sqlite3")
        runtimes = {
            target.info_hash_hex: monitor_module._TargetRuntimeMetrics(target=target)
            for target in config.targets
        }
        clock = [0.0]
        node_ids: list[bytes] = []
        persisted_batch_sizes: list[int] = []
        original_add = RunStore.add_candidates
        real_sleep = asyncio.sleep

        async def fake_sleep(delay: float) -> None:
            clock[0] += delay
            await real_sleep(0)

        async def fake_resolve(*_args: object, **kwargs: object) -> list[tuple[str, int]]:
            issue_hook = kwargs["issue_hook"]
            assert callable(issue_hook)
            issue_hook(BOOTSTRAP_ISSUE_DNS)
            return [("9.9.9.9", 6881)]

        class FakeCrawler:
            def __init__(
                self,
                _bootstrap: object,
                *,
                node_id: bytes,
                config: DHTConfig,
            ) -> None:
                del config
                node_ids.append(node_id)
                self.queries_started = 3
                self.queries_completed = 2
                self.queries_failed = 1
                self.issue_count = 1

            async def discover(
                self,
                target: Target,
                *,
                candidate_callback: object,
                collect: bool,
            ) -> list[PeerCandidate]:
                assert collect is False
                assert callable(candidate_callback)
                total = 306 if target.info_hash == first.info_hash else 305
                second_octet = 10 if target.info_hash == first.info_hash else 11
                candidates = [
                    PeerCandidate(
                        target_label=target.label,
                        info_hash_hex=target.info_hash_hex,
                        ip=f"8.{second_octet}.{index // 250}.{index % 250 + 1}",
                        port=10_000 + index,
                        discovered_at_utc="2026-10-20T12:00:00.000Z",
                        dht_node_ip="9.9.9.9",
                        dht_node_port=6881,
                        transaction_id_hex=f"{index:08x}",
                        response_sha256=f"{index + 1:064x}",
                    )
                    for index in range(total)
                ]
                for start in range(0, total, 5):
                    await candidate_callback(tuple(candidates[start : start + 5]))
                return []

        def recording_add(
            current_store: RunStore,
            candidates: object,
        ) -> int:
            materialized = tuple(candidates)
            persisted_batch_sizes.append(len(materialized))
            return original_add(current_store, materialized)

        monkeypatch.setattr(monitor_module, "resolve_bootstrap_nodes", fake_resolve)
        monkeypatch.setattr(monitor_module, "DHTCrawler", FakeCrawler)
        monkeypatch.setattr(monitor_module.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(monitor_module.asyncio, "sleep", fake_sleep)
        monkeypatch.setattr(RunStore, "add_candidates", recording_add)

        notices = await monitor_module._discover_candidates_to_store(
            config,
            store,
            tmp_path,
            runtimes,
            lambda _message: None,
        )

        metrics = store.metrics_by_hash((first.info_hash_hex, second.info_hash_hex))
        assert metrics[first.info_hash_hex].candidates == 306
        assert metrics[second.info_hash_hex].candidates == 305
        assert sum(item.candidates for item in metrics.values()) == 611
        assert persisted_batch_sizes
        assert all(1 <= size <= 5 for size in persisted_batch_sizes)
        assert 5 in persisted_batch_sizes
        assert 1 in persisted_batch_sizes
        assert len(set(node_ids)) == 1
        assert runtimes[first.info_hash_hex].dht_queries_started > 0
        assert runtimes[second.info_hash_hex].dht_queries_started > 0
        joined = " ".join(notices)
        assert "DNS-Fehler" in joined
        assert "secret-bootstrap" not in joined
        assert "9.9.9.9" not in joined

    asyncio.run(scenario())


def test_all_six_hundred_eleven_candidates_are_checked_in_persisted_five_batches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        first = Target("Ziel A", b"a" * 20)
        second = Target("Ziel B", b"b" * 20)
        config = AppConfig(
            targets=(first, second),
            peer=PeerSettings(retry_attempts=1, retry_backoff_seconds=0.0),
        )
        store = RunStore(tmp_path / "verify.sqlite3")
        candidates = [
            _candidate(
                first,
                ip=f"8.20.{index // 250}.{index % 250 + 1}",
                port=10_000 + index,
            )
            for index in range(306)
        ] + [
            _candidate(
                second,
                ip=f"8.21.{index // 250}.{index % 250 + 1}",
                port=20_000 + index,
            )
            for index in range(305)
        ]
        store.add_candidates(candidates)
        runtimes = {
            target.info_hash_hex: monitor_module._TargetRuntimeMetrics(target=target)
            for target in config.targets
        }
        calls: list[tuple[str, str, int]] = []
        persisted: list[int] = []
        active = 0
        peak = 0
        real_sleep = asyncio.sleep
        original_store = RunStore.store_handshake_batch

        class FakeVerifier:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def verify(
                self,
                candidate: PeerCandidate,
                _info_hash: bytes,
            ) -> HandshakeResult:
                nonlocal active, peak
                active += 1
                peak = max(peak, active)
                calls.append((candidate.info_hash_hex, candidate.ip, candidate.port))
                await real_sleep(0)
                active -= 1
                return _confirmed(candidate)

        def recording_store(
            current_store: RunStore,
            results: object,
        ) -> int:
            materialized = tuple(results)
            persisted.append(len(materialized))
            return original_store(current_store, materialized)

        monkeypatch.setattr(monitor_module, "PeerVerifier", FakeVerifier)
        monkeypatch.setattr(RunStore, "store_handshake_batch", recording_store)
        await monitor_module._verify_all_candidates(
            config,
            store,
            tmp_path,
            runtimes,
            lambda _message: None,
        )

        metrics = store.metrics_by_hash((first.info_hash_hex, second.info_hash_hex))
        assert len(calls) == 611
        assert len(set(calls)) == 611
        assert metrics[first.info_hash_hex].done == 306
        assert metrics[second.info_hash_hex].done == 305
        assert sum(item.offering_observed for item in metrics.values()) == 611
        assert all(size == 5 for size in persisted[:-1])
        assert persisted[-1] == 1
        assert peak == monitor_module.PARALLEL_VERIFY_BATCHES * 5

    asyncio.run(scenario())


def test_retries_keep_best_positive_early_eof_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        target = Target("Ziel", INFO_HASH)
        config = AppConfig(
            targets=(target,),
            peer=PeerSettings(retry_attempts=3, retry_backoff_seconds=0.0),
        )
        store = RunStore(tmp_path / "retry.sqlite3")
        first = _candidate(target, ip="8.8.8.8", port=6881)
        second = _candidate(target, ip="1.1.1.1", port=6882)
        store.add_candidates((first, second))
        runtime = monitor_module._TargetRuntimeMetrics(target=target)
        attempts: dict[str, int] = {first.ip: 0, second.ip: 0}

        class FakeVerifier:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def verify(
                self,
                candidate: PeerCandidate,
                _info_hash: bytes,
            ) -> HandshakeResult:
                attempts[candidate.ip] += 1
                if candidate == first and attempts[candidate.ip] == 3:
                    result = _confirmed(candidate)
                    assert result.availability is not None
                    observation = replace(
                        result.availability,
                        completed_full_window=False,
                        duration_seconds=2.0,
                        termination_reason="peer_closed",
                        error="Peer schloss nach den positiven Signalen.",
                    )
                    return replace(result, availability=observation)
                return monitor_module._failed_handshake(
                    candidate,
                    ConnectionRefusedError("abgelehnt"),
                )

        monkeypatch.setattr(monitor_module, "PeerVerifier", FakeVerifier)
        await monitor_module._verify_all_candidates(
            config,
            store,
            tmp_path,
            {target.info_hash_hex: runtime},
            lambda _message: None,
        )

        results = list(store.iter_handshake_results())
        positive = next(item for item in results if item.candidate == first)
        assert positive.offering_observed
        assert positive.availability is not None
        assert not positive.availability.completed_full_window
        assert attempts == {first.ip: 3, second.ip: 3}
        assert runtime.verification_attempts == 6
        metric = store.metrics_by_hash((target.info_hash_hex,))[target.info_hash_hex]
        assert metric.offering_observed == 1
        assert metric.terminal_failures == 1

    asyncio.run(scenario())


def test_unexpected_verifier_bug_propagates_and_requeues_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        target = Target("Ziel", INFO_HASH)
        config = AppConfig(
            targets=(target,),
            peer=PeerSettings(retry_attempts=1, retry_backoff_seconds=0.0),
        )
        store = RunStore(tmp_path / "bug.sqlite3")
        store.add_candidates((_candidate(target),))
        runtime = monitor_module._TargetRuntimeMetrics(target=target)

        class BrokenVerifier:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def verify(self, *_args: object) -> HandshakeResult:
                raise AssertionError("programming bug")

        monkeypatch.setattr(monitor_module, "PeerVerifier", BrokenVerifier)
        with pytest.raises(AssertionError, match="programming bug"):
            await monitor_module._verify_all_candidates(
                config,
                store,
                tmp_path,
                {target.info_hash_hex: runtime},
                lambda _message: None,
            )
        metric = store.metrics_by_hash((target.info_hash_hex,))[target.info_hash_hex]
        assert metric.pending == 1
        assert metric.in_progress == 0
        assert metric.done == 0

    asyncio.run(scenario())


def test_external_enrichment_processes_every_positive_in_five_batches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bittorrent_beobachter.evidence import EvidenceJournal
    from bittorrent_beobachter.run_store import RunStore

    target = Target("Ziel", INFO_HASH)
    config = AppConfig(
        targets=(target,),
        enrichment=EnrichmentSettings(enabled=True),
    )
    store = RunStore(tmp_path / "enrich.sqlite3")
    candidates = [
        _candidate(
            target,
            ip=f"8.30.{index // 250}.{index % 250 + 1}",
            port=10_000 + index,
        )
        for index in range(26)
    ]
    store.add_candidates(candidates)
    hashes = (target.info_hash_hex,)
    while batch := store.claim_candidate_batch(hashes, size=5):
        store.store_handshake_batch(_confirmed(candidate) for candidate in batch)

    calls: list[str] = []
    persisted: list[int] = []
    original_store = RunStore.store_evidence_batch

    class FakeEnricher:
        def __init__(self, _cache_dir: Path, **_kwargs: object) -> None:
            pass

        def enrich(self, ip: str) -> NetworkEnrichment:
            calls.append(ip)
            return NetworkEnrichment(ip=ip, enriched_at_utc="2026-10-20T12:02:00.000Z")

    def recording_store(current_store: RunStore, records: object) -> int:
        materialized = tuple(records)
        persisted.append(len(materialized))
        return original_store(current_store, materialized)

    monkeypatch.setattr(monitor_module, "NetworkEnricher", FakeEnricher)
    monkeypatch.setattr(RunStore, "store_evidence_batch", recording_store)
    journal = EvidenceJournal(tmp_path / "events.jsonl")
    result = ScanResult(
        run_id="all-enrichment",
        started_at_utc="2026-10-20T12:00:00.000Z",
        run_store_path=store.path,
    )

    known_vpn = monitor_module._persist_all_evidence(
        config,
        tmp_path,
        store,
        journal,
        result,
        lambda _message: None,
        config_sha256="a" * 64,
        software_sha256="b" * 64,
    )

    assert known_vpn == 0
    assert len(calls) == 26
    assert store.evidence_count() == 26
    assert persisted == [5, 5, 5, 5, 5, 1]
    assert result.notices == []


def test_monitor_exposes_no_global_count_or_time_caps() -> None:
    assert not hasattr(monitor_module, "MAX_CANDIDATES_PER_RUN")
    assert not hasattr(monitor_module, "MAX_EXTERNAL_ENRICHMENTS_PER_RUN")
    assert not hasattr(monitor_module, "NETWORK_PHASE_TIMEOUT_SECONDS")
    assert not hasattr(PeerSettings(), "max_checks")
    assert not hasattr(DhtSettings(), "max_candidates")


def test_long_first_round_with_finding_requires_a_zero_followup_round(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        target = Target("Ziel", INFO_HASH)
        config = AppConfig(
            targets=(target,),
            dht=DhtSettings(
                timeout_seconds=0.25,
                overall_timeout_seconds=1.0,
                concurrency=1,
                quiet_seconds=1.0,
                refresh_interval_seconds=0.1,
                bootstrap_nodes=(("bootstrap.invalid", 6881),),
            ),
        )
        store = RunStore(tmp_path / "quiet.sqlite3")
        runtime = monitor_module._TargetRuntimeMetrics(target=target)
        clock = [0.0]
        rounds = [0]
        real_sleep = asyncio.sleep

        async def fake_sleep(delay: float) -> None:
            clock[0] += delay
            await real_sleep(0)

        class FakeCrawler:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                self.queries_started = 1
                self.queries_completed = 1
                self.queries_failed = 0
                self.issue_count = 0

            async def discover(
                self,
                current_target: Target,
                *,
                candidate_callback: object,
                collect: bool,
            ) -> list[PeerCandidate]:
                assert collect is False
                assert callable(candidate_callback)
                rounds[0] += 1
                if rounds[0] == 1:
                    await candidate_callback((_candidate(current_target),))
                    clock[0] += 5.0
                else:
                    clock[0] += 1.1
                return []

        monkeypatch.setattr(monitor_module, "DHTCrawler", FakeCrawler)
        monkeypatch.setattr(monitor_module.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(monitor_module.asyncio, "sleep", fake_sleep)
        await monitor_module._discover_target_until_quiet(
            config,
            target,
            (("9.9.9.9", 6881),),
            b"n" * 20,
            store,
            runtime,
            tmp_path,
            [],
            lambda _message: None,
        )

        assert rounds[0] == 2
        assert store.metrics_by_hash((target.info_hash_hex,))[target.info_hash_hex].candidates == 1

    asyncio.run(scenario())


def test_network_phase_checks_fresh_candidate_before_discovery_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        target = Target("Ziel", INFO_HASH)
        config = AppConfig(
            targets=(target,),
            peer=PeerSettings(retry_attempts=1, retry_backoff_seconds=0.0),
        )
        store = RunStore(tmp_path / "pipeline.sqlite3")
        runtime = monitor_module._TargetRuntimeMetrics(target=target)
        verifier_called = asyncio.Event()
        discovery_finished = False

        async def fake_discovery(
            _config: AppConfig,
            current_store: RunStore,
            _data_dir: Path,
            _runtimes: object,
            _progress: object,
        ) -> list[str]:
            nonlocal discovery_finished
            current_store.add_candidates((_candidate(target),))
            await asyncio.wait_for(verifier_called.wait(), timeout=1.0)
            assert not discovery_finished
            discovery_finished = True
            return []

        class FakeVerifier:
            def __init__(self, **_kwargs: object) -> None:
                pass

            async def verify(
                self,
                candidate: PeerCandidate,
                _info_hash: bytes,
            ) -> HandshakeResult:
                assert not discovery_finished
                verifier_called.set()
                return _confirmed(candidate)

        monkeypatch.setattr(
            monitor_module,
            "_discover_candidates_to_store",
            fake_discovery,
        )
        monkeypatch.setattr(monitor_module, "PeerVerifier", FakeVerifier)
        notices = await monitor_module._network_phase(
            config,
            store,
            tmp_path,
            {target.info_hash_hex: runtime},
            lambda _message: None,
        )

        assert notices == []
        assert discovery_finished
        metric = store.metrics_by_hash((target.info_hash_hex,))[target.info_hash_hex]
        assert metric.done == 1
        assert metric.offering_observed == 1

    asyncio.run(scenario())


def test_network_phase_cancels_discovery_and_verification_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bittorrent_beobachter.run_store import RunStore

    async def scenario() -> None:
        target = Target("Ziel", INFO_HASH)
        config = AppConfig(targets=(target,))
        store = RunStore(tmp_path / "cancel.sqlite3")
        stopped: list[str] = []

        async def wait_forever(*_args: object, **_kwargs: object) -> list[str]:
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append("discovery")
            return []

        async def verify_forever(*_args: object, **_kwargs: object) -> None:
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append("verification")

        monkeypatch.setattr(monitor_module, "_discover_candidates_to_store", wait_forever)
        monkeypatch.setattr(monitor_module, "_verify_all_candidates", verify_forever)
        cancel_event = monitor_module.Event()
        task = asyncio.create_task(
            monitor_module._network_phase(
                config,
                store,
                tmp_path,
                {target.info_hash_hex: monitor_module._TargetRuntimeMetrics(target=target)},
                lambda _message: None,
                cancel_event=cancel_event,
            )
        )
        await asyncio.sleep(0)
        cancel_event.set()

        with pytest.raises(monitor_module.ScanCancelled):
            await asyncio.wait_for(task, timeout=1.0)
        assert sorted(stopped) == ["discovery", "verification"]

    asyncio.run(scenario())
