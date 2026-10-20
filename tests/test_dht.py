"""Offline-Tests für die begrenzte BEP-5/BEP-32-Implementierung."""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bittorrent_beobachter.dht as dht_module
from bittorrent_beobachter.bencode import bdecode, bencode
from bittorrent_beobachter.dht import (
    DHTConfig,
    DHTCrawler,
    DHTNode,
    DHTProtocolError,
    DHTResponse,
    build_get_peers_query,
    is_global_endpoint,
    parse_compact_nodes,
    parse_compact_peers,
    parse_get_peers_response,
    resolve_bootstrap_nodes,
)
from bittorrent_beobachter.models import PeerCandidate, Target


def compact_ipv4(ip: str, port: int) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip) + port.to_bytes(2, "big")


def compact_ipv6(ip: str, port: int) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip) + port.to_bytes(2, "big")


class DHTParsingTests(unittest.TestCase):
    def test_get_peers_query_has_only_the_passive_operation(self) -> None:
        query = build_get_peers_query(b"n" * 20, b"h" * 20, b"tx")

        decoded = bdecode(query)
        self.assertEqual(decoded[b"q"], b"get_peers")
        self.assertEqual(decoded[b"a"][b"info_hash"], b"h" * 20)
        self.assertEqual(decoded[b"a"][b"want"], [b"n4", b"n6"])
        self.assertNotIn(b"announce_peer", query)

    def test_compact_peer_parser_supports_ipv4_and_ipv6(self) -> None:
        values = [
            compact_ipv4("8.8.8.8", 51413),
            compact_ipv6("2606:4700:4700::1111", 6881),
            compact_ipv4("192.168.1.1", 6881),
        ]

        peers = parse_compact_peers(values)

        self.assertEqual(
            peers,
            (("8.8.8.8", 51413), ("2606:4700:4700::1111", 6881)),
        )

    def test_compact_node_parser_supports_bep32_and_filters_private(self) -> None:
        public_id = bytes(range(20))
        private_id = b"p" * 20
        nodes4 = (
            public_id + compact_ipv4("1.1.1.1", 6881) + private_id + compact_ipv4("10.0.0.1", 6881)
        )
        nodes6 = public_id + compact_ipv6("2606:4700:4700::1111", 6881)

        self.assertEqual(
            parse_compact_nodes(nodes4),
            (DHTNode(public_id, "1.1.1.1", 6881),),
        )
        self.assertEqual(
            parse_compact_nodes(nodes6, ipv6=True),
            (DHTNode(public_id, "2606:4700:4700::1111", 6881),),
        )
        with self.assertRaises(DHTProtocolError):
            parse_compact_nodes(b"too short")
        with self.assertRaises(DHTProtocolError):
            parse_compact_peers([b"wrong"])

    def test_response_validation_captures_source_transaction_and_hash(self) -> None:
        packet = bencode(
            {
                b"r": {
                    b"id": b"r" * 20,
                    b"values": [compact_ipv4("8.8.4.4", 6881)],
                },
                b"t": b"aa",
                b"y": b"r",
            }
        )

        response = parse_get_peers_response(
            packet,
            expected_transaction_id=b"aa",
            source=("1.1.1.1", 6881),
        )

        self.assertEqual(response.source, ("1.1.1.1", 6881))
        self.assertEqual(response.transaction_id, b"aa")
        self.assertEqual(response.peers, (("8.8.4.4", 6881),))
        self.assertEqual(response.response_sha256, hashlib.sha256(packet).hexdigest())
        with self.assertRaises(DHTProtocolError):
            parse_get_peers_response(
                packet,
                expected_transaction_id=b"bb",
                source=("1.1.1.1", 6881),
            )

    def test_only_global_numeric_endpoints_are_accepted(self) -> None:
        self.assertTrue(is_global_endpoint("8.8.8.8", 6881))
        self.assertTrue(is_global_endpoint("2606:4700:4700::1111", 6881))
        self.assertFalse(is_global_endpoint("127.0.0.1", 6881))
        self.assertFalse(is_global_endpoint("192.168.0.1", 6881))
        self.assertFalse(is_global_endpoint("example.com", 6881))
        self.assertFalse(is_global_endpoint("8.8.8.8", 0))

    def test_configuration_keeps_only_operational_safety_bounds(self) -> None:
        config = DHTConfig()

        self.assertFalse(hasattr(config, "max_queries"))
        self.assertFalse(hasattr(config, "max_nodes"))
        self.assertFalse(hasattr(config, "max_candidates"))
        with self.assertRaises(ValueError):
            DHTConfig(concurrency=33)
        with self.assertRaises(ValueError):
            DHTConfig(timeout_seconds=31.0)
        with self.assertRaises(ValueError):
            DHTConfig(overall_timeout_seconds=301.0)


class DHTCrawlerTests(unittest.IsolatedAsyncioTestCase):
    async def test_disk_frontier_is_private_deduplicated_and_removed_after_close(
        self,
    ) -> None:
        frontier = dht_module._DHTNodeFrontier()
        database_path = frontier.database_path
        directory = database_path.parent
        try:
            self.assertTrue(database_path.is_file())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(database_path.stat().st_mode), 0o600)

            bootstrap = ("8.8.8.8", 6881)
            discovered = DHTNode(b"d" * 20, "1.1.1.1", 6881)
            frontier.add_bootstrap_nodes((bootstrap, bootstrap))
            frontier.add_discovered_nodes(
                (
                    discovered,
                    discovered,
                    DHTNode(b"p" * 20, "192.168.1.1", 6881),
                ),
                int.from_bytes(b"h" * 20, "big"),
            )

            self.assertEqual(frontier.claim(10), (bootstrap, discovered.endpoint))
            self.assertEqual(frontier.claim(10), ())
        finally:
            frontier.close()

        self.assertFalse(directory.exists())
        frontier.close()

    async def test_frontier_uses_configured_volume_and_stops_at_disk_reserve(self) -> None:
        checked_paths: list[Path] = []

        class LowDiskUsage:
            free = dht_module.DHT_MIN_FREE_SPACE_BYTES - 1

        def low_disk_usage(path: str | os.PathLike[str]) -> LowDiskUsage:
            checked_paths.append(Path(path))
            return LowDiskUsage()

        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            crawler = DHTCrawler(
                [("8.8.8.8", 6881)],
                frontier_directory=root,
            )
            with (
                patch.object(dht_module.shutil, "disk_usage", low_disk_usage),
                self.assertRaisesRegex(
                    dht_module.DHTFrontierStorageError,
                    "Weniger als 100 MB",
                ),
            ):
                await crawler.discover(Target("Test", b"h" * 20))

            self.assertTrue(checked_paths)
            self.assertEqual(checked_paths[0].parent, root)
            self.assertEqual(tuple(root.iterdir()), ())
            self.assertFalse(crawler.has_pending_work)

    async def test_frontier_directory_must_exist(self) -> None:
        with self.assertRaisesRegex(ValueError, "vorhandenes Verzeichnis"):
            DHTCrawler(
                [("8.8.8.8", 6881)],
                frontier_directory=Path("definitely-missing-frontier-directory"),
            )

    async def test_numeric_bootstrap_resolution_needs_no_network(self) -> None:
        resolved = await resolve_bootstrap_nodes(
            [("8.8.8.8", 6881), ("2606:4700:4700::1111", 6881)]
        )

        self.assertEqual(
            resolved,
            [("8.8.8.8", 6881), ("2606:4700:4700::1111", 6881)],
        )

    async def test_bootstrap_timeout_keeps_fast_dns_results(self) -> None:
        hanging_cancelled = asyncio.Event()

        async def fake_getaddrinfo(
            host: str,
            port: int,
            **_kwargs: object,
        ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            if host == "fast.example":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_DGRAM,
                        socket.IPPROTO_UDP,
                        "",
                        ("8.8.8.8", port),
                    )
                ]
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                hanging_cancelled.set()
                raise
            raise AssertionError("Hängender Resolver darf nicht normal zurückkehren")

        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", new=fake_getaddrinfo):
            resolved = await resolve_bootstrap_nodes(
                [("fast.example", 6881), ("hanging.example", 6881)],
                timeout=0.1,
            )

        self.assertEqual(resolved, [("8.8.8.8", 6881)])
        self.assertTrue(hanging_cancelled.is_set())

    async def test_bootstrap_resolution_and_crawler_accept_more_than_sixty_four_addresses(
        self,
    ) -> None:
        addresses = [
            (
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                "",
                (f"8.0.0.{index}", 6881),
            )
            for index in range(1, 71)
        ]
        addresses.append(addresses[-1])

        async def fake_getaddrinfo(
            _host: str,
            _port: int,
            **_kwargs: object,
        ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            return addresses

        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", new=fake_getaddrinfo):
            resolved = await resolve_bootstrap_nodes([("many.example", 6881)])

        self.assertEqual(len(resolved), 70)
        crawler = DHTCrawler(resolved)
        self.assertEqual(len(crawler.bootstrap_nodes), 70)

    async def test_crawler_iterates_returned_nodes_and_builds_candidates(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        second = ("1.1.1.1", 6881)
        calls: list[tuple[str, int]] = []

        async def query(
            endpoint: tuple[str, int], info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            self.assertEqual(info_hash, b"h" * 20)
            calls.append(endpoint)
            if endpoint == bootstrap:
                return DHTResponse(
                    source=bootstrap,
                    transaction_id=transaction_id,
                    nodes=(DHTNode(b"n" * 20, *second),),
                    peers=(("8.8.4.4", 51413),),
                    response_sha256="a" * 64,
                )
            return DHTResponse(
                source=second,
                transaction_id=transaction_id,
                nodes=(),
                peers=(("2606:4700:4700::1111", 6881),),
                response_sha256="b" * 64,
            )

        crawler = DHTCrawler(
            [bootstrap],
            node_id=b"l" * 20,
            config=DHTConfig(concurrency=1),
            query_hook=query,
            transaction_id_factory=lambda: b"tx",
            clock=lambda: "2026-10-20T12:00:00.000Z",
        )

        candidates = await crawler.discover(Target("Test", b"h" * 20))

        self.assertEqual(calls, [bootstrap, second])
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].dht_node_ip, bootstrap[0])
        self.assertEqual(candidates[0].transaction_id_hex, "7478")
        self.assertEqual(candidates[0].response_sha256, "a" * 64)
        self.assertEqual(candidates[1].ip, "2606:4700:4700::1111")
        self.assertEqual(crawler.queries_started, 2)
        self.assertEqual(crawler.queries_completed, 2)

    async def test_crawler_queries_every_node_in_a_wide_front(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        nodes = tuple(
            DHTNode(index.to_bytes(20, "big"), "1.1.1.1", 10_000 + index) for index in range(192)
        )
        calls: list[tuple[str, int]] = []

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            calls.append(endpoint)
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=nodes if endpoint == bootstrap else (),
                peers=(),
                response_sha256="c" * 64,
            )

        crawler = DHTCrawler([bootstrap], query_hook=query)

        self.assertEqual(await crawler.discover(Target("Test", bytes(20))), [])
        self.assertEqual(len(calls), 193)
        self.assertEqual(
            set(calls[1:]),
            {("1.1.1.1", 10_000 + index) for index in range(192)},
        )

    async def test_disk_frontier_keeps_wide_branched_graph_bounded_without_loss(
        self,
    ) -> None:
        bootstrap = ("8.8.8.8", 6881)
        width = 384
        concurrency = 7
        calls: list[tuple[str, int]] = []
        claim_sizes: list[int] = []
        claim_limits: list[int] = []
        active_queries = 0
        peak_active_queries = 0

        def endpoint_for(second_octet: int, index: int) -> tuple[str, int]:
            return (
                f"8.{second_octet}.{index // 250}.{index % 250 + 1}",
                6881,
            )

        first_level = tuple(
            DHTNode(
                (index + 1).to_bytes(20, "big"),
                *endpoint_for(20, index),
            )
            for index in range(width)
        )

        async def query(
            endpoint: tuple[str, int],
            _info_hash: bytes,
            transaction_id: bytes,
        ) -> DHTResponse:
            nonlocal active_queries, peak_active_queries
            active_queries += 1
            peak_active_queries = max(peak_active_queries, active_queries)
            calls.append(endpoint)
            try:
                await asyncio.sleep(0)
                nodes: tuple[DHTNode, ...] = ()
                if endpoint == bootstrap:
                    nodes = (*first_level, first_level[0])
                elif endpoint[0].startswith("8.20."):
                    octets = tuple(int(part) for part in endpoint[0].split("."))
                    index = octets[2] * 250 + octets[3] - 1
                    child = endpoint_for(21, index)
                    nodes = (
                        DHTNode(
                            (width + index + 1).to_bytes(20, "big"),
                            *child,
                        ),
                    )
                return DHTResponse(
                    source=endpoint,
                    transaction_id=transaction_id,
                    nodes=nodes,
                    peers=(),
                    response_sha256="f" * 64,
                )
            finally:
                active_queries -= 1

        original_claim = dht_module._DHTNodeFrontier.claim

        def recording_claim(
            frontier: dht_module._DHTNodeFrontier,
            size: int,
        ) -> tuple[tuple[str, int], ...]:
            claimed = original_claim(frontier, size)
            claim_limits.append(size)
            claim_sizes.append(len(claimed))
            return claimed

        crawler = DHTCrawler(
            [bootstrap],
            config=DHTConfig(
                timeout_seconds=1.0,
                overall_timeout_seconds=10.0,
                concurrency=concurrency,
            ),
            query_hook=query,
        )
        with patch.object(dht_module._DHTNodeFrontier, "claim", new=recording_claim):
            self.assertEqual(await crawler.discover(Target("Test", bytes(20))), [])

        expected = {bootstrap}
        expected.update(endpoint_for(20, index) for index in range(width))
        expected.update(endpoint_for(21, index) for index in range(width))
        self.assertEqual(len(calls), 1 + 2 * width)
        self.assertEqual(set(calls), expected)
        self.assertEqual(crawler.queries_started, len(expected))
        self.assertEqual(crawler.queries_completed, len(expected))
        self.assertEqual(peak_active_queries, concurrency)
        self.assertTrue(claim_sizes)
        self.assertTrue(
            all(
                size <= limit <= concurrency
                for size, limit in zip(claim_sizes, claim_limits, strict=True)
            )
        )

    async def test_cancellation_flushes_partial_candidate_batch_and_propagates(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        hanging = ("1.1.1.1", 6881)
        peers = tuple(("8.8.4.4", 10_000 + index) for index in range(3))
        query_started = asyncio.Event()
        batches: list[tuple[PeerCandidate, ...]] = []

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            if endpoint == hanging:
                query_started.set()
                await asyncio.Event().wait()
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=(DHTNode(b"n" * 20, *hanging),) if endpoint == bootstrap else (),
                peers=peers if endpoint == bootstrap else (),
                response_sha256="c" * 64,
            )

        async def persist(batch: tuple[PeerCandidate, ...]) -> None:
            batches.append(batch)

        crawler = DHTCrawler(
            [bootstrap],
            config=DHTConfig(timeout_seconds=5.0, overall_timeout_seconds=10.0),
            query_hook=query,
        )
        frontier_directories: list[Path] = []

        class RecordingFrontier(dht_module._DHTNodeFrontier):
            def __init__(self, parent_directory: Path | None = None) -> None:
                super().__init__(parent_directory)
                frontier_directories.append(self.database_path.parent)

        with patch.object(dht_module, "_DHTNodeFrontier", RecordingFrontier):
            task = asyncio.create_task(
                crawler.discover(
                    Target("Test", b"h" * 20),
                    candidate_callback=persist,
                    collect=False,
                )
            )
            await asyncio.wait_for(query_started.wait(), timeout=1.0)
            task.cancel()

            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertEqual(len(frontier_directories), 1)
        self.assertFalse(frontier_directories[0].exists())
        self.assertEqual([len(batch) for batch in batches], [3])
        self.assertEqual(crawler.queries_started, 2)
        self.assertEqual(crawler.queries_completed, 1)
        self.assertEqual(crawler.queries_failed, 0)

    async def test_unexpected_error_flushes_partial_batch_before_propagation(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        failing = ("1.1.1.1", 6881)
        peers = tuple(("8.8.4.4", 20_000 + index) for index in range(3))
        batches: list[tuple[PeerCandidate, ...]] = []

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            if endpoint == failing:
                raise AssertionError("programming bug")
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=(DHTNode(b"n" * 20, *failing),),
                peers=peers,
                response_sha256="c" * 64,
            )

        async def persist(batch: tuple[PeerCandidate, ...]) -> None:
            batches.append(batch)

        crawler = DHTCrawler([bootstrap], query_hook=query)
        with self.assertRaisesRegex(AssertionError, "programming bug"):
            await crawler.discover(
                Target("Test", b"h" * 20),
                candidate_callback=persist,
                collect=False,
            )

        self.assertEqual([len(batch) for batch in batches], [3])

    async def test_candidate_callback_streams_every_observation_in_five_item_batches(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        peers = tuple(("1.1.1.1", 10_000 + index) for index in range(12))
        batches: list[tuple[PeerCandidate, ...]] = []

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=(),
                peers=(*peers, peers[0]),
                response_sha256="c" * 64,
            )

        async def collect_batch(batch: tuple[PeerCandidate, ...]) -> None:
            batches.append(batch)

        crawler = DHTCrawler([bootstrap], query_hook=query)
        candidates = await crawler.discover(
            Target("Test", b"h" * 20),
            candidate_callback=collect_batch,
            collect=False,
        )

        self.assertEqual(candidates, [])
        self.assertEqual([len(batch) for batch in batches], [5, 5, 3])
        self.assertEqual(
            [(candidate.ip, candidate.port) for batch in batches for candidate in batch],
            [*peers, peers[0]],
        )

    async def test_candidate_collection_has_no_peer_count_cap(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        peers = tuple(("1.1.1.1", 10_000 + index) for index in range(307))

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=(),
                peers=(*peers, peers[0]),
                response_sha256="d" * 64,
            )

        crawler = DHTCrawler([bootstrap], query_hook=query)

        candidates = await crawler.discover(Target("Test", b"h" * 20))

        self.assertEqual(len(candidates), 307)

    async def test_converging_lookup_has_no_query_count_cap(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        target = Target("Test", bytes(20))
        chain_length = 520
        calls: list[tuple[str, int]] = []

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            calls.append(endpoint)
            step = 0 if endpoint == bootstrap else endpoint[1] - 9_999
            nodes = ()
            if step < chain_length:
                distance = chain_length - step
                nodes = (
                    DHTNode(
                        distance.to_bytes(20, "big"),
                        "1.1.1.1",
                        10_000 + step,
                    ),
                )
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=nodes,
                peers=(),
                response_sha256="e" * 64,
            )

        crawler = DHTCrawler(
            [bootstrap],
            config=DHTConfig(
                timeout_seconds=1.0,
                overall_timeout_seconds=5.0,
                concurrency=1,
            ),
            query_hook=query,
        )

        self.assertEqual(await crawler.discover(target), [])
        self.assertEqual(len(calls), chain_length + 1)
        self.assertEqual(crawler.queries_started, chain_length + 1)
        self.assertEqual(crawler.queries_completed, chain_length + 1)

    async def test_deadline_slice_resumes_deep_frontier_before_bootstrap_refresh(self) -> None:
        bootstrap = ("8.8.8.8", 6881)
        target = Target("Test", bytes(20))
        chain_length = 12
        calls: list[tuple[str, int]] = []
        refresh = False
        frontier_directories: list[Path] = []

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            calls.append(endpoint)
            await asyncio.sleep(0.03)
            nodes = ()
            if not refresh:
                step = 0 if endpoint == bootstrap else endpoint[1] - 9_999
                if step < chain_length:
                    distance = chain_length - step
                    nodes = (
                        DHTNode(
                            distance.to_bytes(20, "big"),
                            "1.1.1.1",
                            10_000 + step,
                        ),
                    )
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=nodes,
                peers=(),
                response_sha256="f" * 64,
            )

        class RecordingFrontier(dht_module._DHTNodeFrontier):
            def __init__(self, parent_directory: Path | None = None) -> None:
                super().__init__(parent_directory)
                frontier_directories.append(self.database_path.parent)

        crawler = DHTCrawler(
            [bootstrap],
            config=DHTConfig(
                timeout_seconds=1.0,
                overall_timeout_seconds=0.1,
                concurrency=1,
            ),
            query_hook=query,
        )

        slices = 0
        with patch.object(dht_module, "_DHTNodeFrontier", RecordingFrontier):
            while True:
                self.assertEqual(await crawler.discover(target), [])
                slices += 1
                if not crawler.has_pending_work:
                    break
                self.assertLess(slices, 30)

            self.assertGreater(slices, 1)
            self.assertEqual(set(calls), {bootstrap} | {("1.1.1.1", 10_000 + i) for i in range(12)})
            self.assertEqual(calls.count(bootstrap), 1)
            self.assertEqual(len(frontier_directories), 1)
            self.assertFalse(frontier_directories[0].exists())

            refresh = True
            self.assertEqual(await crawler.discover(target), [])

        self.assertEqual(calls.count(bootstrap), 2)
        self.assertEqual(len(frontier_directories), 2)
        self.assertFalse(crawler.has_pending_work)
        self.assertFalse(frontier_directories[1].exists())


if __name__ == "__main__":
    unittest.main()
