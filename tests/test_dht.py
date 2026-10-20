"""Offline-Tests für die begrenzte BEP-5/BEP-32-Implementierung."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import unittest
from unittest.mock import patch

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
from bittorrent_beobachter.models import Target


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

    def test_configuration_has_hard_upper_bounds(self) -> None:
        with self.assertRaises(ValueError):
            DHTConfig(max_queries=501)
        with self.assertRaises(ValueError):
            DHTConfig(concurrency=33)
        with self.assertRaises(ValueError):
            DHTConfig(timeout_seconds=31.0)


class DHTCrawlerTests(unittest.IsolatedAsyncioTestCase):
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
            config=DHTConfig(
                max_queries=2,
                concurrency=1,
                max_nodes=10,
                max_candidates=10,
            ),
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

    async def test_candidate_count_is_bounded(self) -> None:
        bootstrap = ("8.8.8.8", 6881)

        async def query(
            endpoint: tuple[str, int], _info_hash: bytes, transaction_id: bytes
        ) -> DHTResponse:
            return DHTResponse(
                source=endpoint,
                transaction_id=transaction_id,
                nodes=(),
                peers=(("1.1.1.1", 1), ("8.8.4.4", 2)),
                response_sha256="c" * 64,
            )

        crawler = DHTCrawler(
            [bootstrap],
            config=DHTConfig(max_candidates=1),
            query_hook=query,
        )

        candidates = await crawler.discover(Target("Test", b"h" * 20))

        self.assertEqual(len(candidates), 1)


if __name__ == "__main__":
    unittest.main()
