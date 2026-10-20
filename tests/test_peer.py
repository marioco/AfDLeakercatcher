"""Offline-Tests für den auf einen Handshake begrenzten TCP-Prüfer."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import bittorrent_beobachter.peer as peer_module
from bittorrent_beobachter.models import PeerCandidate
from bittorrent_beobachter.peer import (
    HANDSHAKE_LENGTH,
    PROTOCOL_NAME,
    PeerHandshakeError,
    PeerVerifier,
    build_handshake,
    parse_handshake_response,
)

INFO_HASH = b"h" * 20
LOCAL_PEER_ID = b"-TEST00-123456789012"
REMOTE_PEER_ID = b"-REMOTE-123456789012"


def candidate(ip: str = "8.8.8.8", info_hash_hex: str = INFO_HASH.hex()) -> PeerCandidate:
    return PeerCandidate(
        target_label="Test",
        info_hash_hex=info_hash_hex,
        ip=ip,
        port=6881,
        discovered_at_utc="2026-10-20T12:00:00.000Z",
        dht_node_ip="1.1.1.1",
        dht_node_port=6881,
        transaction_id_hex="0102",
        response_sha256="a" * 64,
    )


class PeerHandshakeTests(unittest.TestCase):
    def test_outgoing_handshake_is_exactly_standard_and_featureless(self) -> None:
        handshake = build_handshake(INFO_HASH, LOCAL_PEER_ID)

        self.assertEqual(len(handshake), HANDSHAKE_LENGTH)
        self.assertEqual(handshake[0], 19)
        self.assertEqual(handshake[1:20], PROTOCOL_NAME)
        self.assertEqual(handshake[20:28], b"\x00" * 8)
        self.assertEqual(handshake[28:48], INFO_HASH)
        self.assertEqual(handshake[48:68], LOCAL_PEER_ID)

    def test_response_requires_exact_length_protocol_and_same_hash(self) -> None:
        response = build_handshake(INFO_HASH, REMOTE_PEER_ID)

        reserved, peer_id = parse_handshake_response(response, expected_info_hash=INFO_HASH)

        self.assertEqual(reserved, b"\x00" * 8)
        self.assertEqual(peer_id, REMOTE_PEER_ID)
        with self.assertRaises(PeerHandshakeError):
            parse_handshake_response(response[:-1], expected_info_hash=INFO_HASH)
        with self.assertRaises(PeerHandshakeError):
            parse_handshake_response(response, expected_info_hash=b"x" * 20)


class PeerVerifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_verifier_reports_a_matching_68_byte_exchange(self) -> None:
        verifier = PeerVerifier(peer_id=LOCAL_PEER_ID, timeout=1.0)
        sent: list[bytes] = []

        async def exchange(endpoint, outgoing, state):  # type: ignore[no-untyped-def]
            self.assertEqual(endpoint, ("8.8.8.8", 6881))
            sent.append(outgoing)
            state.local_ip = "192.0.2.5"
            state.local_port = 40000
            state.bytes_sent = len(outgoing)
            state.bytes_received = HANDSHAKE_LENGTH
            return build_handshake(INFO_HASH, REMOTE_PEER_ID)

        verifier._exchange = exchange  # type: ignore[method-assign]

        result = await verifier.verify(candidate(), INFO_HASH)

        self.assertTrue(result.confirmed)
        self.assertEqual(sent, [build_handshake(INFO_HASH, LOCAL_PEER_ID)])
        self.assertEqual(result.bytes_sent, 68)
        self.assertEqual(result.bytes_received, 68)
        self.assertEqual(result.remote_peer_id_hex, REMOTE_PEER_ID.hex())
        self.assertEqual(result.local_ip, "192.0.2.5")

    async def test_verifier_refuses_non_global_or_mismatched_candidates(self) -> None:
        verifier = PeerVerifier(peer_id=LOCAL_PEER_ID)

        private_result = await verifier.verify(candidate(ip="127.0.0.1"), INFO_HASH)
        mismatch_result = await verifier.verify(
            candidate(info_hash_hex=(b"x" * 20).hex()), INFO_HASH
        )

        self.assertFalse(private_result.confirmed)
        self.assertEqual(private_result.bytes_sent, 0)
        self.assertIn("Nichtglobaler", private_result.error or "")
        self.assertFalse(mismatch_result.confirmed)
        self.assertEqual(mismatch_result.bytes_sent, 0)
        self.assertIn("Infohash", mismatch_result.error or "")

    async def test_wrong_response_hash_is_not_confirmed(self) -> None:
        verifier = PeerVerifier(peer_id=LOCAL_PEER_ID, timeout=1.0)

        async def exchange(_endpoint, outgoing, state):  # type: ignore[no-untyped-def]
            state.bytes_sent = len(outgoing)
            state.bytes_received = HANDSHAKE_LENGTH
            return build_handshake(b"x" * 20, REMOTE_PEER_ID)

        verifier._exchange = exchange  # type: ignore[method-assign]

        result = await verifier.verify(candidate(), INFO_HASH)

        self.assertFalse(result.confirmed)
        self.assertEqual(result.bytes_received, 68)
        self.assertIn("anderen Infohash", result.error or "")

    async def test_transport_sends_once_reads_at_most_68_and_closes(self) -> None:
        outgoing = build_handshake(INFO_HASH, LOCAL_PEER_ID)
        incoming = build_handshake(INFO_HASH, REMOTE_PEER_ID)

        class FakeSocket:
            def __init__(self) -> None:
                self.closed = False
                self.blocking: bool | None = None

            def setblocking(self, value: bool) -> None:
                self.blocking = value

            def getsockname(self) -> tuple[str, int]:
                return "192.0.2.5", 40_000

            def close(self) -> None:
                self.closed = True

        class FakeLoop:
            def __init__(self) -> None:
                self.sent: list[bytes] = []
                self.receive_sizes: list[int] = []
                self.chunks = [incoming[:17], incoming[17:]]

            async def sock_connect(
                self,
                _socket: object,
                address: tuple[object, ...],
            ) -> None:
                self.test_address = address

            async def sock_sendall(self, _socket: object, payload: bytes) -> None:
                self.sent.append(payload)

            async def sock_recv(self, _socket: object, maximum: int) -> bytes:
                self.receive_sizes.append(maximum)
                chunk = self.chunks.pop(0)
                if len(chunk) > maximum:
                    raise AssertionError("Test-Chunk überschreitet angeforderte Größe.")
                return chunk

        fake_socket = FakeSocket()
        fake_loop = FakeLoop()
        verifier = PeerVerifier(peer_id=LOCAL_PEER_ID, timeout=1.0)
        state = peer_module._ExchangeState()
        with (
            patch.object(peer_module.socket, "socket", return_value=fake_socket),
            patch.object(
                peer_module.asyncio,
                "get_running_loop",
                return_value=fake_loop,
            ),
        ):
            received = await verifier._exchange(("8.8.8.8", 6881), outgoing, state)

        self.assertEqual(received, incoming)
        self.assertEqual(fake_loop.sent, [outgoing])
        self.assertEqual(fake_loop.receive_sizes, [68, 51])
        self.assertEqual(state.bytes_sent, 68)
        self.assertEqual(state.bytes_received, 68)
        self.assertFalse(fake_socket.blocking)
        self.assertTrue(fake_socket.closed)


if __name__ == "__main__":
    unittest.main()
