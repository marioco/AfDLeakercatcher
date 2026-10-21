"""Offline-Tests für die inhaltsfreie Peer-Verfügbarkeitsprüfung."""

from __future__ import annotations

import asyncio
import hashlib
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import bittorrent_beobachter.peer as peer_module
from bittorrent_beobachter.models import HandshakeResult, PeerCandidate, ScanResult
from bittorrent_beobachter.peer import (
    HANDSHAKE_LENGTH,
    INTERESTED_MESSAGE,
    MAX_OBSERVATION_MESSAGES,
    MAX_PEER_MESSAGE_LENGTH,
    PROTOCOL_NAME,
    PeerHandshakeError,
    PeerVerifier,
    build_handshake,
    parse_handshake_response,
)
from bittorrent_beobachter.run_store import RunStore

INFO_HASH = b"h" * 20
LOCAL_PEER_ID = b"-TEST00-123456789012"
REMOTE_PEER_ID = b"-REMOTE-123456789012"
TEST_OBSERVATION_SECONDS = 0.25


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


def peer_message(message_id: int, payload: bytes = b"") -> bytes:
    length = 1 + len(payload)
    return length.to_bytes(4, "big") + bytes((message_id,)) + payload


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
    def __init__(self, incoming: bytes, *, close_when_empty: bool) -> None:
        self.incoming = bytearray(incoming)
        self.close_when_empty = close_when_empty
        self.sent: list[bytes] = []
        self.receive_sizes: list[int] = []
        self.connected_to: tuple[object, ...] | None = None

    async def sock_connect(
        self,
        _socket: object,
        address: tuple[object, ...],
    ) -> None:
        self.connected_to = address

    async def sock_sendall(self, _socket: object, payload: bytes) -> None:
        self.sent.append(payload)

    async def sock_recv(self, _socket: object, maximum: int) -> bytes:
        self.receive_sizes.append(maximum)
        if self.incoming:
            size = min(maximum, len(self.incoming))
            chunk = bytes(self.incoming[:size])
            del self.incoming[:size]
            return chunk
        if self.close_when_empty:
            return b""
        await asyncio.sleep(3_600)
        raise AssertionError("Blockierter Testempfang wurde unerwartet fortgesetzt.")


async def run_verifier(
    incoming_after_handshake: bytes,
    *,
    close_when_empty: bool,
    remote_info_hash: bytes = INFO_HASH,
    observation_seconds: float = TEST_OBSERVATION_SECONDS,
) -> tuple[object, FakeSocket, FakeLoop]:
    incoming = build_handshake(remote_info_hash, REMOTE_PEER_ID) + incoming_after_handshake
    fake_socket = FakeSocket()
    fake_loop = FakeLoop(incoming, close_when_empty=close_when_empty)
    verifier = PeerVerifier(
        peer_id=LOCAL_PEER_ID,
        timeout=1.0,
        observation_seconds=observation_seconds,
    )
    with (
        patch.object(peer_module.socket, "socket", return_value=fake_socket),
        patch.object(peer_module.asyncio, "get_running_loop", return_value=fake_loop),
    ):
        result = await verifier.verify(candidate(), INFO_HASH)
    return result, fake_socket, fake_loop


def as_production_window(result: HandshakeResult) -> HandshakeResult:
    availability = result.availability
    assert availability is not None
    started_at = datetime.fromisoformat(availability.started_at_utc.replace("Z", "+00:00"))
    ended_at = (
        (started_at.astimezone(UTC) + timedelta(seconds=60))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    return replace(
        result,
        availability=replace(
            availability,
            ended_at_utc=ended_at,
            requested_duration_seconds=60.0,
            duration_seconds=60.0,
        ),
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
    async def test_full_window_records_availability_and_never_requests_data(self) -> None:
        bitfield = b"\xa0\x01"
        wire = (
            peer_message(1) + peer_message(5, bitfield) + peer_message(4, (23).to_bytes(4, "big"))
        )

        result, fake_socket, fake_loop = await run_verifier(
            wire,
            close_when_empty=False,
        )

        self.assertTrue(result.confirmed)
        production_result = as_production_window(result)
        self.assertTrue(production_result.offering_observed)
        self.assertEqual(
            fake_loop.sent,
            [build_handshake(INFO_HASH, LOCAL_PEER_ID), INTERESTED_MESSAGE],
        )
        self.assertEqual(result.bytes_sent, 73)
        self.assertEqual(result.remote_peer_id_hex, REMOTE_PEER_ID.hex())
        self.assertEqual(result.local_ip, "192.0.2.5")
        self.assertIsNotNone(result.availability)
        observation = result.availability
        assert observation is not None
        self.assertTrue(observation.completed_full_window)
        self.assertTrue(observation.interested_sent)
        self.assertTrue(observation.non_empty_bitfield)
        self.assertTrue(observation.have_announced)
        self.assertTrue(observation.piece_availability_announced)
        self.assertTrue(observation.unchoked)
        self.assertFalse(observation.peer_choking_at_end)
        self.assertGreater(observation.unchoked_duration_seconds, 0.0)
        self.assertEqual(observation.request_messages_sent, 0)
        self.assertEqual(observation.piece_payload_bytes_received, 0)
        self.assertEqual(observation.metadata_requests_sent, 0)
        self.assertEqual(observation.termination_reason, "duration_elapsed")
        bitfield_event = next(
            event for event in observation.control_events if event.kind == "bitfield"
        )
        self.assertEqual(bitfield_event.payload_sha256, hashlib.sha256(bitfield).hexdigest())
        self.assertEqual(bitfield_event.set_bits, 3)
        have_event = next(event for event in observation.control_events if event.kind == "have")
        self.assertEqual(have_event.piece_index, 23)
        scan_result = ScanResult(
            run_id="test-run",
            started_at_utc="2026-10-20T12:00:00Z",
            handshakes=[production_result],
        )
        self.assertEqual(scan_result.offering_count, 1)
        self.assertFalse(fake_socket.blocking)
        self.assertTrue(fake_socket.closed)

    async def test_event_storage_bound_does_not_stop_an_early_offer(self) -> None:
        have_messages = b"".join(peer_message(4, index.to_bytes(4, "big")) for index in range(513))
        wire = peer_message(1) + peer_message(5, b"\x80") + have_messages + peer_message(0)

        result, _fake_socket, fake_loop = await run_verifier(
            wire,
            close_when_empty=False,
            observation_seconds=0.5,
        )

        observation = result.availability
        assert observation is not None
        self.assertTrue(as_production_window(result).offering_observed)
        self.assertTrue(observation.completed_full_window)
        self.assertIsNone(observation.error)
        self.assertTrue(observation.peer_choking_at_end)
        self.assertEqual(observation.termination_reason, "duration_elapsed")
        self.assertEqual(observation.messages_received, 516)
        self.assertEqual(len(observation.control_events), peer_module.MAX_CONTROL_EVENTS)
        self.assertEqual(fake_loop.incoming, bytearray())

    async def test_event_storage_bound_preserves_an_offer_observed_after_it(self) -> None:
        wire = (
            b"\x00\x00\x00\x00" * 513
            + peer_message(1)
            + peer_message(4, (23).to_bytes(4, "big"))
            + peer_message(0)
        )

        result, _fake_socket, fake_loop = await run_verifier(
            wire,
            close_when_empty=False,
            observation_seconds=0.5,
        )

        observation = result.availability
        assert observation is not None
        self.assertTrue(as_production_window(result).offering_observed)
        self.assertTrue(observation.completed_full_window)
        self.assertIsNone(observation.error)
        self.assertTrue(observation.peer_choking_at_end)
        self.assertEqual(observation.termination_reason, "duration_elapsed")
        self.assertEqual(observation.messages_received, 516)
        self.assertEqual(len(observation.control_events), peer_module.MAX_CONTROL_EVENTS)
        self.assertEqual(
            [event.kind for event in observation.control_events[-2:]],
            ["unchoke", "have"],
        )
        self.assertEqual(fake_loop.incoming, bytearray())

    async def test_keepalive_flood_stops_at_bounded_message_limit(self) -> None:
        wire = b"\x00\x00\x00\x00" * (MAX_OBSERVATION_MESSAGES + 1)

        result, _fake_socket, fake_loop = await run_verifier(
            wire,
            close_when_empty=False,
            observation_seconds=1.0,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertFalse(observation.completed_full_window)
        self.assertEqual(observation.termination_reason, "message_limit")
        self.assertIn("Nachrichten", observation.error or "")
        self.assertEqual(observation.messages_received, MAX_OBSERVATION_MESSAGES + 1)
        self.assertEqual(len(observation.control_events), peer_module.MAX_CONTROL_EVENTS)
        self.assertEqual(fake_loop.incoming, bytearray())

    async def test_choke_timeline_records_end_state(self) -> None:
        wire = peer_message(1) + peer_message(0) + peer_message(5, b"\x80")

        result, _fake_socket, _fake_loop = await run_verifier(
            wire,
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertTrue(observation.unchoked)
        self.assertTrue(observation.peer_choking_at_end)
        self.assertEqual(
            [event.kind for event in observation.control_events],
            ["unchoke", "choke", "bitfield"],
        )

    async def test_repeated_bitfield_is_rejected_without_false_offer(self) -> None:
        second_bitfield = b"\x00"
        wire = peer_message(5, b"\x80") + peer_message(5, second_bitfield) + peer_message(1)

        result, _fake_socket, fake_loop = await run_verifier(
            wire,
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertTrue(result.confirmed)
        self.assertFalse(result.offering_observed)
        self.assertFalse(observation.completed_full_window)
        self.assertEqual(observation.termination_reason, "protocol_or_network_error")
        self.assertIn("mehr als eine BITFIELD", observation.error or "")
        self.assertEqual(
            [event.kind for event in observation.control_events],
            ["bitfield"],
        )
        self.assertEqual(fake_loop.incoming, bytearray(second_bitfield + peer_message(1)))

    async def test_terminal_partial_frames_remain_persistable_diagnostics(self) -> None:
        cases = (
            ("oversized", (MAX_PEER_MESSAGE_LENGTH + 1).to_bytes(4, "big")),
            ("malformed-have", peer_message(4, b"bad")),
            ("repeated-bitfield", peer_message(5, b"\x80") + peer_message(5, b"\x00")),
            ("incomplete-have", b"\x00\x00\x00\x05\x04\x00\x01"),
        )
        for label, wire in cases:
            with self.subTest(label=label):
                result, _fake_socket, _fake_loop = await run_verifier(
                    wire,
                    close_when_empty=True,
                )
                observation = result.availability
                assert observation is not None
                self.assertFalse(result.offering_observed)
                self.assertIsNotNone(observation.error)
                with tempfile.TemporaryDirectory() as temp_name:
                    store = RunStore(Path(temp_name) / "run.sqlite3")
                    self.assertEqual(store.add_candidates([result.candidate]), 1)
                    self.assertEqual(
                        store.claim_candidate_batch([result.candidate.info_hash_hex]),
                        [result.candidate],
                    )
                    self.assertEqual(store.store_handshake_batch([result]), 1)

    async def test_early_disconnect_preserves_signals_without_positive_gate(self) -> None:
        wire = peer_message(1) + peer_message(5, b"\x80")

        result, _fake_socket, _fake_loop = await run_verifier(
            wire,
            close_when_empty=True,
        )

        observation = result.availability
        assert observation is not None
        self.assertTrue(result.confirmed)
        self.assertFalse(result.offering_observed)
        self.assertFalse(observation.completed_full_window)
        self.assertTrue(observation.piece_availability_announced)
        self.assertTrue(observation.unchoked)
        self.assertEqual(observation.termination_reason, "peer_closed")

    async def test_forbidden_messages_are_rejected_without_reading_payload(self) -> None:
        forbidden = ((6, "request_rejected"), (7, "piece_rejected"))
        for message_id, event_kind in forbidden:
            with self.subTest(message_id=message_id):
                payload = b"must-not-be-read"
                wire = peer_message(1) + peer_message(5, b"\x80")
                header_and_id = (1 + len(payload)).to_bytes(4, "big") + bytes((message_id,))
                result, _fake_socket, fake_loop = await run_verifier(
                    wire + header_and_id + payload,
                    close_when_empty=False,
                )

                observation = result.availability
                assert observation is not None
                self.assertFalse(result.offering_observed)
                self.assertIsNotNone(observation.error)
                self.assertEqual(observation.piece_payload_bytes_received, 0)
                self.assertEqual(fake_loop.incoming, bytearray(payload))
                self.assertEqual(observation.control_events[-1].kind, event_kind)

    async def test_supported_control_extensions_are_consumed_without_requests(self) -> None:
        extension_payload = b"\x00" + (b"x" * (peer_module.RECEIVE_CHUNK_BYTES * 2 + 7))
        rejected_request = (
            (23).to_bytes(4, "big") + (16_384).to_bytes(4, "big") + (16_384).to_bytes(4, "big")
        )
        wire = b"".join(
            (
                peer_message(1),
                peer_message(9, (6881).to_bytes(2, "big")),
                peer_message(13, (11).to_bytes(4, "big")),
                peer_message(14),
                peer_message(15),
                peer_message(16, rejected_request),
                peer_message(17, (17).to_bytes(4, "big")),
                peer_message(20, extension_payload),
            )
        )

        result, _fake_socket, fake_loop = await run_verifier(
            wire,
            close_when_empty=True,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertFalse(observation.completed_full_window)
        self.assertEqual(observation.request_messages_sent, 0)
        self.assertEqual(observation.piece_payload_bytes_received, 0)
        self.assertEqual(observation.metadata_requests_sent, 0)
        self.assertEqual(fake_loop.incoming, bytearray())
        self.assertLessEqual(max(fake_loop.receive_sizes), peer_module.RECEIVE_CHUNK_BYTES)
        self.assertEqual(
            [event.kind for event in observation.control_events],
            [
                "unchoke",
                "port",
                "suggest_piece",
                "have_all",
                "have_none",
                "reject_request",
                "allowed_fast",
                "extension_handshake",
            ],
        )
        extension_event = observation.control_events[-1]
        self.assertEqual(extension_event.payload_length, len(extension_payload))
        self.assertEqual(
            extension_event.payload_sha256,
            hashlib.sha256(extension_payload).hexdigest(),
        )

    async def test_unsolicited_extended_payload_is_not_read(self) -> None:
        metadata_payload = b"torrent-metadata-must-remain-unread"
        extended_payload = b"\x03" + metadata_payload
        wire = peer_message(1) + peer_message(5, b"\x80")
        header_and_ids = len(extended_payload + b"\x14").to_bytes(4, "big") + b"\x14\x03"

        result, _fake_socket, fake_loop = await run_verifier(
            wire + header_and_ids + metadata_payload,
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertEqual(observation.metadata_requests_sent, 0)
        self.assertEqual(observation.piece_payload_bytes_received, 0)
        self.assertEqual(fake_loop.incoming, bytearray(metadata_payload))
        self.assertEqual(
            observation.control_events[-1].kind,
            "extension_payload_rejected",
        )

    async def test_have_none_alone_does_not_claim_piece_availability(self) -> None:
        result, _fake_socket, _fake_loop = await run_verifier(
            peer_message(1) + peer_message(15),
            close_when_empty=True,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertFalse(observation.piece_availability_announced)
        self.assertEqual(
            [event.kind for event in observation.control_events],
            ["unchoke", "have_none"],
        )

    async def test_have_none_clears_prior_piece_state_before_unchoke(self) -> None:
        result, _fake_socket, _fake_loop = await run_verifier(
            peer_message(4, (1).to_bytes(4, "big")) + peer_message(15) + peer_message(1),
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertTrue(observation.completed_full_window)
        self.assertIsNone(observation.error)
        self.assertFalse(result.offering_observed)
        self.assertEqual(
            [event.kind for event in observation.control_events],
            ["have", "have_none", "unchoke"],
        )

    async def test_empty_bitfield_clears_prior_piece_state_before_unchoke(self) -> None:
        result, _fake_socket, _fake_loop = await run_verifier(
            peer_message(4, (1).to_bytes(4, "big")) + peer_message(5, b"\x00") + peer_message(1),
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertTrue(observation.completed_full_window)
        self.assertIsNone(observation.error)
        self.assertFalse(result.offering_observed)
        self.assertEqual(
            [event.kind for event in observation.control_events],
            ["have", "bitfield", "unchoke"],
        )

    async def test_malformed_supported_control_frames_stop_before_payload(self) -> None:
        malformed_messages = (
            (9, b"bad"),
            (13, b"bad"),
            (14, b"bad"),
            (15, b"bad"),
            (16, b"bad"),
            (17, b"bad"),
        )
        for message_id, payload in malformed_messages:
            with self.subTest(message_id=message_id):
                header_and_id = (1 + len(payload)).to_bytes(4, "big") + bytes((message_id,))
                result, _fake_socket, fake_loop = await run_verifier(
                    header_and_id + payload,
                    close_when_empty=False,
                )

                observation = result.availability
                assert observation is not None
                self.assertFalse(result.offering_observed)
                self.assertIsNotNone(observation.error)
                self.assertEqual(fake_loop.incoming, bytearray(payload))

        result, _fake_socket, _fake_loop = await run_verifier(
            peer_message(20),
            close_when_empty=False,
        )
        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertIsNotNone(observation.error)

    async def test_late_protocol_error_does_not_erase_positive_signals(self) -> None:
        unknown_payload = b"not-read"
        unknown_frame = (1 + len(unknown_payload)).to_bytes(4, "big") + b"\x63" + unknown_payload
        result, _fake_socket, fake_loop = await run_verifier(
            peer_message(1) + peer_message(5, b"\x80") + unknown_frame,
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertIsNotNone(observation.error)
        self.assertEqual(fake_loop.incoming, bytearray(unknown_payload))

    async def test_unknown_message_and_oversized_frame_stop_before_payload(self) -> None:
        unknown_payload = b"not-read"
        unknown_wire = (1 + len(unknown_payload)).to_bytes(4, "big") + b"\x63" + unknown_payload
        unknown_result, _socket, unknown_loop = await run_verifier(
            unknown_wire,
            close_when_empty=False,
        )
        unknown_observation = unknown_result.availability
        assert unknown_observation is not None
        self.assertFalse(unknown_result.offering_observed)
        self.assertEqual(unknown_loop.incoming, bytearray(unknown_payload))
        self.assertEqual(
            unknown_observation.control_events[-1].kind,
            "unknown_message_rejected",
        )

        oversized_prefix = (MAX_PEER_MESSAGE_LENGTH + 1).to_bytes(4, "big")
        oversized_result, _socket, oversized_loop = await run_verifier(
            oversized_prefix,
            close_when_empty=False,
        )
        oversized_observation = oversized_result.availability
        assert oversized_observation is not None
        self.assertFalse(oversized_result.offering_observed)
        self.assertEqual(oversized_observation.termination_reason, "oversized_message")
        self.assertEqual(oversized_loop.incoming, bytearray())

    async def test_malformed_fixed_control_message_is_not_positive(self) -> None:
        payload = b"not-read"
        malformed = (1 + len(payload)).to_bytes(4, "big") + b"\x01" + payload

        result, _fake_socket, fake_loop = await run_verifier(
            malformed,
            close_when_empty=False,
        )

        observation = result.availability
        assert observation is not None
        self.assertFalse(result.offering_observed)
        self.assertIsNotNone(observation.error)
        self.assertEqual(fake_loop.incoming, bytearray(payload))

    async def test_verifier_refuses_non_global_or_mismatched_candidates(self) -> None:
        verifier = PeerVerifier(
            peer_id=LOCAL_PEER_ID,
            observation_seconds=0.01,
        )

        private_result = await verifier.verify(candidate(ip="127.0.0.1"), INFO_HASH)
        mismatch_result = await verifier.verify(
            candidate(info_hash_hex=(b"x" * 20).hex()), INFO_HASH
        )

        self.assertFalse(private_result.confirmed)
        self.assertFalse(private_result.offering_observed)
        self.assertEqual(private_result.bytes_sent, 0)
        self.assertIn("Nichtglobaler", private_result.error or "")
        self.assertFalse(mismatch_result.confirmed)
        self.assertEqual(mismatch_result.bytes_sent, 0)
        self.assertIn("Infohash", mismatch_result.error or "")

    async def test_wrong_response_hash_is_not_confirmed_or_observed(self) -> None:
        result, _fake_socket, fake_loop = await run_verifier(
            b"",
            close_when_empty=True,
            remote_info_hash=b"x" * 20,
        )

        self.assertFalse(result.confirmed)
        self.assertFalse(result.offering_observed)
        self.assertEqual(result.bytes_received, 68)
        self.assertIsNone(result.availability)
        self.assertIn("anderen Infohash", result.error or "")
        self.assertEqual(fake_loop.sent, [build_handshake(INFO_HASH, LOCAL_PEER_ID)])

    async def test_cancellation_closes_socket_without_suppressing_cancel(self) -> None:
        fake_socket = FakeSocket()
        fake_loop = FakeLoop(
            build_handshake(INFO_HASH, REMOTE_PEER_ID),
            close_when_empty=False,
        )
        verifier = PeerVerifier(
            peer_id=LOCAL_PEER_ID,
            timeout=1.0,
            observation_seconds=60.0,
        )
        with (
            patch.object(peer_module.socket, "socket", return_value=fake_socket),
            patch.object(peer_module.asyncio, "get_running_loop", return_value=fake_loop),
        ):
            task = asyncio.create_task(verifier.verify(candidate(), INFO_HASH))
            for _ in range(100):
                if len(fake_loop.sent) == 2:
                    break
                await asyncio.sleep(0)
            self.assertEqual(len(fake_loop.sent), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertTrue(fake_socket.closed)

    def test_observation_duration_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            PeerVerifier(peer_id=LOCAL_PEER_ID, observation_seconds=0.0)
        with self.assertRaises(ValueError):
            PeerVerifier(peer_id=LOCAL_PEER_ID, observation_seconds=True)
        with self.assertRaises(ValueError):
            PeerVerifier(peer_id=LOCAL_PEER_ID, observation_seconds=301.0)


if __name__ == "__main__":
    unittest.main()
