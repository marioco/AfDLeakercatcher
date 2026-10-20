"""Minimale TCP-Verifikation mit genau einem Standard-BitTorrent-Handshake."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import secrets
import socket
from dataclasses import dataclass
from datetime import UTC, datetime

from .dht import MAX_TIMEOUT_SECONDS, normalize_global_endpoint
from .models import HandshakeResult, PeerCandidate

PROTOCOL_NAME = b"BitTorrent protocol"
HANDSHAKE_LENGTH = 68
RESERVED_BITS = b"\x00" * 8


class PeerHandshakeError(OSError):
    """Der TCP-Peer lieferte keinen vollständigen Standard-Handshake."""


@dataclass(slots=True)
class _ExchangeState:
    bytes_sent: int = 0
    bytes_received: int = 0
    local_ip: str | None = None
    local_port: int | None = None


def _utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _default_peer_id() -> bytes:
    return b"-BB0001-" + secrets.token_bytes(12)


def build_handshake(info_hash: bytes, peer_id: bytes) -> bytes:
    """Baut den exakt 68 Byte langen Standard-Handshake ohne Erweiterungsbits."""
    if not isinstance(info_hash, bytes) or len(info_hash) != 20:
        raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")
    if not isinstance(peer_id, bytes) or len(peer_id) != 20:
        raise ValueError("Lokale Peer-ID muss genau 20 Byte lang sein.")
    handshake = bytes((len(PROTOCOL_NAME),)) + PROTOCOL_NAME + RESERVED_BITS + info_hash + peer_id
    if len(handshake) != HANDSHAKE_LENGTH:
        raise AssertionError("Interner Fehler: Handshake hat nicht 68 Byte.")
    return handshake


def parse_handshake_response(
    response: bytes,
    *,
    expected_info_hash: bytes,
) -> tuple[bytes, bytes]:
    """Validiert Länge, Protokollkennung und denselben v1-Infohash."""
    if not isinstance(expected_info_hash, bytes) or len(expected_info_hash) != 20:
        raise ValueError("Erwarteter Infohash muss genau 20 Byte lang sein.")
    if not isinstance(response, bytes) or len(response) != HANDSHAKE_LENGTH:
        raise PeerHandshakeError("Peer-Handshake muss genau 68 Byte lang sein.")
    if response[0] != len(PROTOCOL_NAME) or response[1:20] != PROTOCOL_NAME:
        raise PeerHandshakeError("Peer antwortete nicht mit dem BitTorrent-Protokoll.")
    received_info_hash = response[28:48]
    if not hmac.compare_digest(received_info_hash, expected_info_hash):
        raise PeerHandshakeError("Peer bestätigte einen anderen Infohash.")
    return response[20:28], response[48:68]


def _normalize_local_address(value: object) -> tuple[str | None, int | None]:
    if not isinstance(value, tuple) or len(value) < 2:
        return None, None
    try:
        address = ipaddress.ip_address(str(value[0])).compressed
        port = int(value[1])
    except (TypeError, ValueError):
        return None, None
    if isinstance(port, bool) or not 1 <= port <= 65_535:
        return None, None
    return address, port


def _safe_error(error: BaseException) -> str:
    text = " ".join(str(error).replace("\x00", "").split())
    label = type(error).__name__
    return f"{label}: {text}"[:500] if text else label


class PeerVerifier:
    """Verifiziert einen Kandidaten ohne Bitfield, Requests oder Inhaltsabruf."""

    def __init__(
        self,
        *,
        peer_id: bytes | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.peer_id = peer_id if peer_id is not None else _default_peer_id()
        if not isinstance(self.peer_id, bytes) or len(self.peer_id) != 20:
            raise ValueError("Lokale Peer-ID muss genau 20 Byte lang sein.")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0.1 <= float(timeout) <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"timeout muss zwischen 0.1 und {MAX_TIMEOUT_SECONDS} Sekunden liegen."
            )
        self.timeout = float(timeout)

    async def _exchange(
        self,
        endpoint: tuple[str, int],
        outgoing_handshake: bytes,
        state: _ExchangeState,
    ) -> bytes:
        if (
            len(outgoing_handshake) != HANDSHAKE_LENGTH
            or outgoing_handshake[20:28] != RESERVED_BITS
        ):
            raise ValueError("Ausgehender Handshake ist nicht exakt und featurefrei.")
        address = ipaddress.ip_address(endpoint[0])
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sockaddr: tuple[object, ...]
        sockaddr = (endpoint[0], endpoint[1], 0, 0) if family == socket.AF_INET6 else endpoint

        loop = asyncio.get_running_loop()
        peer_socket = socket.socket(family, socket.SOCK_STREAM)
        peer_socket.setblocking(False)
        response = bytearray()
        try:
            await loop.sock_connect(peer_socket, sockaddr)
            state.local_ip, state.local_port = _normalize_local_address(peer_socket.getsockname())
            await loop.sock_sendall(peer_socket, outgoing_handshake)
            state.bytes_sent = len(outgoing_handshake)

            while len(response) < HANDSHAKE_LENGTH:
                remaining = HANDSHAKE_LENGTH - len(response)
                chunk = await loop.sock_recv(peer_socket, remaining)
                if not chunk:
                    raise PeerHandshakeError(
                        "TCP-Verbindung endete vor dem vollständigen Peer-Handshake."
                    )
                response.extend(chunk)
                state.bytes_received = len(response)
            return bytes(response)
        finally:
            peer_socket.close()

    async def verify(
        self,
        candidate: PeerCandidate,
        info_hash: bytes,
    ) -> HandshakeResult:
        """Sendet einmal 68 Byte, liest höchstens 68 Byte und schließt sofort."""
        if not isinstance(candidate, PeerCandidate):
            raise TypeError("candidate muss ein PeerCandidate sein.")
        if not isinstance(info_hash, bytes) or len(info_hash) != 20:
            raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")

        attempted_at = _utc_now_text()
        state = _ExchangeState()
        endpoint = normalize_global_endpoint(candidate.ip, candidate.port)
        if endpoint is None:
            return self._result(
                candidate,
                attempted_at,
                state,
                error="Nichtglobaler oder ungültiger Peer-Endpunkt wurde abgelehnt.",
            )
        if (
            not isinstance(candidate.info_hash_hex, str)
            or len(candidate.info_hash_hex) != 40
            or any(character not in "0123456789abcdef" for character in candidate.info_hash_hex)
        ):
            candidate_info_hash = b""
        else:
            candidate_info_hash = bytes.fromhex(candidate.info_hash_hex)
        if len(candidate_info_hash) != 20 or not hmac.compare_digest(
            candidate_info_hash, info_hash
        ):
            return self._result(
                candidate,
                attempted_at,
                state,
                error="Kandidaten-Infohash stimmt nicht mit dem Prüfziel überein.",
            )

        outgoing = build_handshake(info_hash, self.peer_id)
        completed_at: str | None = None
        try:
            response = await asyncio.wait_for(
                self._exchange(endpoint, outgoing, state), timeout=self.timeout
            )
            completed_at = _utc_now_text()
            reserved_bits, remote_peer_id = parse_handshake_response(
                response, expected_info_hash=info_hash
            )
        except OSError as exc:
            return self._result(
                candidate,
                attempted_at,
                state,
                completed_at=completed_at,
                error=_safe_error(exc),
            )

        return HandshakeResult(
            candidate=candidate,
            attempted_at_utc=attempted_at,
            completed_at_utc=completed_at,
            confirmed=True,
            remote_peer_id_hex=remote_peer_id.hex(),
            reserved_bits_hex=reserved_bits.hex(),
            local_ip=state.local_ip,
            local_port=state.local_port,
            bytes_sent=state.bytes_sent,
            bytes_received=state.bytes_received,
            error=None,
        )

    @staticmethod
    def _result(
        candidate: PeerCandidate,
        attempted_at: str,
        state: _ExchangeState,
        *,
        completed_at: str | None = None,
        error: str,
    ) -> HandshakeResult:
        return HandshakeResult(
            candidate=candidate,
            attempted_at_utc=attempted_at,
            completed_at_utc=completed_at,
            confirmed=False,
            remote_peer_id_hex=None,
            reserved_bits_hex=None,
            local_ip=state.local_ip,
            local_port=state.local_port,
            bytes_sent=state.bytes_sent,
            bytes_received=state.bytes_received,
            error=error,
        )


async def verify_peer(
    candidate: PeerCandidate,
    info_hash: bytes,
    *,
    peer_id: bytes | None = None,
    timeout: float = 5.0,
) -> HandshakeResult:
    """Komfortfunktion für eine einzelne, minimalinvasive Peer-Verifikation."""
    verifier = PeerVerifier(peer_id=peer_id, timeout=timeout)
    return await verifier.verify(candidate, info_hash)
