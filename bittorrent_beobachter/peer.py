"""Inhaltsfreie TCP-Prüfung eines BitTorrent-Peers ohne Datenanforderungen."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import secrets
import socket
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .dht import MAX_TIMEOUT_SECONDS, normalize_global_endpoint
from .models import (
    HandshakeResult,
    PeerAvailabilityObservation,
    PeerCandidate,
    PeerControlEvent,
)

PROTOCOL_NAME = b"BitTorrent protocol"
HANDSHAKE_LENGTH = 68
RESERVED_BITS = b"\x00" * 8
INTERESTED_MESSAGE = b"\x00\x00\x00\x01\x02"

DEFAULT_OBSERVATION_SECONDS = 60.0
MIN_OBSERVATION_SECONDS = 0.01
MAX_OBSERVATION_SECONDS = 300.0
MAX_PEER_MESSAGE_LENGTH = 1_048_576
MAX_BITFIELD_BYTES = MAX_PEER_MESSAGE_LENGTH - 1
MAX_OBSERVATION_BYTES = 4_194_304
MAX_CONTROL_EVENTS = 512
RECEIVE_CHUNK_BYTES = 16_384

MESSAGE_CHOKE = 0
MESSAGE_UNCHOKE = 1
MESSAGE_INTERESTED = 2
MESSAGE_NOT_INTERESTED = 3
MESSAGE_HAVE = 4
MESSAGE_BITFIELD = 5
MESSAGE_REQUEST = 6
MESSAGE_PIECE = 7
MESSAGE_PORT = 9
MESSAGE_SUGGEST_PIECE = 13
MESSAGE_HAVE_ALL = 14
MESSAGE_HAVE_NONE = 15
MESSAGE_REJECT_REQUEST = 16
MESSAGE_ALLOWED_FAST = 17
MESSAGE_EXTENSION = 20


class PeerHandshakeError(OSError):
    """Der TCP-Peer lieferte keinen vollständigen Standard-Handshake."""


class PeerProtocolError(OSError):
    """Der Peer lieferte nach dem Handshake eine unzulässige Kontrollnachricht."""


@dataclass(slots=True)
class _ExchangeState:
    bytes_sent: int = 0
    bytes_received: int = 0
    local_ip: str | None = None
    local_port: int | None = None


@dataclass(slots=True)
class _ObservationState:
    started_at_utc: str
    started_monotonic: float
    events: list[PeerControlEvent] = field(default_factory=list)
    messages_received: int = 0
    bytes_received: int = 0
    non_empty_bitfield: bool = False
    have_announced: bool = False
    unchoked: bool = False
    peer_choking: bool = True
    unchoked_since: float | None = None
    completed_unchoked_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class _PeerExchange:
    handshake: bytes
    handshake_completed_at_utc: str
    availability: PeerAvailabilityObservation


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


def _elapsed_seconds(started_monotonic: float, ended_monotonic: float | None = None) -> float:
    end = time.monotonic() if ended_monotonic is None else ended_monotonic
    return round(max(0.0, end - started_monotonic), 6)


def _record_event(
    state: _ObservationState,
    kind: str,
    *,
    payload_length: int,
    piece_index: int | None = None,
    non_empty: bool | None = None,
    payload_sha256: str | None = None,
    set_bits: int | None = None,
) -> float:
    observed_monotonic = time.monotonic()
    state.events.append(
        PeerControlEvent(
            observed_at_utc=_utc_now_text(),
            elapsed_seconds=_elapsed_seconds(state.started_monotonic, observed_monotonic),
            kind=kind,
            payload_length=payload_length,
            piece_index=piece_index,
            non_empty=non_empty,
            payload_sha256=payload_sha256,
            set_bits=set_bits,
        )
    )
    return observed_monotonic


async def _receive_exact(
    loop: asyncio.AbstractEventLoop,
    peer_socket: socket.socket,
    size: int,
    *,
    deadline: float,
    exchange_state: _ExchangeState,
    observation_state: _ObservationState | None = None,
    allow_clean_eof: bool = False,
) -> bytes | None:
    """Liest exakt eine kleine Protokollstruktur innerhalb einer festen Frist."""
    if size < 0:
        raise ValueError("Empfangsgröße darf nicht negativ sein.")
    received = bytearray()
    while len(received) < size:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            if received:
                raise PeerProtocolError("Peer-Nachricht blieb bis zum Fristende unvollständig.")
            raise TimeoutError
        maximum = min(size - len(received), RECEIVE_CHUNK_BYTES)
        try:
            chunk = await asyncio.wait_for(
                loop.sock_recv(peer_socket, maximum),
                timeout=remaining_seconds,
            )
        except TimeoutError:
            if received:
                raise PeerProtocolError(
                    "Peer-Nachricht blieb bis zum Fristende unvollständig."
                ) from None
            raise
        if not chunk:
            if allow_clean_eof and not received:
                return None
            raise PeerProtocolError("TCP-Verbindung endete mitten in einer Peer-Nachricht.")
        received.extend(chunk)
        exchange_state.bytes_received += len(chunk)
        if observation_state is not None:
            observation_state.bytes_received += len(chunk)
    return bytes(received)


async def _read_bitfield(
    loop: asyncio.AbstractEventLoop,
    peer_socket: socket.socket,
    payload_length: int,
    *,
    deadline: float,
    exchange_state: _ExchangeState,
    observation_state: _ObservationState,
) -> tuple[str, int]:
    """Hasht das begrenzte Bitfield blockweise, ohne dessen Bytes aufzubewahren."""
    digest = hashlib.sha256()
    set_bits = 0
    remaining = payload_length
    while remaining:
        chunk_size = min(remaining, RECEIVE_CHUNK_BYTES)
        chunk = await _receive_exact(
            loop,
            peer_socket,
            chunk_size,
            deadline=deadline,
            exchange_state=exchange_state,
            observation_state=observation_state,
        )
        if chunk is None:
            raise AssertionError("Bitfield-Empfang darf kein sauberes EOF liefern.")
        digest.update(chunk)
        set_bits += sum(value.bit_count() for value in chunk)
        remaining -= len(chunk)
    return digest.hexdigest(), set_bits


async def _read_hashed_payload(
    loop: asyncio.AbstractEventLoop,
    peer_socket: socket.socket,
    payload_length: int,
    *,
    deadline: float,
    exchange_state: _ExchangeState,
    observation_state: _ObservationState,
    initial_payload: bytes = b"",
) -> str:
    """Verwirft eine begrenzte Kontrollnutzlast blockweise und liefert nur ihren Hash."""
    if payload_length < 0:
        raise ValueError("Kontrollnutzlast darf nicht negativ sein.")
    if not isinstance(initial_payload, bytes):
        raise TypeError("initial_payload muss eine Bytefolge sein.")
    digest = hashlib.sha256()
    digest.update(initial_payload)
    remaining = payload_length
    while remaining:
        chunk = await _receive_exact(
            loop,
            peer_socket,
            min(remaining, RECEIVE_CHUNK_BYTES),
            deadline=deadline,
            exchange_state=exchange_state,
            observation_state=observation_state,
        )
        if chunk is None:
            raise AssertionError("Kontrollnutzlast darf kein sauberes EOF liefern.")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _availability_result(
    state: _ObservationState,
    *,
    requested_duration_seconds: float,
    interested_sent: bool,
    termination_reason: str,
    completed_full_window: bool,
    error: str | None = None,
) -> PeerAvailabilityObservation:
    ended_monotonic = time.monotonic()
    unchoked_seconds = state.completed_unchoked_seconds
    if not state.peer_choking and state.unchoked_since is not None:
        unchoked_seconds += max(0.0, ended_monotonic - state.unchoked_since)
    return PeerAvailabilityObservation(
        started_at_utc=state.started_at_utc,
        ended_at_utc=_utc_now_text(),
        requested_duration_seconds=requested_duration_seconds,
        duration_seconds=_elapsed_seconds(state.started_monotonic, ended_monotonic),
        completed_full_window=completed_full_window,
        interested_sent=interested_sent,
        non_empty_bitfield=state.non_empty_bitfield,
        have_announced=state.have_announced,
        piece_availability_announced=(state.non_empty_bitfield or state.have_announced),
        unchoked=state.unchoked,
        peer_choking_at_end=state.peer_choking,
        unchoked_duration_seconds=round(unchoked_seconds, 6),
        messages_received=state.messages_received,
        bytes_received=state.bytes_received,
        request_messages_sent=0,
        piece_payload_bytes_received=0,
        metadata_requests_sent=0,
        termination_reason=termination_reason,
        control_events=tuple(state.events),
        error=error,
    )


async def _observe_control_messages(
    loop: asyncio.AbstractEventLoop,
    peer_socket: socket.socket,
    exchange_state: _ExchangeState,
    *,
    observation_seconds: float,
) -> PeerAvailabilityObservation:
    started_monotonic = time.monotonic()
    state = _ObservationState(
        started_at_utc=_utc_now_text(),
        started_monotonic=started_monotonic,
    )
    deadline = started_monotonic + observation_seconds

    while True:
        if len(state.events) >= MAX_CONTROL_EVENTS:
            error = PeerProtocolError(
                f"Kontrollereignis-Limit von {MAX_CONTROL_EVENTS} wurde erreicht."
            )
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="control_event_limit",
                completed_full_window=False,
                error=_safe_error(error),
            )
        if MAX_OBSERVATION_BYTES - state.bytes_received < 4:
            error = PeerProtocolError(
                f"Beobachtungs-Limit von {MAX_OBSERVATION_BYTES} Byte wurde erreicht."
            )
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="byte_limit",
                completed_full_window=False,
                error=_safe_error(error),
            )

        try:
            length_prefix = await _receive_exact(
                loop,
                peer_socket,
                4,
                deadline=deadline,
                exchange_state=exchange_state,
                observation_state=state,
                allow_clean_eof=True,
            )
        except TimeoutError:
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="duration_elapsed",
                completed_full_window=True,
            )
        except (OSError, PeerProtocolError) as exc:
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="protocol_or_network_error",
                completed_full_window=time.monotonic() >= deadline,
                error=_safe_error(exc),
            )

        if length_prefix is None:
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="peer_closed",
                completed_full_window=False,
            )

        message_length = int.from_bytes(length_prefix, "big")
        state.messages_received += 1
        if message_length == 0:
            _record_event(state, "keepalive", payload_length=0)
            continue
        if message_length > MAX_PEER_MESSAGE_LENGTH:
            error = PeerProtocolError(
                f"Peer-Nachricht überschreitet {MAX_PEER_MESSAGE_LENGTH} Byte."
            )
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="oversized_message",
                completed_full_window=False,
                error=_safe_error(error),
            )
        if state.bytes_received + message_length > MAX_OBSERVATION_BYTES:
            error = PeerProtocolError(
                f"Peer-Nachricht überschreitet das Beobachtungs-Limit von "
                f"{MAX_OBSERVATION_BYTES} Byte."
            )
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="byte_limit",
                completed_full_window=False,
                error=_safe_error(error),
            )

        try:
            message_id_bytes = await _receive_exact(
                loop,
                peer_socket,
                1,
                deadline=deadline,
                exchange_state=exchange_state,
                observation_state=state,
            )
            if message_id_bytes is None:
                raise AssertionError("Nachrichten-ID darf kein sauberes EOF liefern.")
            message_id = message_id_bytes[0]
            payload_length = message_length - 1

            if message_id in {
                MESSAGE_CHOKE,
                MESSAGE_UNCHOKE,
                MESSAGE_INTERESTED,
                MESSAGE_NOT_INTERESTED,
            }:
                if payload_length != 0:
                    raise PeerProtocolError(
                        f"Kontrollnachricht {message_id} hat eine ungültige Länge."
                    )
                event_kind = {
                    MESSAGE_CHOKE: "choke",
                    MESSAGE_UNCHOKE: "unchoke",
                    MESSAGE_INTERESTED: "peer_interested",
                    MESSAGE_NOT_INTERESTED: "peer_not_interested",
                }[message_id]
                event_monotonic = _record_event(state, event_kind, payload_length=0)
                if message_id == MESSAGE_UNCHOKE:
                    state.unchoked = True
                    if state.peer_choking:
                        state.peer_choking = False
                        state.unchoked_since = event_monotonic
                elif message_id == MESSAGE_CHOKE and not state.peer_choking:
                    if state.unchoked_since is not None:
                        state.completed_unchoked_seconds += max(
                            0.0, event_monotonic - state.unchoked_since
                        )
                    state.peer_choking = True
                    state.unchoked_since = None
                continue

            if message_id == MESSAGE_HAVE:
                if payload_length != 4:
                    raise PeerProtocolError("HAVE-Nachricht muss genau 5 Byte lang sein.")
                piece_bytes = await _receive_exact(
                    loop,
                    peer_socket,
                    4,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                )
                if piece_bytes is None:
                    raise AssertionError("HAVE-Nutzlast darf kein sauberes EOF liefern.")
                piece_index = int.from_bytes(piece_bytes, "big")
                state.have_announced = True
                _record_event(
                    state,
                    "have",
                    payload_length=4,
                    piece_index=piece_index,
                )
                continue

            if message_id == MESSAGE_BITFIELD:
                if not 1 <= payload_length <= MAX_BITFIELD_BYTES:
                    raise PeerProtocolError("BITFIELD-Nachricht hat eine ungültige Länge.")
                payload_sha256, set_bits = await _read_bitfield(
                    loop,
                    peer_socket,
                    payload_length,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                )
                non_empty = set_bits > 0
                state.non_empty_bitfield = state.non_empty_bitfield or non_empty
                _record_event(
                    state,
                    "bitfield",
                    payload_length=payload_length,
                    non_empty=non_empty,
                    payload_sha256=payload_sha256,
                    set_bits=set_bits,
                )
                continue

            if message_id == MESSAGE_PORT:
                if payload_length != 2:
                    raise PeerProtocolError("PORT-Nachricht muss genau 3 Byte lang sein.")
                port_bytes = await _receive_exact(
                    loop,
                    peer_socket,
                    2,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                )
                if port_bytes is None:
                    raise AssertionError("PORT-Nutzlast darf kein sauberes EOF liefern.")
                _record_event(state, "port", payload_length=2)
                continue

            if message_id in {MESSAGE_HAVE_ALL, MESSAGE_HAVE_NONE}:
                if payload_length != 0:
                    raise PeerProtocolError(
                        f"Fast-Extension-Nachricht {message_id} darf keine Nutzlast haben."
                    )
                if message_id == MESSAGE_HAVE_ALL:
                    state.have_announced = True
                    event_kind = "have_all"
                else:
                    event_kind = "have_none"
                _record_event(state, event_kind, payload_length=0)
                continue

            if message_id in {MESSAGE_SUGGEST_PIECE, MESSAGE_ALLOWED_FAST}:
                if payload_length != 4:
                    raise PeerProtocolError(
                        f"Fast-Extension-Nachricht {message_id} muss genau 5 Byte lang sein."
                    )
                piece_bytes = await _receive_exact(
                    loop,
                    peer_socket,
                    4,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                )
                if piece_bytes is None:
                    raise AssertionError("Fast-Extension-Nutzlast darf kein sauberes EOF liefern.")
                _record_event(
                    state,
                    "suggest_piece" if message_id == MESSAGE_SUGGEST_PIECE else "allowed_fast",
                    payload_length=4,
                    piece_index=int.from_bytes(piece_bytes, "big"),
                )
                continue

            if message_id == MESSAGE_REJECT_REQUEST:
                if payload_length != 12:
                    raise PeerProtocolError(
                        "REJECT_REQUEST-Nachricht muss genau 13 Byte lang sein."
                    )
                rejected_request = await _receive_exact(
                    loop,
                    peer_socket,
                    12,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                )
                if rejected_request is None:
                    raise AssertionError("REJECT_REQUEST-Nutzlast darf kein sauberes EOF liefern.")
                _record_event(
                    state,
                    "reject_request",
                    payload_length=12,
                    piece_index=int.from_bytes(rejected_request[:4], "big"),
                )
                continue

            if message_id == MESSAGE_EXTENSION:
                if payload_length < 1:
                    raise PeerProtocolError(
                        "Extended-Nachricht benötigt mindestens eine Erweiterungs-ID."
                    )
                extension_id_bytes = await _receive_exact(
                    loop,
                    peer_socket,
                    1,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                )
                if extension_id_bytes is None:
                    raise AssertionError("Erweiterungs-ID darf kein sauberes EOF liefern.")
                extension_id = extension_id_bytes[0]
                if extension_id != 0:
                    _record_event(
                        state,
                        "extension_payload_rejected",
                        payload_length=payload_length,
                    )
                    raise PeerProtocolError(
                        "Nicht angeforderte Extended-Nutzlast wird nicht eingelesen."
                    )
                payload_sha256 = await _read_hashed_payload(
                    loop,
                    peer_socket,
                    payload_length - 1,
                    deadline=deadline,
                    exchange_state=exchange_state,
                    observation_state=state,
                    initial_payload=extension_id_bytes,
                )
                _record_event(
                    state,
                    "extension_handshake",
                    payload_length=payload_length,
                    payload_sha256=payload_sha256,
                )
                continue

            rejected_kind = {
                MESSAGE_REQUEST: "request_rejected",
                MESSAGE_PIECE: "piece_rejected",
            }.get(message_id, "unknown_message_rejected")
            _record_event(state, rejected_kind, payload_length=payload_length)
            raise PeerProtocolError(
                f"Peer-Nachricht {message_id} wird ohne Einlesen der Nutzlast abgelehnt."
            )
        except TimeoutError:
            error = PeerProtocolError("Peer-Nachricht blieb bis zum Fristende unvollständig.")
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="incomplete_message",
                completed_full_window=True,
                error=_safe_error(error),
            )
        except (OSError, PeerProtocolError) as exc:
            return _availability_result(
                state,
                requested_duration_seconds=observation_seconds,
                interested_sent=True,
                termination_reason="protocol_or_network_error",
                completed_full_window=time.monotonic() >= deadline,
                error=_safe_error(exc),
            )


class PeerVerifier:
    """Prüft Handshake und Kontrollmeldungen, ohne Inhaltsblöcke anzufordern."""

    def __init__(
        self,
        *,
        peer_id: bytes | None = None,
        timeout: float = 5.0,
        observation_seconds: float = DEFAULT_OBSERVATION_SECONDS,
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
        if (
            isinstance(observation_seconds, bool)
            or not isinstance(observation_seconds, (int, float))
            or not MIN_OBSERVATION_SECONDS <= float(observation_seconds) <= MAX_OBSERVATION_SECONDS
        ):
            raise ValueError(
                "observation_seconds muss zwischen "
                f"{MIN_OBSERVATION_SECONDS} und {MAX_OBSERVATION_SECONDS} Sekunden liegen."
            )
        self.timeout = float(timeout)
        self.observation_seconds = float(observation_seconds)

    async def _exchange(
        self,
        endpoint: tuple[str, int],
        outgoing_handshake: bytes,
        state: _ExchangeState,
    ) -> _PeerExchange:
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
        try:
            peer_socket.setblocking(False)
            await asyncio.wait_for(
                loop.sock_connect(peer_socket, sockaddr),
                timeout=self.timeout,
            )
            state.local_ip, state.local_port = _normalize_local_address(peer_socket.getsockname())
            await asyncio.wait_for(
                loop.sock_sendall(peer_socket, outgoing_handshake),
                timeout=self.timeout,
            )
            state.bytes_sent = len(outgoing_handshake)

            response = await _receive_exact(
                loop,
                peer_socket,
                HANDSHAKE_LENGTH,
                deadline=time.monotonic() + self.timeout,
                exchange_state=state,
            )
            if response is None:
                raise AssertionError("Handshake-Empfang darf kein sauberes EOF liefern.")
            parse_handshake_response(
                response,
                expected_info_hash=outgoing_handshake[28:48],
            )
            handshake_completed_at = _utc_now_text()

            try:
                await asyncio.wait_for(
                    loop.sock_sendall(peer_socket, INTERESTED_MESSAGE),
                    timeout=self.timeout,
                )
                state.bytes_sent += len(INTERESTED_MESSAGE)
            except OSError as exc:
                now_monotonic = time.monotonic()
                failed_state = _ObservationState(
                    started_at_utc=_utc_now_text(),
                    started_monotonic=now_monotonic,
                )
                availability = _availability_result(
                    failed_state,
                    requested_duration_seconds=self.observation_seconds,
                    interested_sent=False,
                    termination_reason="interested_send_error",
                    completed_full_window=False,
                    error=_safe_error(exc),
                )
            else:
                availability = await _observe_control_messages(
                    loop,
                    peer_socket,
                    state,
                    observation_seconds=self.observation_seconds,
                )
            return _PeerExchange(
                handshake=response,
                handshake_completed_at_utc=handshake_completed_at,
                availability=availability,
            )
        finally:
            peer_socket.close()

    async def verify(
        self,
        candidate: PeerCandidate,
        info_hash: bytes,
    ) -> HandshakeResult:
        """Beobachtet einen passenden Peer zeitlich begrenzt und vollständig inhaltsfrei."""
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
        try:
            exchange = await self._exchange(endpoint, outgoing, state)
            reserved_bits, remote_peer_id = parse_handshake_response(
                exchange.handshake,
                expected_info_hash=info_hash,
            )
        except OSError as exc:
            return self._result(
                candidate,
                attempted_at,
                state,
                error=_safe_error(exc),
            )

        return HandshakeResult(
            candidate=candidate,
            attempted_at_utc=attempted_at,
            completed_at_utc=exchange.handshake_completed_at_utc,
            confirmed=True,
            remote_peer_id_hex=remote_peer_id.hex(),
            reserved_bits_hex=reserved_bits.hex(),
            local_ip=state.local_ip,
            local_port=state.local_port,
            bytes_sent=state.bytes_sent,
            bytes_received=state.bytes_received,
            error=None,
            availability=exchange.availability,
        )

    @staticmethod
    def _result(
        candidate: PeerCandidate,
        attempted_at: str,
        state: _ExchangeState,
        *,
        error: str,
    ) -> HandshakeResult:
        return HandshakeResult(
            candidate=candidate,
            attempted_at_utc=attempted_at,
            completed_at_utc=None,
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
    observation_seconds: float = DEFAULT_OBSERVATION_SECONDS,
) -> HandshakeResult:
    """Komfortfunktion für eine einzelne inhaltsfreie Peer-Verfügbarkeitsprüfung."""
    verifier = PeerVerifier(
        peer_id=peer_id,
        timeout=timeout,
        observation_seconds=observation_seconds,
    )
    return await verifier.verify(candidate, info_hash)
