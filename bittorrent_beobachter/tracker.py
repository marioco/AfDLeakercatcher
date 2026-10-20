"""Inhaltsfreie Peer-Ermittlung ueber UDP-Tracker nach BEP 15.

Eine Tracker-Anfrage uebermittelt dem Tracker technisch unvermeidbar die
oeffentliche Quell-IP und den angefragten Infohash. Der Baustein fordert weder
Torrent-Metadaten noch Inhaltsbloecke an. Zur tatsaechlichen Peer-Ermittlung
wird ein standardkonformer ``started``-Announce mit unbekannter Restmenge und
einem zufaelligen, nicht geoeffneten Port gesendet. Direkt danach wird derselbe
kurzlebige Tracker-Eintrag ueber dieselbe Verbindung bestmoeglich mit
``stopped`` entfernt. Das Programm oeffnet keinen Listener und bietet selbst
keinen Upload an.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import secrets
import socket
import struct
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from .dht import normalize_global_endpoint
from .models import PeerCandidate, Target

Endpoint = tuple[str, int]
CandidateBatchHook = Callable[[tuple[PeerCandidate, ...]], Awaitable[None]]
ExchangeHook = Callable[[Endpoint, bytes], Awaitable[bytes]]

LOGGER = logging.getLogger("bittorrent_beobachter")

UDP_TRACKER_PROTOCOL_ID = 0x41727101980
TRACKER_ACTION_CONNECT = 0
TRACKER_ACTION_ANNOUNCE = 1
TRACKER_ACTION_ERROR = 3
TRACKER_EVENT_STARTED = 2
TRACKER_EVENT_STOPPED = 3
TRACKER_NUM_WANT_DEFAULT = 0x7FFF_FFFF
TRACKER_NUM_WANT_NONE = 0
TRACKER_LEFT_UNKNOWN = 0xFFFF_FFFF_FFFF_FFFF

CONNECT_REQUEST_BYTES = 16
CONNECT_RESPONSE_BYTES = 16
ANNOUNCE_REQUEST_BYTES = 98
ANNOUNCE_RESPONSE_HEADER_BYTES = 20
MAX_TRACKER_RESPONSE_BYTES = 65_507
MAX_TRACKER_URL_BYTES = 4_096
MAX_TRACKER_HOST_LENGTH = 253
MAX_TRACKER_TIMEOUT_SECONDS = 30.0
TRACKER_EXCHANGE_ATTEMPTS = 3
TRACKER_RETRY_BACKOFF_SECONDS = 0.1
TRACKER_DISCOVERY_CONCURRENCY = 8
CANDIDATE_BATCH_SIZE = 5


class TrackerProtocolError(ValueError):
    """Eine UDP-Tracker-Antwort verletzt das erwartete BEP-15-Format."""


@dataclass(frozen=True, slots=True)
class TrackerURL:
    """Validierter UDP-Tracker ohne Zugangsdaten."""

    host: str
    port: int


@dataclass(frozen=True, slots=True)
class TrackerAnnounceResponse:
    """Validierte, auf Endpunkte und Nachweisfelder reduzierte Antwort."""

    tracker: Endpoint
    transaction_id: int
    peers: tuple[Endpoint, ...]
    response_sha256: str
    cleanup_failed: bool = False


@dataclass(slots=True)
class TrackerDiscoveryStats:
    """Kleine, laufweit aggregierbare Zaehler ohne Endpunktlisten."""

    trackers_configured: int = 0
    endpoints_attempted: int = 0
    queries_completed: int = 0
    queries_failed: int = 0
    stop_queries_failed: int = 0


def _utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _require_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout muss eine Zahl sein.")
    normalized = float(timeout)
    if not 0.1 <= normalized <= MAX_TRACKER_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout muss zwischen 0.1 und {MAX_TRACKER_TIMEOUT_SECONDS:.1f} Sekunden liegen."
        )
    return normalized


def parse_tracker_url(value: str) -> TrackerURL:
    """Validiert eine einzelne, zugangsdatenfreie ``udp://``-Tracker-URL."""
    if not isinstance(value, str):
        raise TypeError("Tracker-URL muss eine Zeichenkette sein.")
    try:
        encoded_value = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Tracker-URL enthaelt unzulaessige Unicode-Zeichen.") from exc
    if not value or len(encoded_value) > MAX_TRACKER_URL_BYTES:
        raise ValueError("Tracker-URL ist leer oder zu lang.")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("Tracker-URL enthaelt unzulaessige Zeichen.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Tracker-URL enthaelt keinen gueltigen Endpunkt.") from exc
    if parsed.scheme.lower() != "udp":
        raise ValueError("Es werden ausschliesslich udp://-Tracker akzeptiert.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Tracker-URLs mit Zugangsdaten werden nicht akzeptiert.")
    if parsed.fragment:
        raise ValueError("Tracker-URLs mit Fragmenten werden nicht akzeptiert.")
    host = parsed.hostname
    if host is None or not host or len(host) > MAX_TRACKER_HOST_LENGTH:
        raise ValueError("Tracker-URL enthaelt keinen gueltigen Hostnamen.")
    if port is None or not 1 <= port <= 65_535:
        raise ValueError("UDP-Tracker-URL muss einen gueltigen Port enthalten.")
    return TrackerURL(host=host, port=port)


def build_connect_request(transaction_id: int) -> bytes:
    """Erstellt eine BEP-15-Connect-Anfrage."""
    if isinstance(transaction_id, bool) or not isinstance(transaction_id, int):
        raise TypeError("Tracker-Transaktions-ID muss eine ganze Zahl sein.")
    if not 0 <= transaction_id <= 0xFFFF_FFFF:
        raise ValueError("Tracker-Transaktions-ID liegt ausserhalb von uint32.")
    return struct.pack("!QII", UDP_TRACKER_PROTOCOL_ID, TRACKER_ACTION_CONNECT, transaction_id)


def parse_connect_response(packet: bytes, *, expected_transaction_id: int) -> int:
    """Prueft eine Connect-Antwort und liefert die kurzlebige Connection-ID."""
    _require_packet(packet)
    if len(packet) < 8:
        raise TrackerProtocolError("UDP-Tracker-Antwort ist zu kurz.")
    action, transaction_id = struct.unpack_from("!II", packet)
    if transaction_id != expected_transaction_id:
        raise TrackerProtocolError("UDP-Tracker-Transaktions-ID stimmt nicht ueberein.")
    if action == TRACKER_ACTION_ERROR:
        raise TrackerProtocolError("UDP-Tracker meldete einen Fehler.")
    if action != TRACKER_ACTION_CONNECT or len(packet) < CONNECT_RESPONSE_BYTES:
        raise TrackerProtocolError("UDP-Tracker-Connect-Antwort ist ungueltig.")
    return struct.unpack_from("!Q", packet, 8)[0]


def build_announce_request(
    connection_id: int,
    transaction_id: int,
    info_hash: bytes,
    peer_id: bytes,
    key: int,
    *,
    event: int,
    port: int,
    num_want: int = TRACKER_NUM_WANT_DEFAULT,
) -> bytes:
    """Erstellt einen validierten BEP-15-Announce ohne Transferzaehler."""
    for name, value, maximum in (
        ("connection_id", connection_id, 0xFFFF_FFFF_FFFF_FFFF),
        ("transaction_id", transaction_id, 0xFFFF_FFFF),
        ("key", key, 0xFFFF_FFFF),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} muss eine ganze Zahl sein.")
        if not 0 <= value <= maximum:
            raise ValueError(f"{name} liegt ausserhalb des Protokollbereichs.")
    if not isinstance(info_hash, bytes) or len(info_hash) != 20:
        raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")
    if not isinstance(peer_id, bytes) or len(peer_id) != 20:
        raise ValueError("Tracker-Peer-ID muss genau 20 Byte lang sein.")
    if event not in {TRACKER_EVENT_STARTED, TRACKER_EVENT_STOPPED}:
        raise ValueError("Tracker-Ereignis muss started oder stopped sein.")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("Tracker-Announce-Port muss zwischen 1 und 65535 liegen.")
    if (
        isinstance(num_want, bool)
        or not isinstance(num_want, int)
        or not -1 <= num_want <= 0x7FFF_FFFF
    ):
        raise ValueError("num_want liegt ausserhalb des BEP-15-Bereichs.")

    packet = struct.pack(
        "!QII20s20sQQQIIIiH",
        connection_id,
        TRACKER_ACTION_ANNOUNCE,
        transaction_id,
        info_hash,
        peer_id,
        0,  # downloaded
        TRACKER_LEFT_UNKNOWN,
        0,  # uploaded
        event,
        0,  # Tracker soll die Quell-IP des UDP-Pakets verwenden.
        key,
        num_want,
        port,
    )
    if len(packet) != ANNOUNCE_REQUEST_BYTES:  # pragma: no cover - strukturelle Invariante
        raise AssertionError("Interner Fehler bei der BEP-15-Paketgroesse.")
    return packet


def parse_announce_response(
    packet: bytes,
    *,
    expected_transaction_id: int,
    family: socket.AddressFamily,
) -> tuple[Endpoint, ...]:
    """Dekodiert die kompakte IPv4- oder IPv6-Peerliste einer Antwort."""
    _require_packet(packet)
    if len(packet) < 8:
        raise TrackerProtocolError("UDP-Tracker-Antwort ist zu kurz.")
    action, transaction_id = struct.unpack_from("!II", packet)
    if transaction_id != expected_transaction_id:
        raise TrackerProtocolError("UDP-Tracker-Transaktions-ID stimmt nicht ueberein.")
    if action == TRACKER_ACTION_ERROR:
        raise TrackerProtocolError("UDP-Tracker meldete einen Fehler.")
    if action != TRACKER_ACTION_ANNOUNCE or len(packet) < ANNOUNCE_RESPONSE_HEADER_BYTES:
        raise TrackerProtocolError("UDP-Tracker-Announce-Antwort ist ungueltig.")
    if family == socket.AF_INET:
        address_bytes = 4
    elif family == socket.AF_INET6:
        address_bytes = 16
    else:
        raise ValueError("Tracker-Adressfamilie muss IPv4 oder IPv6 sein.")

    peer_bytes = address_bytes + 2
    compact_peers = packet[ANNOUNCE_RESPONSE_HEADER_BYTES:]
    if len(compact_peers) % peer_bytes:
        raise TrackerProtocolError("Kompakte UDP-Tracker-Peerliste hat eine ungueltige Laenge.")

    peers: list[Endpoint] = []
    for offset in range(0, len(compact_peers), peer_bytes):
        encoded_ip = compact_peers[offset : offset + address_bytes]
        port = int.from_bytes(
            compact_peers[offset + address_bytes : offset + peer_bytes],
            "big",
        )
        ip = socket.inet_ntop(family, encoded_ip)
        endpoint = normalize_global_endpoint(ip, port)
        if endpoint is not None:
            peers.append(endpoint)
    return tuple(peers)


def _require_packet(packet: bytes) -> None:
    if not isinstance(packet, bytes):
        raise TypeError("UDP-Tracker-Paket muss eine Bytefolge sein.")
    if not packet or len(packet) > MAX_TRACKER_RESPONSE_BYTES:
        raise TrackerProtocolError("UDP-Tracker-Antwort hat eine unzulaessige Groesse.")


async def iter_resolved_tracker_endpoints(
    tracker: TrackerURL,
    *,
    timeout: float,
) -> AsyncIterator[Endpoint]:
    """Loest einen Tracker zeitbegrenzt auf und liefert jede eindeutige globale IP."""
    if not isinstance(tracker, TrackerURL):
        raise TypeError("tracker muss ein TrackerURL sein.")
    normalized_timeout = _require_timeout(timeout)
    numeric = normalize_global_endpoint(tracker.host, tracker.port)
    if numeric is not None:
        yield numeric
        return
    try:
        ipaddress.ip_address(tracker.host)
    except ValueError:
        pass
    else:
        return

    loop = asyncio.get_running_loop()
    addresses = await asyncio.wait_for(
        loop.getaddrinfo(
            tracker.host,
            tracker.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        ),
        timeout=normalized_timeout,
    )
    seen: set[Endpoint] = set()
    for family, sock_type, protocol, _canonical_name, sockaddr in addresses:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        if sock_type != socket.SOCK_DGRAM or protocol not in {0, socket.IPPROTO_UDP}:
            continue
        endpoint = normalize_global_endpoint(str(sockaddr[0]), int(sockaddr[1]))
        if endpoint is None or endpoint in seen:
            continue
        seen.add(endpoint)
        yield endpoint


async def resolve_tracker(
    tracker: TrackerURL,
    *,
    timeout: float,
) -> tuple[Endpoint, ...]:
    """Kompatibilitaetshelfer, der alle aufgeloesten Tracker-Endpunkte sammelt."""
    endpoints: list[Endpoint] = []
    async for endpoint in iter_resolved_tracker_endpoints(
        tracker,
        timeout=timeout,
    ):
        endpoints.append(endpoint)
    return tuple(endpoints)


async def _announce_to_endpoint(
    target: Target,
    tracker: Endpoint,
    *,
    timeout: float,
    peer_id: bytes,
    exchange_hook: ExchangeHook | None = None,
    transaction_id_factory: Callable[[], int] | None = None,
    key_factory: Callable[[], int] | None = None,
    announce_port_factory: Callable[[], int] | None = None,
    exchange_attempts: int = TRACKER_EXCHANGE_ATTEMPTS,
    retry_backoff_seconds: float = TRACKER_RETRY_BACKOFF_SECONDS,
) -> TrackerAnnounceResponse:
    """Ermittelt Peers und entfernt danach bestmoeglich den Tracker-Eintrag."""
    if not isinstance(target, Target):
        raise TypeError("target muss ein Target sein.")
    if not isinstance(target.info_hash, bytes) or len(target.info_hash) != 20:
        raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")
    normalized_tracker = normalize_global_endpoint(*tracker)
    if normalized_tracker is None:
        raise ValueError("Tracker-Endpunkt muss eine globale numerische IP enthalten.")
    normalized_timeout = _require_timeout(timeout)
    if not isinstance(peer_id, bytes) or len(peer_id) != 20:
        raise ValueError("Tracker-Peer-ID muss genau 20 Byte lang sein.")
    if (
        isinstance(exchange_attempts, bool)
        or not isinstance(exchange_attempts, int)
        or not 1 <= exchange_attempts <= 5
    ):
        raise ValueError("exchange_attempts muss zwischen 1 und 5 liegen.")
    if (
        isinstance(retry_backoff_seconds, bool)
        or not isinstance(retry_backoff_seconds, (int, float))
        or not 0.0 <= float(retry_backoff_seconds) <= MAX_TRACKER_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "retry_backoff_seconds muss zwischen 0 und "
            f"{MAX_TRACKER_TIMEOUT_SECONDS:.1f} Sekunden liegen."
        )
    normalized_backoff = float(retry_backoff_seconds)

    address = ipaddress.ip_address(normalized_tracker[0])
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    transaction_factory = transaction_id_factory or (lambda: secrets.randbits(32))
    make_key = key_factory or (lambda: secrets.randbits(32))
    make_port = announce_port_factory or (lambda: secrets.randbelow(65_535) + 1)
    connect_transaction = _new_uint32(transaction_factory, "transaction_id_factory")
    started_transaction = _new_uint32(transaction_factory, "transaction_id_factory")
    key = _new_uint32(make_key, "key_factory")
    announce_port = _new_announce_port(make_port)

    udp_socket: socket.socket | None = None
    loop = asyncio.get_running_loop()
    if exchange_hook is None:
        udp_socket = socket.socket(family, socket.SOCK_DGRAM)
        try:
            udp_socket.setblocking(False)
            sockaddr: tuple[Any, ...]
            sockaddr = (
                (normalized_tracker[0], normalized_tracker[1], 0, 0)
                if family == socket.AF_INET6
                else normalized_tracker
            )
            await asyncio.wait_for(
                loop.sock_connect(udp_socket, sockaddr),
                timeout=normalized_timeout,
            )
        except BaseException:
            udp_socket.close()
            raise

    async def exchange(payload: bytes) -> bytes:
        if exchange_hook is not None:
            response = await exchange_hook(normalized_tracker, payload)
        else:
            if udp_socket is None:  # pragma: no cover - Typ-Invariante
                raise AssertionError("UDP-Socket wurde nicht initialisiert.")
            await loop.sock_sendall(udp_socket, payload)
            response = await loop.sock_recv(udp_socket, MAX_TRACKER_RESPONSE_BYTES + 1)
        _require_packet(response)
        return response

    async def exchange_with_retries(
        payload: bytes,
        validator: Callable[[bytes], object] | None = None,
    ) -> bytes:
        for attempt in range(exchange_attempts):
            try:
                response = await asyncio.wait_for(
                    exchange(payload),
                    timeout=normalized_timeout,
                )
                if validator is not None:
                    validator(response)
                return response
            except (TimeoutError, OSError, TrackerProtocolError):
                if attempt + 1 >= exchange_attempts:
                    raise
                if normalized_backoff:
                    await asyncio.sleep(min(normalized_backoff * (2**attempt), normalized_timeout))
        raise AssertionError("Tracker-Retryschleife endete ohne Ergebnis.")

    try:
        connect_packet = build_connect_request(connect_transaction)
        connect_response = await exchange_with_retries(
            connect_packet,
            lambda response: parse_connect_response(
                response,
                expected_transaction_id=connect_transaction,
            ),
        )
        connection_id = parse_connect_response(
            connect_response,
            expected_transaction_id=connect_transaction,
        )

        started_packet = build_announce_request(
            connection_id,
            started_transaction,
            target.info_hash,
            peer_id,
            key,
            event=TRACKER_EVENT_STARTED,
            port=announce_port,
        )
        cleanup_failed = False
        try:
            started_response = await exchange_with_retries(
                started_packet,
                lambda response: parse_announce_response(
                    response,
                    expected_transaction_id=started_transaction,
                    family=family,
                ),
            )
            peers = parse_announce_response(
                started_response,
                expected_transaction_id=started_transaction,
                family=family,
            )
        finally:
            try:
                stopped_transaction = _new_uint32(
                    transaction_factory,
                    "transaction_id_factory",
                )
                stopped_packet = build_announce_request(
                    connection_id,
                    stopped_transaction,
                    target.info_hash,
                    peer_id,
                    key,
                    event=TRACKER_EVENT_STOPPED,
                    port=announce_port,
                    num_want=TRACKER_NUM_WANT_NONE,
                )
                stopped_response = await asyncio.wait_for(
                    exchange(stopped_packet),
                    timeout=normalized_timeout,
                )
                parse_announce_response(
                    stopped_response,
                    expected_transaction_id=stopped_transaction,
                    family=family,
                )
            except (TimeoutError, OSError, TrackerProtocolError) as exc:
                cleanup_failed = True
                LOGGER.warning(
                    "UDP-Tracker-STOPPED-Aufraeumen fehlgeschlagen (%s).",
                    type(exc).__name__,
                )

        return TrackerAnnounceResponse(
            tracker=normalized_tracker,
            transaction_id=started_transaction,
            peers=peers,
            response_sha256=hashlib.sha256(started_response).hexdigest(),
            cleanup_failed=cleanup_failed,
        )
    finally:
        if udp_socket is not None:
            udp_socket.close()


def _new_uint32(factory: Callable[[], int], name: str) -> int:
    value = factory()
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF:
        raise ValueError(f"{name} muss uint32-Werte liefern.")
    return value


def _new_announce_port(factory: Callable[[], int]) -> int:
    value = factory()
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_535:
        raise ValueError("announce_port_factory muss Ports von 1 bis 65535 liefern.")
    return value


async def discover_tracker_peers(
    target: Target,
    tracker_urls: Iterable[str],
    *,
    timeout: float,
    candidate_callback: CandidateBatchHook | None,
    collect: bool = False,
    stats: TrackerDiscoveryStats | None = None,
) -> list[PeerCandidate]:
    """Fragt UDP-Tracker parallel ab und streamt Kandidaten seriell.

    ``collect=False`` behaelt weder eine Kandidatenliste noch ein laufweites
    Peer-Deduplizierungsset im Speicher. Wiederholte Nennungen werden deshalb
    ebenfalls an den Callback weitergereicht und koennen beim persistenten
    Schreiben dedupliziert werden. Im expliziten Kompatibilitaetsmodus
    ``collect=True`` werden eindeutige Kandidaten gesammelt und zurueckgegeben.
    Die begrenzte Parallelitaet ist nur eine Arbeitsbreite und kein Mengenlimit.
    """
    if not isinstance(target, Target):
        raise TypeError("target muss ein Target sein.")
    if not isinstance(target.info_hash, bytes) or len(target.info_hash) != 20:
        raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")
    normalized_timeout = _require_timeout(timeout)
    if candidate_callback is not None and not callable(candidate_callback):
        raise TypeError("candidate_callback muss aufrufbar sein.")
    if not isinstance(collect, bool):
        raise TypeError("collect muss ein boolescher Wert sein.")
    if not collect and candidate_callback is None:
        raise ValueError("collect=False erfordert einen candidate_callback.")
    if stats is not None and not isinstance(stats, TrackerDiscoveryStats):
        raise TypeError("stats muss TrackerDiscoveryStats sein.")

    trackers = tuple(parse_tracker_url(value) for value in tracker_urls)
    if stats is not None:
        stats.trackers_configured += len(trackers)
    peer_id = secrets.token_bytes(20)
    candidates: list[PeerCandidate] = []
    collected_endpoints: set[Endpoint] | None = set() if collect else None
    callback_batch: list[PeerCandidate] = []
    response_queue: asyncio.Queue[TrackerAnnounceResponse | None] = asyncio.Queue(
        maxsize=TRACKER_DISCOVERY_CONCURRENCY * 2
    )
    query_semaphore = asyncio.Semaphore(TRACKER_DISCOVERY_CONCURRENCY)
    resolver_semaphore = asyncio.Semaphore(TRACKER_DISCOVERY_CONCURRENCY)

    async def query_endpoint(tracker_endpoint: Endpoint) -> None:
        async with query_semaphore:
            if stats is not None:
                stats.endpoints_attempted += 1
            try:
                response = await _announce_to_endpoint(
                    target,
                    tracker_endpoint,
                    timeout=normalized_timeout,
                    peer_id=peer_id,
                )
            except (TimeoutError, OSError, TrackerProtocolError) as exc:
                LOGGER.warning(
                    "UDP-Tracker-Anfrage fehlgeschlagen (%s).",
                    type(exc).__name__,
                )
                if stats is not None:
                    stats.queries_failed += 1
                return
            if stats is not None:
                stats.queries_completed += 1
                if response.cleanup_failed:
                    stats.stop_queries_failed += 1
            await response_queue.put(response)

    async def query_tracker(tracker_url: TrackerURL) -> None:
        endpoint_tasks: list[asyncio.Task[None]] = []
        resolution_failed = False
        try:
            try:
                async with resolver_semaphore:
                    async for tracker_endpoint in iter_resolved_tracker_endpoints(
                        tracker_url,
                        timeout=normalized_timeout,
                    ):
                        endpoint_tasks.append(asyncio.create_task(query_endpoint(tracker_endpoint)))
            except (TimeoutError, socket.gaierror, OSError) as exc:
                resolution_failed = True
                LOGGER.warning(
                    "UDP-Tracker-DNS-Aufloesung fehlgeschlagen (%s).",
                    type(exc).__name__,
                )
                if stats is not None:
                    stats.queries_failed += 1

            if not endpoint_tasks:
                if not resolution_failed:
                    LOGGER.warning("UDP-Tracker hat keine global erreichbare Adresse.")
                    if stats is not None:
                        stats.queries_failed += 1
                return
            await asyncio.gather(*endpoint_tasks)
        except BaseException:
            for task in endpoint_tasks:
                task.cancel()
            await asyncio.gather(*endpoint_tasks, return_exceptions=True)
            raise

    producer_tasks = [asyncio.create_task(query_tracker(tracker)) for tracker in trackers]

    async def supervise_producers() -> None:
        outcomes = await asyncio.gather(*producer_tasks, return_exceptions=True)
        await response_queue.put(None)
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                raise outcome

    supervisor = asyncio.create_task(supervise_producers())
    failure: BaseException | None = None
    try:
        while True:
            response = await response_queue.get()
            if response is None:
                break
            observed_at = _utc_now_text()
            for peer_ip, peer_port in response.peers:
                peer_endpoint = normalize_global_endpoint(peer_ip, peer_port)
                if peer_endpoint is None:
                    continue
                if collected_endpoints is not None:
                    if peer_endpoint in collected_endpoints:
                        continue
                    collected_endpoints.add(peer_endpoint)
                candidate = PeerCandidate(
                    target_label=target.label,
                    info_hash_hex=target.info_hash_hex,
                    ip=peer_endpoint[0],
                    port=peer_endpoint[1],
                    discovered_at_utc=observed_at,
                    dht_node_ip=response.tracker[0],
                    dht_node_port=response.tracker[1],
                    transaction_id_hex=response.transaction_id.to_bytes(4, "big").hex(),
                    response_sha256=response.response_sha256,
                    source_note=target.source_note,
                    discovery_source="tracker",
                )
                if collect:
                    candidates.append(candidate)
                if candidate_callback is not None:
                    callback_batch.append(candidate)
                    if len(callback_batch) == CANDIDATE_BATCH_SIZE:
                        await candidate_callback(tuple(callback_batch))
                        callback_batch.clear()
        await supervisor
    except BaseException as exc:
        failure = exc
    finally:
        supervisor.cancel()
        for task in producer_tasks:
            task.cancel()
        await asyncio.gather(supervisor, *producer_tasks, return_exceptions=True)
        if candidate_callback is not None and callback_batch:
            pending_batch = tuple(callback_batch)
            try:
                await candidate_callback(pending_batch)
            except BaseException as flush_error:
                if failure is None or isinstance(flush_error, asyncio.CancelledError):
                    failure = flush_error
                else:
                    failure.add_note(
                        "Der letzte Tracker-Kandidatenbatch konnte nicht persistiert werden: "
                        f"{type(flush_error).__name__}."
                    )
            else:
                callback_batch.clear()

    if failure is not None:
        raise failure
    return candidates
