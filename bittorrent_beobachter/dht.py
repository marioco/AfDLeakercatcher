"""Begrenzte, inhaltsfreie Peer-Suche über BEP 5 und BEP 32."""

from __future__ import annotations

import asyncio
import hashlib
import heapq
import hmac
import ipaddress
import secrets
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .bencode import BencodeDecodeError, BencodeLimits, bdecode, bencode
from .models import PeerCandidate, Target

Endpoint = tuple[str, int]
QueryHook = Callable[[Endpoint, bytes, bytes], Awaitable["DHTResponse"]]
BootstrapIssueHook = Callable[[str], None]

MAX_TIMEOUT_SECONDS = 30.0
MAX_OVERALL_TIMEOUT_SECONDS = 300.0
MAX_QUERIES = 500
MAX_CONCURRENCY = 32
MAX_NODES = 10_000
MAX_CANDIDATES = 5_000
MAX_RESPONSE_BYTES = 65_507
MAX_BOOTSTRAP_NODES = 16
MAX_BOOTSTRAP_RESULTS = 64

BOOTSTRAP_ISSUE_DNS = "dns"
BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS = "no_global_address"
BOOTSTRAP_ISSUE_RESOLVER = "resolver"
BOOTSTRAP_ISSUE_TIMEOUT = "timeout"

DHT_ISSUE_DEADLINE = "deadline"
DHT_ISSUE_NETWORK = "network"
DHT_ISSUE_PROTOCOL = "protocol"
DHT_ISSUE_TIMEOUT = "timeout"

_DHT_ISSUE_MESSAGES = {
    DHT_ISSUE_DEADLINE: "Gesamtzeitlimit der DHT-Suche erreicht.",
    DHT_ISSUE_NETWORK: "DHT-Anfrage scheiterte wegen eines Netzwerkfehlers.",
    DHT_ISSUE_PROTOCOL: "DHT-Antwort verletzte das erwartete Protokollformat.",
    DHT_ISSUE_TIMEOUT: "Zeitueberschreitung bei DHT-Anfrage.",
}


class DHTProtocolError(ValueError):
    """Ein DHT-Paket verletzt das erwartete, begrenzte Protokollformat."""


class DHTQueryError(OSError):
    """Eine einzelne DHT-Anfrage konnte nicht sicher abgeschlossen werden."""

    def __init__(self, message: str, *, category: str = DHT_ISSUE_NETWORK) -> None:
        if category not in _DHT_ISSUE_MESSAGES:
            raise ValueError("Unbekannte DHT-Fehlerkategorie.")
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, slots=True)
class DHTConfig:
    """Harte Laufzeit- und Mengenbegrenzungen eines Suchlaufs."""

    timeout_seconds: float = 2.5
    overall_timeout_seconds: float = 30.0
    max_queries: int = 80
    concurrency: int = 8
    max_nodes: int = 1_000
    max_candidates: int = 300
    max_response_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        _require_bounded_number("timeout_seconds", self.timeout_seconds, 0.1, MAX_TIMEOUT_SECONDS)
        _require_bounded_number(
            "overall_timeout_seconds",
            self.overall_timeout_seconds,
            0.1,
            MAX_OVERALL_TIMEOUT_SECONDS,
        )
        _require_bounded_integer("max_queries", self.max_queries, 1, MAX_QUERIES)
        _require_bounded_integer("concurrency", self.concurrency, 1, MAX_CONCURRENCY)
        _require_bounded_integer("max_nodes", self.max_nodes, 1, MAX_NODES)
        _require_bounded_integer("max_candidates", self.max_candidates, 1, MAX_CANDIDATES)
        _require_bounded_integer(
            "max_response_bytes", self.max_response_bytes, 512, MAX_RESPONSE_BYTES
        )


@dataclass(frozen=True, slots=True)
class DHTNode:
    """Ein validierter, global erreichbarer DHT-Knoten."""

    node_id: bytes
    ip: str
    port: int

    @property
    def endpoint(self) -> Endpoint:
        return self.ip, self.port


@dataclass(frozen=True, slots=True)
class DHTResponse:
    """Validierter, auf beweisrelevante Metadaten reduzierter DHT-Reply."""

    source: Endpoint
    transaction_id: bytes
    nodes: tuple[DHTNode, ...]
    peers: tuple[Endpoint, ...]
    response_sha256: str


def _require_bounded_integer(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} muss eine ganze Zahl sein.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} muss zwischen {minimum} und {maximum} liegen.")


def _require_bounded_number(
    name: str,
    value: float,
    minimum: float,
    maximum: float,
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} muss eine Zahl sein.")
    if not minimum <= float(value) <= maximum:
        raise ValueError(f"{name} muss zwischen {minimum} und {maximum} liegen.")


def utc_now_text() -> str:
    """Liefert einen stabilen UTC-Zeitstempel für Evidenzdatensätze."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_global_endpoint(ip: str, port: int) -> Endpoint | None:
    """Normalisiert ausschließlich global routbare numerische IP-Endpunkte."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        return None
    if not isinstance(ip, str) or not ip or "%" in ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return None
    if not address.is_global:
        return None
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
        or address.is_unspecified
    ):
        return None
    return address.compressed, port


def is_global_endpoint(ip: str, port: int) -> bool:
    """Prüft einen Endpunkt ohne DNS-Auflösung auf globale Erreichbarkeit."""
    return normalize_global_endpoint(ip, port) is not None


def _parse_compact_endpoint(value: bytes) -> Endpoint | None:
    if len(value) == 6:
        address = socket.inet_ntop(socket.AF_INET, value[:4])
        port = int.from_bytes(value[4:], "big")
    elif len(value) == 18:
        address = socket.inet_ntop(socket.AF_INET6, value[:16])
        port = int.from_bytes(value[16:], "big")
    else:
        raise DHTProtocolError("Kompakter Peer-Endpunkt muss 6 oder 18 Byte lang sein.")
    return normalize_global_endpoint(address, port)


def parse_compact_peers(values: Any) -> tuple[Endpoint, ...]:
    """Dekodiert die BEP-5/BEP-32-Peerliste für IPv4 und IPv6 strikt."""
    if not isinstance(values, list):
        raise DHTProtocolError("DHT-Feld values muss eine Liste sein.")
    peers: list[Endpoint] = []
    seen: set[Endpoint] = set()
    for value in values:
        if not isinstance(value, bytes):
            raise DHTProtocolError("Ein kompakter Peer-Endpunkt muss eine Bytefolge sein.")
        endpoint = _parse_compact_endpoint(value)
        if endpoint is not None and endpoint not in seen:
            seen.add(endpoint)
            peers.append(endpoint)
    return tuple(peers)


def parse_compact_nodes(value: Any, *, ipv6: bool = False) -> tuple[DHTNode, ...]:
    """Dekodiert kompakte BEP-5- oder BEP-32-Knoteneinträge strikt."""
    if not isinstance(value, bytes):
        raise DHTProtocolError("Kompakte DHT-Knoten müssen als Bytefolge vorliegen.")
    address_length = 16 if ipv6 else 4
    entry_length = 20 + address_length + 2
    if len(value) % entry_length:
        raise DHTProtocolError("Kompakte DHT-Knotenliste hat eine ungültige Länge.")

    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    nodes: list[DHTNode] = []
    seen: set[Endpoint] = set()
    for offset in range(0, len(value), entry_length):
        node_id = value[offset : offset + 20]
        address_start = offset + 20
        address_end = address_start + address_length
        address = socket.inet_ntop(family, value[address_start:address_end])
        port = int.from_bytes(value[address_end : address_end + 2], "big")
        endpoint = normalize_global_endpoint(address, port)
        if endpoint is None or endpoint in seen:
            continue
        seen.add(endpoint)
        nodes.append(DHTNode(node_id=node_id, ip=endpoint[0], port=endpoint[1]))
    return tuple(nodes)


def build_get_peers_query(
    node_id: bytes,
    info_hash: bytes,
    transaction_id: bytes,
) -> bytes:
    """Erstellt ausschließlich eine kanonische BEP-5-get_peers-Anfrage."""
    if not isinstance(node_id, bytes) or len(node_id) != 20:
        raise ValueError("DHT-Knoten-ID muss genau 20 Byte lang sein.")
    if not isinstance(info_hash, bytes) or len(info_hash) != 20:
        raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")
    if not isinstance(transaction_id, bytes) or not 1 <= len(transaction_id) <= 8:
        raise ValueError("DHT-Transaktions-ID muss zwischen 1 und 8 Byte lang sein.")
    return bencode(
        {
            b"a": {
                b"id": node_id,
                b"info_hash": info_hash,
                b"want": [b"n4", b"n6"],
            },
            b"q": b"get_peers",
            b"t": transaction_id,
            b"y": b"q",
        }
    )


def parse_get_peers_response(
    packet: bytes,
    *,
    expected_transaction_id: bytes,
    source: Endpoint,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> DHTResponse:
    """Validiert eine einzelne Antwort samt Quelle, Transaktion und Hash."""
    if not isinstance(expected_transaction_id, bytes) or not 1 <= len(expected_transaction_id) <= 8:
        raise ValueError("Erwartete DHT-Transaktions-ID muss 1 bis 8 Byte lang sein.")
    _require_bounded_integer("max_response_bytes", max_response_bytes, 512, MAX_RESPONSE_BYTES)
    normalized_source = normalize_global_endpoint(*source)
    if normalized_source is None:
        raise DHTProtocolError("DHT-Antwort stammt nicht von einem globalen Endpunkt.")
    if not isinstance(packet, bytes):
        raise TypeError("packet muss bytes sein.")
    if not packet or len(packet) > max_response_bytes:
        raise DHTProtocolError("DHT-Antwort hat eine unzulässige Größe.")

    limits = BencodeLimits(
        max_payload_bytes=max_response_bytes,
        max_depth=8,
        max_items=20_000,
        max_string_length=max_response_bytes,
        max_integer_digits=32,
    )
    try:
        message = bdecode(packet, limits=limits)
    except BencodeDecodeError as exc:
        raise DHTProtocolError(f"Ungültiges Bencode in DHT-Antwort: {exc}") from exc
    if not isinstance(message, dict):
        raise DHTProtocolError("DHT-Antwort muss ein Wörterbuch sein.")

    transaction_id = message.get(b"t")
    if not isinstance(transaction_id, bytes) or not hmac.compare_digest(
        transaction_id, expected_transaction_id
    ):
        raise DHTProtocolError("DHT-Transaktions-ID stimmt nicht überein.")
    if message.get(b"y") != b"r":
        raise DHTProtocolError("DHT-Paket ist keine erfolgreiche Antwort.")
    response = message.get(b"r")
    if not isinstance(response, dict):
        raise DHTProtocolError("DHT-Antwort enthält kein gültiges r-Wörterbuch.")
    responder_id = response.get(b"id")
    if not isinstance(responder_id, bytes) or len(responder_id) != 20:
        raise DHTProtocolError("DHT-Antwort enthält keine gültige Knoten-ID.")

    nodes: list[DHTNode] = []
    if b"nodes" in response:
        nodes.extend(parse_compact_nodes(response[b"nodes"], ipv6=False))
    if b"nodes6" in response:
        nodes.extend(parse_compact_nodes(response[b"nodes6"], ipv6=True))

    peers: tuple[Endpoint, ...] = ()
    if b"values" in response:
        peers = parse_compact_peers(response[b"values"])
    return DHTResponse(
        source=normalized_source,
        transaction_id=transaction_id,
        nodes=tuple(nodes),
        peers=peers,
        response_sha256=hashlib.sha256(packet).hexdigest(),
    )


async def resolve_bootstrap_nodes(
    nodes: Iterable[Endpoint],
    *,
    timeout: float = 5.0,
    max_results: int = 32,
    issue_hook: BootstrapIssueHook | None = None,
) -> list[Endpoint]:
    """Löst eine kleine Bootstrap-Liste auf und verwirft nichtglobale Ziele."""
    _require_bounded_number("timeout", timeout, 0.1, MAX_TIMEOUT_SECONDS)
    _require_bounded_integer("max_results", max_results, 1, MAX_BOOTSTRAP_RESULTS)
    if issue_hook is not None and not callable(issue_hook):
        raise TypeError("issue_hook muss aufrufbar sein.")

    requested: list[Endpoint] = []
    for raw in nodes:
        if len(requested) >= MAX_BOOTSTRAP_NODES:
            raise ValueError("Zu viele Bootstrap-Knoten.")
        if not isinstance(raw, tuple) or len(raw) != 2:
            raise ValueError("Bootstrap-Endpunkt muss ein Tupel aus Host und Port sein.")
        host, port = raw
        if not isinstance(host, str) or not host or len(host) > 253:
            raise ValueError("Bootstrap-Host ist ungültig.")
        if any(character.isspace() for character in host):
            raise ValueError("Bootstrap-Host darf keine Leerzeichen enthalten.")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("Bootstrap-Port ist ungültig.")
        requested.append((host, port))
    if not requested:
        raise ValueError("Mindestens ein Bootstrap-Knoten ist erforderlich.")

    loop = asyncio.get_running_loop()

    async def resolve_one(host: str, port: int) -> list[Endpoint]:
        numeric = normalize_global_endpoint(host, port)
        if numeric is not None:
            return [numeric]
        try:
            is_numeric_address = ipaddress.ip_address(host) is not None
        except ValueError:
            is_numeric_address = False
        if is_numeric_address:
            return []

        addresses = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
        results: list[Endpoint] = []
        for _family, _type, _proto, _canonical_name, sockaddr in addresses:
            endpoint = normalize_global_endpoint(str(sockaddr[0]), int(sockaddr[1]))
            if endpoint is not None:
                results.append(endpoint)
        return results

    tasks = [asyncio.create_task(resolve_one(host, port)) for host, port in requested]
    completed: set[asyncio.Task[list[Endpoint]]] = set()
    pending: set[asyncio.Task[list[Endpoint]]] = set(tasks)
    try:
        completed, pending = await asyncio.wait(
            tasks,
            timeout=float(timeout),
            return_when=asyncio.ALL_COMPLETED,
        )
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def report_issue(category: str) -> None:
        if issue_hook is not None:
            issue_hook(category)

    resolved_groups: list[list[Endpoint]] = []
    for task in tasks:
        if task not in completed:
            report_issue(BOOTSTRAP_ISSUE_TIMEOUT)
            continue
        try:
            group = task.result()
        except socket.gaierror:
            report_issue(BOOTSTRAP_ISSUE_DNS)
            continue
        except OSError:
            report_issue(BOOTSTRAP_ISSUE_RESOLVER)
            continue
        except (Exception, asyncio.CancelledError):
            report_issue(BOOTSTRAP_ISSUE_RESOLVER)
            continue
        if not group:
            report_issue(BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS)
            continue
        resolved_groups.append(group)

    resolved: list[Endpoint] = []
    seen: set[Endpoint] = set()
    for group in resolved_groups:
        for endpoint in group:
            if endpoint not in seen:
                seen.add(endpoint)
                resolved.append(endpoint)
                if len(resolved) >= max_results:
                    return resolved
    return resolved


class DHTCrawler:
    """Iterative, mengenbegrenzte Suche nach Peers eines einzelnen Infohashes."""

    def __init__(
        self,
        bootstrap_nodes: Iterable[Endpoint],
        *,
        node_id: bytes | None = None,
        config: DHTConfig | None = None,
        query_hook: QueryHook | None = None,
        transaction_id_factory: Callable[[], bytes] | None = None,
        clock: Callable[[], str] = utc_now_text,
    ) -> None:
        self.config = config or DHTConfig()
        self.node_id = node_id if node_id is not None else secrets.token_bytes(20)
        if not isinstance(self.node_id, bytes) or len(self.node_id) != 20:
            raise ValueError("DHT-Knoten-ID muss genau 20 Byte lang sein.")
        self.bootstrap_nodes = tuple(self._validated_bootstrap(bootstrap_nodes))
        self.query_hook = query_hook
        self.transaction_id_factory = transaction_id_factory or (lambda: secrets.token_bytes(4))
        self.clock = clock
        self.errors: tuple[str, ...] = ()
        self.issue_counts: dict[str, int] = {}
        self.queries_started = 0
        self.queries_completed = 0
        self.queries_failed = 0

    @property
    def issue_count(self) -> int:
        """Liefert die ungekürzte Zahl technischer DHT-Teilfehler."""
        return sum(self.issue_counts.values())

    def _record_issue(self, errors: list[str], category: str) -> None:
        if category not in _DHT_ISSUE_MESSAGES:
            category = DHT_ISSUE_PROTOCOL
        self.issue_counts[category] = self.issue_counts.get(category, 0) + 1
        if len(errors) < 100:
            errors.append(_DHT_ISSUE_MESSAGES[category])

    def _validated_bootstrap(self, nodes: Iterable[Endpoint]) -> list[Endpoint]:
        normalized: list[Endpoint] = []
        seen: set[Endpoint] = set()
        for index, raw in enumerate(nodes):
            if index >= MAX_BOOTSTRAP_RESULTS:
                raise ValueError("Zu viele aufgelöste Bootstrap-Endpunkte.")
            if not isinstance(raw, tuple) or len(raw) != 2:
                raise ValueError("Bootstrap-Endpunkt muss ein Tupel aus IP und Port sein.")
            endpoint = normalize_global_endpoint(raw[0], raw[1])
            if endpoint is None:
                raise ValueError("Bootstrap-Endpunkte müssen globale numerische IPs sein.")
            if endpoint not in seen:
                seen.add(endpoint)
                normalized.append(endpoint)
        if not normalized:
            raise ValueError("Mindestens ein globaler Bootstrap-Endpunkt ist erforderlich.")
        if len(normalized) > MAX_BOOTSTRAP_RESULTS:
            raise ValueError("Zu viele aufgelöste Bootstrap-Endpunkte.")
        if len(normalized) > self.config.max_nodes:
            raise ValueError("Mehr Bootstrap-Endpunkte als erlaubte DHT-Knoten.")
        return normalized

    async def _query_node(
        self,
        endpoint: Endpoint,
        info_hash: bytes,
        transaction_id: bytes,
    ) -> DHTResponse:
        if self.query_hook is not None:
            try:
                return await asyncio.wait_for(
                    self.query_hook(endpoint, info_hash, transaction_id),
                    timeout=self.config.timeout_seconds,
                )
            except DHTQueryError:
                raise
            except TimeoutError as exc:
                raise DHTQueryError(
                    "DHT-Anfrage überschritt ihr Zeitlimit.", category=DHT_ISSUE_TIMEOUT
                ) from exc
            except DHTProtocolError as exc:
                raise DHTQueryError("Ungültige DHT-Antwort.", category=DHT_ISSUE_PROTOCOL) from exc
            except OSError as exc:
                raise DHTQueryError("DHT-Netzwerkfehler.", category=DHT_ISSUE_NETWORK) from exc

        query = build_get_peers_query(self.node_id, info_hash, transaction_id)
        address = ipaddress.ip_address(endpoint[0])
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sockaddr: tuple[Any, ...]
        sockaddr = (endpoint[0], endpoint[1], 0, 0) if family == socket.AF_INET6 else endpoint

        async def exchange() -> DHTResponse:
            loop = asyncio.get_running_loop()
            udp_socket = socket.socket(family, socket.SOCK_DGRAM)
            try:
                udp_socket.setblocking(False)
                await loop.sock_connect(udp_socket, sockaddr)
                await loop.sock_sendall(udp_socket, query)
                packet, source_address = await loop.sock_recvfrom(
                    udp_socket, self.config.max_response_bytes + 1
                )
            finally:
                udp_socket.close()
            if len(packet) > self.config.max_response_bytes:
                raise DHTProtocolError("DHT-Antwort überschreitet die Paketgrenze.")
            source = normalize_global_endpoint(str(source_address[0]), int(source_address[1]))
            if source != endpoint:
                raise DHTProtocolError("DHT-Antwort stammt von einem anderen Endpunkt.")
            return parse_get_peers_response(
                packet,
                expected_transaction_id=transaction_id,
                source=source,
                max_response_bytes=self.config.max_response_bytes,
            )

        try:
            return await asyncio.wait_for(exchange(), self.config.timeout_seconds)
        except TimeoutError as exc:
            raise DHTQueryError(
                "DHT-Anfrage überschritt ihr Zeitlimit.", category=DHT_ISSUE_TIMEOUT
            ) from exc
        except DHTProtocolError as exc:
            raise DHTQueryError("Ungültige DHT-Antwort.", category=DHT_ISSUE_PROTOCOL) from exc
        except OSError as exc:
            raise DHTQueryError("DHT-Netzwerkfehler.", category=DHT_ISSUE_NETWORK) from exc

    def _new_transaction_id(self) -> bytes:
        transaction_id = self.transaction_id_factory()
        if not isinstance(transaction_id, bytes) or not 1 <= len(transaction_id) <= 8:
            raise ValueError("transaction_id_factory muss eine Bytefolge mit 1 bis 8 Byte liefern.")
        return transaction_id

    async def discover(self, target: Target) -> list[PeerCandidate]:
        """Durchläuft zurückgelieferte Knoten nach XOR-Nähe, ohne etwas anzukündigen."""
        if not isinstance(target, Target):
            raise TypeError("target muss ein Target sein.")
        if not isinstance(target.info_hash, bytes) or len(target.info_hash) != 20:
            raise ValueError("BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")

        self.queries_started = 0
        self.queries_completed = 0
        self.queries_failed = 0
        self.issue_counts = {}
        errors: list[str] = []
        candidates: list[PeerCandidate] = []
        candidate_endpoints: set[Endpoint] = set()
        known_nodes: set[Endpoint] = set(self.bootstrap_nodes)
        queued_nodes: set[Endpoint] = set(self.bootstrap_nodes)
        queried_nodes: set[Endpoint] = set()
        queue: list[tuple[int, int, Endpoint]] = []
        serial = 0
        for endpoint in self.bootstrap_nodes:
            heapq.heappush(queue, (-1, serial, endpoint))
            serial += 1

        active: dict[asyncio.Task[DHTResponse], tuple[Endpoint, bytes]] = {}
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.config.overall_timeout_seconds

        try:
            while queue or active:
                while (
                    queue
                    and len(active) < self.config.concurrency
                    and self.queries_started < self.config.max_queries
                    and len(candidates) < self.config.max_candidates
                ):
                    _distance, _serial, endpoint = heapq.heappop(queue)
                    queued_nodes.discard(endpoint)
                    if endpoint in queried_nodes:
                        continue
                    queried_nodes.add(endpoint)
                    transaction_id = self._new_transaction_id()
                    task = asyncio.create_task(
                        self._query_node(endpoint, target.info_hash, transaction_id)
                    )
                    active[task] = (endpoint, transaction_id)
                    self.queries_started += 1

                if not active:
                    break
                remaining = deadline - loop.time()
                if remaining <= 0:
                    self._record_issue(errors, DHT_ISSUE_DEADLINE)
                    break
                done, _pending = await asyncio.wait(
                    active,
                    timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    self._record_issue(errors, DHT_ISSUE_DEADLINE)
                    break

                for task in done:
                    endpoint, expected_transaction_id = active.pop(task)
                    try:
                        response = task.result()
                        if not isinstance(response, DHTResponse):
                            raise DHTProtocolError("DHT-Abfrage lieferte keinen DHTResponse.")
                        if not isinstance(response.source, tuple) or len(response.source) != 2:
                            raise DHTProtocolError("DHT-Antwortquelle ist ungültig.")
                        if normalize_global_endpoint(*response.source) != endpoint:
                            raise DHTProtocolError("DHT-Antwortquelle stimmt nicht überein.")
                        if not isinstance(
                            response.transaction_id, bytes
                        ) or not hmac.compare_digest(
                            response.transaction_id, expected_transaction_id
                        ):
                            raise DHTProtocolError("DHT-Transaktions-ID stimmt nicht überein.")
                        if (
                            not isinstance(response.response_sha256, str)
                            or len(response.response_sha256) != 64
                            or any(
                                character not in "0123456789abcdef"
                                for character in response.response_sha256
                            )
                        ):
                            raise DHTProtocolError("DHT-Antworthash ist ungültig.")
                    except DHTQueryError as exc:
                        self.queries_failed += 1
                        self._record_issue(errors, exc.category)
                        continue
                    except DHTProtocolError:
                        self.queries_failed += 1
                        self._record_issue(errors, DHT_ISSUE_PROTOCOL)
                        continue
                    except OSError:
                        self.queries_failed += 1
                        self._record_issue(errors, DHT_ISSUE_NETWORK)
                        continue
                    self.queries_completed += 1

                    observed_at = self.clock()
                    for peer_ip, peer_port in response.peers:
                        if len(candidates) >= self.config.max_candidates:
                            break
                        peer_endpoint = normalize_global_endpoint(peer_ip, peer_port)
                        if peer_endpoint is None:
                            continue
                        peer_ip, peer_port = peer_endpoint
                        if peer_endpoint in candidate_endpoints:
                            continue
                        candidate_endpoints.add(peer_endpoint)
                        candidates.append(
                            PeerCandidate(
                                target_label=target.label,
                                info_hash_hex=target.info_hash_hex,
                                ip=peer_ip,
                                port=peer_port,
                                discovered_at_utc=observed_at,
                                dht_node_ip=response.source[0],
                                dht_node_port=response.source[1],
                                transaction_id_hex=response.transaction_id.hex(),
                                response_sha256=response.response_sha256,
                                source_note=target.source_note,
                            )
                        )
                        if len(candidates) >= self.config.max_candidates:
                            break

                    for node in response.nodes:
                        if len(known_nodes) >= self.config.max_nodes:
                            break
                        if (
                            not isinstance(node, DHTNode)
                            or not isinstance(node.node_id, bytes)
                            or len(node.node_id) != 20
                        ):
                            continue
                        node_endpoint = normalize_global_endpoint(node.ip, node.port)
                        if node_endpoint is None:
                            continue
                        if (
                            node_endpoint in known_nodes
                            or node_endpoint in queried_nodes
                            or node_endpoint in queued_nodes
                        ):
                            continue
                        known_nodes.add(node_endpoint)
                        queued_nodes.add(node_endpoint)
                        distance = int.from_bytes(node.node_id, "big") ^ int.from_bytes(
                            target.info_hash, "big"
                        )
                        heapq.heappush(queue, (distance, serial, node_endpoint))
                        serial += 1

                if (self.queries_started >= self.config.max_queries and not active) or len(
                    candidates
                ) >= self.config.max_candidates:
                    break
        finally:
            for task in active:
                task.cancel()
            if active:
                await asyncio.gather(*active, return_exceptions=True)
            self.errors = tuple(errors)

        return candidates


async def discover_peers(
    target: Target,
    bootstrap_nodes: Iterable[Endpoint],
    *,
    node_id: bytes | None = None,
    config: DHTConfig | None = None,
) -> list[PeerCandidate]:
    """Löst Bootstrap-Hosts auf und führt genau einen begrenzten Suchlauf aus."""
    active_config = config or DHTConfig()
    resolved = await resolve_bootstrap_nodes(
        bootstrap_nodes,
        timeout=min(active_config.timeout_seconds, 5.0),
        max_results=min(active_config.max_nodes, MAX_BOOTSTRAP_RESULTS),
    )
    if not resolved:
        raise DHTQueryError("Kein global erreichbarer Bootstrap-Endpunkt auflösbar.")
    crawler = DHTCrawler(resolved, node_id=node_id, config=active_config)
    return await crawler.discover(target)
