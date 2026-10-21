"""Gemeinsame, unveränderliche Datenmodelle der Anwendung."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

OBSERVATION_ROUNDING_TOLERANCE_SECONDS = 1e-6
OBSERVATION_WALL_CLOCK_TOLERANCE_SECONDS = 2.0
REQUIRED_PEER_OBSERVATION_SECONDS = 60.0
MAX_PEER_PIECE_INDEX = (1 << 32) - 1
MAX_PEER_CONTROL_PAYLOAD_BYTES = 1_048_575
MAX_PEER_OBSERVATION_BYTES = 4_194_304
MAX_PEER_OBSERVATION_MESSAGES = 16_384
MAX_RETAINED_PEER_CONTROL_EVENTS = 512
TERMINAL_PEER_DIAGNOSTIC_KINDS = frozenset(
    {
        "extension_payload_rejected",
        "request_rejected",
        "piece_rejected",
        "unknown_message_rejected",
    }
)


@dataclass(frozen=True, slots=True)
class Target:
    """Ein ausdrücklich konfigurierter BitTorrent-v1-Infohash."""

    label: str
    info_hash: bytes
    source_note: str = ""
    trackers: tuple[str, ...] = ()

    @property
    def info_hash_hex(self) -> str:
        return self.info_hash.hex()


@dataclass(frozen=True, slots=True)
class PeerCandidate:
    """Ein von DHT oder UDP-Tracker genannter öffentlicher Peer-Endpunkt."""

    target_label: str
    info_hash_hex: str
    ip: str
    port: int
    discovered_at_utc: str
    dht_node_ip: str
    dht_node_port: int
    transaction_id_hex: str
    response_sha256: str
    source_note: str = ""
    discovery_source: str = "dht"

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.ip, self.port


@dataclass(frozen=True, slots=True)
class PeerControlEvent:
    """Ein inhaltsfreies, zeitlich eingeordnetes Ereignis des Peer-Protokolls."""

    observed_at_utc: str
    elapsed_seconds: float
    kind: str
    payload_length: int
    piece_index: int | None = None
    non_empty: bool | None = None
    payload_sha256: str | None = None
    set_bits: int | None = None


@dataclass(frozen=True, slots=True)
class PeerAvailabilityObservation:
    """Inhaltsfreie Beobachtung gemeldeter Verfügbarkeit und Freigabe."""

    started_at_utc: str
    ended_at_utc: str
    requested_duration_seconds: float
    duration_seconds: float
    completed_full_window: bool
    interested_sent: bool
    non_empty_bitfield: bool
    have_announced: bool
    piece_availability_announced: bool
    unchoked: bool
    peer_choking_at_end: bool
    unchoked_duration_seconds: float
    messages_received: int
    bytes_received: int
    request_messages_sent: int
    piece_payload_bytes_received: int
    metadata_requests_sent: int
    termination_reason: str
    control_events: tuple[PeerControlEvent, ...]
    error: str | None = None


@dataclass(frozen=True, slots=True)
class HandshakeResult:
    """Resultat von Handshake und optionaler inhaltsfreier Verfügbarkeitsprüfung."""

    candidate: PeerCandidate
    attempted_at_utc: str
    completed_at_utc: str | None
    confirmed: bool
    remote_peer_id_hex: str | None
    reserved_bits_hex: str | None
    local_ip: str | None
    local_port: int | None
    bytes_sent: int
    bytes_received: int
    error: str | None
    availability: PeerAvailabilityObservation | None = None

    @staticmethod
    def _simultaneous_offer_observed(
        observation: PeerAvailabilityObservation,
    ) -> bool:
        """Prüft, ob gemeldete Stücke und UNCHOKE zeitgleich galten.

        Historische Einzelmerkmale reichen nicht: Ein Peer, der zuerst kurz
        UNCHOKE und erst nach einem späteren CHOKE ein BITFIELD sendet, hat zu
        keinem dokumentierten Zeitpunkt Datenanfragen für gemeldete Stücke
        freigegeben.
        """
        peer_choking = True
        pieces_available = False
        bitfield_seen = False
        offer_seen = False
        for event in observation.control_events:
            if event.kind == "unchoke":
                if not HandshakeResult._is_empty_control_event(event):
                    return False
                peer_choking = False
            elif event.kind == "choke":
                if not HandshakeResult._is_empty_control_event(event):
                    return False
                peer_choking = True
            elif event.kind == "have":
                if not HandshakeResult._is_valid_have_event(event):
                    return False
                pieces_available = True
            elif event.kind == "bitfield":
                if bitfield_seen or not HandshakeResult._is_valid_bitfield_event(event):
                    return False
                bitfield_seen = True
                pieces_available = event.non_empty is True
            elif event.kind == "have_none":
                if not HandshakeResult._is_empty_control_event(event):
                    return False
                pieces_available = False
            if pieces_available and not peer_choking:
                offer_seen = True
        return offer_seen

    @staticmethod
    def _is_empty_control_event(event: PeerControlEvent) -> bool:
        return bool(
            type(event.payload_length) is int
            and event.payload_length == 0
            and event.piece_index is None
            and event.non_empty is None
            and event.payload_sha256 is None
            and event.set_bits is None
        )

    @staticmethod
    def _is_valid_have_event(event: PeerControlEvent) -> bool:
        return bool(
            type(event.payload_length) is int
            and event.payload_length == 4
            and type(event.piece_index) is int
            and 0 <= event.piece_index <= MAX_PEER_PIECE_INDEX
            and event.non_empty is None
            and event.payload_sha256 is None
            and event.set_bits is None
        )

    @staticmethod
    def _is_valid_bitfield_event(event: PeerControlEvent) -> bool:
        digest = event.payload_sha256
        return bool(
            type(event.payload_length) is int
            and event.payload_length >= 1
            and event.piece_index is None
            and type(event.non_empty) is bool
            and isinstance(digest, str)
            and len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest)
            and type(event.set_bits) is int
            and 0 <= event.set_bits <= event.payload_length * 8
            and event.non_empty == (event.set_bits > 0)
        )

    @staticmethod
    def _minimum_recorded_control_bytes(
        events: tuple[PeerControlEvent, ...],
    ) -> int | None:
        """Berechnet eine konservative Untergrenze der empfangenen Wire-Bytes."""
        total = 0
        regular_kinds = {
            "choke",
            "unchoke",
            "peer_interested",
            "peer_not_interested",
            "have",
            "bitfield",
            "port",
            "suggest_piece",
            "have_all",
            "have_none",
            "reject_request",
            "allowed_fast",
            "extension_handshake",
        }
        header_only_kinds = {
            "request_rejected",
            "piece_rejected",
            "unknown_message_rejected",
        }
        for event in events:
            if (
                type(event.payload_length) is not int
                or event.payload_length < 0
                or event.payload_length > MAX_PEER_CONTROL_PAYLOAD_BYTES
            ):
                return None
            if event.kind == "keepalive":
                total += 4
            elif event.kind in regular_kinds:
                total += 5 + event.payload_length
            elif event.kind == "extension_payload_rejected":
                total += 6
            elif event.kind in header_only_kinds:
                total += 5
            else:
                return None
        return total

    @staticmethod
    def _wall_clock_duration_is_consistent(
        observation: PeerAvailabilityObservation,
    ) -> bool:
        try:
            started_at = datetime.fromisoformat(observation.started_at_utc.replace("Z", "+00:00"))
            ended_at = datetime.fromisoformat(observation.ended_at_utc.replace("Z", "+00:00"))
            wall_clock_duration = (ended_at - started_at).total_seconds()
        except (AttributeError, TypeError, ValueError):
            return False
        return bool(
            started_at.utcoffset() is not None
            and ended_at.utcoffset() is not None
            and wall_clock_duration >= 0
            and abs(wall_clock_duration - observation.duration_seconds)
            <= OBSERVATION_WALL_CLOCK_TOLERANCE_SECONDS
        )

    @staticmethod
    def _control_event_times_are_consistent(
        observation: PeerAvailabilityObservation,
    ) -> bool:
        try:
            started_at = datetime.fromisoformat(observation.started_at_utc.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            return False
        if started_at.utcoffset() is None:
            return False
        previous_elapsed: float | None = None
        for event in observation.control_events:
            try:
                observed_at = datetime.fromisoformat(event.observed_at_utc.replace("Z", "+00:00"))
                elapsed = float(event.elapsed_seconds)
                wall_clock_elapsed = (observed_at - started_at).total_seconds()
            except (AttributeError, TypeError, ValueError):
                return False
            if (
                observed_at.utcoffset() is None
                or isinstance(event.elapsed_seconds, bool)
                or elapsed < 0
                or (previous_elapsed is not None and elapsed < previous_elapsed)
                or abs(wall_clock_elapsed - elapsed) > OBSERVATION_WALL_CLOCK_TOLERANCE_SECONDS
            ):
                return False
            previous_elapsed = elapsed
        return True

    @property
    def offering_observed(self) -> bool:
        """Ein fehlerfrei über das volle Zeitfenster validierter Angebotsbefund."""
        observation = self.availability
        minimum_control_bytes = (
            self._minimum_recorded_control_bytes(observation.control_events)
            if observation is not None
            else None
        )
        if (
            observation is not None
            and type(observation.messages_received) is int
            and len(observation.control_events)
            == min(observation.messages_received, MAX_RETAINED_PEER_CONTROL_EVENTS)
            and minimum_control_bytes is not None
        ):
            minimum_control_bytes += 4 * (
                observation.messages_received - len(observation.control_events)
            )
        exact_control_bytes = bool(
            observation is not None
            and minimum_control_bytes is not None
            and (
                observation.bytes_received == minimum_control_bytes
                if observation.messages_received <= MAX_RETAINED_PEER_CONTROL_EVENTS
                else observation.bytes_received >= minimum_control_bytes
            )
        )
        return bool(
            self.confirmed
            and self.error is None
            and self.bytes_sent == 73
            and observation is not None
            and self.bytes_received == 68 + observation.bytes_received
            and observation.completed_full_window
            and observation.error is None
            and abs(observation.requested_duration_seconds - REQUIRED_PEER_OBSERVATION_SECONDS)
            <= OBSERVATION_ROUNDING_TOLERANCE_SECONDS
            and observation.duration_seconds + OBSERVATION_ROUNDING_TOLERANCE_SECONDS
            >= observation.requested_duration_seconds
            and self._wall_clock_duration_is_consistent(observation)
            and self._control_event_times_are_consistent(observation)
            and observation.termination_reason == "duration_elapsed"
            and observation.interested_sent
            and observation.piece_availability_announced
            and observation.unchoked
            and type(observation.messages_received) is int
            and 0 <= observation.messages_received <= MAX_PEER_OBSERVATION_MESSAGES
            and len(observation.control_events)
            == min(observation.messages_received, MAX_RETAINED_PEER_CONTROL_EVENTS)
            and type(observation.bytes_received) is int
            and 0 <= observation.bytes_received <= MAX_PEER_OBSERVATION_BYTES
            and minimum_control_bytes is not None
            and exact_control_bytes
            and not any(
                event.kind in TERMINAL_PEER_DIAGNOSTIC_KINDS for event in observation.control_events
            )
            and self._simultaneous_offer_observed(observation)
            and observation.request_messages_sent == 0
            and observation.piece_payload_bytes_received == 0
            and observation.metadata_requests_sent == 0
        )


@dataclass(frozen=True, slots=True)
class NetworkEnrichment:
    """Öffentliche Netzbetreiberangaben, ausdrücklich keine Personenidentität."""

    ip: str
    enriched_at_utc: str
    prefix: str | None = None
    asns: tuple[int, ...] = ()
    holder: str | None = None
    rdap_name: str | None = None
    rdap_handle: str | None = None
    country: str | None = None
    abuse_email: str | None = None
    source_urls: tuple[str, ...] = ()
    source_fetched_at_utc: tuple[tuple[str, str], ...] = ()
    cached_sources: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class VpnClassification:
    """Konservative Einordnung anhand expliziter Präfixe oder Markennamen."""

    status: str
    provider: str | None = None
    reason: str | None = None
    source: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Bestätigte Beobachtung samt Einordnung und Journal-Hash."""

    handshake: HandshakeResult
    enrichment: NetworkEnrichment
    vpn: VpnClassification
    evidence_event_sha256: str


@dataclass(frozen=True, slots=True)
class TargetScanMetrics:
    """Kompakte Fortschritts- und Abschlusszahlen eines einzelnen Infohashes."""

    target_label: str
    info_hash_hex: str
    dht_queries_started: int = 0
    dht_queries_completed: int = 0
    dht_queries_failed: int = 0
    tracker_queries_completed: int = 0
    tracker_queries_failed: int = 0
    candidates_discovered: int = 0
    candidates_checked: int = 0
    verification_attempts: int = 0
    confirmed_handshakes: int = 0
    piece_availability_observed: int = 0
    unchoke_observed: int = 0
    positive_findings: int = 0
    terminal_failures: int = 0
    failure_reasons: tuple[tuple[str, int], ...] = ()


@dataclass(slots=True)
class ScanResult:
    """Gesamtergebnis eines vollständigen, speicherschonenden Prüflaufs."""

    run_id: str
    started_at_utc: str
    completed_at_utc: str | None = None
    candidates: list[PeerCandidate] = field(default_factory=list)
    handshakes: list[HandshakeResult] = field(default_factory=list)
    records: list[EvidenceRecord] = field(default_factory=list)
    candidate_count: int = 0
    handshake_count: int = 0
    confirmed_handshake_count: int = 0
    offering_observation_count: int = 0
    known_vpn_total: int = 0
    target_metrics: tuple[TargetScanMetrics, ...] = ()
    run_store_path: Path | None = None
    report_paths: list[Path] = field(default_factory=list)
    cancelled: bool = False
    enrichment_failure_count: int = 0
    errors: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)

    @property
    def total_candidate_count(self) -> int:
        return max(self.candidate_count, len(self.candidates))

    @property
    def total_handshake_count(self) -> int:
        return max(self.handshake_count, len(self.handshakes))

    @property
    def confirmed_count(self) -> int:
        return max(
            self.confirmed_handshake_count,
            sum(result.confirmed for result in self.handshakes),
        )

    @property
    def offering_count(self) -> int:
        return max(
            self.offering_observation_count,
            sum(result.offering_observed for result in self.handshakes),
        )

    @property
    def known_vpn_count(self) -> int:
        return max(
            self.known_vpn_total,
            sum(record.vpn.status == "known_vpn" for record in self.records),
        )
