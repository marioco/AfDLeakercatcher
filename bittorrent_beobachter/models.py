"""Gemeinsame, unveränderliche Datenmodelle der Anwendung."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


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
        for event in observation.control_events:
            if event.kind == "unchoke":
                peer_choking = False
            elif event.kind == "choke":
                peer_choking = True
            elif event.kind == "have" or (event.kind == "bitfield" and event.non_empty):
                pieces_available = True
            if pieces_available and not peer_choking:
                return True
        return bool(
            observation.piece_availability_announced and not observation.peer_choking_at_end
        )

    @property
    def offering_observed(self) -> bool:
        """Ein direkt validierter Verfügbarkeits- und Freigabebefund ohne Datenabruf."""
        observation = self.availability
        return bool(
            self.confirmed
            and observation is not None
            and observation.interested_sent
            and observation.piece_availability_announced
            and observation.unchoked
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
