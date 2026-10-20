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

    @property
    def info_hash_hex(self) -> str:
        return self.info_hash.hex()


@dataclass(frozen=True, slots=True)
class PeerCandidate:
    """Ein von einer DHT-Antwort genannter öffentlicher Peer-Endpunkt."""

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

    @property
    def offering_observed(self) -> bool:
        """Nur der vollständig und fehlerfrei beobachtete positive Gesamtbefund."""
        observation = self.availability
        return bool(
            self.confirmed
            and observation is not None
            and observation.completed_full_window
            and observation.interested_sent
            and observation.piece_availability_announced
            and observation.unchoked
            and observation.error is None
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


@dataclass(slots=True)
class ScanResult:
    """Gesamtergebnis eines begrenzten Prüflaufs."""

    run_id: str
    started_at_utc: str
    completed_at_utc: str | None = None
    candidates: list[PeerCandidate] = field(default_factory=list)
    handshakes: list[HandshakeResult] = field(default_factory=list)
    records: list[EvidenceRecord] = field(default_factory=list)
    report_paths: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return sum(result.confirmed for result in self.handshakes)

    @property
    def offering_count(self) -> int:
        return sum(result.offering_observed for result in self.handshakes)

    @property
    def known_vpn_count(self) -> int:
        return sum(record.vpn.status == "known_vpn" for record in self.records)
