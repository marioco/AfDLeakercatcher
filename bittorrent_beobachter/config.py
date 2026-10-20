"""Validierte Konfiguration und plattformgerechte Ablagepfade."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import stat
import sys
import tempfile
import unicodedata
from dataclasses import dataclass, replace
from email.headerregistry import Address
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .dht import DHT_QUERY_SCHEDULING_MARGIN_SECONDS, MAX_BOOTSTRAP_NODES
from .models import Target

MAX_CONFIG_BYTES = 256_000
MAX_CONFIG_TARGETS = 20
BUNDLED_PRESET_REVISION = 4
DEFAULT_BOOTSTRAP_NODES = (
    ("router.bittorrent.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
)
DEFAULT_TRACKERS = (
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://open.stealth.si:80/announce",
    "udp://explodie.org:6969/announce",
    "udp://tracker.dler.org:6969/announce",
    "udp://tracker.bittor.pw:1337/announce",
    "udp://retracker01-msk-virt.corbina.net:80/announce",
)
DEFAULT_VPN_PROVIDER_MARKERS = (
    ("Mullvad", ("mullvad vpn ab", "mullvad vpn")),
    ("Proton VPN", ("proton vpn", "protonvpn")),
    ("NordVPN", ("nordvpn", "nord vpn")),
    ("Surfshark", ("surfshark",)),
    ("ExpressVPN", ("expressvpn", "express vpn")),
    ("CyberGhost", ("cyberghost",)),
    ("Private Internet Access", ("private internet access",)),
    ("Windscribe", ("windscribe",)),
    ("IVPN", ("ivpn",)),
    ("OVPN", ("ovpn integritet", "ovpn vpn")),
    ("AirVPN", ("airvpn",)),
)


class ConfigError(ValueError):
    """Die Konfiguration ist unvollständig oder fachlich ungültig."""


@dataclass(frozen=True, slots=True)
class DhtSettings:
    timeout_seconds: float = 2.5
    overall_timeout_seconds: float = 60.0
    concurrency: int = 8
    quiet_seconds: float = 30.0
    refresh_interval_seconds: float = 2.0
    bootstrap_nodes: tuple[tuple[str, int], ...] = DEFAULT_BOOTSTRAP_NODES

    def __post_init__(self) -> None:
        if (
            self.overall_timeout_seconds - self.timeout_seconds
            < DHT_QUERY_SCHEDULING_MARGIN_SECONDS
        ):
            raise ConfigError(
                "dht.overall_timeout_seconds muss mindestens "
                f"{DHT_QUERY_SCHEDULING_MARGIN_SECONDS:.1f} Sekunden groesser als "
                "dht.timeout_seconds sein."
            )


@dataclass(frozen=True, slots=True)
class PeerSettings:
    timeout_seconds: float = 8.0
    observation_seconds: float = 60.0
    retry_attempts: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass(frozen=True, slots=True)
class EnrichmentSettings:
    enabled: bool = False
    timeout_seconds: float = 8.0
    cache_days: int = 7
    vpn_ranges: tuple[tuple[str, str], ...] = ()
    vpn_provider_markers: tuple[tuple[str, tuple[str, ...]], ...] = DEFAULT_VPN_PROVIDER_MARKERS


@dataclass(frozen=True, slots=True)
class ReportingSettings:
    reporter_name: str = ""
    reporter_email: str = ""
    police_recipient: str = ""
    legal_notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AppConfig:
    targets: tuple[Target, ...]
    preset_revision: int = BUNDLED_PRESET_REVISION
    interval_minutes: int = 30
    dht: DhtSettings = DhtSettings()
    peer: PeerSettings = PeerSettings()
    enrichment: EnrichmentSettings = EnrichmentSettings()
    reporting: ReportingSettings = ReportingSettings()


DEFAULT_TARGETS = (
    Target(
        label="Voreingestellter Infohash 1",
        info_hash=bytes.fromhex("852795102149749ad91123af01ceac5da6f9eb5a"),
        trackers=DEFAULT_TRACKERS,
    ),
    Target(
        label="Voreingestellter Infohash 2",
        info_hash=bytes.fromhex("db503db679f508aa31a9e07913b2aa8cf7aa6dff"),
        trackers=DEFAULT_TRACKERS,
    ),
)


def default_app_config() -> AppConfig:
    """Liefert die sichtbaren Erststart-Ziele, ohne einen Netzlauf zu beginnen."""
    return AppConfig(targets=DEFAULT_TARGETS)


def with_bundled_presets(config: AppConfig) -> AppConfig:
    """Ergänzt und neutralisiert Projektvorgaben genau einmal je Revision."""
    if config.preset_revision >= BUNDLED_PRESET_REVISION:
        return config

    presets_by_hash = {target.info_hash: target for target in DEFAULT_TARGETS}
    if config.preset_revision < 2:
        normalized_targets = tuple(
            presets_by_hash.get(target.info_hash, target) for target in config.targets
        )
    else:
        normalized_targets = tuple(
            replace(target, trackers=presets_by_hash[target.info_hash].trackers)
            if (
                target.info_hash in presets_by_hash
                and not target.trackers
                and config.preset_revision < 4
            )
            else target
            for target in config.targets
        )
    existing_hashes = {target.info_hash for target in normalized_targets}
    missing = (
        tuple(target for target in DEFAULT_TARGETS if target.info_hash not in existing_hashes)
        if config.preset_revision == 0
        else ()
    )
    if len(normalized_targets) + len(missing) > MAX_CONFIG_TARGETS:
        raise ConfigError(
            "Die einmalige Voreinstellungs-Aktualisierung überschreitet das "
            f"Ziel-Limit von {MAX_CONFIG_TARGETS}."
        )
    return replace(
        config,
        targets=(*normalized_targets, *missing),
        preset_revision=BUNDLED_PRESET_REVISION,
    )


def default_data_dir() -> Path:
    """Liefert einen beschreibbaren Laufzeitpfad passend zum Betriebssystem."""
    override = os.environ.get("BITTORRENT_BEOBACHTER_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()

    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "BitTorrent-Beobachter"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "BitTorrent-Beobachter"

    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "bittorrent-beobachter"


def default_config_path(data_dir: Path | None = None) -> Path:
    """Liefert Override oder Konfigurationsdatei in der App-Ablage."""
    override = os.environ.get("BITTORRENT_BEOBACHTER_CONFIG")
    if override:
        return Path(override).expanduser().resolve()
    return (data_dir or default_data_dir()) / "config.json"


def _decode_btih(value: str) -> bytes:
    normalized = value.strip()
    if len(normalized) == 40:
        try:
            decoded = bytes.fromhex(normalized)
        except ValueError as exc:
            raise ConfigError("Der btih-Infohash ist nicht gültig hexadezimal.") from exc
    elif len(normalized) == 32:
        try:
            decoded = base64.b32decode(normalized.upper(), casefold=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ConfigError("Der btih-Infohash ist nicht gültig Base32-kodiert.") from exc
    else:
        raise ConfigError("Unterstützt werden nur 40-stellige oder 32-stellige btih-Hashes.")

    if len(decoded) != 20:
        raise ConfigError("Ein BitTorrent-v1-Infohash muss genau 20 Byte lang sein.")
    return decoded


def _validated_udp_tracker(value: Any, field: str) -> str:
    """Validiert eine öffentliche UDP-Tracker-URL ohne sie aufzulösen."""
    tracker = _clean_optional_text(value, field, 2_048)
    if not tracker:
        raise ConfigError(f"{field} darf nicht leer sein.")
    try:
        parts = urlsplit(tracker)
        port = parts.port
    except ValueError as exc:
        raise ConfigError(f"{field} enthält keinen gültigen Port.") from exc
    if parts.scheme.lower() != "udp":
        raise ConfigError(f"{field} muss eine udp://-Tracker-Adresse sein.")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"{field} darf keine Zugangsdaten enthalten.")
    host = parts.hostname
    if not host or port is None or not 1 <= port <= 65_535:
        raise ConfigError(f"{field} benötigt Host und Port.")
    if parts.query or parts.fragment:
        raise ConfigError(f"{field} darf weder Abfrage noch Fragment enthalten.")
    if parts.path not in {"", "/announce"}:
        raise ConfigError(f"{field} darf nur den Pfad /announce enthalten.")
    if any(character.isspace() for character in host):
        raise ConfigError(f"{field} enthält einen ungültigen Host.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ConfigError(f"{field} enthält einen ungültigen Host.") from exc
        labels = ascii_host.rstrip(".").split(".")
        if len(ascii_host) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise ConfigError(f"{field} enthält einen ungültigen Host.") from None
    else:
        if not address.is_global or address.is_multicast:
            raise ConfigError(f"{field} muss auf eine öffentliche Adresse zeigen.")
    return tracker


def _validated_tracker_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ConfigError(f"{field} muss eine Liste sein.")
    trackers: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        tracker = _validated_udp_tracker(item, f"{field}[{index}]")
        dedupe_key = tracker.casefold()
        if dedupe_key not in seen:
            seen.add(dedupe_key)
            trackers.append(tracker)
    return tuple(trackers)


def parse_magnet(
    magnet: str,
    *,
    label_override: str | None = None,
    source_note: str = "",
) -> Target:
    """Extrahiert v1-Infohash und validierte UDP-Tracker, nie den fremden Namen."""
    if len(magnet) > 32_000:
        raise ConfigError("Der Magnet-Link ist ungewöhnlich lang.")
    parts = urlsplit(magnet.strip())
    if parts.scheme.lower() != "magnet":
        raise ConfigError("Erwartet wird ein Magnet-Link mit dem Schema magnet:.")

    query = parse_qs(parts.query, keep_blank_values=False)
    hashes = [value[9:] for value in query.get("xt", []) if value.lower().startswith("urn:btih:")]
    if len(hashes) != 1:
        raise ConfigError("Der Magnet-Link muss genau einen urn:btih-Infohash enthalten.")

    info_hash = _decode_btih(hashes[0])
    label = _clean_optional_text(
        label_override or f"Infohash {info_hash.hex()[:12]}",
        "Bezeichnung",
        120,
    )
    if not 1 <= len(label) <= 120:
        raise ConfigError("Die Bezeichnung muss zwischen 1 und 120 Zeichen lang sein.")
    cleaned_source_note = _clean_optional_text(
        source_note,
        "Quellenhinweis",
        1_000,
    )
    trackers = _validated_tracker_tuple(query.get("tr", []), "Magnet-Tracker")
    return Target(
        label=label,
        info_hash=info_hash,
        source_note=cleaned_source_note,
        trackers=trackers,
    )


def _require_mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{field} muss ein JSON-Objekt sein.")
    return value


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{field} muss eine ganze Zahl sein.")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{field} muss zwischen {minimum} und {maximum} liegen.")
    return value


def _bounded_float(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{field} muss eine Zahl sein.")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ConfigError(f"{field} muss zwischen {minimum} und {maximum} liegen.")
    return result


def _clean_optional_text(value: Any, field: str, maximum: int = 1_000) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"{field} muss Text sein.")
    result = value.strip()
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in result):
        raise ConfigError(f"{field} darf keine Steuer- oder unsichtbaren Formatzeichen enthalten.")
    if "\u2028" in result or "\u2029" in result:
        raise ConfigError(f"{field} darf keinen Unicode-Zeilenumbruch enthalten.")
    if len(result) > maximum:
        raise ConfigError(f"{field} darf höchstens {maximum} Zeichen lang sein.")
    return result


def _clean_optional_email(value: Any, field: str) -> str:
    cleaned = _clean_optional_text(value, field, 254)
    if not cleaned:
        return ""
    try:
        parsed = Address(addr_spec=cleaned)
    except (IndexError, TypeError, ValueError) as exc:
        raise ConfigError(f"{field} enthält keine gültige E-Mail-Adresse.") from exc
    if not parsed.username or not parsed.domain:
        raise ConfigError(f"{field} enthält keine vollständige E-Mail-Adresse.")
    return cleaned


def validate_reporting_settings(settings: ReportingSettings) -> ReportingSettings:
    """Validiert Entwurfsangaben, bevor ein Dialog sie übernimmt."""

    if not isinstance(settings, ReportingSettings):
        raise ConfigError("Entwurfsangaben haben ein ungültiges Format.")
    if not isinstance(settings.legal_notes, (list, tuple)) or len(settings.legal_notes) > 20:
        raise ConfigError("legal_notes muss eine Liste mit höchstens 20 Texten sein.")
    return ReportingSettings(
        reporter_name=_clean_optional_text(settings.reporter_name, "reporter_name", 120),
        reporter_email=_clean_optional_email(settings.reporter_email, "reporter_email"),
        police_recipient=_clean_optional_email(
            settings.police_recipient,
            "police_recipient",
        ),
        legal_notes=tuple(
            _clean_optional_text(note, "legal_notes", 500) for note in settings.legal_notes
        ),
    )


def config_from_dict(raw: dict[str, Any]) -> AppConfig:
    """Validiert die JSON-Struktur vollständig und baut eine AppConfig."""
    if raw.get("schema_version", 1) != 1:
        raise ConfigError("Diese Konfigurationsversion wird nicht unterstützt.")
    preset_revision = _bounded_int(
        raw.get("bundled_preset_revision", 0),
        "bundled_preset_revision",
        0,
        BUNDLED_PRESET_REVISION,
    )

    target_items = raw.get("targets")
    if not isinstance(target_items, list):
        raise ConfigError("targets muss eine Liste sein.")
    if len(target_items) > MAX_CONFIG_TARGETS:
        raise ConfigError(f"Höchstens {MAX_CONFIG_TARGETS} Ziele pro Installation sind erlaubt.")

    targets: list[Target] = []
    seen_hashes: set[bytes] = set()
    for index, item in enumerate(target_items):
        target_raw = _require_mapping(item, f"targets[{index}]")
        label = _clean_optional_text(target_raw.get("label"), f"targets[{index}].label", 120)
        source_note = _clean_optional_text(
            target_raw.get("source_note"), f"targets[{index}].source_note"
        )
        magnet = target_raw.get("magnet")
        info_hash_text = target_raw.get("info_hash")
        if isinstance(magnet, str) and magnet.strip():
            target = parse_magnet(
                magnet,
                label_override=label or None,
                source_note=source_note,
            )
        elif isinstance(info_hash_text, str):
            info_hash = _decode_btih(info_hash_text)
            target = Target(
                label=label or f"Infohash {info_hash.hex()[:12]}",
                info_hash=info_hash,
                source_note=source_note,
                trackers=_validated_tracker_tuple(
                    target_raw.get("trackers", []),
                    f"targets[{index}].trackers",
                ),
            )
        else:
            raise ConfigError(f"targets[{index}] benötigt magnet oder info_hash.")
        if target.info_hash in seen_hashes:
            raise ConfigError(f"Doppelter Infohash bei targets[{index}].")
        seen_hashes.add(target.info_hash)
        targets.append(target)

    dht_raw = _require_mapping(raw.get("dht", {}), "dht")
    bootstrap_raw = dht_raw.get("bootstrap_nodes", DEFAULT_BOOTSTRAP_NODES)
    if not isinstance(bootstrap_raw, (list, tuple)) or not bootstrap_raw:
        raise ConfigError("dht.bootstrap_nodes muss mindestens einen Eintrag enthalten.")
    if len(bootstrap_raw) > MAX_BOOTSTRAP_NODES:
        raise ConfigError(
            f"dht.bootstrap_nodes darf höchstens {MAX_BOOTSTRAP_NODES} Einträge enthalten."
        )
    bootstrap: list[tuple[str, int]] = []
    for index, node in enumerate(bootstrap_raw):
        if not isinstance(node, (list, tuple)) or len(node) != 2:
            raise ConfigError(f"dht.bootstrap_nodes[{index}] muss [Host, Port] sein.")
        host = _clean_optional_text(node[0], f"dht.bootstrap_nodes[{index}][0]", 253)
        if not host or any(character.isspace() for character in host):
            raise ConfigError(f"Ungültiger Bootstrap-Host an Position {index}.")
        port = _bounded_int(node[1], f"dht.bootstrap_nodes[{index}][1]", 1, 65_535)
        bootstrap.append((host, port))

    quiet_seconds = _bounded_float(
        dht_raw.get("quiet_seconds", 30.0), "dht.quiet_seconds", 1.0, 600.0
    )
    refresh_interval_seconds = _bounded_float(
        dht_raw.get("refresh_interval_seconds", 2.0),
        "dht.refresh_interval_seconds",
        0.1,
        60.0,
    )
    if refresh_interval_seconds > quiet_seconds:
        raise ConfigError(
            "dht.refresh_interval_seconds darf dht.quiet_seconds nicht überschreiten."
        )
    dht = DhtSettings(
        timeout_seconds=_bounded_float(
            dht_raw.get("timeout_seconds", 2.5), "dht.timeout_seconds", 0.25, 30.0
        ),
        overall_timeout_seconds=_bounded_float(
            dht_raw.get("overall_timeout_seconds", 60.0),
            "dht.overall_timeout_seconds",
            1.0,
            300.0,
        ),
        concurrency=_bounded_int(
            dht_raw.get("concurrency", dht_raw.get("alpha", 8)),
            "dht.concurrency",
            1,
            32,
        ),
        quiet_seconds=quiet_seconds,
        refresh_interval_seconds=refresh_interval_seconds,
        bootstrap_nodes=tuple(bootstrap),
    )

    peer_raw = _require_mapping(raw.get("peer", {}), "peer")
    peer = PeerSettings(
        timeout_seconds=_bounded_float(
            peer_raw.get("timeout_seconds", 8.0), "peer.timeout_seconds", 0.25, 30.0
        ),
        observation_seconds=_bounded_float(
            peer_raw.get("observation_seconds", 60.0),
            "peer.observation_seconds",
            60.0,
            60.0,
        ),
        retry_attempts=_bounded_int(
            peer_raw.get("retry_attempts", 3), "peer.retry_attempts", 1, 10
        ),
        retry_backoff_seconds=_bounded_float(
            peer_raw.get("retry_backoff_seconds", 1.0),
            "peer.retry_backoff_seconds",
            0.0,
            30.0,
        ),
    )

    enrichment_raw = _require_mapping(raw.get("enrichment", {}), "enrichment")
    enabled = enrichment_raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("enrichment.enabled muss true oder false sein.")
    range_items = enrichment_raw.get("vpn_ranges", [])
    if not isinstance(range_items, list):
        raise ConfigError("enrichment.vpn_ranges muss eine Liste sein.")
    vpn_ranges: list[tuple[str, str]] = []
    for index, item in enumerate(range_items):
        item_raw = _require_mapping(item, f"enrichment.vpn_ranges[{index}]")
        network = _clean_optional_text(
            item_raw.get("network"), f"enrichment.vpn_ranges[{index}].network", 80
        )
        provider = _clean_optional_text(
            item_raw.get("provider"), f"enrichment.vpn_ranges[{index}].provider", 120
        )
        if not network or not provider:
            raise ConfigError(f"VPN-Präfix {index} benötigt network und provider.")
        try:
            parsed_network = ipaddress.ip_network(network, strict=True)
        except ValueError as exc:
            raise ConfigError(f"VPN-Präfix {index} ist ungültig.") from exc
        if not parsed_network.is_global or parsed_network.network_address.is_multicast:
            raise ConfigError(f"VPN-Präfix {index} ist nicht global routbar.")
        vpn_ranges.append((parsed_network.with_prefixlen, provider))

    markers_raw = enrichment_raw.get("vpn_provider_markers")
    if markers_raw is None:
        markers = DEFAULT_VPN_PROVIDER_MARKERS
    else:
        if not isinstance(markers_raw, list):
            raise ConfigError("enrichment.vpn_provider_markers muss eine Liste sein.")
        parsed_markers: list[tuple[str, tuple[str, ...]]] = []
        for index, item in enumerate(markers_raw):
            item_raw = _require_mapping(item, f"enrichment.vpn_provider_markers[{index}]")
            provider = _clean_optional_text(
                item_raw.get("provider"),
                f"enrichment.vpn_provider_markers[{index}].provider",
                120,
            )
            item_markers = item_raw.get("markers")
            if not provider or not isinstance(item_markers, list) or not item_markers:
                raise ConfigError(f"VPN-Marker {index} benötigt provider und markers.")
            clean_markers = tuple(
                _clean_optional_text(marker, f"VPN-Marker {index}", 120).casefold()
                for marker in item_markers
            )
            if any(not marker for marker in clean_markers):
                raise ConfigError(f"VPN-Marker {index} enthält einen leeren Marker.")
            parsed_markers.append((provider, clean_markers))
        markers = tuple(parsed_markers)

    enrichment = EnrichmentSettings(
        enabled=enabled,
        timeout_seconds=_bounded_float(
            enrichment_raw.get("timeout_seconds", 8.0),
            "enrichment.timeout_seconds",
            0.5,
            10.0,
        ),
        cache_days=_bounded_int(
            enrichment_raw.get("cache_days", 7), "enrichment.cache_days", 1, 90
        ),
        vpn_ranges=tuple(vpn_ranges),
        vpn_provider_markers=tuple(markers),
    )

    reporting_raw = _require_mapping(raw.get("reporting", {}), "reporting")
    legal_notes_raw = reporting_raw.get("legal_notes", [])
    if not isinstance(legal_notes_raw, list) or len(legal_notes_raw) > 20:
        raise ConfigError("reporting.legal_notes muss eine Liste mit höchstens 20 Texten sein.")
    reporting = validate_reporting_settings(
        ReportingSettings(
            reporter_name=reporting_raw.get("reporter_name"),
            reporter_email=reporting_raw.get("reporter_email"),
            police_recipient=reporting_raw.get("police_recipient"),
            legal_notes=tuple(legal_notes_raw),
        )
    )
    return AppConfig(
        targets=tuple(targets),
        preset_revision=preset_revision,
        interval_minutes=_bounded_int(
            raw.get("interval_minutes", 30), "interval_minutes", 5, 1_440
        ),
        dht=dht,
        peer=peer,
        enrichment=enrichment,
        reporting=reporting,
    )


def load_config(path: Path) -> AppConfig:
    """Lädt eine größenbegrenzte UTF-8-JSON-Konfiguration."""
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigError(f"Konfiguration ist keine reguläre Datei: {path}")
        size = metadata.st_size
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            path.chmod(0o600)
    except FileNotFoundError as exc:
        raise ConfigError(f"Konfiguration nicht gefunden: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"Konfiguration kann nicht geschützt werden: {path}: {exc}") from exc
    if size > MAX_CONFIG_BYTES:
        raise ConfigError(f"Konfiguration ist größer als {MAX_CONFIG_BYTES} Byte.")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Konfiguration kann nicht gelesen werden: {path}: {exc}") from exc
    return config_from_dict(_require_mapping(raw, "Konfiguration"))


def config_to_dict(config: AppConfig) -> dict[str, Any]:
    """Serialisiert ausschließlich validierte Laufzeitkonfiguration."""
    return {
        "schema_version": 1,
        "bundled_preset_revision": config.preset_revision,
        "interval_minutes": config.interval_minutes,
        "targets": [
            {
                "label": target.label,
                "info_hash": target.info_hash_hex,
                "source_note": target.source_note,
                "trackers": list(target.trackers),
            }
            for target in config.targets
        ],
        "dht": {
            "timeout_seconds": config.dht.timeout_seconds,
            "overall_timeout_seconds": config.dht.overall_timeout_seconds,
            "concurrency": config.dht.concurrency,
            "quiet_seconds": config.dht.quiet_seconds,
            "refresh_interval_seconds": config.dht.refresh_interval_seconds,
            "bootstrap_nodes": [list(node) for node in config.dht.bootstrap_nodes],
        },
        "peer": {
            "timeout_seconds": config.peer.timeout_seconds,
            "observation_seconds": config.peer.observation_seconds,
            "retry_attempts": config.peer.retry_attempts,
            "retry_backoff_seconds": config.peer.retry_backoff_seconds,
        },
        "enrichment": {
            "enabled": config.enrichment.enabled,
            "timeout_seconds": config.enrichment.timeout_seconds,
            "cache_days": config.enrichment.cache_days,
            "vpn_ranges": [
                {"network": network, "provider": provider}
                for network, provider in config.enrichment.vpn_ranges
            ],
            "vpn_provider_markers": [
                {"provider": provider, "markers": list(markers)}
                for provider, markers in config.enrichment.vpn_provider_markers
            ],
        },
        "reporting": {
            "reporter_name": config.reporting.reporter_name,
            "reporter_email": config.reporting.reporter_email,
            "police_recipient": config.reporting.police_recipient,
            "legal_notes": list(config.reporting.legal_notes),
        },
    }


def save_config(path: Path, config: AppConfig) -> None:
    """Validiert und schreibt die Konfiguration atomar mit privaten Rechten."""
    validated_config = config_from_dict(config_to_dict(config))
    payload = json.dumps(config_to_dict(validated_config), ensure_ascii=False, indent=2) + "\n"

    _create_private_directories(path.parent)
    temporary_root = path.parent
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=temporary_root,
            prefix="bittorrent-beobachter-config-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temporary_path = Path(handle.name)
        temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
        path.chmod(0o600)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _create_private_directories(directory: Path) -> None:
    """Erzeugt nur fehlende Verzeichnisse privat und verändert vorhandene nicht."""

    missing: list[Path] = []
    current = directory
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for path in reversed(missing):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        if os.name != "nt":
            path.chmod(0o700)


def load_migrated_config(path: Path) -> AppConfig:
    """Lädt, migriert und speichert alte Programmvorgaben atomar."""

    config = load_config(path)
    migrated = with_bundled_presets(config)
    if migrated != config:
        save_config(path, migrated)
    return migrated
