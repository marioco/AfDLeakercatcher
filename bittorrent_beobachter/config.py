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
from dataclasses import dataclass
from email.headerregistry import Address
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .dht import MAX_BOOTSTRAP_NODES
from .models import Target

MAX_CONFIG_BYTES = 256_000
DEFAULT_BOOTSTRAP_NODES = (
    ("router.bittorrent.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
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
    max_queries: int = 80
    alpha: int = 8
    max_nodes: int = 1_000
    max_candidates: int = 300
    bootstrap_nodes: tuple[tuple[str, int], ...] = DEFAULT_BOOTSTRAP_NODES


@dataclass(frozen=True, slots=True)
class PeerSettings:
    timeout_seconds: float = 4.0
    max_checks: int = 120
    workers: int = 8


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
    interval_minutes: int = 30
    dht: DhtSettings = DhtSettings()
    peer: PeerSettings = PeerSettings()
    enrichment: EnrichmentSettings = EnrichmentSettings()
    reporting: ReportingSettings = ReportingSettings()


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


def parse_magnet(
    magnet: str,
    *,
    label_override: str | None = None,
    source_note: str = "",
) -> Target:
    """Extrahiert nur Name und v1-Infohash; Tracker werden absichtlich ignoriert."""
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
    display_name = unquote(query.get("dn", [""])[0]).strip()
    label = _clean_optional_text(
        label_override or display_name or f"Infohash {info_hash.hex()[:12]}",
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
    return Target(label=label, info_hash=info_hash, source_note=cleaned_source_note)


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


def config_from_dict(raw: dict[str, Any]) -> AppConfig:
    """Validiert die JSON-Struktur vollständig und baut eine AppConfig."""
    if raw.get("schema_version", 1) != 1:
        raise ConfigError("Diese Konfigurationsversion wird nicht unterstützt.")

    target_items = raw.get("targets")
    if not isinstance(target_items, list) or not target_items:
        raise ConfigError("Mindestens ein Ziel muss unter targets eingetragen sein.")
    if len(target_items) > 20:
        raise ConfigError("Höchstens 20 Ziele pro Installation sind erlaubt.")

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

    dht = DhtSettings(
        timeout_seconds=_bounded_float(
            dht_raw.get("timeout_seconds", 2.5), "dht.timeout_seconds", 0.25, 30.0
        ),
        max_queries=_bounded_int(dht_raw.get("max_queries", 80), "dht.max_queries", 1, 500),
        alpha=_bounded_int(dht_raw.get("alpha", 8), "dht.alpha", 1, 32),
        max_nodes=_bounded_int(dht_raw.get("max_nodes", 1_000), "dht.max_nodes", 8, 10_000),
        max_candidates=_bounded_int(
            dht_raw.get("max_candidates", 300), "dht.max_candidates", 1, 5_000
        ),
        bootstrap_nodes=tuple(bootstrap),
    )

    peer_raw = _require_mapping(raw.get("peer", {}), "peer")
    peer = PeerSettings(
        timeout_seconds=_bounded_float(
            peer_raw.get("timeout_seconds", 4.0), "peer.timeout_seconds", 0.25, 30.0
        ),
        max_checks=_bounded_int(peer_raw.get("max_checks", 120), "peer.max_checks", 1, 2_000),
        workers=_bounded_int(peer_raw.get("workers", 8), "peer.workers", 1, 32),
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
    reporting = ReportingSettings(
        reporter_name=_clean_optional_text(
            reporting_raw.get("reporter_name"), "reporter_name", 120
        ),
        reporter_email=_clean_optional_email(reporting_raw.get("reporter_email"), "reporter_email"),
        police_recipient=_clean_optional_email(
            reporting_raw.get("police_recipient"), "police_recipient"
        ),
        legal_notes=tuple(
            _clean_optional_text(note, "legal_notes", 500) for note in legal_notes_raw
        ),
    )
    return AppConfig(
        targets=tuple(targets),
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
        size = metadata.st_size
        if os.name != "nt":
            if stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
                path.parent.chmod(0o700)
            if stat.S_IMODE(metadata.st_mode) != 0o600:
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
    """Serialisiert ohne Magnet-Tracker oder andere nicht benötigte Daten."""
    return {
        "schema_version": 1,
        "interval_minutes": config.interval_minutes,
        "targets": [
            {
                "label": target.label,
                "info_hash": target.info_hash_hex,
                "source_note": target.source_note,
            }
            for target in config.targets
        ],
        "dht": {
            "timeout_seconds": config.dht.timeout_seconds,
            "max_queries": config.dht.max_queries,
            "alpha": config.dht.alpha,
            "max_nodes": config.dht.max_nodes,
            "max_candidates": config.dht.max_candidates,
            "bootstrap_nodes": [list(node) for node in config.dht.bootstrap_nodes],
        },
        "peer": {
            "timeout_seconds": config.peer.timeout_seconds,
            "max_checks": config.peer.max_checks,
            "workers": config.peer.workers,
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

    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.parent.chmod(0o700)
    temporary_root = path.parent
    temporary_root.mkdir(parents=True, exist_ok=True)
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
