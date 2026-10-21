"""Datensparsame Auskunft zu oeffentlichen IP-Netzen und VPN-Markierungen.

Externe Auskuenfte sind standardmaessig gesperrt. Bei ausdruecklicher
Aktivierung wird die zu pruefende IP an ``rdap.org``, das von dort bestimmte
autoritative RIR-RDAP-Ziel und ``stat.ripe.net`` uebertragen. Das Modul fuehrt
weder Reverse-DNS- noch Geolokalisierungs- oder Personenrecherchen durch. Rohe
Antworten werden nicht gespeichert.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import stat
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Event
from typing import Any

from . import APP_NAME, VERSION
from .evidence import atomic_write_json, canonical_json_bytes
from .models import NetworkEnrichment, VpnClassification

RDAP_BASE_URL = "https://rdap.org/ip/"
RIPESTAT_PREFIX_URL = "https://stat.ripe.net/data/prefix-overview/data.json"
USER_AGENT = f"{APP_NAME}/{VERSION} (+public-network-evidence)"
MAX_RESPONSE_BYTES = 2_000_000
MAX_CACHE_BYTES = 100_000
MAX_CACHE_FILES = 512
MAX_CACHE_TOTAL_BYTES = 32 * 1024 * 1024
CACHE_FORMAT_VERSION = 3
MAX_REDIRECTS = 5
ENRICHMENT_CANCELLED_REASON = "Netzauskunft wegen kontrolliertem Abbruch uebersprungen."
RDAP_REDIRECT_PATHS = {
    "rdap.org": ("/ip/",),
    "rdap.arin.net": ("/registry/ip/",),
    "rdap.db.ripe.net": ("/ip/",),
    "rdap.apnic.net": ("/ip/",),
    "rdap.lacnic.net": ("/rdap/ip/",),
    "rdap.afrinic.net": ("/rdap/ip/",),
}
RIPESTAT_HOST = "stat.ripe.net"
RIPESTAT_PATH = "/data/prefix-overview/data.json"
_REQUEST_SOURCE_ATTRIBUTE = "_bittorrent_beobachter_source"
_REQUEST_IP_ATTRIBUTE = "_bittorrent_beobachter_ip"
_REQUEST_REDIRECT_URLS_ATTRIBUTE = "_bittorrent_beobachter_redirect_urls"
EXTERNAL_LOOKUP_DISCLOSURE = (
    "Eine Aktivierung uebertraegt jede abgefragte Peer-IP an rdap.org. "
    "rdap.org leitet die Anfrage an das fuer die IP zustaendige autoritative "
    "RIR-RDAP-Ziel weiter (zum Beispiel rdap.db.ripe.net, rdap.arin.net, "
    "rdap.apnic.net, rdap.lacnic.net oder rdap.afrinic.net). Zusaetzlich wird "
    "die IP an stat.ripe.net uebertragen. Alle beteiligten Dienste koennen die "
    "Anfragen protokollieren. Dies muss vorab klar angezeigt und ausdruecklich "
    "aktiviert werden."
)


class EnrichmentError(RuntimeError):
    """Eine oeffentliche Netzauskunft konnte nicht verlaesslich geladen werden."""


class ExternalLookupDisabledError(EnrichmentError):
    """Die notwendige informierte Freigabe fuer externe Abfragen fehlt."""


class RedirectPolicyError(EnrichmentError):
    """Eine HTTP-Weiterleitung verletzt die feste Zielrichtlinie."""


def _secure_url_parts(
    url: str,
    *,
    allowed_hosts: frozenset[str],
) -> urllib.parse.SplitResult:
    """Pruefe das gemeinsame HTTPS-, Host- und Anmeldeinformationsprofil."""

    if not isinstance(url, str) or not url or len(url) > 2_048:
        raise RedirectPolicyError("HTTP-Ziel ist leer oder zu lang")
    if "\\" in url or any(ord(character) < 32 for character in url):
        raise RedirectPolicyError("HTTP-Ziel enthaelt unzulaessige Zeichen")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise RedirectPolicyError("HTTP-Ziel ist syntaktisch ungueltig") from exc
    if parts.scheme.casefold() != "https":
        raise RedirectPolicyError("Weiterleitungen sind ausschliesslich per HTTPS erlaubt")
    if parts.username is not None or parts.password is not None:
        raise RedirectPolicyError("Anmeldeinformationen im Weiterleitungsziel sind verboten")
    host = parts.hostname
    if host is None or host.casefold() not in allowed_hosts:
        raise RedirectPolicyError(f"Weiterleitungsziel ist nicht erlaubt: {host or 'ohne Host'}")
    if port not in (None, 443):
        raise RedirectPolicyError("Weiterleitungsziel verwendet keinen erlaubten HTTPS-Port")
    if parts.fragment:
        raise RedirectPolicyError("Fragmente im Weiterleitungsziel sind nicht erlaubt")
    return parts


def _resource_ip(value: str, *, source_name: str) -> str:
    try:
        decoded = urllib.parse.unquote(value, errors="strict")
        return validate_public_ip(decoded)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RedirectPolicyError(
            f"{source_name}-Ziel enthaelt keine global routbare Ressourcen-IP"
        ) from exc


def _validate_service_url(url: str, source: str, *, initial: bool) -> str:
    """Validiere feste Startziele bzw. eng begrenzte Weiterleitungsziele."""

    if source == "rdap":
        allowed_hosts = frozenset({"rdap.org"}) if initial else frozenset(RDAP_REDIRECT_PATHS)
        parts = _secure_url_parts(url, allowed_hosts=allowed_hosts)
        host = parts.hostname.casefold() if parts.hostname is not None else ""
        matching_prefix = next(
            (prefix for prefix in RDAP_REDIRECT_PATHS[host] if parts.path.startswith(prefix)),
            None,
        )
        if matching_prefix is None:
            raise RedirectPolicyError("RDAP-Ziel verwendet keinen erlaubten IP-Abfragepfad")
        resource = parts.path.removeprefix(matching_prefix)
        if not resource or "/" in resource or parts.query:
            raise RedirectPolicyError("RDAP-Ziel enthaelt keine eindeutige IP-Abfrage")
        normalized_ip = _resource_ip(resource, source_name="RDAP")
        if initial:
            expected = RDAP_BASE_URL + urllib.parse.quote(normalized_ip, safe="")
            if url != expected:
                raise RedirectPolicyError("RDAP-Start-URL weicht vom festen Ziel ab")
        return normalized_ip

    if source == "ripestat-prefix-overview":
        parts = _secure_url_parts(url, allowed_hosts=frozenset({RIPESTAT_HOST}))
        if parts.path != RIPESTAT_PATH:
            raise RedirectPolicyError("RIPEstat-Ziel verwendet keinen erlaubten Abfragepfad")
        try:
            query = urllib.parse.parse_qsl(
                parts.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError as exc:
            raise RedirectPolicyError("RIPEstat-Ziel enthaelt eine ungueltige Abfrage") from exc
        if len(query) != 1 or query[0][0] != "resource":
            raise RedirectPolicyError("RIPEstat-Ziel enthaelt keine eindeutige IP-Abfrage")
        normalized_ip = _resource_ip(query[0][1], source_name="RIPEstat")
        if initial:
            expected = (
                RIPESTAT_PREFIX_URL + "?" + urllib.parse.urlencode({"resource": normalized_ip})
            )
            if url != expected:
                raise RedirectPolicyError("RIPEstat-Start-URL weicht vom festen Ziel ab")
        return normalized_ip

    raise RedirectPolicyError(f"Unbekannte externe Datenquelle: {source}")


class _RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Folge nur HTTPS-Weiterleitungen zu fest erlaubten Dienstzielen."""

    max_repeats = 2
    max_redirections = MAX_REDIRECTS

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        source = getattr(request, _REQUEST_SOURCE_ATTRIBUTE, None)
        expected_ip = getattr(request, _REQUEST_IP_ATTRIBUTE, None)
        redirect_urls = getattr(request, _REQUEST_REDIRECT_URLS_ATTRIBUTE, None)
        if (
            not isinstance(source, str)
            or not isinstance(expected_ip, str)
            or not isinstance(redirect_urls, list)
            or not all(isinstance(item, str) for item in redirect_urls)
        ):
            raise RedirectPolicyError("Weiterleitung besitzt keinen geprueften Ausgangspunkt")
        try:
            absolute_url = urllib.parse.urljoin(request.full_url, new_url)
        except (TypeError, ValueError) as exc:
            raise RedirectPolicyError("Weiterleitungsziel ist syntaktisch ungueltig") from exc
        redirected_ip = _validate_service_url(absolute_url, source, initial=False)
        if redirected_ip != expected_ip:
            raise RedirectPolicyError("Weiterleitungsziel veraendert die abgefragte Ressourcen-IP")
        redirect_urls.append(absolute_url)
        redirected = super().redirect_request(
            request,
            file_pointer,
            code,
            message,
            headers,
            absolute_url,
        )
        if redirected is not None:
            setattr(redirected, _REQUEST_SOURCE_ATTRIBUTE, source)
            setattr(redirected, _REQUEST_IP_ATTRIBUTE, expected_ip)
            setattr(redirected, _REQUEST_REDIRECT_URLS_ATTRIBUTE, redirect_urls)
        return redirected


def _restricted_urlopen() -> Callable[..., Any]:
    """Erzeuge den Standard-HTTP-Client mit enger Redirect-Allowlist."""

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _RestrictedRedirectHandler()
    )
    return opener.open


@dataclass(frozen=True, slots=True)
class _VpnRangeRule:
    provider: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class _SourceResult:
    data: dict[str, Any]
    final_url: str
    redirect_urls: tuple[str, ...]
    fetched_at_utc: str
    from_cache: bool


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_public_ip(ip: str) -> str:
    """Validiere und normalisiere eine global routbare IPv4- oder IPv6-Adresse."""

    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("IP-Adresse fehlt")
    candidate = ip.strip()
    if "%" in candidate:
        raise ValueError("IPv6-Zonenkennungen sind fuer oeffentliche Peers nicht erlaubt")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(f"Ungueltige IP-Adresse: {candidate}") from exc
    if not parsed.is_global or parsed.is_multicast:
        raise ValueError(f"IP-Adresse ist nicht global routbar: {parsed.compressed}")
    return parsed.compressed


def _clean_text(value: Any, *, maximum_length: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    # Externe Registrytexte duerfen weder PDF/XML-Steuerzeichen noch
    # unsichtbare Schreibrichtungswechsel in lokale Berichte einschleusen.
    printable = "".join(
        character if not unicodedata.category(character).startswith("C") else " "
        for character in value
    )
    cleaned = " ".join(printable.split()).strip()
    if not cleaned:
        return None
    return cleaned[:maximum_length]


def _clean_country(value: Any) -> str | None:
    """Uebernehme das Registrierungsland des Netzes, keine IP-Geolokation."""

    cleaned = _clean_text(value, maximum_length=2)
    if cleaned is None or len(cleaned) != 2 or not cleaned.isalpha():
        return None
    return cleaned.upper()


def _clean_abuse_email(value: Any) -> str | None:
    cleaned = _clean_text(value, maximum_length=254)
    if cleaned is None or cleaned.count("@") != 1 or any(char.isspace() for char in cleaned):
        return None
    local_part, domain = cleaned.rsplit("@", 1)
    if not local_part or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return None
    return cleaned


def _iter_abuse_entities(entities: Any, *, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    """Durchlaufe nur als Abuse markierte RDAP-Entitaeten in begrenzter Tiefe."""

    if depth > 4 or not isinstance(entities, list):
        return
    for entity in entities:
        if not isinstance(entity, Mapping):
            continue
        roles = entity.get("roles")
        if isinstance(roles, list) and any(
            isinstance(role, str) and role.casefold() == "abuse" for role in roles
        ):
            yield entity
        nested = entity.get("entities")
        if isinstance(nested, list):
            yield from _iter_abuse_entities(nested, depth=depth + 1)


def _abuse_email_from_entity(entity: Mapping[str, Any]) -> str | None:
    """Extrahiere ausschliesslich die E-Mail-Eigenschaft einer Abuse-vCard."""

    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) != 2 or not isinstance(vcard[1], list):
        return None
    for property_value in vcard[1]:
        if (
            isinstance(property_value, list)
            and len(property_value) >= 4
            and isinstance(property_value[0], str)
            and property_value[0].casefold() == "email"
        ):
            email = _clean_abuse_email(property_value[3])
            if email is not None:
                return email
    return None


def _project_rdap(payload: Any, requested_ip: str | None = None) -> dict[str, Any]:
    """Reduziere RDAP sofort auf erlaubte Netzfelder und eine Abuse-Adresse."""

    if not isinstance(payload, Mapping):
        raise EnrichmentError("RDAP-Antwort ist kein JSON-Objekt")
    start_value = payload.get("startAddress")
    end_value = payload.get("endAddress")
    if requested_ip is not None:
        if not isinstance(start_value, str) or not isinstance(end_value, str):
            raise EnrichmentError(
                "RDAP-Antwort enthaelt keinen vollstaendigen, pruefbaren Netzbereich"
            )
        try:
            requested = ipaddress.ip_address(requested_ip)
            start_address = ipaddress.ip_address(start_value)
            end_address = ipaddress.ip_address(end_value)
        except ValueError as exc:
            raise EnrichmentError("RDAP-Netzbereich enthaelt ungueltige Adressen") from exc
        if (
            requested.version != start_address.version
            or requested.version != end_address.version
            or not start_address <= requested <= end_address
        ):
            raise EnrichmentError("RDAP-Netzbereich umfasst die abgefragte IP nicht")
    abuse_email = None
    for entity in _iter_abuse_entities(payload.get("entities")):
        abuse_email = _abuse_email_from_entity(entity)
        if abuse_email is not None:
            break
    return {
        "rdap_name": _clean_text(payload.get("name")),
        "rdap_handle": _clean_text(payload.get("handle")),
        "country": _clean_country(payload.get("country")),
        "abuse_email": abuse_email,
    }


def _project_ripestat(payload: Any, requested_ip: str | None = None) -> dict[str, Any]:
    """Reduziere RIPEstat auf Praefix, ASN und Netzinhaberbezeichnung."""

    if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), Mapping):
        raise EnrichmentError("RIPEstat-Antwort enthaelt kein Datenobjekt")
    data = payload["data"]
    prefix_value = _clean_text(data.get("prefix"), maximum_length=64)
    if prefix_value is None:
        raise EnrichmentError("RIPEstat-Antwort enthaelt kein Netzpraefix")
    try:
        parsed_prefix = ipaddress.ip_network(prefix_value, strict=False)
    except ValueError as exc:
        raise EnrichmentError("RIPEstat-Antwort enthaelt ein ungueltiges Netzpraefix") from exc
    if not parsed_prefix.is_global or parsed_prefix.network_address.is_multicast:
        raise EnrichmentError("RIPEstat-Antwort enthaelt kein oeffentliches Netzpraefix")
    prefix = parsed_prefix.with_prefixlen
    if (
        requested_ip is not None
        and prefix is not None
        and ipaddress.ip_address(requested_ip) not in ipaddress.ip_network(prefix, strict=True)
    ):
        raise EnrichmentError("RIPEstat-Praefix umfasst die abgefragte IP nicht")

    raw_asns = data.get("asns")
    asns = (
        sorted(
            {
                raw_asn
                for raw_asn in raw_asns
                if type(raw_asn) is int and 0 < raw_asn <= 4_294_967_295
            }
        )
        if isinstance(raw_asns, list)
        else []
    )
    return {
        "prefix": prefix,
        "asns": asns,
        "holder": _clean_text(data.get("holder")),
    }


def _normalize_cached_rdap(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise EnrichmentError("RDAP-Cache enthaelt kein Objekt")
    return {
        "rdap_name": _clean_text(payload.get("rdap_name")),
        "rdap_handle": _clean_text(payload.get("rdap_handle")),
        "country": _clean_country(payload.get("country")),
        "abuse_email": _clean_abuse_email(payload.get("abuse_email")),
    }


def _normalize_cached_ripestat(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise EnrichmentError("RIPEstat-Cache enthaelt kein Objekt")
    prefix_value = _clean_text(payload.get("prefix"), maximum_length=64)
    if prefix_value is None:
        raise EnrichmentError("RIPEstat-Cache enthaelt kein Netzpraefix")
    try:
        parsed_prefix = ipaddress.ip_network(prefix_value, strict=True)
    except ValueError as exc:
        raise EnrichmentError("RIPEstat-Cache enthaelt ein ungueltiges Netzpraefix") from exc
    if not parsed_prefix.is_global or parsed_prefix.network_address.is_multicast:
        raise EnrichmentError("RIPEstat-Cache enthaelt kein oeffentliches Netzpraefix")
    prefix = parsed_prefix.with_prefixlen
    raw_asns = payload.get("asns")
    asns = (
        sorted(
            {
                raw_asn
                for raw_asn in raw_asns
                if type(raw_asn) is int and 0 < raw_asn <= 4_294_967_295
            }
        )
        if isinstance(raw_asns, list)
        else []
    )
    return {
        "prefix": prefix,
        "asns": asns,
        "holder": _clean_text(payload.get("holder")),
    }


class NetworkEnricher:
    """Ermittle nach explizitem Opt-in oeffentliche Netzbetreiberdaten.

    ``external_lookup_enabled=True`` bestaetigt, dass die aufrufende Anwendung
    den Nutzer ueber die Uebertragung jeder IP an RDAP.org, das zustaendige
    autoritative RIR-RDAP-Ziel und RIPEstat sowie ueber eine moegliche
    Protokollierung durch diese Dienste informiert und die Funktion
    ausdruecklich aktiviert hat.
    """

    def __init__(
        self,
        cache_dir: Path,
        timeout_seconds: float = 10.0,
        cache_days: float = 7.0,
        *,
        external_lookup_enabled: bool = False,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.25,
        urlopen: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds muss groesser als null sein")
        if (
            isinstance(cache_days, bool)
            or not isinstance(cache_days, (int, float))
            or not math.isfinite(cache_days)
            or cache_days <= 0
        ):
            raise ValueError("cache_days muss groesser als null sein")
        if type(max_retries) is not int or max_retries < 0 or max_retries > 5:
            raise ValueError("max_retries muss zwischen 0 und 5 liegen")
        if (
            isinstance(retry_backoff_seconds, bool)
            or not isinstance(retry_backoff_seconds, (int, float))
            or not math.isfinite(retry_backoff_seconds)
            or retry_backoff_seconds < 0
            or retry_backoff_seconds > 10
        ):
            raise ValueError("retry_backoff_seconds muss zwischen 0 und 10 liegen")
        if urlopen is not None and not callable(urlopen):
            raise TypeError("urlopen muss aufrufbar oder None sein")
        if not callable(sleep) or not callable(now):
            raise TypeError("sleep und now muessen aufrufbar sein")
        self.cache_dir = Path(cache_dir)
        self.timeout_seconds = float(timeout_seconds)
        self.cache_duration = timedelta(days=float(cache_days))
        self.external_lookup_enabled = external_lookup_enabled is True
        self.max_retries = max_retries
        self.retry_backoff_seconds = float(retry_backoff_seconds)
        self._urlopen = urlopen if urlopen is not None else _restricted_urlopen()
        self._sleep = sleep
        self._now = now

    def _current_time(self) -> datetime:
        now = self._now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise EnrichmentError("Die Zeitquelle muss einen Zeitzonenbezug enthalten")
        return now.astimezone(UTC)

    @staticmethod
    def _urls(ip: str) -> tuple[str, str]:
        rdap_url = RDAP_BASE_URL + urllib.parse.quote(ip, safe="")
        ripestat_url = RIPESTAT_PREFIX_URL + "?" + urllib.parse.urlencode({"resource": ip})
        return rdap_url, ripestat_url

    def _cache_path(self, source: str, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{source}-{digest}.json"

    @staticmethod
    def _is_managed_cache_file(path: Path) -> bool:
        name = path.name
        if not name.endswith(".json"):
            return False
        for prefix in ("rdap-", "ripestat-prefix-overview-"):
            if name.startswith(prefix):
                digest = name[len(prefix) : -len(".json")]
                return len(digest) == 64 and all(
                    character in "0123456789abcdef" for character in digest
                )
        return False

    def _prune_cache(self, *, keep: Path) -> None:
        """Begrenze ausschließlich eigene Cachedateien deterministisch."""

        try:
            paths = list(self.cache_dir.iterdir())
        except FileNotFoundError:
            return
        entries: list[tuple[int, str, Path, int]] = []
        for path in paths:
            if not self._is_managed_cache_file(path):
                continue
            try:
                metadata = path.stat()
            except FileNotFoundError:
                continue
            if not path.is_file():
                continue
            entries.append((metadata.st_mtime_ns, path.name, path, metadata.st_size))

        entries.sort()
        total_bytes = sum(entry[3] for entry in entries)
        while len(entries) > MAX_CACHE_FILES or total_bytes > MAX_CACHE_TOTAL_BYTES:
            removable_index = next(
                (index for index, entry in enumerate(entries) if entry[2] != keep),
                None,
            )
            if removable_index is None:
                raise EnrichmentError("Neue Cachedatei ueberschreitet das Gesamtlimit")
            _mtime, _name, path, size = entries.pop(removable_index)
            with suppress(FileNotFoundError):
                path.unlink()
            total_bytes -= size

    def _load_cache(
        self,
        source: str,
        url: str,
        normalizer: Callable[[Any], dict[str, Any]],
    ) -> _SourceResult | None:
        path = self._cache_path(source, url)
        try:
            if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != 0o600:
                path.chmod(0o600)
            with path.open("rb") as file_handle:
                raw_bytes = file_handle.read(MAX_CACHE_BYTES + 1)
            if len(raw_bytes) > MAX_CACHE_BYTES:
                return None
            raw = raw_bytes.decode("utf-8")
        except OSError:
            return None
        except UnicodeDecodeError:
            return None
        try:
            cached = json.loads(raw)
            if (
                not isinstance(cached, Mapping)
                or cached.get("cache_version") != CACHE_FORMAT_VERSION
                or cached.get("source") != source
                or cached.get("request_url") != url
                or not isinstance(cached.get("final_url"), str)
                or not isinstance(cached.get("redirect_urls"), list)
                or not all(isinstance(item, str) for item in cached["redirect_urls"])
            ):
                return None
            fetched_at_raw = cached.get("fetched_at_utc")
            if not isinstance(fetched_at_raw, str) or not fetched_at_raw.endswith("Z"):
                return None
            fetched_at = datetime.fromisoformat(fetched_at_raw.removesuffix("Z") + "+00:00")
            now = self._current_time()
            if fetched_at > now + timedelta(minutes=5) or now - fetched_at > self.cache_duration:
                return None
            initial_ip = _validate_service_url(url, source, initial=True)
            final_url = cached["final_url"]
            final_ip = _validate_service_url(final_url, source, initial=False)
            if final_ip != initial_ip:
                return None
            redirect_urls = tuple(dict.fromkeys(cached["redirect_urls"]))
            for redirect_url in redirect_urls:
                if _validate_service_url(redirect_url, source, initial=False) != initial_ip:
                    return None
            if redirect_urls and redirect_urls[-1] != final_url:
                return None
            if final_url != url and not redirect_urls:
                return None
            return _SourceResult(
                data=normalizer(cached.get("data")),
                final_url=final_url,
                redirect_urls=redirect_urls,
                fetched_at_utc=_utc_text(fetched_at),
                from_cache=True,
            )
        except (ValueError, TypeError, EnrichmentError):
            return None

    def _store_cache(
        self,
        source: str,
        request_url: str,
        final_url: str,
        redirect_urls: tuple[str, ...],
        fetched_at_utc: str,
        data: Mapping[str, Any],
    ) -> None:
        cache_path = self._cache_path(source, request_url)
        cache_record = {
            "cache_version": CACHE_FORMAT_VERSION,
            "source": source,
            "request_url": request_url,
            "final_url": final_url,
            "redirect_urls": list(redirect_urls),
            "fetched_at_utc": fetched_at_utc,
            "data": data,
        }
        payload_size = len(canonical_json_bytes(cache_record)) + 1
        if payload_size > min(MAX_CACHE_BYTES, MAX_CACHE_TOTAL_BYTES):
            raise EnrichmentError("Cacheeintrag ueberschreitet das Groessenlimit")
        atomic_write_json(cache_path, cache_record)
        self._prune_cache(keep=cache_path)

    def _retry_after_seconds(self, error: urllib.error.HTTPError) -> float | None:
        value = error.headers.get("Retry-After") if error.headers is not None else None
        if not value:
            return None
        try:
            seconds = float(value)
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(value)
            except (TypeError, ValueError, OverflowError):
                return None
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=UTC)
            seconds = (retry_at - self._current_time()).total_seconds()
        if not math.isfinite(seconds):
            return None
        return min(max(seconds, 0.0), 10.0)

    @staticmethod
    def _raise_if_cancelled(
        cancel_event: Event | None, *, cause: BaseException | None = None
    ) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise EnrichmentError(ENRICHMENT_CANCELLED_REASON) from cause

    def _wait_before_retry(self, delay: float, cancel_event: Event | None) -> None:
        if cancel_event is None:
            self._sleep(delay)
            return
        if cancel_event.wait(delay):
            raise EnrichmentError(ENRICHMENT_CANCELLED_REASON)

    def _request_json(
        self,
        source: str,
        url: str,
        *,
        cancel_event: Event | None = None,
    ) -> tuple[Any, str, tuple[str, ...]]:
        requested_ip = _validate_service_url(url, source, initial=True)
        last_error: BaseException | None = None
        attempts = self.max_retries + 1
        for attempt in range(attempts):
            self._raise_if_cancelled(cancel_event, cause=last_error)
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                method="GET",
            )
            setattr(request, _REQUEST_SOURCE_ATTRIBUTE, source)
            setattr(request, _REQUEST_IP_ATTRIBUTE, requested_ip)
            redirect_urls: list[str] = []
            setattr(request, _REQUEST_REDIRECT_URLS_ATTRIBUTE, redirect_urls)
            retry_delay: float | None = None
            try:
                with self._urlopen(request, timeout=self.timeout_seconds) as response:
                    status = getattr(response, "status", None)
                    if status is None:
                        status = response.getcode()
                    if status is not None and not 200 <= int(status) < 300:
                        raise urllib.error.HTTPError(
                            url,
                            int(status),
                            f"Unerwarteter HTTP-Status {status}",
                            getattr(response, "headers", None),
                            None,
                        )
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise EnrichmentError("HTTP-Antwort ueberschreitet das Groessenlimit")
                    get_url = getattr(response, "geturl", None)
                    final_url = get_url() if callable(get_url) else url
                    if not isinstance(final_url, str):
                        raise RedirectPolicyError("HTTP-Antwort nennt kein gueltiges Endziel")
                    final_ip = _validate_service_url(final_url, source, initial=False)
                    if final_ip != requested_ip:
                        raise RedirectPolicyError(
                            "HTTP-Endziel veraendert die abgefragte Ressourcen-IP"
                        )
                    if final_url != url and final_url not in redirect_urls:
                        # Auch ein injizierter/testbarer HTTP-Client ohne unseren
                        # Redirect-Handler muss sein abweichendes Endziel offenlegen.
                        redirect_urls.append(final_url)
                    return (
                        json.loads(raw.decode("utf-8")),
                        final_url,
                        tuple(dict.fromkeys(redirect_urls)),
                    )
            except RedirectPolicyError:
                raise
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code != 429 and not 500 <= exc.code < 600:
                    raise EnrichmentError(f"HTTP-Anfrage abgelehnt (Status {exc.code})") from exc
                retry_delay = self._retry_after_seconds(exc)
            except (
                urllib.error.URLError,
                TimeoutError,
                ConnectionError,
                json.JSONDecodeError,
                RecursionError,
                UnicodeDecodeError,
                EnrichmentError,
            ) as exc:
                last_error = exc

            self._raise_if_cancelled(cancel_event, cause=last_error)
            if attempt >= attempts - 1:
                break
            if retry_delay is None:
                retry_delay = min(self.retry_backoff_seconds * (2**attempt), 10.0)
            self._wait_before_retry(retry_delay, cancel_event)

        detail = type(last_error).__name__ if last_error is not None else "unbekannter Fehler"
        raise EnrichmentError(
            f"HTTP-Abruf ist nach {attempts} Versuch(en) fehlgeschlagen ({detail})"
        ) from last_error

    def _load_source(
        self,
        *,
        source: str,
        url: str,
        projector: Callable[[Any], dict[str, Any]],
        cache_normalizer: Callable[[Any], dict[str, Any]],
        cancel_event: Event | None = None,
    ) -> _SourceResult:
        _validate_service_url(url, source, initial=True)
        cached = self._load_cache(source, url, cache_normalizer)
        if cached is not None:
            return cached
        payload, final_url, redirect_urls = self._request_json(
            source, url, cancel_event=cancel_event
        )
        projected = projector(payload)
        fetched_at_utc = _utc_text(self._current_time())
        self._store_cache(
            source,
            url,
            final_url,
            redirect_urls,
            fetched_at_utc,
            projected,
        )
        return _SourceResult(
            data=projected,
            final_url=final_url,
            redirect_urls=redirect_urls,
            fetched_at_utc=fetched_at_utc,
            from_cache=False,
        )

    def enrich(self, ip: str, *, cancel_event: Event | None = None) -> NetworkEnrichment:
        """Liefere nach Opt-in Netz-/Organisationsfelder fuer eine oeffentliche IP."""

        normalized_ip = validate_public_ip(ip)
        if not self.external_lookup_enabled:
            raise ExternalLookupDisabledError(
                "Externe Netzauskunft ist deaktiviert. " + EXTERNAL_LOOKUP_DISCLOSURE
            )
        rdap_url, ripestat_url = self._urls(normalized_ip)
        errors: list[str] = []
        rdap: dict[str, Any] = {}
        ripestat: dict[str, Any] = {}
        source_results: list[tuple[str, _SourceResult]] = []
        rdap_started = False
        ripestat_started = False
        if cancel_event is not None and cancel_event.is_set():
            errors.append(f"RDAP: {ENRICHMENT_CANCELLED_REASON}")
        else:
            rdap_started = True
            try:
                rdap_result = self._load_source(
                    source="rdap",
                    url=rdap_url,
                    projector=lambda payload: _project_rdap(payload, normalized_ip),
                    cache_normalizer=_normalize_cached_rdap,
                    cancel_event=cancel_event,
                )
                rdap = rdap_result.data
                source_results.append(("rdap", rdap_result))
            except (EnrichmentError, OSError) as exc:
                errors.append(f"RDAP: {exc}")
        if cancel_event is not None and cancel_event.is_set():
            errors.append(f"RIPEstat: {ENRICHMENT_CANCELLED_REASON}")
        else:
            ripestat_started = True
            try:
                ripestat_result = self._load_source(
                    source="ripestat-prefix-overview",
                    url=ripestat_url,
                    projector=lambda payload: _project_ripestat(payload, normalized_ip),
                    cache_normalizer=_normalize_cached_ripestat,
                    cancel_event=cancel_event,
                )
                ripestat = ripestat_result.data
                source_results.append(("ripestat-prefix-overview", ripestat_result))
            except (EnrichmentError, OSError) as exc:
                errors.append(f"RIPEstat: {exc}")
        prefix = ripestat.get("prefix")
        if prefix is not None and ipaddress.ip_address(normalized_ip) not in ipaddress.ip_network(
            prefix, strict=True
        ):
            errors.append("RIPEstat: Das gelieferte Praefix umfasst die abgefragte IP nicht")
            ripestat = {}

        rdap_redirect_urls = [
            url
            for source, result in source_results
            if source == "rdap"
            for url in result.redirect_urls
        ]
        ripestat_redirect_urls = [
            url
            for source, result in source_results
            if source != "rdap"
            for url in result.redirect_urls
        ]
        source_url_values: list[str] = []
        if rdap_started:
            source_url_values.extend((rdap_url, *rdap_redirect_urls))
        if ripestat_started:
            source_url_values.extend((ripestat_url, *ripestat_redirect_urls))
        source_urls = tuple(dict.fromkeys(source_url_values))
        assembled_at_utc = _utc_text(self._current_time())

        return NetworkEnrichment(
            ip=normalized_ip,
            # Dies ist der Zeitpunkt der lokalen Zusammenstellung. Die moeglicherweise
            # aelteren Abrufzeitpunkte der einzelnen Quellen stehen separat darunter.
            enriched_at_utc=assembled_at_utc,
            prefix=ripestat.get("prefix"),
            asns=tuple(ripestat.get("asns", ())),
            holder=ripestat.get("holder"),
            rdap_name=rdap.get("rdap_name"),
            rdap_handle=rdap.get("rdap_handle"),
            country=rdap.get("country"),
            abuse_email=rdap.get("abuse_email"),
            source_urls=source_urls,
            source_fetched_at_utc=tuple(
                (source, result.fetched_at_utc) for source, result in source_results
            ),
            cached_sources=tuple(source for source, result in source_results if result.from_cache),
            error="; ".join(errors) if errors else None,
        )


def _configured_values(values: Iterable[str] | str) -> tuple[str, ...]:
    if isinstance(values, str):
        return (values,)
    return tuple(values)


def _matches_vpn_marker(value: str, marker: str) -> bool:
    """Akzeptiere einen Marker nur exakt oder als erstes abgegrenztes Wort."""

    if value == marker:
        return True
    if not value.startswith(marker):
        return False
    boundary_category = unicodedata.category(value[len(marker)])
    return boundary_category[0] not in {"L", "M", "N"} and boundary_category != "Pc"


class VpnClassifier:
    """Klassifiziere offline nur anhand expliziter Netze und abgegrenzter Marker."""

    def __init__(
        self,
        vpn_ranges: (Mapping[str, Iterable[str] | str] | Iterable[tuple[str, str]] | None) = None,
        vpn_provider_markers: (
            Mapping[str, Iterable[str] | str] | Iterable[tuple[str, Iterable[str] | str]] | None
        ) = None,
    ) -> None:
        range_rules: list[_VpnRangeRule] = []
        if isinstance(vpn_ranges, Mapping):
            configured_ranges = (
                (network, provider)
                for provider, ranges in vpn_ranges.items()
                for network in _configured_values(ranges)
            )
        else:
            configured_ranges = iter(vpn_ranges or ())
        for value, provider in configured_ranges:
            cleaned_provider = _clean_text(provider, maximum_length=200)
            if cleaned_provider is None:
                raise ValueError("VPN-Anbietername darf nicht leer sein")
            try:
                network = ipaddress.ip_network(value, strict=True)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Ungueltiges VPN-Praefix fuer {cleaned_provider}: {value}"
                ) from exc
            if not network.is_global or network.network_address.is_multicast:
                raise ValueError(f"VPN-Praefix ist nicht global routbar: {network.with_prefixlen}")
            range_rules.append(_VpnRangeRule(cleaned_provider, network))

        marker_rules: dict[str, set[str]] = {}
        if isinstance(vpn_provider_markers, Mapping):
            configured_markers = vpn_provider_markers.items()
        else:
            configured_markers = iter(vpn_provider_markers or ())
        for provider, markers in configured_markers:
            cleaned_provider = _clean_text(provider, maximum_length=200)
            if cleaned_provider is None:
                raise ValueError("VPN-Anbietername darf nicht leer sein")
            for marker in _configured_values(markers):
                cleaned_marker = _clean_text(marker)
                if cleaned_marker is None:
                    raise ValueError(f"Leerer VPN-Anbietermarker fuer {cleaned_provider}")
                marker_rules.setdefault(cleaned_marker.casefold(), set()).add(cleaned_provider)
        self._range_rules = tuple(range_rules)
        self._marker_rules = {
            marker: frozenset(providers) for marker, providers in marker_rules.items()
        }

    @staticmethod
    def _unknown(reason: str) -> VpnClassification:
        return VpnClassification(status="unknown", reason=reason)

    def classify(
        self,
        enrichment: NetworkEnrichment | str,
        *,
        holder: str | None = None,
        rdap_name: str | None = None,
    ) -> VpnClassification:
        """Gib ``known_vpn`` nur bei einem ausdruecklichen Konfigurationstreffer zurueck."""

        if isinstance(enrichment, NetworkEnrichment):
            ip_text = enrichment.ip
            holder_value = enrichment.holder
            rdap_name_value = enrichment.rdap_name
        else:
            ip_text = enrichment
            holder_value = holder
            rdap_name_value = rdap_name
        parsed_ip = ipaddress.ip_address(validate_public_ip(ip_text))
        matches = [
            rule
            for rule in self._range_rules
            if rule.network.version == parsed_ip.version and parsed_ip in rule.network
        ]
        if matches:
            longest_prefix = max(rule.network.prefixlen for rule in matches)
            most_specific = [rule for rule in matches if rule.network.prefixlen == longest_prefix]
            providers = {rule.provider for rule in most_specific}
            if len(providers) == 1:
                rule = most_specific[0]
                return VpnClassification(
                    status="known_vpn",
                    provider=rule.provider,
                    reason=(
                        "IP liegt im ausdruecklich konfigurierten VPN-Praefix "
                        f"{rule.network.with_prefixlen}."
                    ),
                    source="configured_cidr",
                )
            return self._unknown("Mehrdeutige Anbieterzuordnung fuer das konfigurierte Praefix.")

        provider_matches: set[str] = set()
        matched_fields: set[str] = set()
        for field_name, value in (("holder", holder_value), ("rdap_name", rdap_name_value)):
            cleaned = _clean_text(value)
            if cleaned is None:
                continue
            folded_value = cleaned.casefold()
            field_matched = False
            for marker, providers in self._marker_rules.items():
                if not _matches_vpn_marker(folded_value, marker):
                    continue
                provider_matches.update(providers)
                field_matched = True
            if field_matched:
                matched_fields.add(field_name)
        if len(provider_matches) == 1:
            provider = next(iter(provider_matches))
            return VpnClassification(
                status="known_vpn",
                provider=provider,
                reason=(
                    "Treffer eines ausdruecklich konfigurierten Anbietermarkers am Feldanfang."
                ),
                source="configured_exact_marker:" + ",".join(sorted(matched_fields)),
            )
        if len(provider_matches) > 1:
            return self._unknown("Mehrdeutige Zuordnung durch konfigurierte Anbietermarker.")
        return self._unknown(
            "Kein expliziter VPN-Treffer; daraus folgt keine Aussage, ob die IP ein VPN ist."
        )


def classify_vpn(
    enrichment: NetworkEnrichment,
    *,
    vpn_ranges: (Mapping[str, Iterable[str] | str] | Iterable[tuple[str, str]] | None) = None,
    vpn_provider_markers: (
        Mapping[str, Iterable[str] | str] | Iterable[tuple[str, Iterable[str] | str]] | None
    ) = None,
) -> VpnClassification:
    """Klassifiziere eine Netzauskunft ueber eine funktionale Schnittstelle."""

    return VpnClassifier(vpn_ranges, vpn_provider_markers).classify(enrichment)
