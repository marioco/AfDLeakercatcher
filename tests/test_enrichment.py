"""Tests fuer datensparsame Netzauskunft und konservative VPN-Einordnung."""

from __future__ import annotations

import errno
import json
import os
import stat
import unicodedata
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

import bittorrent_beobachter.enrichment as enrichment_module
from bittorrent_beobachter.enrichment import (
    _REQUEST_IP_ATTRIBUTE,
    _REQUEST_REDIRECT_URLS_ATTRIBUTE,
    _REQUEST_SOURCE_ATTRIBUTE,
    EXTERNAL_LOOKUP_DISCLOSURE,
    ExternalLookupDisabledError,
    NetworkEnricher,
    RedirectPolicyError,
    VpnClassifier,
    _RestrictedRedirectHandler,
    validate_public_ip,
)
from bittorrent_beobachter.models import NetworkEnrichment

FIXED_NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


class _JsonResponse:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.body = json.dumps(payload).encode("utf-8")
        self.status = status

    def __enter__(self) -> _JsonResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def _rdap_payload() -> dict[str, Any]:
    return {
        "name": "EXAMPLE-NET",
        "handle": "NET-8-8-8-0-1",
        "country": "US",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Jane Mustermann"],
                        ["adr", {}, "text", "Vertrauliche Privatanschrift"],
                    ],
                ],
            },
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Abuse Team"],
                        ["email", {}, "text", "abuse@example.net"],
                    ],
                ],
            },
        ],
    }


def _ripestat_payload() -> dict[str, Any]:
    return {
        "data": {
            "prefix": "8.8.8.0/24",
            "asns": [15169, 15169, "invalid"],
            "holder": "Example Network LLC",
        }
    }


def test_external_lookup_is_disabled_by_default(tmp_path: Path) -> None:
    calls = 0

    def forbidden_urlopen(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise AssertionError("Es darf kein HTTP-Aufruf erfolgen")

    enricher = NetworkEnricher(tmp_path, urlopen=forbidden_urlopen)

    with pytest.raises(ExternalLookupDisabledError) as caught:
        enricher.enrich("8.8.8.8")

    assert calls == 0
    assert "rdap.org" in str(caught.value)
    assert "stat.ripe.net" in str(caught.value)
    assert "autoritative RIR-RDAP-Ziel" in EXTERNAL_LOOKUP_DISCLOSURE
    assert "rdap.afrinic.net" in EXTERNAL_LOOKUP_DISCLOSURE
    assert "rdap.lacnic.net" in EXTERNAL_LOOKUP_DISCLOSURE
    assert "stat.ripe.net" in EXTERNAL_LOOKUP_DISCLOSURE
    assert "protokollieren" in EXTERNAL_LOOKUP_DISCLOSURE


def test_default_http_client_ignores_proxy_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")

    enricher = NetworkEnricher(tmp_path)
    opener = enricher._urlopen.__self__
    proxy_handlers = [
        handler for handler in opener.handlers if isinstance(handler, urllib.request.ProxyHandler)
    ]
    assert not any(handler.proxies for handler in proxy_handlers)


@pytest.mark.parametrize(
    "target",
    [
        "https://attacker.example/ip/8.8.8.8",
        "http://rdap.db.ripe.net/ip/8.8.8.8",
        "https://user:secret@rdap.db.ripe.net/ip/8.8.8.8",
        "https://rdap.db.ripe.net:444/ip/8.8.8.8",
    ],
)
def test_redirect_policy_rejects_unsafe_targets(target: str) -> None:
    request = urllib.request.Request("https://rdap.org/ip/8.8.8.8", method="GET")
    setattr(request, _REQUEST_SOURCE_ATTRIBUTE, "rdap")
    setattr(request, _REQUEST_IP_ATTRIBUTE, "8.8.8.8")
    setattr(request, _REQUEST_REDIRECT_URLS_ATTRIBUTE, [])
    with pytest.raises(RedirectPolicyError):
        _RestrictedRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            Message(),
            target,
        )


def test_redirect_policy_allows_authoritative_rir_https_target() -> None:
    request = urllib.request.Request("https://rdap.org/ip/8.8.8.8", method="GET")
    setattr(request, _REQUEST_SOURCE_ATTRIBUTE, "rdap")
    setattr(request, _REQUEST_IP_ATTRIBUTE, "8.8.8.8")
    redirect_urls: list[str] = []
    setattr(request, _REQUEST_REDIRECT_URLS_ATTRIBUTE, redirect_urls)
    redirected = _RestrictedRedirectHandler().redirect_request(
        request,
        None,
        302,
        "Found",
        Message(),
        "https://rdap.db.ripe.net/ip/8.8.8.8",
    )
    assert redirected is not None
    assert redirected.full_url == "https://rdap.db.ripe.net/ip/8.8.8.8"
    assert getattr(redirected, _REQUEST_SOURCE_ATTRIBUTE) == "rdap"
    assert getattr(redirected, _REQUEST_IP_ATTRIBUTE) == "8.8.8.8"
    assert redirect_urls == ["https://rdap.db.ripe.net/ip/8.8.8.8"]
    assert getattr(redirected, _REQUEST_REDIRECT_URLS_ATTRIBUTE) is redirect_urls
    assert _RestrictedRedirectHandler.max_redirections == 5


def test_enrichment_projects_allowed_fields_and_caches_only_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, float]] = []

    def fake_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        requests.append((request.full_url, timeout))
        if "rdap.org" in request.full_url:
            response = _JsonResponse(_rdap_payload())
            response.geturl = lambda: "https://rdap.db.ripe.net/ip/8.8.8.8"
            return response
        return _JsonResponse(_ripestat_payload())

    enricher = NetworkEnricher(
        tmp_path,
        timeout_seconds=3.5,
        external_lookup_enabled=True,
        urlopen=fake_urlopen,
        now=lambda: FIXED_NOW,
    )

    result = enricher.enrich("8.8.8.8")

    assert result.prefix == "8.8.8.0/24"
    assert result.asns == (15169,)
    assert result.holder == "Example Network LLC"
    assert result.rdap_name == "EXAMPLE-NET"
    assert result.rdap_handle == "NET-8-8-8-0-1"
    assert result.country == "US"
    assert result.abuse_email == "abuse@example.net"
    assert result.error is None
    assert len(requests) == 2
    assert all(timeout == 3.5 for _, timeout in requests)

    cache_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(tmp_path.glob("*.json"))
    )
    assert "Jane Mustermann" not in cache_text
    assert "Vertrauliche Privatanschrift" not in cache_text
    assert "Abuse Team" not in cache_text
    assert "abuse@example.net" in cache_text
    assert "rdap.db.ripe.net" in cache_text
    assert '"redirect_urls":["https://rdap.db.ripe.net/ip/8.8.8.8"]' in cache_text
    assert "https://rdap.db.ripe.net/ip/8.8.8.8" in result.source_urls
    cache_paths = sorted(tmp_path.glob("*.json"))

    def no_second_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Gueltige Cachewerte muessen Netzaufrufe vermeiden")

    def read_only_chmod(
        _path: Path,
        _mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        del follow_symlinks
        raise OSError(errno.EROFS, "read-only file system")

    with monkeypatch.context() as read_only_context:
        read_only_context.setattr(Path, "chmod", read_only_chmod)
        cached = NetworkEnricher(
            tmp_path,
            external_lookup_enabled=True,
            urlopen=no_second_network_call,
            now=lambda: FIXED_NOW + timedelta(days=1),
        ).enrich("8.8.8.8")
    assert cached.holder == result.holder
    assert cached.abuse_email == result.abuse_email
    assert result.enriched_at_utc == "2026-10-20T12:00:00Z"
    assert cached.enriched_at_utc == "2026-10-21T12:00:00Z"
    assert cached.source_fetched_at_utc == result.source_fetched_at_utc
    assert cached.cached_sources == ("rdap", "ripestat-prefix-overview")
    assert result.cached_sources == ()
    if os.name != "nt":
        for path in cache_paths:
            path.chmod(0o664)
        hardened_cached = NetworkEnricher(
            tmp_path,
            external_lookup_enabled=True,
            urlopen=no_second_network_call,
            now=lambda: FIXED_NOW + timedelta(days=1),
        ).enrich("8.8.8.8")
        assert hardened_cached.cached_sources == ("rdap", "ripestat-prefix-overview")
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in cache_paths)


def test_external_text_strips_control_and_direction_override_characters(
    tmp_path: Path,
) -> None:
    rdap = _rdap_payload()
    rdap["name"] = "Safe\x00\u202eName"
    ripestat = _ripestat_payload()
    ripestat["data"]["holder"] = "Example\ud800 Network"

    def fake_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        del timeout
        return _JsonResponse(rdap if "rdap.org" in request.full_url else ripestat)

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=0,
        urlopen=fake_urlopen,
        now=lambda: FIXED_NOW,
    ).enrich("8.8.8.8")

    assert result.rdap_name == "Safe Name"
    assert result.holder == "Example Network"
    assert all(
        not unicodedata.category(character).startswith("C")
        for value in (result.rdap_name, result.holder)
        for character in value or ""
    )


@pytest.mark.parametrize(
    ("file_limit", "byte_limit"),
    [(2, 100), (10, 8)],
)
def test_cache_pruning_is_bounded_and_ignores_unmanaged_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_limit: int,
    byte_limit: int,
) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    managed = [cache_dir / f"rdap-{index:064x}.json" for index in range(1, 4)]
    for index, path in enumerate(managed, start=1):
        path.write_bytes(b"data")
        os.utime(path, ns=(index, index))
    unmanaged = cache_dir / "do-not-delete.json"
    unmanaged.write_bytes(b"user data")
    monkeypatch.setattr(enrichment_module, "MAX_CACHE_FILES", file_limit)
    monkeypatch.setattr(enrichment_module, "MAX_CACHE_TOTAL_BYTES", byte_limit)

    NetworkEnricher(cache_dir)._prune_cache(keep=managed[-1])

    assert not managed[0].exists()
    assert managed[1].exists()
    assert managed[2].exists()
    assert unmanaged.read_bytes() == b"user data"


def test_store_cache_invokes_pruning_after_atomic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = NetworkEnricher(tmp_path)
    pruned: list[Path] = []

    def fake_prune(*, keep: Path) -> None:
        assert keep.exists()
        pruned.append(keep)

    monkeypatch.setattr(enricher, "_prune_cache", fake_prune)
    enricher._store_cache(
        "rdap",
        "https://rdap.org/ip/8.8.8.8",
        "https://rdap.db.ripe.net/ip/8.8.8.8",
        ("https://rdap.db.ripe.net/ip/8.8.8.8",),
        "2026-10-20T12:00:00Z",
        {"rdap_name": "Example"},
    )

    assert len(pruned) == 1
    assert pruned[0].read_text(encoding="utf-8").endswith("\n")


def test_retry_is_bounded_for_retryable_http_error(tmp_path: Path) -> None:
    calls = 0
    sleeps: list[float] = []

    def flaky_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        nonlocal calls
        del timeout
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "temporary",
                Message(),
                None,
            )
        if "rdap.org" in request.full_url:
            return _JsonResponse(_rdap_payload())
        return _JsonResponse(_ripestat_payload())

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=1,
        retry_backoff_seconds=0.125,
        urlopen=flaky_urlopen,
        sleep=sleeps.append,
        now=lambda: FIXED_NOW,
    ).enrich("8.8.8.8")

    assert result.error is None
    assert calls == 3
    assert sleeps == [0.125]


def test_retry_after_429_uses_header_without_touching_cache_state(
    tmp_path: Path,
) -> None:
    calls = 0
    sleeps: list[float] = []

    def rate_limited_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        nonlocal calls
        del timeout
        calls += 1
        if calls == 1:
            headers = Message()
            headers["Retry-After"] = "0"
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "rate limited",
                headers,
                None,
            )
        if "rdap.org" in request.full_url:
            return _JsonResponse(_rdap_payload())
        return _JsonResponse(_ripestat_payload())

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=1,
        urlopen=rate_limited_urlopen,
        sleep=sleeps.append,
        now=lambda: FIXED_NOW,
    ).enrich("8.8.8.8")

    assert result.error is None
    assert calls == 3
    assert sleeps == [0.0]


def test_non_retryable_http_status_is_not_retried(tmp_path: Path) -> None:
    calls: list[str] = []
    sleeps: list[float] = []

    def fake_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        del timeout
        calls.append(request.full_url)
        if "rdap.org" in request.full_url:
            return _JsonResponse({}, status=404)
        return _JsonResponse(_ripestat_payload())

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=2,
        urlopen=fake_urlopen,
        sleep=sleeps.append,
        now=lambda: FIXED_NOW,
    ).enrich("8.8.8.8")

    assert len(calls) == 2
    assert sleeps == []
    assert result.rdap_name is None
    assert "Status 404" in (result.error or "")


def test_unrelated_source_networks_are_rejected(tmp_path: Path) -> None:
    rdap = _rdap_payload()
    rdap["startAddress"] = "1.1.1.0"
    rdap["endAddress"] = "1.1.1.255"
    ripestat = _ripestat_payload()
    ripestat["data"]["prefix"] = "1.1.1.0/24"

    def fake_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        del timeout
        return _JsonResponse(rdap if "rdap.org" in request.full_url else ripestat)

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=0,
        urlopen=fake_urlopen,
        now=lambda: FIXED_NOW,
    ).enrich("8.8.8.8")

    assert result.rdap_name is None
    assert result.prefix is None
    assert result.holder is None
    assert "umfasst die abgefragte IP nicht" in (result.error or "")


def test_rdap_without_verifiable_range_is_not_attributed_to_ip(tmp_path: Path) -> None:
    rdap = _rdap_payload()
    rdap.pop("startAddress")
    rdap.pop("endAddress")

    def fake_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        del timeout
        return _JsonResponse(rdap if "rdap.org" in request.full_url else _ripestat_payload())

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=0,
        urlopen=fake_urlopen,
        now=lambda: FIXED_NOW,
    ).enrich("8.8.8.8")

    assert result.rdap_name is None
    assert result.rdap_handle is None
    assert result.country is None
    assert result.abuse_email is None
    assert result.prefix == "8.8.8.0/24"
    assert "pruefbaren Netzbereich" in (result.error or "")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-an-ip",
        "10.0.0.1",
        "127.0.0.1",
        "224.0.0.1",
        "::1",
        "ff02::1",
        "fe80::1%eth0",
    ],
)
def test_validate_public_ip_rejects_non_global_values(value: str) -> None:
    with pytest.raises(ValueError):
        validate_public_ip(value)


def test_validate_public_ip_normalizes_global_ipv6() -> None:
    assert validate_public_ip("2606:4700:4700:0:0:0:0:1111") == "2606:4700:4700::1111"


def test_ipv6_lookup_keeps_ip_binding_and_uses_encoded_start_url(tmp_path: Path) -> None:
    requests: list[str] = []
    rdap = {
        **_rdap_payload(),
        "startAddress": "2606:4700:4700::",
        "endAddress": "2606:4700:4700:ffff:ffff:ffff:ffff:ffff",
    }
    ripestat = {
        "data": {
            "prefix": "2606:4700:4700::/48",
            "asns": [13335],
            "holder": "IPv6 Example Network",
        }
    }

    def fake_urlopen(request: Any, *, timeout: float) -> _JsonResponse:
        del timeout
        requests.append(request.full_url)
        if "rdap.org" in request.full_url:
            response = _JsonResponse(rdap)
            response.geturl = lambda: "https://rdap.arin.net/registry/ip/2606:4700:4700::1111"
            return response
        return _JsonResponse(ripestat)

    result = NetworkEnricher(
        tmp_path,
        external_lookup_enabled=True,
        max_retries=0,
        urlopen=fake_urlopen,
        now=lambda: FIXED_NOW,
    ).enrich("2606:4700:4700:0:0:0:0:1111")

    assert result.ip == "2606:4700:4700::1111"
    assert result.prefix == "2606:4700:4700::/48"
    assert result.asns == (13335,)
    assert result.error is None
    assert requests[0] == "https://rdap.org/ip/2606%3A4700%3A4700%3A%3A1111"
    assert "https://rdap.arin.net/registry/ip/2606:4700:4700::1111" in result.source_urls


def test_vpn_classifier_uses_only_explicit_cidr_or_configured_marker() -> None:
    classifier = VpnClassifier(
        vpn_ranges={"Configured VPN": ("8.8.8.0/24",)},
        vpn_provider_markers={"Marker VPN": ("Exact VPN Network",)},
    )

    by_range = classifier.classify("8.8.8.8")
    by_marker = classifier.classify(
        "9.9.9.9",
        holder="Exact VPN Network",
    )
    substring = classifier.classify(
        "9.9.9.9",
        holder="Subsidiary of Exact VPN Network",
    )

    assert by_range.status == "known_vpn"
    assert by_range.provider == "Configured VPN"
    assert by_marker.status == "known_vpn"
    assert by_marker.provider == "Marker VPN"
    assert substring.status == "unknown"
    assert substring.provider is None
    assert "keine Aussage" in (substring.reason or "")


@pytest.mark.parametrize(
    "holder",
    [
        "protonvpn",
        "ProtonVPN-2 Proton AG",
        "PROTONVPN Proton AG",
        "ProtonVPN/Proton AG",
    ],
)
def test_vpn_classifier_accepts_exact_or_delimited_marker_at_start(holder: str) -> None:
    result = VpnClassifier(vpn_provider_markers={"Proton VPN": "protonvpn"}).classify(
        "9.9.9.9",
        holder=holder,
    )

    assert result.status == "known_vpn"
    assert result.provider == "Proton VPN"


@pytest.mark.parametrize(
    "holder",
    [
        "Example ProtonVPN-2 Proton AG",
        "NotProtonVPN",
        "ProtonVPN2 Proton AG",
        "ProtonVPNPlus AG",
        "ProtonVPN_2 Proton AG",
    ],
)
def test_vpn_classifier_rejects_substrings_and_unbounded_prefixes(holder: str) -> None:
    result = VpnClassifier(vpn_provider_markers={"Proton VPN": "protonvpn"}).classify(
        "9.9.9.9",
        holder=holder,
    )

    assert result.status == "unknown"
    assert result.provider is None


def test_vpn_classifier_supports_explicit_ipv6_ranges() -> None:
    result = VpnClassifier(vpn_ranges={"Configured IPv6 VPN": ("2606:4700:4700::/48",)}).classify(
        "2606:4700:4700::1111"
    )

    assert result.status == "known_vpn"
    assert result.provider == "Configured IPv6 VPN"


def test_vpn_classifier_accepts_enrichment_model() -> None:
    enrichment = NetworkEnrichment(
        ip="9.9.9.9",
        enriched_at_utc="2026-10-20T12:00:00Z",
        rdap_name="Exact VPN Network",
    )
    result = VpnClassifier(vpn_provider_markers={"Marker VPN": "Exact VPN Network"}).classify(
        enrichment
    )

    assert result.status == "known_vpn"
    assert result.provider == "Marker VPN"


def test_vpn_classifier_accepts_application_config_tuple_shape() -> None:
    result = VpnClassifier(
        vpn_ranges=(("8.8.8.0/24", "Configured VPN"),),
        vpn_provider_markers=(("Marker VPN", ("Exact VPN Network",)),),
    ).classify("8.8.8.8")

    assert result.status == "known_vpn"
    assert result.provider == "Configured VPN"
