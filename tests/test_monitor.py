"""Offline-Tests fuer die begrenzte Monitor-Orchestrierung."""

from __future__ import annotations

import errno
import json
import logging
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bittorrent_beobachter.config import (
    AppConfig,
    ConfigError,
    DhtSettings,
    EnrichmentSettings,
    PeerSettings,
    ReportingSettings,
    load_config,
    save_config,
)
from bittorrent_beobachter.evidence import EvidenceJournal
from bittorrent_beobachter.models import (
    HandshakeResult,
    NetworkEnrichment,
    PeerCandidate,
    ScanResult,
    Target,
)
from bittorrent_beobachter.monitor import MonitorError, run_scan

HASH_A = bytes.fromhex("11" * 20)
HASH_B = bytes.fromhex("22" * 20)


def _candidate(target: Target, ip: str, port: int) -> PeerCandidate:
    return PeerCandidate(
        target_label=target.label,
        info_hash_hex=target.info_hash_hex,
        ip=ip,
        port=port,
        discovered_at_utc="2026-10-20T10:00:00.000Z",
        dht_node_ip="9.9.9.9",
        dht_node_port=6881,
        transaction_id_hex="01020304",
        response_sha256="ab" * 32,
        source_note=target.source_note,
    )


def _handshake(candidate: PeerCandidate, *, confirmed: bool = True) -> HandshakeResult:
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc="2026-10-20T10:00:01.000Z",
        completed_at_utc="2026-10-20T10:00:01.100Z" if confirmed else None,
        confirmed=confirmed,
        remote_peer_id_hex="cd" * 20 if confirmed else None,
        reserved_bits_hex="00" * 8 if confirmed else None,
        local_ip="192.0.2.10" if confirmed else None,
        local_port=50_000 if confirmed else None,
        bytes_sent=68 if confirmed else 0,
        bytes_received=68 if confirmed else 0,
        error=None if confirmed else "ConnectionRefusedError: abgelehnt",
    )


def _config(*, enrichment_enabled: bool = True) -> AppConfig:
    targets = (
        Target(
            label="Ziel A",
            info_hash=HASH_A,
            source_note="Hinweis ausschließlich für Ziel A.",
        ),
        Target(
            label="Ziel B",
            info_hash=HASH_B,
            source_note="Hinweis ausschließlich für Ziel B.",
        ),
    )
    return AppConfig(
        targets=targets,
        dht=DhtSettings(
            timeout_seconds=1.25,
            max_queries=12,
            alpha=3,
            max_nodes=80,
            max_candidates=10,
            bootstrap_nodes=(("bootstrap.invalid", 6881),),
        ),
        peer=PeerSettings(timeout_seconds=2.0, max_checks=3, workers=2),
        enrichment=EnrichmentSettings(
            enabled=enrichment_enabled,
            timeout_seconds=3.0,
            cache_days=5,
            vpn_ranges=(("8.8.8.0/24", "Test VPN"),),
            vpn_provider_markers=(("Marker VPN", ("marker network",)),),
        ),
        reporting=ReportingSettings(
            reporter_name="Teststelle",
            reporter_email="test@example.org",
            police_recipient="polizei@example.org",
            legal_notes=("Nur pruefen.",),
        ),
    )


def _install_successful_network_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    second_confirmed: bool = True,
    crawler_errors: tuple[str, ...] = (),
) -> dict[str, Any]:
    import bittorrent_beobachter.monitor as monitor

    calls: dict[str, Any] = {
        "crawler_configs": [],
        "verified": [],
        "enriched": [],
        "enricher_kwargs": None,
        "report": None,
    }

    async def fake_resolve(*_args: Any, **_kwargs: Any) -> list[tuple[str, int]]:
        return [("9.9.9.9", 6881)]

    class FakeCrawler:
        def __init__(self, _bootstrap: Any, *, config: Any) -> None:
            self.config = config
            self.queries_started = 2
            self.queries_completed = 1
            self.errors = crawler_errors
            calls["crawler_configs"].append(config)

        async def discover(self, target: Target) -> list[PeerCandidate]:
            if target.info_hash == HASH_A:
                return [
                    _candidate(target, "8.8.8.8", 6001),
                    _candidate(target, "1.0.0.1", 6002),
                ]
            return [
                _candidate(target, "1.1.1.1", 7001),
                _candidate(target, "208.67.222.222", 7002),
            ]

    class FakeVerifier:
        def __init__(self, *, timeout: float) -> None:
            calls["verifier_timeout"] = timeout

        async def verify(self, candidate: PeerCandidate, _info_hash: bytes) -> HandshakeResult:
            calls["verified"].append((candidate.info_hash_hex, candidate.ip))
            confirmed = second_confirmed or candidate.ip != "1.1.1.1"
            return _handshake(candidate, confirmed=confirmed)

    class FakeEnricher:
        def __init__(self, cache_dir: Path, **kwargs: Any) -> None:
            calls["enricher_cache"] = cache_dir
            calls["enricher_kwargs"] = kwargs

        def enrich(self, ip: str) -> NetworkEnrichment:
            calls["enriched"].append(ip)
            return NetworkEnrichment(
                ip=ip,
                enriched_at_utc="2026-10-20T10:00:02Z",
                prefix="1.1.1.0/24",
                asns=(13335,),
                holder="Cloudflare",
                rdap_name="marker network" if ip == "1.1.1.1" else "Cloudflare",
                source_urls=("https://rdap.example/", "https://ripe.example/"),
            )

    def fake_generate_reports(
        result: Any,
        output_dir: Path,
        report_config: Any,
        *,
        generated_at_utc: str,
    ) -> list[Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "bericht.pdf"
        report_path.write_bytes(b"offline-test")
        calls["report"] = (result, output_dir, report_config, generated_at_utc)
        return [report_path]

    monkeypatch.setattr(monitor, "resolve_bootstrap_nodes", fake_resolve)
    monkeypatch.setattr(monitor, "DHTCrawler", FakeCrawler)
    monkeypatch.setattr(monitor, "PeerVerifier", FakeVerifier)
    monkeypatch.setattr(monitor, "NetworkEnricher", FakeEnricher)
    monkeypatch.setattr(monitor, "generate_reports", fake_generate_reports)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    return calls


def test_run_scan_integrates_fair_checks_opt_in_and_canonical_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_successful_network_fakes(monkeypatch)
    batches: list[tuple[str, ...]] = []
    original_append_many = EvidenceJournal.append_many

    def recording_append_many(
        journal: EvidenceJournal,
        events: Any,
        *,
        recorded_at_utc: str | None = None,
    ) -> Any:
        materialized = tuple(events)
        batches.append(tuple(event["event_type"] for event in materialized))
        return original_append_many(
            journal,
            materialized,
            recorded_at_utc=recorded_at_utc,
        )

    monkeypatch.setattr(EvidenceJournal, "append_many", recording_append_many)
    if os.name != "nt":
        tmp_path.chmod(0o775)
        for private_dir in (
            tmp_path / "evidence",
            tmp_path / "reports",
            tmp_path / "cache",
            tmp_path / "cache" / "network",
        ):
            private_dir.mkdir(parents=True, exist_ok=True)
            private_dir.chmod(0o775)

    result = run_scan(_config(), tmp_path)

    assert [item[1] for item in calls["verified"]] == [
        "8.8.8.8",
        "1.1.1.1",
        "1.0.0.1",
    ]
    assert result.confirmed_count == 3
    assert len(result.records) == 3
    assert result.errors == []
    assert result.report_paths == [tmp_path / "reports" / result.run_id / "bericht.pdf"]
    if os.name != "nt":
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(result.report_paths[0].stat().st_mode) == 0o600
        for private_dir in (
            tmp_path / "evidence",
            tmp_path / "reports",
            tmp_path / "cache",
            tmp_path / "cache" / "network",
            result.report_paths[0].parent,
        ):
            assert stat.S_IMODE(private_dir.stat().st_mode) == 0o700

    dht_config = calls["crawler_configs"][0]
    assert dht_config.timeout_seconds == 1.25
    assert dht_config.max_queries == 12
    assert dht_config.concurrency == 3
    assert dht_config.max_nodes == 80
    assert dht_config.max_candidates == 10
    assert calls["verifier_timeout"] == 2.0

    # Der konfigurierte VPN-CIDR wird offline erkannt und niemals extern abgefragt.
    assert calls["enriched"] == ["1.1.1.1", "1.0.0.1"]
    assert calls["enricher_kwargs"]["external_lookup_enabled"] is True
    assert calls["enricher_kwargs"]["max_retries"] == 0
    assert result.records[0].vpn.status == "known_vpn"
    assert result.records[1].vpn.provider == "Marker VPN"

    report_result, report_dir, report_config, generated_at = calls["report"]
    assert report_result is result
    assert report_dir == tmp_path / "reports" / result.run_id
    assert report_config.reporter_name == "Teststelle"
    assert report_config.recipient_email == "polizei@example.org"
    assert report_config.legal_notes == ("Nur pruefen.",)
    assert {
        record.handshake.candidate.info_hash_hex: record.handshake.candidate.source_note
        for record in result.records
    } == {
        HASH_A.hex(): "Hinweis ausschließlich für Ziel A.",
        HASH_B.hex(): "Hinweis ausschließlich für Ziel B.",
    }
    assert generated_at.endswith("Z")

    journal_path = tmp_path / "evidence" / "events.jsonl"
    assert EvidenceJournal(journal_path).verify().valid
    events = [json.loads(line)["event"] for line in journal_path.read_text().splitlines()]
    assert [event["event_type"] for event in events] == [
        "scan_started",
        "confirmed_bittorrent_handshake",
        "confirmed_bittorrent_handshake",
        "confirmed_bittorrent_handshake",
        "scan_completed",
    ]
    assert batches == [
        ("scan_started",),
        (
            "confirmed_bittorrent_handshake",
            "confirmed_bittorrent_handshake",
            "confirmed_bittorrent_handshake",
        ),
        ("scan_completed",),
    ]
    for event in events:
        assert event["run_id"] == result.run_id
        assert len(event["config_sha256"]) == 64
        assert event["software_sha256"] == "ef" * 32


def test_peer_rejection_is_not_a_run_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_successful_network_fakes(monkeypatch, second_confirmed=False)

    result = run_scan(_config(), tmp_path)

    assert result.confirmed_count == 2
    assert len(result.records) == 2
    assert result.errors == []
    assert any(not handshake.confirmed for handshake in result.handshakes)


def test_partial_dht_failures_are_reported_as_nonfatal_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_successful_network_fakes(
        monkeypatch,
        crawler_errors=("Timeout bei 192.0.2.55:6881",),
    )

    result = run_scan(_config(), tmp_path)

    assert result.confirmed_count == 3
    assert len(result.errors) == 2
    assert all("DHT-Teilprobleme" in warning for warning in result.errors)
    assert all("192.0.2.55" not in warning for warning in result.errors)


def test_disabled_enrichment_never_constructs_network_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_successful_network_fakes(monkeypatch)
    import bittorrent_beobachter.monitor as monitor

    def forbidden_enricher(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("NetworkEnricher darf ohne Opt-in nicht erzeugt werden")

    monkeypatch.setattr(monitor, "NetworkEnricher", forbidden_enricher)
    result = run_scan(_config(enrichment_enabled=False), tmp_path)

    assert calls["enriched"] == []
    assert result.records[0].vpn.status == "known_vpn"
    assert result.records[1].vpn.status == "unknown"
    assert result.records[1].enrichment.source_urls == ()
    assert "deaktiviert" in (result.records[1].enrichment.error or "")


def test_corrupt_journal_aborts_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor

    journal_path = tmp_path / "evidence" / "events.jsonl"
    journal_path.parent.mkdir(parents=True)
    journal_path.write_text("kein-json\n", encoding="utf-8")

    async def forbidden_resolve(*_args: Any, **_kwargs: Any) -> list[tuple[str, int]]:
        raise AssertionError("Bei defektem Journal darf kein Netzwerkzugriff erfolgen")

    monkeypatch.setattr(monitor, "resolve_bootstrap_nodes", forbidden_resolve)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    with pytest.raises(MonitorError, match="Evidenzjournal"):
        run_scan(_config(), tmp_path)


@pytest.mark.parametrize("directory_name", ["reports", "evidence"])
def test_storage_capacity_aborts_before_network_without_deletion(
    directory_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor

    storage_dir = tmp_path / directory_name
    storage_dir.mkdir()
    retained = storage_dir / "behalten.bin"
    retained.write_bytes(b"01234567890")
    monkeypatch.setattr(monitor, "MAX_REPORT_STORAGE_BYTES", 20)
    monkeypatch.setattr(monitor, "REPORT_RUN_RESERVE_BYTES", 10)
    monkeypatch.setattr(monitor, "MAX_EVIDENCE_STORAGE_BYTES", 20)
    monkeypatch.setattr(monitor, "EVIDENCE_RUN_RESERVE_BYTES", 10)

    async def forbidden_resolve(*_args: Any, **_kwargs: Any) -> list[tuple[str, int]]:
        raise AssertionError("Bei voller Ablage darf kein Netzwerkzugriff erfolgen")

    monkeypatch.setattr(monitor, "resolve_bootstrap_nodes", forbidden_resolve)
    with pytest.raises(MonitorError, match="archivieren"):
        run_scan(_config(), tmp_path)
    assert retained.read_bytes() == b"01234567890"


@pytest.mark.parametrize("failure", ["bootstrap", "queries"])
def test_fatal_dht_failures(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor

    async def fake_resolve(*_args: Any, **_kwargs: Any) -> list[tuple[str, int]]:
        return [] if failure == "bootstrap" else [("9.9.9.9", 6881)]

    class FailedCrawler:
        def __init__(self, _bootstrap: Any, *, config: Any) -> None:
            self.queries_started = config.max_queries
            self.queries_completed = 0
            self.errors = ("Zeitueberschreitung",)

        async def discover(self, _target: Target) -> list[PeerCandidate]:
            return []

    monkeypatch.setattr(monitor, "resolve_bootstrap_nodes", fake_resolve)
    monkeypatch.setattr(monitor, "DHTCrawler", FailedCrawler)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    with pytest.raises(MonitorError, match=r"Bootstrap|Alle DHT-Anfragen"):
        run_scan(_config(), tmp_path)
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "scan_started",
        "scan_failed",
    ]


def test_network_phase_deadline_cancels_and_records_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio
    import threading

    import bittorrent_beobachter.monitor as monitor

    cancelled = threading.Event()

    async def never_finishes(
        _config_value: AppConfig,
        _progress: Any,
    ) -> tuple[list[PeerCandidate], list[HandshakeResult], list[str]]:
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    monkeypatch.setattr(monitor, "_network_phase", never_finishes)
    monkeypatch.setattr(monitor, "NETWORK_PHASE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)

    with pytest.raises(MonitorError, match="Zeitgrenze"):
        run_scan(_config(), tmp_path)
    assert cancelled.is_set()
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert [event["event_type"] for event in events] == [
        "scan_started",
        "scan_failed",
    ]
    assert events[-1]["error_type"] == "MonitorError"


def test_scan_once_treats_reported_partial_problems_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import logging

    import bittorrent_beobachter.cli as cli
    import bittorrent_beobachter.monitor as monitor
    from bittorrent_beobachter.models import ScanResult

    config_path = tmp_path / "config.json"
    fake_result = ScanResult(
        run_id="run",
        started_at_utc="2026-10-20T10:00:00Z",
        completed_at_utc="2026-10-20T10:00:01Z",
        errors=["Optionale Netzauskunft war nicht erreichbar"],
    )
    monkeypatch.setattr(cli, "load_config", lambda _path: _config())
    monkeypatch.setattr(monitor, "run_scan", lambda *_args, **_kwargs: fake_result)

    assert (
        cli._scan_once(
            config_path,
            tmp_path,
            logging.getLogger("test-scan"),
        )
        == 0
    )


def test_cli_scan_and_watch_require_public_network_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor
    from bittorrent_beobachter.cli import main

    config_path = tmp_path / "config.json"
    save_config(config_path, _config(enrichment_enabled=False))
    calls: list[Path] = []

    def fake_run_scan(
        _config_value: AppConfig,
        data_dir: Path,
        **_kwargs: Any,
    ) -> ScanResult:
        calls.append(data_dir)
        return ScanResult(
            run_id="ack-run",
            started_at_utc="2026-10-20T10:00:00Z",
            completed_at_utc="2026-10-20T10:00:01Z",
        )

    monkeypatch.setattr(monitor, "run_scan", fake_run_scan)
    common = [
        "--config",
        str(config_path),
        "--data-dir",
        str(tmp_path / "data"),
        "--log-file",
        str(tmp_path / "monitor.log"),
    ]
    assert main([*common, "scan"]) == 2
    assert main([*common, "watch"]) == 2
    assert calls == []
    assert main([*common, "scan", "--acknowledge-public-network"]) == 0
    assert calls == [(tmp_path / "data").resolve()]


def test_cli_enrichment_requires_explicit_opt_in(
    tmp_path: Path,
) -> None:
    from bittorrent_beobachter.cli import main
    from bittorrent_beobachter.config import load_config

    magnet = f"magnet:?xt=urn:btih:{HASH_A.hex()}&dn=offline-test"
    plain_path = tmp_path / "plain.json"
    enabled_path = tmp_path / "enabled.json"
    assert main(["--config", str(plain_path), "init", "--magnet", magnet]) == 0
    assert load_config(plain_path).enrichment.enabled is False
    assert (
        main(
            [
                "--config",
                str(enabled_path),
                "init",
                "--magnet",
                magnet,
                "--enable-network-enrichment",
            ]
        )
        == 0
    )
    assert load_config(enabled_path).enrichment.enabled is True


def test_cli_source_notes_are_bound_positionally(
    tmp_path: Path,
) -> None:
    from bittorrent_beobachter.cli import main
    from bittorrent_beobachter.config import load_config

    path = tmp_path / "positioned.json"
    first = f"magnet:?xt=urn:btih:{HASH_A.hex()}&dn=alpha"
    second = f"magnet:?xt=urn:btih:{HASH_B.hex()}&dn=beta"
    assert (
        main(
            [
                "--config",
                str(path),
                "init",
                "--magnet",
                first,
                "--source-note",
                "Nur Alpha",
                "--magnet",
                second,
                "--source-note",
                "Nur Beta",
            ]
        )
        == 0
    )
    config = load_config(path)
    assert [target.source_note for target in config.targets] == [
        "Nur Alpha",
        "Nur Beta",
    ]


def test_reporting_settings_replace_preserves_legal_notes() -> None:
    settings = ReportingSettings(legal_notes=("behalten",))

    updated = replace(settings, reporter_name="Neu")

    assert updated.legal_notes == ("behalten",)


def test_invalid_email_is_rejected_before_save_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor

    invalid = replace(
        _config(),
        reporting=replace(_config().reporting, reporter_email="keine-adresse"),
    )
    config_path = tmp_path / "config.json"
    with pytest.raises(ConfigError, match="E-Mail"):
        save_config(config_path, invalid)
    assert not config_path.exists()

    async def forbidden_resolve(*_args: Any, **_kwargs: Any) -> list[tuple[str, int]]:
        raise AssertionError("Bei ungültiger Konfiguration darf kein Netzwerkzugriff erfolgen")

    monkeypatch.setattr(monitor, "resolve_bootstrap_nodes", forbidden_resolve)
    runtime_dir = tmp_path / "runtime"
    with pytest.raises(ConfigError, match="E-Mail"):
        run_scan(invalid, runtime_dir)
    assert not runtime_dir.exists()


def test_control_characters_and_invalid_vpn_cidr_fail_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor
    from bittorrent_beobachter.config import parse_magnet

    magnet = f"magnet:?xt=urn:btih:{HASH_A.hex()}"
    with pytest.raises(ConfigError, match="Steuer-"):
        parse_magnet(magnet, label_override="Ziel\ngefälschte Logzeile")
    with pytest.raises(ConfigError, match="Formatzeichen"):
        parse_magnet(magnet, label_override="harmlos\u202eexe.pdf")

    invalid = replace(
        _config(),
        enrichment=replace(
            _config().enrichment,
            vpn_ranges=(("8.8.8.1/24", "Fehlerhaft"),),
        ),
    )

    async def forbidden_resolve(*_args: Any, **_kwargs: Any) -> list[tuple[str, int]]:
        raise AssertionError("Bei ungültigem VPN-Präfix darf kein Netzwerkzugriff erfolgen")

    monkeypatch.setattr(monitor, "resolve_bootstrap_nodes", forbidden_resolve)
    runtime_dir = tmp_path / "runtime"
    with pytest.raises(ConfigError, match="VPN-Präfix"):
        run_scan(invalid, runtime_dir)
    assert not runtime_dir.exists()

    too_many_bootstrap = replace(
        _config(),
        dht=replace(
            _config().dht,
            bootstrap_nodes=tuple((f"bootstrap-{index}.invalid", 6881) for index in range(17)),
        ),
    )
    with pytest.raises(ConfigError, match="höchstens 16"):
        run_scan(too_many_bootstrap, runtime_dir)
    assert not runtime_dir.exists()


def test_external_enrichment_is_capped_and_rotated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.monitor as monitor

    target = _config().targets[0]
    public_ips = tuple(f"1.1.2.{index}" for index in range(1, 26))
    handshakes = [
        _handshake(_candidate(target, ip, 6_000 + index))
        for index, ip in enumerate(("8.8.8.8", *public_ips))
    ]
    calls: list[str] = []

    class FakeEnricher:
        def __init__(self, _cache_dir: Path, **_kwargs: Any) -> None:
            pass

        def enrich(self, ip: str) -> NetworkEnrichment:
            calls.append(ip)
            return NetworkEnrichment(
                ip=ip,
                enriched_at_utc="2026-10-20T10:00:02Z",
            )

    monkeypatch.setattr(monitor, "NetworkEnricher", FakeEnricher)
    result = ScanResult(run_id="limit-run", started_at_utc="2026-10-20T10:00:00Z")
    enrichment = monitor._enrich_confirmed_handshakes(
        _config(),
        tmp_path,
        handshakes,
        result,
        lambda _message: None,
    )

    assert len(calls) == monitor.MAX_EXTERNAL_ENRICHMENTS_PER_RUN
    assert "8.8.8.8" not in calls
    assert enrichment["8.8.8.8"][1].status == "known_vpn"
    skipped = [
        data
        for ip, (data, _classification) in enrichment.items()
        if ip != "8.8.8.8" and ip not in calls
    ]
    assert len(skipped) == 5
    assert all("Mengenlimit" in (data.error or "") for data in skipped)
    assert len(result.errors) == 1
    assert "20" in result.errors[0]
    selections = {monitor._rotated_external_ips(public_ips, f"run-{index}") for index in range(12)}
    assert len(selections) > 1
    assert all(len(selection) == 20 for selection in selections)


def test_open_directory_uses_platform_file_manager(
    tmp_path: Path,
) -> None:
    from bittorrent_beobachter.desktop import open_directory

    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_runner(command: list[str], **kwargs: Any) -> None:
        calls.append((command, kwargs))

    open_directory(tmp_path, platform="linux", runner=fake_runner)
    assert calls[0][0] == ["xdg-open", str(tmp_path.resolve())]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 10

    windows_paths: list[str] = []
    open_directory(
        tmp_path,
        platform="win32",
        startfile=windows_paths.append,
    )
    assert windows_paths == [str(tmp_path.resolve())]


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Modi gelten nicht unter Windows")
def test_private_log_rotation_keeps_log_and_old_at_0600(tmp_path: Path) -> None:
    import bittorrent_beobachter.cli as cli

    log_dir = tmp_path / "logs"
    log_dir.mkdir(mode=0o775)
    log_dir.chmod(0o775)
    log_path = log_dir / "monitor.log"
    log_path.write_text("vorhandener Logeintrag\n", encoding="utf-8")
    log_path.chmod(0o664)
    logger = logging.getLogger("bittorrent_beobachter")
    previous_handlers = logger.handlers[:]
    logger.handlers.clear()
    old_umask = os.umask(0o002)
    try:
        configured = cli.setup_logging(log_path)
        handler = next(
            item for item in configured.handlers if isinstance(item, cli.PrivateRotatingFileHandler)
        )
        configured.info("erste Zeile")
        handler.doRollover()
        configured.info("zweite Zeile")
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers[:] = previous_handlers
        os.umask(old_umask)

    old_path = log_path.with_suffix(".old")
    assert old_path.exists()
    assert stat.S_IMODE(log_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(old_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Modi gelten nicht unter Windows")
def test_save_config_hardens_existing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir(mode=0o775)
    config_dir.chmod(0o775)
    config_path = config_dir / "settings.json"

    save_config(config_path, _config())

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
        assert load_config(config_path) == _config()

    config_dir.chmod(0o775)
    config_path.chmod(0o664)
    assert load_config(config_path) == _config()

    assert stat.S_IMODE(config_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_setup_logging_works_without_console_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittorrent_beobachter.cli as cli

    logger = logging.getLogger("bittorrent_beobachter")
    previous_handlers = logger.handlers[:]
    logger.handlers.clear()
    monkeypatch.setattr(cli.sys, "stdout", None)
    try:
        configured = cli.setup_logging(tmp_path / "monitor.log")
        assert len(configured.handlers) == 1
        assert isinstance(configured.handlers[0], cli.PrivateRotatingFileHandler)
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers[:] = previous_handlers
