"""Offline-Tests fuer die diskbasierte Monitor-Orchestrierung ohne Mengencaps."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bittorrent_beobachter.monitor as monitor
from bittorrent_beobachter.config import (
    AppConfig,
    ConfigError,
    DhtSettings,
    EnrichmentSettings,
    PeerSettings,
    ReportingSettings,
    config_from_dict,
    config_to_dict,
    default_app_config,
    parse_magnet,
)
from bittorrent_beobachter.evidence import EvidenceJournal
from bittorrent_beobachter.models import (
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    Target,
)
from bittorrent_beobachter.monitor import MonitorError, run_scan
from bittorrent_beobachter.run_store import RunStore

HASH_A = bytes.fromhex("11" * 20)
HASH_B = bytes.fromhex("22" * 20)


def _candidate(target: Target, index: int) -> PeerCandidate:
    return PeerCandidate(
        target_label=target.label,
        info_hash_hex=target.info_hash_hex,
        ip=f"8.{1 if target.info_hash == HASH_A else 2}.{index // 250}.{index % 250 + 1}",
        port=10_000 + index,
        discovered_at_utc="2026-10-20T10:00:00.000Z",
        dht_node_ip="9.9.9.9",
        dht_node_port=6881,
        transaction_id_hex=f"{index:08x}",
        response_sha256=f"{index + 1:064x}",
        source_note=target.source_note,
    )


def _handshake(
    candidate: PeerCandidate,
    *,
    offering: bool = True,
    completed_full_window: bool = True,
) -> HandshakeResult:
    availability = PeerAvailabilityObservation(
        started_at_utc="2026-10-20T10:00:01.000Z",
        ended_at_utc="2026-10-20T10:00:02.000Z",
        requested_duration_seconds=60.0,
        duration_seconds=1.0 if not completed_full_window else 60.0,
        completed_full_window=completed_full_window,
        interested_sent=True,
        non_empty_bitfield=offering,
        have_announced=False,
        piece_availability_announced=offering,
        unchoked=offering,
        peer_choking_at_end=not offering,
        unchoked_duration_seconds=1.0 if offering else 0.0,
        messages_received=2,
        bytes_received=8,
        request_messages_sent=0,
        piece_payload_bytes_received=0,
        metadata_requests_sent=0,
        termination_reason="peer_closed" if not completed_full_window else "duration_elapsed",
        control_events=(),
        error="Peer schloss nach positiven Signalen." if not completed_full_window else None,
    )
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc="2026-10-20T10:00:00.500Z",
        completed_at_utc="2026-10-20T10:00:01.000Z",
        confirmed=True,
        remote_peer_id_hex="ab" * 20,
        reserved_bits_hex="00" * 8,
        local_ip="192.0.2.20",
        local_port=50_000,
        bytes_sent=73,
        bytes_received=77,
        error=None,
        availability=availability,
    )


def _config(*, enrichment_enabled: bool = True) -> AppConfig:
    targets = (
        Target("Ziel A", HASH_A, "Hinweis A"),
        Target("Ziel B", HASH_B, "Hinweis B"),
    )
    return AppConfig(
        targets=targets,
        dht=DhtSettings(
            timeout_seconds=1.0,
            overall_timeout_seconds=1.0,
            concurrency=3,
            quiet_seconds=1.0,
            refresh_interval_seconds=0.1,
            bootstrap_nodes=(("bootstrap.invalid", 6881),),
        ),
        peer=PeerSettings(
            timeout_seconds=2.0,
            observation_seconds=60.0,
            retry_attempts=3,
            retry_backoff_seconds=0.0,
        ),
        enrichment=EnrichmentSettings(
            enabled=enrichment_enabled,
            timeout_seconds=3.0,
            cache_days=5,
            vpn_ranges=(("8.1.0.0/16", "Test VPN"),),
            vpn_provider_markers=(("Marker VPN", ("marker network",)),),
        ),
        reporting=ReportingSettings(
            reporter_name="Teststelle",
            reporter_email="test@example.org",
            police_recipient="polizei@example.org",
            legal_notes=("Nur pruefen.",),
        ),
    )


def test_default_config_has_two_targets_trackers_and_no_count_caps() -> None:
    config = default_app_config()

    assert len(config.targets) == 2
    assert all(target.trackers for target in config.targets)
    assert config.peer.observation_seconds == 60.0
    serialized = config_to_dict(config)
    flattened = json.dumps(serialized, ensure_ascii=False).casefold()
    for removed in (
        "max_checks",
        "max_candidates",
        "max_queries",
        "max_nodes",
        "observation_workers",
    ):
        assert removed not in flattened
    assert "magnet:" not in flattened
    assert "afd" not in flattened


def test_config_requires_exact_one_minute_peer_observation() -> None:
    raw = config_to_dict(default_app_config())
    raw["peer"]["observation_seconds"] = 59.0

    with pytest.raises(ConfigError, match=r"peer\.observation_seconds"):
        config_from_dict(raw)


def test_parse_magnet_ignores_display_name_but_keeps_udp_tracker() -> None:
    tracker = "udp://tracker.example.org:1337/announce"
    target = parse_magnet(
        f"magnet:?xt=urn:btih:{HASH_A.hex()}&dn=Ungepruefte+Behauptung&tr={tracker}"
    )

    assert target.label == f"Infohash {HASH_A.hex()[:12]}"
    assert target.source_note == ""
    assert target.trackers == (tracker,)


def _install_run_fake(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], list[int]]:
    enrichment_calls: list[str] = []
    persisted_batches: list[int] = []

    async def fake_network_phase(
        config: AppConfig,
        store: RunStore,
        _data_dir: Path,
        runtimes: dict[str, Any],
        _progress: Any,
    ) -> list[str]:
        candidates = [
            *(_candidate(config.targets[0], index) for index in range(4)),
            *(_candidate(config.targets[1], 100 + index) for index in range(4)),
        ]
        assert store.add_candidates(candidates[:5]) == 5
        assert store.add_candidates(candidates[5:]) == 3
        hashes = tuple(target.info_hash_hex for target in config.targets)
        while batch := store.claim_candidate_batch(hashes, size=5):
            results = tuple(
                _handshake(
                    candidate,
                    completed_full_window=candidate.ip.endswith(".1"),
                )
                for candidate in batch
            )
            persisted_batches.append(len(results))
            store.store_handshake_batch(results)
            for candidate in batch:
                runtimes[candidate.info_hash_hex].verification_attempts += 1
        return []

    class FakeEnricher:
        def __init__(self, _cache_dir: Path, **_kwargs: Any) -> None:
            pass

        def enrich(self, ip: str) -> NetworkEnrichment:
            enrichment_calls.append(ip)
            return NetworkEnrichment(
                ip=ip,
                enriched_at_utc="2026-10-20T10:00:03.000Z",
                prefix=f"{ip}/32",
                holder="Testnetz",
                rdap_name="marker network" if ip.endswith(".101") else "Testnetz",
            )

    def fake_generate_reports(
        _result: Any,
        output_dir: Path,
        _report_config: Any,
        *,
        generated_at_utc: str,
    ) -> list[Path]:
        assert generated_at_utc.endswith("Z")
        output_dir.mkdir(parents=True, exist_ok=True)
        report = output_dir / "bericht.pdf"
        report.write_bytes(b"offline-test")
        return [report]

    monkeypatch.setattr(monitor, "_network_phase", fake_network_phase)
    monkeypatch.setattr(monitor, "NetworkEnricher", FakeEnricher)
    monkeypatch.setattr(monitor, "generate_reports", fake_generate_reports)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    return enrichment_calls, persisted_batches


def test_run_scan_persists_batches_and_keeps_large_lists_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrichment_calls, handshake_batches = _install_run_fake(monkeypatch)
    journal_batch_sizes: list[int] = []
    original_append_many = EvidenceJournal.append_many

    def recording_append_many(
        journal: EvidenceJournal,
        events: Any,
        *,
        recorded_at_utc: str | None = None,
    ) -> Any:
        materialized = tuple(events)
        journal_batch_sizes.append(len(materialized))
        return original_append_many(
            journal,
            materialized,
            recorded_at_utc=recorded_at_utc,
        )

    monkeypatch.setattr(EvidenceJournal, "append_many", recording_append_many)
    result = run_scan(_config(), tmp_path)

    assert result.total_candidate_count == 8
    assert result.total_handshake_count == 8
    assert result.confirmed_count == 8
    assert result.offering_count == 8
    assert result.known_vpn_count == 5
    assert result.candidates == []
    assert result.handshakes == []
    assert result.records == []
    assert handshake_batches == [5, 3]
    assert result.run_store_path is not None
    store = RunStore(result.run_store_path)
    records = list(store.iter_evidence_records(batch_size=5))
    assert len(records) == 8
    assert store.evidence_count() == 8
    assert journal_batch_sizes == [1, 5, 3, 1]
    assert len(enrichment_calls) == 4
    assert {item.info_hash_hex for item in result.target_metrics} == {
        HASH_A.hex(),
        HASH_B.hex(),
    }
    assert all(item.candidates_discovered == 4 for item in result.target_metrics)
    assert all(item.candidates_checked == 4 for item in result.target_metrics)
    assert result.report_paths == [tmp_path / "reports" / result.run_id / "bericht.pdf"]

    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert events[0]["event_type"] == "scan_started"
    assert events[-1]["event_type"] == "scan_completed"
    assert events[-1]["candidate_count"] == 8
    assert len(events[-1]["target_metrics"]) == 2
    assert events[-1]["report_file_count"] == 1
    assert events[-1]["report_manifest"] == "bericht.pdf"
    assert events[-1]["report_manifest_sha256"] == hashlib.sha256(b"offline-test").hexdigest()
    assert "report_files" not in events[-1]

    if os.name != "nt":
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
        assert stat.S_IMODE(result.run_store_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(result.report_paths[0].stat().st_mode) == 0o600


def test_disabled_enrichment_never_constructs_network_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_run_fake(monkeypatch)

    def forbidden_enricher(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("NetworkEnricher darf ohne Opt-in nicht erzeugt werden")

    monkeypatch.setattr(monitor, "NetworkEnricher", forbidden_enricher)
    result = run_scan(_config(enrichment_enabled=False), tmp_path)
    assert result.run_store_path is not None
    records = list(RunStore(result.run_store_path).iter_evidence_records())
    assert len(records) == 8
    assert all(
        record.vpn.status == "known_vpn" or "deaktiviert" in (record.enrichment.error or "")
        for record in records
    )


def test_corrupt_journal_aborts_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_path = tmp_path / "evidence" / "events.jsonl"
    journal_path.parent.mkdir(parents=True)
    journal_path.write_text("kein-json\n", encoding="utf-8")

    async def forbidden_network(*_args: Any, **_kwargs: Any) -> list[str]:
        raise AssertionError("Bei defektem Journal darf kein Netzwerkzugriff erfolgen")

    monkeypatch.setattr(monitor, "_network_phase", forbidden_network)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    with pytest.raises(MonitorError, match="Evidenzjournal"):
        run_scan(_config(), tmp_path)


def test_low_physical_free_space_aborts_without_deleting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained = tmp_path / "behalten.bin"
    retained.write_bytes(b"behalten")
    monkeypatch.setattr(
        monitor.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=monitor.MIN_FREE_SPACE_BYTES - 1),
    )

    with pytest.raises(MonitorError, match="Speicherplatz"):
        run_scan(_config(), tmp_path)
    assert retained.read_bytes() == b"behalten"


def test_network_timeout_is_sanitized_and_journaled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def inner_timeout(*_args: Any, **_kwargs: Any) -> list[str]:
        raise TimeoutError("sensitive endpoint 203.0.113.14:6881")

    monkeypatch.setattr(monitor, "_network_phase", inner_timeout)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    with pytest.raises(MonitorError) as caught:
        run_scan(_config(), tmp_path)

    assert "203.0.113" not in str(caught.value)
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert [event["event_type"] for event in events] == ["scan_started", "scan_failed"]
    assert "203.0.113" not in json.dumps(events[-1])
