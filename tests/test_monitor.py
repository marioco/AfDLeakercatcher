"""Offline-Tests fuer die diskbasierte Monitor-Orchestrierung ohne Mengencaps."""

from __future__ import annotations

import asyncio
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
from bittorrent_beobachter.evidence import EvidenceJournal, canonical_json_bytes
from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    Target,
    VpnClassification,
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
) -> tuple[list[str], list[int], list[int]]:
    enrichment_calls: list[str] = []
    persisted_batches: list[int] = []
    report_generations: list[int] = []

    async def fake_network_phase(
        config: AppConfig,
        store: RunStore,
        _data_dir: Path,
        runtimes: dict[str, Any],
        _progress: Any,
        *,
        cancel_event: Any = None,
        evidence_ready: Any = None,
    ) -> list[str]:
        assert cancel_event is None
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
            if evidence_ready is not None:
                await evidence_ready()
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
        changed_ips: Any = None,
    ) -> list[Path]:
        assert generated_at_utc.endswith("Z")
        assert changed_ips is None or len(changed_ips) <= 5
        report_generations.append(_result.offering_count)
        output_dir.mkdir(parents=True, exist_ok=True)
        report = output_dir / "bericht.pdf"
        report.write_bytes(b"offline-test")
        return [report]

    monkeypatch.setattr(monitor, "_network_phase", fake_network_phase)
    monkeypatch.setattr(monitor, "NetworkEnricher", FakeEnricher)
    monkeypatch.setattr(monitor, "generate_reports", fake_generate_reports)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)
    return enrichment_calls, persisted_batches, report_generations


def test_run_scan_persists_batches_and_keeps_large_lists_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrichment_calls, handshake_batches, report_generations = _install_run_fake(monkeypatch)
    ready_events: list[tuple[Path, int]] = []
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
    result = run_scan(
        _config(),
        tmp_path,
        reports_ready=lambda path, count: ready_events.append((path, count)),
    )

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
    assert report_generations == [5, 8]
    assert [count for _path, count in ready_events] == [5, 8]
    intermediate_dirs = tuple((tmp_path / "reports" / result.run_id).glob("zwischenstand-*"))
    assert len(intermediate_dirs) == 1
    assert (intermediate_dirs[0] / "bericht.pdf").is_file()
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

    config_snapshot = result.run_store_path.with_suffix(".config.json")
    snapshot_payload = json.loads(config_snapshot.read_text(encoding="utf-8"))
    assert (
        hashlib.sha256(canonical_json_bytes(snapshot_payload)).hexdigest()
        == events[0]["config_sha256"]
    )
    assert events[0]["config_snapshot"] == config_snapshot.name
    assert (
        events[0]["config_snapshot_file_sha256"]
        == hashlib.sha256(config_snapshot.read_bytes()).hexdigest()
    )
    assert events[-1]["config_snapshot"] == config_snapshot.name

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


def test_previous_evidence_is_recovered_before_new_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    ready_events: list[tuple[Path, int]] = []
    config = _config(enrichment_enabled=False)
    candidate = _candidate(config.targets[0], 7)
    record = EvidenceRecord(
        handshake=_handshake(candidate),
        enrichment=NetworkEnrichment(
            ip=candidate.ip,
            enriched_at_utc="2026-10-20T10:01:00.000Z",
        ),
        vpn=VpnClassification(status="unknown", provider=None, reason="kein Treffer"),
        evidence_event_sha256="ab" * 32,
    )

    def fake_recover(
        evidence_dir: Path,
        *,
        on_reconciled: Any,
        **_kwargs: Any,
    ) -> Any:
        order.append("recovery")
        assert not tuple((evidence_dir / "runs").glob("*.sqlite3"))
        on_reconciled(
            monitor.RecoveredEvidenceBatch(
                run_id="legacy-compatible-run",
                config_sha256=monitor._config_sha256(config),
                software_sha256="ef" * 32,
                config_snapshot=None,
                config_snapshot_file_sha256=None,
                records=(record,),
            )
        )
        return SimpleNamespace(inserted_records=1)

    async def fake_network(*_args: Any, **_kwargs: Any) -> list[str]:
        order.append("network")
        return []

    def fake_reports(
        result: Any,
        output_dir: Path,
        _report_config: Any,
        **_kwargs: Any,
    ) -> list[Path]:
        order.append("recovery-report" if result.records else "final-report")
        output_dir.mkdir(parents=True, exist_ok=True)
        report = output_dir / "bericht.pdf"
        report.write_bytes(b"offline-test")
        return [report]

    monkeypatch.setattr(monitor, "recover_evidence_journal", fake_recover)
    monkeypatch.setattr(monitor, "_network_phase", fake_network)
    monkeypatch.setattr(monitor, "generate_reports", fake_reports)
    monkeypatch.setattr(monitor, "_software_sha256", lambda: "ef" * 32)

    run_scan(
        config,
        tmp_path,
        reports_ready=lambda path, count: ready_events.append((path, count)),
    )

    assert order[:3] == ["recovery", "recovery-report", "network"]
    assert ready_events[0][1] == 1
    assert "legacy-compatible-run" in str(ready_events[0][0])


def test_terminal_journal_event_is_not_duplicated_after_permission_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_run_fake(monkeypatch)
    original_ensure_private_file = monitor._ensure_private_file

    def fail_after_terminal_append(path: Path) -> None:
        if path.name == "events.jsonl" and path.is_file():
            events = [json.loads(line)["event"] for line in path.read_text().splitlines()]
            if events and events[-1]["event_type"] == "scan_completed":
                raise OSError("simulierter chmod-Fehler")
        original_ensure_private_file(path)

    monkeypatch.setattr(monitor, "_ensure_private_file", fail_after_terminal_append)

    with pytest.raises(OSError, match="chmod-Fehler"):
        run_scan(_config(enrichment_enabled=False), tmp_path)

    events = [
        json.loads(line)["event"]["event_type"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert events.count("scan_completed") == 1
    assert "scan_failed" not in events


def test_controlled_cancel_flushes_partial_batch_and_writes_final_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_run_fake(monkeypatch)
    cancel_event = monitor.Event()
    cancel_event.set()

    async def fake_cancelled_network(
        config: AppConfig,
        store: RunStore,
        _data_dir: Path,
        runtimes: dict[str, Any],
        _progress: Any,
        *,
        cancel_event: Any,
        evidence_ready: Any,
    ) -> list[str]:
        assert cancel_event.is_set()
        candidates = tuple(_candidate(config.targets[0], index) for index in range(3))
        store.add_candidates(candidates)
        batch = store.claim_candidate_batch((config.targets[0].info_hash_hex,), size=5)
        results = tuple(_handshake(candidate) for candidate in batch)
        store.store_handshake_batch(results)
        runtimes[config.targets[0].info_hash_hex].verification_attempts += len(results)
        await evidence_ready()
        raise monitor.ScanCancelled("abgebrochen")

    monkeypatch.setattr(monitor, "_network_phase", fake_cancelled_network)
    result = run_scan(
        _config(enrichment_enabled=False),
        tmp_path,
        cancel_event=cancel_event,
    )

    assert result.cancelled is True
    assert result.offering_count == 3
    assert result.run_store_path is not None
    assert RunStore(result.run_store_path).evidence_count() == 3
    assert result.report_paths[0].is_file()
    events = [
        json.loads(line)["event"]["event_type"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert events[-1] == "scan_cancelled"


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


def test_network_failure_flushes_positive_rest_batch_and_final_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_run_fake(monkeypatch)
    ready_events: list[tuple[Path, int]] = []

    async def fail_after_three_results(
        config: AppConfig,
        store: RunStore,
        _data_dir: Path,
        runtimes: dict[str, Any],
        _progress: Any,
        **_kwargs: Any,
    ) -> list[str]:
        candidates = tuple(_candidate(config.targets[0], index) for index in range(3))
        store.add_candidates(candidates)
        claimed = store.claim_candidate_batch((config.targets[0].info_hash_hex,), size=5)
        results = tuple(_handshake(candidate) for candidate in claimed)
        store.store_handshake_batch(results)
        runtimes[config.targets[0].info_hash_hex].verification_attempts += len(results)
        raise OSError("sensitive endpoint 203.0.113.20:6881")

    monkeypatch.setattr(monitor, "_network_phase", fail_after_three_results)

    with pytest.raises(MonitorError, match="Netzwerkfehler"):
        run_scan(
            _config(enrichment_enabled=False),
            tmp_path,
            reports_ready=lambda path, count: ready_events.append((path, count)),
        )

    run_databases = tuple((tmp_path / "evidence" / "runs").glob("*.sqlite3"))
    assert len(run_databases) == 1
    assert RunStore(run_databases[0]).evidence_count() == 3
    assert ready_events and ready_events[-1][1] == 3
    assert any((tmp_path / "reports").rglob("bericht.pdf"))
    events = [
        json.loads(line)["event"]
        for line in (tmp_path / "evidence" / "events.jsonl").read_text().splitlines()
    ]
    assert events[-1]["event_type"] == "scan_failed"
    assert events[-1]["evidence_count"] == 3
    assert "203.0.113" not in json.dumps(events[-1])


def test_discovery_fails_when_no_configured_source_answers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        target = Target("Ziel ohne Quelle", HASH_A)
        config = AppConfig(
            targets=(target,),
            dht=DhtSettings(
                timeout_seconds=1.0,
                overall_timeout_seconds=1.0,
                concurrency=1,
                quiet_seconds=1.0,
                refresh_interval_seconds=0.1,
                bootstrap_nodes=(("bootstrap.invalid", 6881),),
            ),
        )
        store = RunStore(tmp_path / "no-source.sqlite3")
        runtime = monitor._TargetRuntimeMetrics(target=target)
        clock = [0.0]
        real_sleep = asyncio.sleep

        async def fake_sleep(delay: float) -> None:
            clock[0] += delay
            await real_sleep(0)

        class NoAnswerCrawler:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                self.queries_started = 1
                self.queries_completed = 0
                self.queries_failed = 1
                self.issue_count = 1
                self.has_pending_work = False

            def close(self) -> None:
                return None

            async def discover(self, *_args: object, **_kwargs: object) -> list[PeerCandidate]:
                return []

        monkeypatch.setattr(monitor, "DHTCrawler", NoAnswerCrawler)
        monkeypatch.setattr(monitor.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(monitor.asyncio, "sleep", fake_sleep)

        with pytest.raises(MonitorError, match="Keine Peer-Quelle"):
            await monitor._discover_target_until_quiet(
                config,
                target,
                (("9.9.9.9", 6881),),
                b"n" * 20,
                store,
                runtime,
                tmp_path,
                [],
                lambda _message: None,
            )

    asyncio.run(scenario())
