"""Regressionstests für die unbegrenzte, trackerfähige Konfiguration."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from urllib.parse import quote

import pytest

from bittorrent_beobachter.config import (
    BUNDLED_PRESET_REVISION,
    DEFAULT_TARGETS,
    DEFAULT_TRACKERS,
    AppConfig,
    ConfigError,
    DhtSettings,
    PeerSettings,
    config_from_dict,
    config_to_dict,
    load_config,
    parse_magnet,
    save_config,
    with_bundled_presets,
)
from bittorrent_beobachter.models import PeerCandidate, ScanResult, Target, TargetScanMetrics


def test_defaults_have_no_candidate_or_check_count_limits() -> None:
    dht = DhtSettings()
    peer = PeerSettings()

    assert not hasattr(dht, "max_queries")
    assert not hasattr(dht, "max_nodes")
    assert not hasattr(dht, "max_candidates")
    assert not hasattr(peer, "max_checks")
    assert not hasattr(peer, "workers")
    assert not hasattr(peer, "observation_workers")
    assert dht.overall_timeout_seconds == 60.0
    assert dht.quiet_seconds == 30.0
    assert peer.retry_attempts == 3
    assert peer.retry_backoff_seconds == 1.0


def test_dht_slice_budget_must_exceed_single_query_timeout() -> None:
    raw = config_to_dict(AppConfig(targets=()))
    raw["dht"]["timeout_seconds"] = 2.0
    raw["dht"]["overall_timeout_seconds"] = 2.05

    with pytest.raises(ConfigError, match="overall_timeout_seconds"):
        config_from_dict(raw)
    with pytest.raises(ConfigError, match="overall_timeout_seconds"):
        DhtSettings(timeout_seconds=2.0, overall_timeout_seconds=2.05)

    valid = DhtSettings(timeout_seconds=2.0, overall_timeout_seconds=2.1)
    assert valid.overall_timeout_seconds == 2.1


def test_bundled_targets_contain_all_original_udp_trackers() -> None:
    assert BUNDLED_PRESET_REVISION == 4
    assert len(DEFAULT_TRACKERS) == 10
    assert all(tracker.startswith("udp://") for tracker in DEFAULT_TRACKERS)
    assert all(target.trackers == DEFAULT_TRACKERS for target in DEFAULT_TARGETS)


def test_legacy_count_limit_fields_are_ignored_and_not_serialized() -> None:
    raw = config_to_dict(AppConfig(targets=()))
    raw["dht"].pop("concurrency")
    raw["dht"].update(
        {
            "alpha": 7,
            "max_queries": {"alt": "ungültig"},
            "max_nodes": None,
            "max_candidates": -999,
        }
    )
    raw["peer"].update(
        {
            "max_checks": {"alt": "ungültig"},
            "workers": None,
            "observation_workers": -999,
        }
    )

    loaded = config_from_dict(raw)
    serialized = config_to_dict(loaded)

    assert loaded.dht.concurrency == 7
    assert not {"max_queries", "max_nodes", "max_candidates", "alpha"} & serialized["dht"].keys()
    assert not {"max_checks", "workers", "observation_workers"} & serialized["peer"].keys()


def test_parse_magnet_keeps_valid_udp_trackers_but_not_display_name() -> None:
    first = "udp://tracker.example.invalid:1337/announce"
    second = "udp://tracker2.example.invalid:6969/announce"
    magnet = (
        "magnet:?xt=urn:btih:"
        + "11" * 20
        + "&dn=Nicht+als+Label+verwenden"
        + "&tr="
        + quote(first, safe="")
        + "&tr="
        + quote("UDP://TRACKER.EXAMPLE.INVALID:1337/announce", safe="")
        + "&tr="
        + quote(second, safe="")
    )

    target = parse_magnet(magnet)

    assert target.label == "Infohash 111111111111"
    assert target.trackers == (first, second)


@pytest.mark.parametrize(
    "tracker",
    [
        "https://tracker.example.invalid:443/announce",
        "udp://user:secret@tracker.example.invalid:1337/announce",
        "udp://tracker.example.invalid/announce",
        "udp://127.0.0.1:1337/announce",
        "udp://tracker.example.invalid:1337/anderer-pfad",
    ],
)
def test_parse_magnet_rejects_unsafe_tracker_urls(tracker: str) -> None:
    magnet = "magnet:?xt=urn:btih:" + "22" * 20 + "&tr=" + quote(tracker, safe="")

    with pytest.raises(ConfigError, match="Tracker"):
        parse_magnet(magnet)


def test_revision_four_adds_trackers_without_restoring_targets_or_labels() -> None:
    customized = Target(
        label="Bewusst eigener Titel",
        info_hash=DEFAULT_TARGETS[0].info_hash,
        source_note="Bewusst eigene Notiz",
    )

    migrated = with_bundled_presets(AppConfig(targets=(customized,), preset_revision=3))
    intentionally_empty = with_bundled_presets(AppConfig(targets=(), preset_revision=3))

    assert migrated.targets == (
        Target(
            label=customized.label,
            info_hash=customized.info_hash,
            source_note=customized.source_note,
            trackers=DEFAULT_TRACKERS,
        ),
    )
    assert intentionally_empty.targets == ()
    assert intentionally_empty.preset_revision == 4


def test_revision_four_preserves_explicit_custom_trackers() -> None:
    custom_tracker = ("udp://tracker.example.invalid:9000/announce",)
    customized = Target(
        label="Eigener Titel",
        info_hash=DEFAULT_TARGETS[0].info_hash,
        trackers=custom_tracker,
    )

    migrated = with_bundled_presets(AppConfig(targets=(customized,), preset_revision=3))

    assert migrated.targets == (customized,)


def test_tracker_configuration_round_trips() -> None:
    config = AppConfig(
        targets=(
            Target(
                label="Eigenes Ziel",
                info_hash=bytes.fromhex("33" * 20),
                trackers=("udp://tracker.example.invalid:1337/announce",),
            ),
        ),
        dht=DhtSettings(
            timeout_seconds=3.0,
            overall_timeout_seconds=90.0,
            concurrency=12,
            quiet_seconds=45.0,
            refresh_interval_seconds=3.0,
        ),
        peer=PeerSettings(
            timeout_seconds=9.0,
            retry_attempts=4,
            retry_backoff_seconds=1.5,
        ),
    )

    assert config_from_dict(config_to_dict(config)) == config


def test_scan_result_explicit_totals_and_legacy_lists_are_compatible() -> None:
    candidate = PeerCandidate(
        target_label="Ziel",
        info_hash_hex="44" * 20,
        ip="8.8.8.8",
        port=6881,
        discovered_at_utc="2026-10-20T10:00:00.000Z",
        dht_node_ip="1.1.1.1",
        dht_node_port=6881,
        transaction_id_hex="0102",
        response_sha256="ab" * 32,
    )
    legacy = ScanResult(
        run_id="legacy",
        started_at_utc="2026-10-20T10:00:00Z",
        candidates=[candidate],
    )
    streamed = ScanResult(
        run_id="streamed",
        started_at_utc="2026-10-20T10:00:00Z",
        candidate_count=305,
        handshake_count=305,
        confirmed_handshake_count=17,
        offering_observation_count=11,
        known_vpn_total=4,
        target_metrics=(
            TargetScanMetrics(
                target_label="Ziel",
                info_hash_hex="44" * 20,
                candidates_discovered=305,
                candidates_checked=305,
            ),
        ),
    )

    assert legacy.total_candidate_count == 1
    assert streamed.total_candidate_count == 305
    assert streamed.total_handshake_count == 305
    assert streamed.confirmed_count == 17
    assert streamed.offering_count == 11
    assert streamed.known_vpn_count == 4


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Dateirechte")
def test_config_io_preserves_existing_custom_parent_permissions(tmp_path: Path) -> None:
    config_directory = tmp_path / "frei-gewaehlt"
    config_directory.mkdir()
    config_directory.chmod(0o755)
    config_path = config_directory / "config.json"
    config = AppConfig(targets=())

    save_config(config_path, config)
    assert stat.S_IMODE(config_directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600

    config_directory.chmod(0o755)
    assert load_config(config_path) == config
    assert stat.S_IMODE(config_directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_load_config_rejects_directory_before_changing_its_permissions(tmp_path: Path) -> None:
    config_directory = tmp_path / "versehentlich-als-konfiguration-gewaehlt"
    config_directory.mkdir()
    expected_mode: int | None = None
    if os.name != "nt":
        config_directory.chmod(0o755)
        expected_mode = stat.S_IMODE(config_directory.stat().st_mode)

    with pytest.raises(ConfigError, match="keine reguläre Datei"):
        load_config(config_directory)

    if expected_mode is not None:
        assert stat.S_IMODE(config_directory.stat().st_mode) == expected_mode


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Dateirechte")
def test_save_config_makes_only_new_application_directories_private(tmp_path: Path) -> None:
    existing_parent = tmp_path / "bestehend"
    existing_parent.mkdir()
    existing_parent.chmod(0o755)
    first_new = existing_parent / "afdleakercatcher"
    second_new = first_new / "einstellungen"
    config_path = second_new / "config.json"

    save_config(config_path, AppConfig(targets=()))

    assert stat.S_IMODE(existing_parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(first_new.stat().st_mode) == 0o700
    assert stat.S_IMODE(second_new.stat().st_mode) == 0o700
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
