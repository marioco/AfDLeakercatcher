"""Tests fuer kompakte CLI-Abschlusszahlen der diskbasierten Pipeline."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

import bittorrent_beobachter.cli as cli
import bittorrent_beobachter.monitor as monitor
from bittorrent_beobachter.config import AppConfig
from bittorrent_beobachter.models import ScanResult, TargetScanMetrics


def test_scan_once_logs_persisted_totals_and_each_infohash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = ScanResult(
        run_id="streaming",
        started_at_utc="2026-10-20T10:00:00Z",
        completed_at_utc="2026-10-20T10:01:00Z",
        candidate_count=307,
        handshake_count=305,
        confirmed_handshake_count=41,
        offering_observation_count=9,
        known_vpn_total=2,
        target_metrics=(
            TargetScanMetrics(
                target_label="Ziel A",
                info_hash_hex="a" * 40,
                candidates_discovered=307,
                candidates_checked=305,
                verification_attempts=712,
                confirmed_handshakes=41,
                positive_findings=9,
                failure_reasons=(("availability:no_unchoke", 4),),
            ),
            TargetScanMetrics(
                target_label="Ziel B",
                info_hash_hex="b" * 40,
            ),
        ),
    )
    monkeypatch.setattr(cli, "load_migrated_config", lambda _path: AppConfig(targets=()))
    monkeypatch.setattr(monitor, "run_scan", lambda *_args, **_kwargs: result)
    logger = mock.Mock()

    assert cli._scan_once(tmp_path / "config.json", tmp_path, logger) == 0

    summary_call = next(
        call
        for call in logger.info.call_args_list
        if call.args and str(call.args[0]).startswith("Prüflauf beendet:")
    )
    assert summary_call.args[1:] == (307, 305, 41, 9, 2)

    metric_calls = [
        call
        for call in logger.info.call_args_list
        if call.args and str(call.args[0]).startswith("Infohash ")
    ]
    assert len(metric_calls) == 2
    assert metric_calls[0].args[1:8] == (
        "a" * 40,
        "Ziel A",
        307,
        305,
        712,
        41,
        9,
    )
    assert metric_calls[0].args[8] == "availability:no_unchoke=4"
    assert metric_calls[1].args[2] == "Ziel B"
    assert metric_calls[1].args[3:8] == (0, 0, 0, 0, 0)
    assert metric_calls[1].args[8] == "keine"
