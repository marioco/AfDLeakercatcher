"""Tests fuer kompakte CLI-Abschlusszahlen der diskbasierten Pipeline."""

from __future__ import annotations

import logging
import os
import signal
import stat
import sys
import threading
import types
from pathlib import Path
from unittest import mock

import pytest

import bittorrent_beobachter.cli as cli
import bittorrent_beobachter.monitor as monitor
from bittorrent_beobachter.config import AppConfig
from bittorrent_beobachter.models import ScanResult, TargetScanMetrics


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Dateirechte")
def test_setup_logging_preserves_existing_custom_parent_permissions(tmp_path: Path) -> None:
    log_directory = tmp_path / "frei-gewaehlt"
    log_directory.mkdir()
    log_directory.chmod(0o755)
    logger = logging.getLogger("bittorrent_beobachter")
    previous_handlers = logger.handlers[:]
    logger.handlers.clear()

    try:
        configured = cli.setup_logging(log_directory / "app.log")
        assert stat.S_IMODE(log_directory.stat().st_mode) == 0o755
        assert stat.S_IMODE((log_directory / "app.log").stat().st_mode) == 0o600
    finally:
        for handler in logger.handlers[:]:
            handler.close()
        logger.handlers[:] = previous_handlers

    assert configured is logger


@pytest.mark.skipif(os.name == "nt", reason="Symlink-Erzeugung ist unter Windows eingeschränkt")
def test_setup_logging_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "external.log"
    target.write_text("unverändert", encoding="utf-8")
    target.chmod(0o644)
    linked = tmp_path / "monitor.log"
    linked.symlink_to(target)
    logger = logging.getLogger("bittorrent_beobachter")
    previous_handlers = logger.handlers[:]
    logger.handlers.clear()

    try:
        with pytest.raises(OSError, match="Symlink"):
            cli.setup_logging(linked)
    finally:
        logger.handlers[:] = previous_handlers

    assert target.read_text(encoding="utf-8") == "unverändert"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


@pytest.mark.skipif(os.name == "nt", reason="Symlink-Erzeugung ist unter Windows eingeschränkt")
def test_cli_rejects_symlink_data_root_before_creating_logs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "external-data"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    linked = tmp_path / "linked-data"
    linked.symlink_to(target, target_is_directory=True)

    assert cli.main(["--data-dir", str(linked), "verify-journal"]) == 2

    captured = capsys.readouterr()
    assert "Datenpfad darf keine Symlink-Komponente enthalten" in captured.err
    assert tuple(target.iterdir()) == ()
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_cli_reports_unreadable_path_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def deny_path_inspection(_path: Path) -> bool:
        raise PermissionError("Pfad darf nicht gelesen werden")

    monkeypatch.setattr(cli, "_path_has_symlink_component", deny_path_inspection)

    assert cli.main(["--data-dir", str(tmp_path / "blocked"), "verify-journal"]) == 2

    captured = capsys.readouterr()
    assert "Pfad darf nicht gelesen werden" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.skipif(os.name == "nt", reason="Symlink-Erzeugung ist unter Windows eingeschränkt")
@pytest.mark.parametrize(
    ("environment_name", "suffix"),
    (
        ("BITTORRENT_BEOBACHTER_DATA_DIR", "data"),
        ("BITTORRENT_BEOBACHTER_CONFIG", "config.json"),
    ),
)
def test_cli_rejects_symlink_component_from_environment_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    environment_name: str,
    suffix: str,
) -> None:
    external = tmp_path / "external"
    external.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(external, target_is_directory=True)
    monkeypatch.setenv(environment_name, str(alias / suffix))

    assert cli.main(["verify-journal"]) == 2

    assert "Symlink-Komponente" in capsys.readouterr().err
    assert tuple(external.iterdir()) == ()


def test_cli_logging_start_error_is_readable_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid_parent = tmp_path / "keine-map"
    invalid_parent.write_text("Datei statt Verzeichnis", encoding="utf-8")
    logger = logging.getLogger("bittorrent_beobachter")
    previous_handlers = logger.handlers[:]
    logger.handlers.clear()

    try:
        exit_code = cli.main(
            [
                "--log-file",
                str(invalid_parent / "monitor.log"),
                "verify-journal",
            ]
        )
    finally:
        for handler in logger.handlers[:]:
            handler.close()
        logger.handlers[:] = previous_handlers

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Protokolldatei" in captured.err
    assert "kann nicht verwendet werden" in captured.err
    assert "Traceback" not in captured.err


def test_gui_continues_with_visible_warning_when_log_path_is_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid_parent = tmp_path / "keine-map"
    invalid_parent.write_text("Datei statt Verzeichnis", encoding="utf-8")
    logger = logging.getLogger("bittorrent_beobachter")
    previous_handlers = logger.handlers[:]
    logger.handlers.clear()
    received: dict[str, object] = {}

    def fake_launch_gui(
        config_path: Path,
        data_dir: Path,
        *,
        startup_warning: str | None = None,
    ) -> int:
        received.update(
            config_path=config_path,
            data_dir=data_dir,
            startup_warning=startup_warning,
        )
        return 0

    gui_module = types.ModuleType("bittorrent_beobachter.gui")
    gui_module.launch_gui = fake_launch_gui
    monkeypatch.setitem(sys.modules, "bittorrent_beobachter.gui", gui_module)
    try:
        exit_code = cli.main(["--log-file", str(invalid_parent / "monitor.log")])
    finally:
        for handler in logger.handlers[:]:
            handler.close()
        logger.handlers[:] = previous_handlers

    assert exit_code == 0
    assert "Protokolldatei" in str(received["startup_warning"])


def test_hidden_gui_smoke_test_uses_packaged_gui_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    gui_module = types.ModuleType("bittorrent_beobachter.gui")
    gui_module.verify_gui_runtime = lambda: calls.append("gui") or 0
    monkeypatch.setitem(sys.modules, "bittorrent_beobachter.gui", gui_module)

    assert cli.main(["--gui-smoke-test"]) == 0
    assert calls == ["gui"]


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


def test_scan_once_passes_cancel_event_to_monitor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancel_event = threading.Event()
    result = ScanResult(
        run_id="cancel-event",
        started_at_utc="2026-10-20T10:00:00Z",
        completed_at_utc="2026-10-20T10:01:00Z",
    )

    def fake_run_scan(
        _config: AppConfig,
        _data_dir: Path,
        *,
        progress: object,
        cancel_event: threading.Event | None,
        reports_ready: object,
    ) -> ScanResult:
        assert progress is logger.info
        assert cancel_event is expected_event
        assert callable(reports_ready)
        reports_ready(tmp_path / "reports" / "lauf", 5)
        return result

    expected_event = cancel_event
    logger = mock.Mock()
    monkeypatch.setattr(cli, "load_migrated_config", lambda _path: AppConfig(targets=()))
    monkeypatch.setattr(monitor, "run_scan", fake_run_scan)

    assert (
        cli._scan_once(
            tmp_path / "config.json",
            tmp_path,
            logger,
            cancel_event=cancel_event,
        )
        == 0
    )
    logger.info.assert_any_call(
        "Ergebnisse bereits verwendbar: %s (%d positive Befunde)",
        tmp_path / "reports" / "lauf",
        5,
    )


def test_watch_passes_stop_event_to_active_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: dict[int, object] = {}
    received_events: list[threading.Event] = []

    def fake_signal(signum: int, handler: object) -> object:
        handlers[signum] = handler
        return signal.SIG_DFL

    def fake_scan_once(
        _config_path: Path,
        _data_dir: Path,
        _logger: object,
        *,
        cancel_event: threading.Event | None,
    ) -> int:
        assert cancel_event is not None
        received_events.append(cancel_event)
        request_stop = handlers[signal.SIGTERM]
        assert callable(request_stop)
        request_stop(signal.SIGTERM, None)
        return 0

    def forbidden_load_config(_path: Path) -> AppConfig:
        raise AssertionError("Nach dem Stoppsignal darf kein Intervall mehr geladen werden")

    monkeypatch.setattr(cli.signal, "signal", fake_signal)
    monkeypatch.setattr(cli, "_scan_once", fake_scan_once)
    monkeypatch.setattr(cli, "load_config", forbidden_load_config)

    assert cli._watch(tmp_path / "config.json", tmp_path, mock.Mock()) == 0
    assert len(received_events) == 1
    assert received_events[0].is_set()


def test_watch_continues_after_monitor_error_then_stops_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received_events: list[threading.Event] = []

    def fake_scan_once(
        _config_path: Path,
        _data_dir: Path,
        _logger: object,
        *,
        cancel_event: threading.Event | None,
    ) -> int:
        assert cancel_event is not None
        received_events.append(cancel_event)
        if len(received_events) == 1:
            raise monitor.MonitorError("temporärer Laufabbruch")
        cancel_event.set()
        return 0

    logger = mock.Mock()
    monkeypatch.setattr(cli.signal, "signal", lambda *_args: signal.SIG_DFL)
    monkeypatch.setattr(cli, "_scan_once", fake_scan_once)
    monkeypatch.setattr(
        cli,
        "load_config",
        lambda _path: types.SimpleNamespace(interval_minutes=0),
    )

    assert cli._watch(tmp_path / "config.json", tmp_path, logger) == 0
    assert len(received_events) == 2
    assert received_events[0] is received_events[1]
    assert received_events[1].is_set()
    logger.exception.assert_called_once_with(
        "Prüflauf fehlgeschlagen; die Überwachung wird nach dem Intervall fortgesetzt"
    )
    logger.info.assert_any_call(
        "Nächster Prüflauf in %d Minuten (letzter Exitcode %d)",
        0,
        1,
    )


def test_verify_journal_reports_missing_file_without_creating_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    journal_path = tmp_path / "evidence" / "events.jsonl"

    assert cli._verify_journal(tmp_path) == 1

    captured = capsys.readouterr()
    assert captured.out == f"FEHLER: Kein Evidenzjournal vorhanden: {journal_path}\n"
    assert not journal_path.parent.exists()


def test_verify_journal_accepts_existing_empty_chain(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    journal_path = tmp_path / "evidence" / "events.jsonl"
    journal_path.parent.mkdir()
    journal_path.write_bytes(b"")

    assert cli._verify_journal(tmp_path) == 0

    captured = capsys.readouterr()
    assert captured.out == f"Hash-Kette ist gültig: {journal_path} (0 Ereignis(se))\n"


@pytest.mark.parametrize(
    ("signum", "expected_exit_code"),
    [(signal.SIGINT, 130), (signal.SIGTERM, 143)],
)
def test_single_scan_cancels_on_signal_and_restores_handlers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signum: int,
    expected_exit_code: int,
) -> None:
    original_handlers = {
        signal.SIGINT: object(),
        signal.SIGTERM: object(),
    }
    current_handlers = dict(original_handlers)
    received_events: list[threading.Event] = []

    def fake_signal(signal_number: int, handler: object) -> object:
        previous_handler = current_handlers[signal_number]
        current_handlers[signal_number] = handler
        return previous_handler

    def fake_scan_once(
        _config_path: Path,
        _data_dir: Path,
        _logger: object,
        *,
        cancel_event: threading.Event | None,
    ) -> int:
        assert cancel_event is not None
        received_events.append(cancel_event)
        request_stop = current_handlers[signum]
        assert callable(request_stop)
        request_stop(signum, None)
        assert cancel_event.is_set()
        return 0

    monkeypatch.setattr(cli.signal, "signal", fake_signal)
    monkeypatch.setattr(cli, "_scan_once", fake_scan_once)

    exit_code = cli._scan_once_with_signal_cancellation(
        tmp_path / "config.json",
        tmp_path,
        mock.Mock(),
    )

    assert exit_code == expected_exit_code
    assert len(received_events) == 1
    assert current_handlers == original_handlers
