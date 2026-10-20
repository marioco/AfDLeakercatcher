"""Offline-Tests für den einfachen Erststart der Desktop-Oberfläche."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from bittorrent_beobachter.config import AppConfig, load_config, save_config
from bittorrent_beobachter.models import ScanResult


def _bare_app(config_path: Path) -> Any:
    pytest.importorskip("tkinter")
    from bittorrent_beobachter.gui import ObserverApp

    app = ObserverApp.__new__(ObserverApp)
    app.config_path = config_path
    app.root = object()
    return app


def test_first_start_persists_presets_without_starting_network(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    app = _bare_app(config_path)

    config = app._load_initial_config()

    assert config_path.exists()
    assert load_config(config_path) == config
    assert [target.info_hash_hex for target in config.targets] == [
        "852795102149749ad91123af01ceac5da6f9eb5a",
        "db503db679f508aa31a9e07913b2aa8cf7aa6dff",
    ]


def test_intentionally_empty_config_does_not_restore_presets(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    save_config(config_path, AppConfig(targets=()))
    app = _bare_app(config_path)

    config = app._load_initial_config()

    assert config.targets == ()


def test_add_target_uses_one_dialog_and_discards_name_and_tracker(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    pytest.importorskip("tkinter")
    import bittorrent_beobachter.gui as gui

    config_path = tmp_path / "config.json"
    app = _bare_app(config_path)
    app.config = AppConfig(targets=())
    app._refresh_targets = lambda: None
    prompts: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    magnet = (
        "magnet:?xt=urn:btih:3333333333333333333333333333333333333333"
        "&dn=Behaupteter+brisanter+Inhalt"
        "&tr=udp%3A%2F%2Ftracker.example.invalid%3A1337%2Fannounce"
    )

    def ask_once(*args: Any, **kwargs: Any) -> str:
        prompts.append((args, kwargs))
        return magnet

    monkeypatch.setattr(gui.simpledialog, "askstring", ask_once)

    app._add_target()

    assert len(prompts) == 1
    stored = load_config(config_path)
    assert len(stored.targets) == 1
    assert stored.targets[0].label == "Infohash 333333333333"
    assert stored.targets[0].source_note == ""
    serialized = config_path.read_text(encoding="utf-8").casefold()
    assert "behaupteter" not in serialized
    assert "tracker.example.invalid" not in serialized
    assert "magnet:" not in serialized


class _WidgetDouble:
    def __init__(self) -> None:
        self.value = ""

    def get_children(self) -> tuple[()]:
        return ()

    def delete(self, *_args: Any) -> None:
        return None

    def insert(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def configure(self, **_kwargs: Any) -> None:
        return None

    def set(self, value: str) -> None:
        self.value = value


def test_technical_notice_updates_status_without_warning_popup(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    pytest.importorskip("tkinter")
    import bittorrent_beobachter.gui as gui

    app = _bare_app(tmp_path / "config.json")
    app.result_tree = _WidgetDouble()
    app.status_text = _WidgetDouble()
    app.open_button = _WidgetDouble()
    app.latest_output_dir = None
    app._finish_running_state = lambda: None

    def forbidden_warning(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("Technische Laufhinweise dürfen kein Warnfenster öffnen.")

    monkeypatch.setattr(gui.messagebox, "showwarning", forbidden_warning)
    result = ScanResult(
        run_id="offline",
        started_at_utc="2026-10-20T10:00:00Z",
        notices=["Ein Ziel war vorübergehend nicht erreichbar."],
    )

    app._show_result(result)

    assert "1 technischer Laufhinweis steht im Bericht" in app.status_text.value
