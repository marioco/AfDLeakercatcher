"""Offline-Tests für Erststart und Zustände der Desktop-Oberfläche."""

from __future__ import annotations

import importlib
import json
import queue
import sys
import types
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from bittorrent_beobachter.config import (
    BUNDLED_PRESET_REVISION,
    DEFAULT_TARGETS,
    AppConfig,
    ConfigError,
    ReportingSettings,
    config_to_dict,
    load_config,
    save_config,
    validate_reporting_settings,
)
from bittorrent_beobachter.models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerAvailabilityObservation,
    PeerCandidate,
    ScanResult,
    VpnClassification,
)


def _install_headless_tkinter() -> None:
    """Stellt nur die Importoberfläche bereit, wenn Linux kein Tk-Paket hat."""

    try:
        import tkinter  # noqa: F401
    except ModuleNotFoundError:
        module = types.ModuleType("tkinter")

        class _TkBase:
            pass

        module.BOTH = "both"
        module.END = "end"
        module.LEFT = "left"
        module.RIGHT = "right"
        module.X = "x"
        module.BooleanVar = object
        module.StringVar = object
        module.Tk = _TkBase
        module.Toplevel = _TkBase
        module.messagebox = types.SimpleNamespace()
        module.simpledialog = types.SimpleNamespace()
        module.ttk = types.SimpleNamespace()
        sys.modules["tkinter"] = module


_install_headless_tkinter()
gui = importlib.import_module("bittorrent_beobachter.gui")


class _VariableDouble:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def get(self) -> Any:
        return self.value

    def set(self, value: Any) -> None:
        self.value = value


class _WidgetDouble:
    def __init__(self, *, selection: tuple[str, ...] = ()) -> None:
        self.value = ""
        self.selection_value = selection
        self.inserted: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.options: dict[str, Any] = {}
        self.started = False
        self.stopped = False

    def get_children(self) -> tuple[str, ...]:
        return tuple(str(index) for index, _item in enumerate(self.inserted))

    def delete(self, *_args: Any) -> None:
        self.inserted.clear()

    def insert(self, *args: Any, **kwargs: Any) -> None:
        self.inserted.append((args, kwargs))

    def configure(self, **kwargs: Any) -> None:
        self.options.update(kwargs)

    def set(self, value: str) -> None:
        self.value = value

    def selection(self) -> tuple[str, ...]:
        return self.selection_value

    def start(self, _interval: int) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True


class _RootDouble:
    def __init__(self) -> None:
        self.destroy_count = 0
        self.after_calls: list[tuple[int, Any]] = []
        self.waited_for: list[Any] = []

    def destroy(self) -> None:
        self.destroy_count += 1

    def after(self, delay: int, callback: Any) -> None:
        self.after_calls.append((delay, callback))

    def wait_window(self, dialog: Any) -> None:
        self.waited_for.append(dialog)


def _bare_app(config_path: Path) -> Any:
    app = gui.ObserverApp.__new__(gui.ObserverApp)
    app.config_path = config_path
    app.root = _RootDouble()
    return app


def _runtime_app(tmp_path: Path, config: AppConfig | None = None) -> Any:
    app = _bare_app(tmp_path / "config.json")
    app.data_dir = tmp_path / "data"
    app.events = queue.Queue()
    app.running = False
    app.scan_thread = None
    app.close_requested = False
    app.latest_output_dir = None
    app.config = config or AppConfig(targets=DEFAULT_TARGETS)
    app.scan_button = _WidgetDouble()
    app.open_button = _WidgetDouble()
    app.progress = _WidgetDouble()
    app.result_tree = _WidgetDouble()
    app.status_text = _WidgetDouble()
    app.config_controls = (_WidgetDouble(), _WidgetDouble(), _WidgetDouble())
    return app


def _candidate(*, ipv6: bool = False) -> PeerCandidate:
    target = DEFAULT_TARGETS[0]
    return PeerCandidate(
        target_label=target.label,
        info_hash_hex=target.info_hash_hex,
        ip="2001:4860:4860::8888" if ipv6 else "8.8.8.8",
        port=51413,
        discovered_at_utc="2026-10-20T10:00:00Z",
        dht_node_ip="1.1.1.1",
        dht_node_port=6881,
        transaction_id_hex="0102",
        response_sha256="a" * 64,
    )


def _handshake(*, confirmed: bool = True, ipv6: bool = False) -> HandshakeResult:
    availability = (
        PeerAvailabilityObservation(
            started_at_utc="2026-10-20T10:00:02Z",
            ended_at_utc="2026-10-20T10:01:02Z",
            requested_duration_seconds=60.0,
            duration_seconds=60.0,
            completed_full_window=True,
            interested_sent=True,
            non_empty_bitfield=True,
            have_announced=False,
            piece_availability_announced=True,
            unchoked=True,
            peer_choking_at_end=False,
            unchoked_duration_seconds=58.0,
            messages_received=2,
            bytes_received=8,
            request_messages_sent=0,
            piece_payload_bytes_received=0,
            metadata_requests_sent=0,
            termination_reason="duration_elapsed",
            control_events=(),
        )
        if confirmed
        else None
    )
    return HandshakeResult(
        candidate=_candidate(ipv6=ipv6),
        attempted_at_utc="2026-10-20T10:00:01Z",
        completed_at_utc="2026-10-20T10:00:02Z" if confirmed else None,
        confirmed=confirmed,
        remote_peer_id_hex="b" * 40 if confirmed else None,
        reserved_bits_hex="00" * 8 if confirmed else None,
        local_ip="192.0.2.1" if confirmed else None,
        local_port=50000 if confirmed else None,
        bytes_sent=68 if confirmed else 0,
        bytes_received=68 if confirmed else 0,
        error=None if confirmed else "Zeitüberschreitung",
        availability=availability,
    )


def test_first_start_persists_two_presets_without_starting_network(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    app = _bare_app(config_path)

    config = app._load_initial_config()

    assert config_path.exists()
    assert load_config(config_path) == config
    assert [target.info_hash_hex for target in config.targets] == [
        "852795102149749ad91123af01ceac5da6f9eb5a",
        "db503db679f508aa31a9e07913b2aa8cf7aa6dff",
    ]
    assert config.enrichment.enabled is False


def test_first_start_save_error_keeps_safe_presets_in_memory(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _bare_app(tmp_path / "config.json")
    errors: list[str] = []
    monkeypatch.setattr(gui, "save_config", lambda *_args: (_ for _ in ()).throw(OSError("voll")))
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    config = app._load_initial_config()

    assert config.targets == DEFAULT_TARGETS
    assert config.enrichment.enabled is False
    assert errors == ["voll"]


def test_unreadable_config_shows_presets_but_is_not_silently_overwritten(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{kaputt", encoding="utf-8")
    app = _bare_app(config_path)
    messages: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: messages.append(message),
        raising=False,
    )

    config = app._load_initial_config()

    assert config.targets == DEFAULT_TARGETS
    assert config.enrichment.enabled is False
    assert config_path.read_text(encoding="utf-8") == "{kaputt"
    assert "Es wurde kein Prüflauf gestartet" in messages[0]


def test_legacy_config_receives_missing_presets_once(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    raw = config_to_dict(AppConfig(targets=()))
    raw["bundled_preset_revision"] = 0
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    config = _bare_app(config_path)._load_initial_config()

    assert config.targets == DEFAULT_TARGETS
    assert load_config(config_path) == config


def test_upgrade_neutralizes_old_preset_claims_without_touching_other_targets(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    unrelated = replace(
        DEFAULT_TARGETS[0],
        label="Eigenes neutrales Ziel",
        info_hash=bytes.fromhex("3" * 40),
        source_note="eigene Notiz",
    )
    old_preset = replace(
        DEFAULT_TARGETS[0],
        label="Erzwungener alter Titel",
        source_note="Ungeprüfte alte Inhaltsbehauptung",
    )
    raw = config_to_dict(
        AppConfig(
            targets=(unrelated, old_preset),
            preset_revision=1,
        )
    )
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    config = _bare_app(config_path)._load_initial_config()

    assert config.preset_revision == BUNDLED_PRESET_REVISION
    assert config.targets[0] == unrelated
    assert config.targets[1] == DEFAULT_TARGETS[0]
    assert len(config.targets) == 2
    serialized = config_path.read_text(encoding="utf-8")
    assert "Erzwungener alter Titel" not in serialized
    assert "Ungeprüfte alte Inhaltsbehauptung" not in serialized


def test_intentionally_empty_config_does_not_restore_presets(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    save_config(config_path, AppConfig(targets=()))

    config = _bare_app(config_path)._load_initial_config()

    assert config.targets == ()


def test_revision_one_empty_config_stays_empty_during_neutralization_upgrade(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    raw = config_to_dict(AppConfig(targets=()))
    raw["bundled_preset_revision"] = 1
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    config = _bare_app(config_path)._load_initial_config()

    assert config.preset_revision == BUNDLED_PRESET_REVISION
    assert config.targets == ()


def test_gui_migrates_old_peer_limits_without_restoring_targets(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    raw = config_to_dict(AppConfig(targets=()))
    raw["bundled_preset_revision"] = 2
    raw["peer"]["max_checks"] = 120
    raw["peer"]["observation_workers"] = 32
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    config = _bare_app(config_path)._load_initial_config()

    assert config.targets == ()
    assert config.peer.max_checks == 600
    assert config.peer.observation_workers == 120
    assert load_config(config_path) == config


def test_refresh_targets_shows_both_presets_and_no_running_scan(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app.target_tree = _WidgetDouble()

    app._refresh_targets()

    values = [entry[1]["values"] for entry in app.target_tree.inserted]
    assert values == [
        ("Voreingestellter Infohash 1", DEFAULT_TARGETS[0].info_hash_hex),
        ("Voreingestellter Infohash 2", DEFAULT_TARGETS[1].info_hash_hex),
    ]
    assert "es läuft kein Prüflauf" in app.status_text.value


def test_add_target_uses_one_dialog_and_discards_name_and_tracker(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _bare_app(tmp_path / "config.json")
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

    monkeypatch.setattr(gui.simpledialog, "askstring", ask_once, raising=False)

    app._add_target()

    assert len(prompts) == 1
    stored = load_config(app.config_path)
    assert len(stored.targets) == 1
    assert stored.targets[0].label == "Infohash 333333333333"
    assert stored.targets[0].source_note == ""
    serialized = app.config_path.read_text(encoding="utf-8").casefold()
    assert "behaupteter" not in serialized
    assert "tracker.example.invalid" not in serialized
    assert "magnet:" not in serialized


def test_cancelled_add_target_changes_nothing(tmp_path: Path, monkeypatch: Any) -> None:
    app = _bare_app(tmp_path / "config.json")
    app.config = AppConfig(targets=())
    app._refresh_targets = lambda: (_ for _ in ()).throw(AssertionError("kein Refresh"))
    monkeypatch.setattr(
        gui.simpledialog, "askstring", lambda *_args, **_kwargs: None, raising=False
    )

    app._add_target()

    assert app.config.targets == ()
    assert not app.config_path.exists()


@pytest.mark.parametrize(
    "magnet, expected_fragment",
    [
        ("kein Magnet", "Magnet-Link"),
        (
            "magnet:?xt=urn:btih:852795102149749ad91123af01ceac5da6f9eb5a",
            "bereits eingetragen",
        ),
    ],
)
def test_invalid_or_duplicate_target_is_explained_without_state_change(
    tmp_path: Path,
    monkeypatch: Any,
    magnet: str,
    expected_fragment: str,
) -> None:
    app = _bare_app(tmp_path / "config.json")
    app.config = AppConfig(targets=DEFAULT_TARGETS)
    app._refresh_targets = lambda: (_ for _ in ()).throw(AssertionError("kein Refresh"))
    errors: list[str] = []
    monkeypatch.setattr(
        gui.simpledialog,
        "askstring",
        lambda *_args, **_kwargs: magnet,
        raising=False,
    )
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    app._add_target()

    assert app.config.targets == DEFAULT_TARGETS
    assert expected_fragment in errors[0]


def test_remove_requires_selection_and_confirmation(tmp_path: Path, monkeypatch: Any) -> None:
    app = _runtime_app(tmp_path)
    infos: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showinfo",
        lambda _title, message, **_kwargs: infos.append(message),
        raising=False,
    )
    app.target_tree = _WidgetDouble()

    app._remove_target()

    assert "zuerst ein Ziel auswählen" in infos[0]
    app.target_tree.selection_value = ("0",)
    monkeypatch.setattr(
        gui.messagebox,
        "askyesno",
        lambda *_args, **_kwargs: False,
        raising=False,
    )
    app._remove_target()
    assert app.config.targets == DEFAULT_TARGETS


def test_removing_last_target_persists_intentionally_empty_list(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path, AppConfig(targets=(DEFAULT_TARGETS[0],)))
    app.target_tree = _WidgetDouble(selection=("0",))
    app._refresh_targets = lambda: None
    monkeypatch.setattr(
        gui.messagebox,
        "askyesno",
        lambda *_args, **_kwargs: True,
        raising=False,
    )

    app._remove_target()

    assert app.config.targets == ()
    assert load_config(app.config_path).targets == ()
    assert _bare_app(app.config_path)._load_initial_config().targets == ()


def test_remove_save_error_keeps_original_target(tmp_path: Path, monkeypatch: Any) -> None:
    app = _runtime_app(tmp_path, AppConfig(targets=(DEFAULT_TARGETS[0],)))
    app.target_tree = _WidgetDouble(selection=("0",))
    app._refresh_targets = lambda: None
    errors: list[str] = []
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(gui, "save_config", lambda *_args: (_ for _ in ()).throw(OSError("voll")))
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    app._remove_target()

    assert app.config.targets == (DEFAULT_TARGETS[0],)
    assert errors == ["voll"]


def test_reporting_validation_rejects_bad_email_and_normalizes_text() -> None:
    with pytest.raises(ConfigError, match="gültige E-Mail-Adresse"):
        validate_reporting_settings(ReportingSettings(reporter_email="keine-adresse"))

    validated = validate_reporting_settings(
        ReportingSettings(
            reporter_name="  Beispiel  ",
            reporter_email="person@example.org",
            police_recipient="stelle@example.org",
            legal_notes=("  nur prüfen  ",),
        )
    )
    assert validated.reporter_name == "Beispiel"
    assert validated.legal_notes == ("nur prüfen",)


def test_settings_dialog_keeps_invalid_input_open(monkeypatch: Any) -> None:
    dialog = types.SimpleNamespace(
        settings=ReportingSettings(),
        name=_VariableDouble("Name"),
        email=_VariableDouble("ungültig"),
        recipient=_VariableDouble(""),
        result="nicht zurückgesetzt",
        destroy_count=0,
    )
    dialog.destroy = lambda: setattr(dialog, "destroy_count", dialog.destroy_count + 1)
    errors: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    gui.SettingsDialog._save(dialog)

    assert dialog.result is None
    assert dialog.destroy_count == 0
    assert "E-Mail-Adresse" in errors[0]


def test_settings_dialog_accepts_valid_optional_values() -> None:
    dialog = types.SimpleNamespace(
        settings=ReportingSettings(legal_notes=("Prüfhinweis",)),
        name=_VariableDouble("  Name  "),
        email=_VariableDouble("person@example.org"),
        recipient=_VariableDouble(""),
        result=None,
        destroy_count=0,
    )
    dialog.destroy = lambda: setattr(dialog, "destroy_count", dialog.destroy_count + 1)

    gui.SettingsDialog._save(dialog)

    assert dialog.result.reporter_name == "Name"
    assert dialog.result.police_recipient == ""
    assert dialog.result.legal_notes == ("Prüfhinweis",)
    assert dialog.destroy_count == 1


def test_edit_settings_cancel_does_not_write(tmp_path: Path, monkeypatch: Any) -> None:
    app = _runtime_app(tmp_path)
    dialog = types.SimpleNamespace(result=None)
    monkeypatch.setattr(gui, "SettingsDialog", lambda *_args: dialog)
    monkeypatch.setattr(gui, "save_config", lambda *_args: (_ for _ in ()).throw(AssertionError))

    app._edit_settings()

    assert app.root.waited_for == [dialog]


def test_network_enrichment_requires_explicit_consent_and_persists(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app.enrichment_enabled = _VariableDouble(True)
    confirmations: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "askyesno",
        lambda _title, message, **_kwargs: confirmations.append(message) or False,
        raising=False,
    )

    app._toggle_network_enrichment()

    assert app.enrichment_enabled.get() is False
    assert app.config.enrichment.enabled is False
    assert not app.config_path.exists()
    assert "protokollieren" in confirmations[0]

    app.enrichment_enabled.set(True)
    monkeypatch.setattr(
        gui.messagebox,
        "askyesno",
        lambda *_args, **_kwargs: True,
        raising=False,
    )
    app._toggle_network_enrichment()
    assert app.config.enrichment.enabled is True
    assert load_config(app.config_path).enrichment.enabled is True


def test_enrichment_save_error_reverts_checkbox(tmp_path: Path, monkeypatch: Any) -> None:
    app = _runtime_app(tmp_path)
    app.enrichment_enabled = _VariableDouble(True)
    errors: list[str] = []
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(gui, "save_config", lambda *_args: (_ for _ in ()).throw(OSError("voll")))
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    app._toggle_network_enrichment()

    assert app.enrichment_enabled.get() is False
    assert app.config.enrichment.enabled is False
    assert errors == ["voll"]


def test_start_scan_is_explicit_and_disables_mutating_controls(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    created_threads: list[Any] = []

    class _ThreadDouble:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            self.started = False
            created_threads.append(self)

        def start(self) -> None:
            self.started = True

    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(gui.threading, "Thread", _ThreadDouble)

    app._start_scan()

    assert app.running is True
    assert app.scan_button.options["state"] == "disabled"
    assert all(control.options["state"] == "disabled" for control in app.config_controls)
    assert app.open_button.options["state"] == "disabled"
    assert app.progress.started is True
    assert app.status_text.value == "Prüflauf wird vorbereitet …"
    assert created_threads[0].started is True
    assert created_threads[0].kwargs["args"] == (app.config,)
    assert load_config(app.config_path) == app.config


def test_start_scan_cancel_or_missing_target_does_not_start_thread(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path, AppConfig(targets=()))
    infos: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showinfo",
        lambda _title, message, **_kwargs: infos.append(message),
        raising=False,
    )
    monkeypatch.setattr(
        gui.threading,
        "Thread",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("kein Thread")),
    )
    app._start_scan()
    assert "mindestens einen Magnet-Link" in infos[0]

    app.config = AppConfig(targets=DEFAULT_TARGETS)
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: False, raising=False)
    app._start_scan()
    assert app.running is False
    assert not app.config_path.exists()


def test_start_scan_save_error_leaves_idle_state(tmp_path: Path, monkeypatch: Any) -> None:
    app = _runtime_app(tmp_path)
    errors: list[str] = []
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(gui, "save_config", lambda *_args: (_ for _ in ()).throw(OSError("voll")))
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    app._start_scan()

    assert app.running is False
    assert app.progress.started is False
    assert errors == ["voll"]


def test_scan_worker_queues_result_or_safe_error(tmp_path: Path, monkeypatch: Any) -> None:
    import bittorrent_beobachter.monitor as monitor

    app = _runtime_app(tmp_path)
    result = ScanResult(run_id="offline", started_at_utc="2026-10-20T10:00:00Z")
    monkeypatch.setattr(monitor, "run_scan", lambda *_args, **_kwargs: result)
    app._scan_worker(app.config)
    assert app.events.get_nowait() == ("done", result)

    monkeypatch.setattr(
        monitor,
        "run_scan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline kaputt")),
    )
    app._scan_worker(app.config)
    event, payload = app.events.get_nowait()
    assert event == "error"
    assert payload == "RuntimeError: offline kaputt"


def test_progress_does_not_overwrite_pending_close_message(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app.close_requested = True
    app.running = True
    app.status_text.set("Fenster schließt nach Abschluss.")
    app.events.put(("progress", "DHT-Suche läuft"))

    app._poll_events()

    assert app.status_text.value == "Fenster schließt nach Abschluss."
    assert app.root.after_calls


def test_error_event_is_explained_without_closing_window(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app.running = True
    app.events.put(("error", "MonitorError: keine Antwort"))
    errors: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )

    app._poll_events()

    assert app.running is False
    assert errors == ["MonitorError: keine Antwort"]
    assert "fehlgeschlagen" in app.status_text.value
    assert app.root.destroy_count == 0


def test_error_event_closes_silently_after_confirmed_window_close(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app.running = True
    app.close_requested = True
    app.events.put(("error", "MonitorError: keine Antwort"))
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("kein Popup")),
        raising=False,
    )

    app._poll_events()

    assert app.root.destroy_count == 1
    assert app.root.after_calls == []


def test_finish_restores_previous_report_button_after_failed_retry(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    previous = tmp_path / "reports" / "vorher"
    previous.mkdir(parents=True)
    app.latest_output_dir = previous
    app.running = True

    app._finish_running_state()

    assert app.running is False
    assert app.scan_button.options["state"] == "normal"
    assert all(control.options["state"] == "normal" for control in app.config_controls)
    assert app.open_button.options["state"] == "normal"
    assert app.progress.stopped is True


def test_window_close_is_immediate_when_idle_and_deferred_when_running(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    idle = _runtime_app(tmp_path / "idle")
    idle._request_close()
    assert idle.root.destroy_count == 1

    running = _runtime_app(tmp_path / "running")
    running.running = True
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: False, raising=False)
    running._request_close()
    assert running.close_requested is False
    assert running.root.destroy_count == 0

    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_args, **_kwargs: True, raising=False)
    running._request_close()
    assert running.close_requested is True
    assert "schließt nach dem Abschluss" in running.status_text.value


def test_technical_notice_updates_status_without_warning_popup(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app._finish_running_state = lambda: None
    monkeypatch.setattr(
        gui.messagebox,
        "showwarning",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("Technische Laufhinweise dürfen kein Warnfenster öffnen.")
        ),
        raising=False,
    )
    result = ScanResult(
        run_id="offline",
        started_at_utc="2026-10-20T10:00:00Z",
        notices=["Ein Ziel war vorübergehend nicht erreichbar."],
    )

    app._show_result(result)

    assert "1 technischer Laufhinweis steht im Bericht" in app.status_text.value
    assert "kein Programmfehler" in app.status_text.value


def test_result_table_uses_plain_language_and_ipv6_endpoint(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app._finish_running_state = lambda: None
    handshake = _handshake(ipv6=True)
    record = EvidenceRecord(
        handshake=handshake,
        enrichment=NetworkEnrichment(
            ip=handshake.candidate.ip,
            enriched_at_utc="2026-10-20T10:00:03Z",
            holder="Beispielnetz",
        ),
        vpn=VpnClassification(status="known_vpn", provider="Beispiel-VPN"),
        evidence_event_sha256="c" * 64,
    )
    result = ScanResult(
        run_id="offline",
        started_at_utc="2026-10-20T10:00:00Z",
        candidates=[handshake.candidate],
        handshakes=[handshake],
        records=[record],
    )

    app._show_result(result)

    values = app.result_tree.inserted[0][1]["values"]
    assert values[2] == "[2001:4860:4860::8888]:51413"
    assert values[3] == "Teile gemeldet; Anfragen erlaubt"
    assert values[4] == "Beispielnetz"
    assert values[5] == "VPN: Beispiel-VPN"
    assert "1 DHT-Treffer, 1 direkt geprüft" in app.status_text.value


def test_real_partial_result_errors_still_get_one_warning(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app._finish_running_state = lambda: None
    warnings: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showwarning",
        lambda _title, message, **_kwargs: warnings.append(message),
        raising=False,
    )
    result = ScanResult(
        run_id="offline",
        started_at_utc="2026-10-20T10:00:00Z",
        errors=["Netzauskunft war unvollständig."],
    )

    app._show_result(result)

    assert len(warnings) == 1
    assert "Netzauskunft war unvollständig" in warnings[0]


def test_open_output_handles_missing_folder_success_and_os_error(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    infos: list[str] = []
    errors: list[str] = []
    opened: list[Path] = []
    monkeypatch.setattr(
        gui.messagebox,
        "showinfo",
        lambda _title, message, **_kwargs: infos.append(message),
        raising=False,
    )
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )
    app._open_output()
    assert "noch kein Ergebnis" in infos[0]

    output = tmp_path / "reports" / "lauf"
    output.mkdir(parents=True)
    app.latest_output_dir = output
    monkeypatch.setattr(gui, "open_directory", lambda path: opened.append(path))
    app._open_output()
    assert opened == [output]

    monkeypatch.setattr(gui, "open_directory", lambda _path: (_ for _ in ()).throw(OSError("x")))
    app._open_output()
    assert errors == ["x"]
