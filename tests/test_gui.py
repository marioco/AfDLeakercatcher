"""Offline-Tests für Erststart und Zustände der Desktop-Oberfläche."""

from __future__ import annotations

import importlib
import json
import queue
import sys
import threading
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
    PeerControlEvent,
    ScanResult,
    TargetScanMetrics,
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
        module.Canvas = _TkBase
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
        self.scroll_calls: list[tuple[int, str]] = []

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

    def yview_scroll(self, amount: int, units: str) -> None:
        self.scroll_calls.append((amount, units))


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


class _ScreenRootDouble:
    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height
        self.geometry_value: str | None = None
        self.minimum_size: tuple[int, int] | None = None

    def winfo_screenwidth(self) -> int:
        return self.width

    def winfo_screenheight(self) -> int:
        return self.height

    def geometry(self, value: str) -> None:
        self.geometry_value = value

    def minsize(self, width: int, height: int) -> None:
        self.minimum_size = (width, height)


class _ThemeRootDouble:
    def __init__(self) -> None:
        self.options: dict[str, str] = {}
        self.option_database: dict[str, str] = {}

    def configure(self, **kwargs: str) -> None:
        self.options.update(kwargs)

    def option_add(self, pattern: str, value: str) -> None:
        self.option_database[pattern] = value


class _StyleDouble:
    def __init__(self, root: object) -> None:
        self.root = root
        self.selected_theme: str | None = None
        self.configurations: dict[str, dict[str, Any]] = {}
        self.mappings: dict[str, dict[str, Any]] = {}

    def theme_names(self) -> tuple[str, ...]:
        return ("vista", "clam")

    def theme_use(self, theme: str) -> None:
        self.selected_theme = theme

    def configure(self, style_name: str, **kwargs: Any) -> None:
        self.configurations[style_name] = kwargs

    def map(self, style_name: str, **kwargs: Any) -> None:
        self.mappings[style_name] = kwargs


def _bare_app(config_path: Path) -> Any:
    app = gui.ObserverApp.__new__(gui.ObserverApp)
    app.config_path = config_path
    app.root = _RootDouble()
    return app


def _runtime_app(tmp_path: Path, config: AppConfig | None = None) -> Any:
    app = _bare_app(tmp_path / "config.json")
    app.data_dir = tmp_path / "data"
    app.events = queue.Queue()
    app.progress_events = queue.Queue(maxsize=1)
    app._progress_event_lock = threading.Lock()
    app.running = False
    app.scan_thread = None
    app.cancel_event = threading.Event()
    app.close_requested = False
    app.latest_output_dir = None
    app._run_output_dir = None
    app.config = config or AppConfig(targets=DEFAULT_TARGETS)
    app.scan_button = _WidgetDouble()
    app.cancel_button = _WidgetDouble()
    app.open_button = _WidgetDouble()
    app.progress = _WidgetDouble()
    app.result_tree = _WidgetDouble()
    app.status_text = _WidgetDouble()
    app.status_label = _WidgetDouble()
    app.config_controls = (_WidgetDouble(), _WidgetDouble(), _WidgetDouble())
    return app


def test_gui_smoke_builds_real_observer_app_in_temporary_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, Path, Path, str | None]] = []

    class SmokeRoot:
        def __init__(self) -> None:
            self.tk = self
            self.withdrawn = False
            self.updated = False
            self.destroyed = False

        def withdraw(self) -> None:
            self.withdrawn = True

        def update_idletasks(self) -> None:
            self.updated = True

        def call(self, *args: str) -> str:
            assert args == ("info", "patchlevel")
            return "9.0.4"

        def destroy(self) -> None:
            self.destroyed = True

    root = SmokeRoot()

    def fake_observer_app(
        received_root: object,
        config_path: Path,
        data_dir: Path,
        *,
        startup_warning: str | None = None,
    ) -> None:
        calls.append((received_root, config_path, data_dir, startup_warning))

    monkeypatch.setattr(gui, "Tk", lambda: root)
    monkeypatch.setattr(gui, "ObserverApp", fake_observer_app)

    assert gui.verify_gui_runtime() == 0
    assert len(calls) == 1
    assert calls[0][0] is root
    assert calls[0][1].name == "config.json"
    assert calls[0][2].name == "data"
    assert calls[0][3] is None
    assert root.withdrawn is True
    assert root.updated is True
    assert root.destroyed is True


def test_observer_app_shows_logging_startup_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shown: list[tuple[str, str, object]] = []

    class WarningRoot:
        def title(self, _value: str) -> None:
            pass

        def protocol(self, _name: str, _callback: object) -> None:
            pass

    root = WarningRoot()
    monkeypatch.setattr(gui, "_configure_cyberpunk_theme", lambda _root: None)
    monkeypatch.setattr(gui, "_configure_window_geometry", lambda _root: None)
    monkeypatch.setattr(gui.ObserverApp, "_load_initial_config", lambda _app: AppConfig(targets=()))
    monkeypatch.setattr(gui.ObserverApp, "_build_ui", lambda _app: None)
    monkeypatch.setattr(gui.ObserverApp, "_refresh_targets", lambda _app: None)
    monkeypatch.setattr(gui.ObserverApp, "_poll_events", lambda _app: None)
    monkeypatch.setattr(
        gui.messagebox,
        "showwarning",
        lambda title, message, *, parent: shown.append((title, message, parent)),
        raising=False,
    )

    gui.ObserverApp(
        root,
        tmp_path / "config.json",
        tmp_path / "data",
        startup_warning="Logpfad unbrauchbar",
    )

    assert len(shown) == 1
    assert shown[0][0] == "Protokolldatei nicht verfügbar"
    assert "Logpfad unbrauchbar" in shown[0][1]
    assert "ohne Dateiprotokoll" in shown[0][1]
    assert shown[0][2] is root


def test_launch_gui_passes_startup_warning_to_observer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Path, Path, str | None]] = []

    class LaunchRoot:
        def __init__(self) -> None:
            self.mainloop_called = False

        def mainloop(self) -> None:
            self.mainloop_called = True

    root = LaunchRoot()

    def fake_observer_app(
        received_root: object,
        config_path: Path,
        data_dir: Path,
        *,
        startup_warning: str | None = None,
    ) -> None:
        assert received_root is root
        calls.append((config_path, data_dir, startup_warning))

    monkeypatch.setattr(gui, "Tk", lambda: root)
    monkeypatch.setattr(gui, "ObserverApp", fake_observer_app)

    assert (
        gui.launch_gui(
            tmp_path / "config.json",
            tmp_path / "data",
            startup_warning="Logpfad unbrauchbar",
        )
        == 0
    )
    assert calls == [(tmp_path / "config.json", tmp_path / "data", "Logpfad unbrauchbar")]
    assert root.mainloop_called is True


def test_main_window_fits_small_high_dpi_desktop() -> None:
    root = _ScreenRootDouble(800, 500)

    gui._configure_window_geometry(root)

    assert root.geometry_value == "760x450"
    assert root.minimum_size == (760, 450)


def test_main_window_keeps_normal_desktop_dimensions() -> None:
    root = _ScreenRootDouble(1920, 1080)

    gui._configure_window_geometry(root)

    assert root.geometry_value == "1040x700"
    assert root.minimum_size == (880, 600)


def test_cyberpunk_theme_configures_cross_platform_focus_and_disabled_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _ThemeRootDouble()
    style = _StyleDouble(root)
    monkeypatch.setattr(gui.ttk, "Style", lambda received_root: style, raising=False)

    configured_style = gui._configure_cyberpunk_theme(root)

    assert configured_style is style
    assert style.selected_theme == "clam"
    assert root.options["background"] == gui.CYBER_COLORS["background"]
    assert root.option_database == {
        "*selectBackground": gui.CYBER_COLORS["accent"],
        "*selectForeground": gui.CYBER_COLORS["background"],
        "*insertBackground": gui.CYBER_COLORS["accent"],
    }
    assert {
        "Hero.TLabel",
        "Status.Ready.TLabel",
        "Status.Running.TLabel",
        "Status.Success.TLabel",
        "Status.Warning.TLabel",
        "Status.Error.TLabel",
        "Accent.TButton",
        "Danger.TButton",
        "Treeview",
        "Treeview.Heading",
        "Cyber.Horizontal.TProgressbar",
    }.issubset(style.configurations)
    assert style.configurations["Treeview"]["rowheight"] >= 28
    assert ("focus", gui.CYBER_COLORS["accent"]) in style.mappings["TButton"]["bordercolor"]
    assert ("disabled", gui.CYBER_COLORS["muted"]) in style.mappings["TButton"]["foreground"]
    for button_style in ("Accent.TButton", "Danger.TButton"):
        assert (
            "disabled",
            gui.CYBER_COLORS["surface_raised"],
        ) in style.mappings[button_style]["background"]
        assert ("disabled", gui.CYBER_COLORS["muted"]) in style.mappings[button_style]["foreground"]
    assert ("selected", gui.CYBER_COLORS["accent"]) in style.mappings["TCheckbutton"][
        "indicatorcolor"
    ]


def test_cyberpunk_text_and_status_colors_have_accessible_contrast() -> None:
    def relative_luminance(color: str) -> float:
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    def contrast_ratio(foreground: str, background: str) -> float:
        light, dark = sorted(
            (relative_luminance(foreground), relative_luminance(background)),
            reverse=True,
        )
        return (light + 0.05) / (dark + 0.05)

    colors = gui.CYBER_COLORS
    text_pairs = (
        ("text", "background"),
        ("muted", "background"),
        ("text", "surface"),
        ("muted", "surface"),
        ("accent", "surface"),
        ("success", "surface"),
        ("warning", "surface"),
        ("danger", "surface"),
        ("background", "accent"),
        ("background", "magenta"),
        ("accent", "positive_surface"),
        ("warning", "warning_surface"),
    )

    for foreground, background in text_pairs:
        assert contrast_ratio(colors[foreground], colors[background]) >= 4.5


@pytest.mark.parametrize(
    ("state", "expected_style"),
    tuple(gui.STATUS_STYLE_BY_STATE.items()),
)
def test_status_state_keeps_explanatory_text_and_sets_distinct_style(
    tmp_path: Path,
    state: str,
    expected_style: str,
) -> None:
    app = _runtime_app(tmp_path)

    app._set_status(f"Klartext für {state}", state=state)

    assert app.status_text.value == f"Klartext für {state}"
    assert app.status_label.options["style"] == expected_style


class _SettingsScreenDouble(_ScreenRootDouble):
    def __init__(
        self,
        width: int,
        height: int,
        requested_width: int,
        requested_height: int,
    ) -> None:
        super().__init__(width, height)
        self.requested_width = requested_width
        self.requested_height = requested_height
        self.updated = False

    def update_idletasks(self) -> None:
        self.updated = True

    def winfo_reqwidth(self) -> int:
        return self.requested_width

    def winfo_reqheight(self) -> int:
        return self.requested_height


def test_settings_dialog_fits_small_high_dpi_desktop() -> None:
    dialog = _SettingsScreenDouble(800, 500, 900, 700)

    gui._configure_settings_dialog_geometry(dialog)

    assert dialog.updated is True
    assert dialog.geometry_value == "760x450"
    assert dialog.minimum_size == (320, 240)


def test_settings_dialog_keeps_comfortable_size_on_normal_desktop() -> None:
    assert gui._fit_settings_dialog_to_screen(1920, 1080, 500, 280) == (
        540,
        330,
        320,
        240,
    )


def test_main_mousewheel_scrolls_page_but_not_result_table(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app._content_canvas = _WidgetDouble()

    handled = app._scroll_main_view(types.SimpleNamespace(widget=object(), delta=-120, num=0))
    result_table_event = app._scroll_main_view(
        types.SimpleNamespace(widget=app.result_tree, delta=-120, num=0)
    )

    assert handled == "break"
    assert app._content_canvas.scroll_calls == [(1, "units")]
    assert result_table_event is None


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
            bytes_received=11,
            request_messages_sent=0,
            piece_payload_bytes_received=0,
            metadata_requests_sent=0,
            termination_reason="duration_elapsed",
            control_events=(
                PeerControlEvent(
                    observed_at_utc="2026-10-20T10:00:02.200Z",
                    elapsed_seconds=0.2,
                    kind="bitfield",
                    payload_length=1,
                    non_empty=True,
                    payload_sha256="12" * 32,
                    set_bits=1,
                ),
                PeerControlEvent(
                    observed_at_utc="2026-10-20T10:00:02.300Z",
                    elapsed_seconds=0.3,
                    kind="unchoke",
                    payload_length=0,
                ),
            ),
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
        bytes_sent=73 if confirmed else 0,
        bytes_received=79 if confirmed else 0,
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


def test_gui_discards_old_peer_caps_without_restoring_targets(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    raw = config_to_dict(AppConfig(targets=()))
    raw["bundled_preset_revision"] = 2
    raw["peer"]["max_checks"] = 120
    raw["peer"]["observation_workers"] = 32
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    config = _bare_app(config_path)._load_initial_config()

    assert config.targets == ()
    assert config.peer.retry_attempts == 3
    assert config.peer.retry_backoff_seconds == 1.0
    assert load_config(config_path) == config
    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert "max_checks" not in persisted["peer"]
    assert "observation_workers" not in persisted["peer"]


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


def test_add_target_uses_one_dialog_discards_name_and_keeps_udp_tracker(
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
    assert stored.targets[0].trackers == ("udp://tracker.example.invalid:1337/announce",)
    assert "tracker.example.invalid" in serialized
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
    confirmations: list[str] = []

    class _ThreadDouble:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            self.started = False
            created_threads.append(self)

        def start(self) -> None:
            self.started = True

    monkeypatch.setattr(
        gui.messagebox,
        "askyesno",
        lambda _title, message, **_kwargs: confirmations.append(message) or True,
        raising=False,
    )
    monkeypatch.setattr(gui.threading, "Thread", _ThreadDouble)

    app._start_scan()

    assert app.running is True
    assert app.scan_button.options["state"] == "disabled"
    assert app.cancel_button.options["state"] == "normal"
    assert all(control.options["state"] == "disabled" for control in app.config_controls)
    assert app.open_button.options["state"] == "disabled"
    assert app.progress.started is True
    assert app.status_text.value == "Prüflauf wird vorbereitet …"
    assert created_threads[0].started is True
    assert created_threads[0].kwargs["args"] == (app.config,)
    assert load_config(app.config_path) == app.config
    assert "STARTED" in confirmations[0]
    assert "STOPPED" in confirmations[0]
    assert "als Peer" in confirmations[0]


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
    app._publish_progress("DHT-Suche läuft")

    app._poll_events()

    assert app.status_text.value == "Fenster schließt nach Abschluss."
    assert app.root.after_calls


def test_many_progress_updates_keep_only_latest_text(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app.running = True
    failures: list[Exception] = []

    def publish(worker: int) -> None:
        try:
            for sequence in range(2_000):
                app._publish_progress(f"Worker {worker}: {sequence}")
        except Exception as exc:  # pragma: no cover - nur Diagnose bei Threadfehlern
            failures.append(exc)

    threads = [threading.Thread(target=publish, args=(worker,)) for worker in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    app._publish_progress("Neuester Fortschritt")

    assert failures == []
    assert app.progress_events.maxsize == 1
    assert app.progress_events.qsize() == 1
    assert app.events.qsize() == 0

    app._poll_events()

    assert app.status_text.value == "Neuester Fortschritt"
    assert app.progress_events.empty()


def test_terminal_event_is_not_blocked_by_progress_flood(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app.running = True
    app.status_text.set("Prüflauf läuft")
    result = ScanResult(run_id="offline", started_at_utc="2026-10-20T10:00:00Z")
    shown: list[ScanResult] = []
    app._show_result = shown.append

    for sequence in range(10_000):
        app._publish_progress(f"Fortschritt {sequence}")
    app.events.put_nowait(("done", result))

    app._poll_events()

    assert shown == [result]
    assert app.status_text.value == "Prüflauf läuft"
    assert app.progress_events.empty()
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
    assert app.cancel_button.options["state"] == "disabled"
    assert all(control.options["state"] == "normal" for control in app.config_controls)
    assert app.open_button.options["state"] == "normal"
    assert app.progress.stopped is True


def test_new_early_failure_does_not_present_previous_run_as_partial_result(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    previous = tmp_path / "reports" / "vorher"
    previous.mkdir(parents=True)
    app.running = True
    app._publish_reports_ready(previous, 5)
    app._poll_events()
    app._finish_running_state()

    class _ThreadDouble:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def start(self) -> None:
            return None

    errors: list[str] = []
    monkeypatch.setattr(
        gui.messagebox,
        "askyesno",
        lambda *_args, **_kwargs: True,
        raising=False,
    )
    monkeypatch.setattr(
        gui.messagebox,
        "showerror",
        lambda _title, message, **_kwargs: errors.append(message),
        raising=False,
    )
    monkeypatch.setattr(gui.threading, "Thread", _ThreadDouble)

    app._start_scan()

    assert app.latest_output_dir == previous
    assert app._run_output_dir is None
    assert app.open_button.options["state"] == "disabled"

    app.events.put(("error", "MonitorError: früher Fehler"))
    app._poll_events()

    assert errors == ["MonitorError: früher Fehler"]
    assert app.latest_output_dir == previous
    assert app._run_output_dir is None
    assert app.open_button.options["state"] == "disabled"
    assert "Teilergebnisse" not in app.status_text.value
    assert "fehlgeschlagen" in app.status_text.value

    opened: list[Path] = []
    monkeypatch.setattr(gui, "open_directory", lambda path: opened.append(path))
    app._open_output()
    assert opened == [previous]


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
    assert running.cancel_event.is_set()
    assert "kontrolliert abgebrochen" in running.status_text.value


def test_cancel_and_incremental_reports_are_visible_immediately(tmp_path: Path) -> None:
    app = _runtime_app(tmp_path)
    app.running = True

    output_dir = tmp_path / "data" / "reports" / "lauf"
    output_dir.mkdir(parents=True)
    app._publish_reports_ready(output_dir, 5)
    app._poll_events()

    assert app.latest_output_dir == output_dir
    assert app.open_button.options["state"] == "normal"
    assert "5 positive Befund" in app.status_text.value
    assert app.running is True

    app._cancel_scan()
    assert app.cancel_event.is_set()
    assert app.cancel_button.options["state"] == "disabled"
    assert "kontrolliert abgebrochen" in app.status_text.value


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
    assert app.result_tree.inserted[0][1]["tags"] == ("known_vpn",)
    assert values[2] == "[2001:4860:4860::8888]:51413"
    assert values[3] == "Teile gemeldet; Anfragen erlaubt"
    assert values[4] == "Beispielnetz"
    assert values[5] == "VPN: Beispiel-VPN"
    assert "1 Kandidaten gefunden, 1 direkt geprüft" in app.status_text.value


def test_result_table_streams_only_positive_database_records_and_uses_totals(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app._finish_running_state = lambda: None
    positive_handshake = _handshake(ipv6=True)
    positive_record = EvidenceRecord(
        handshake=positive_handshake,
        enrichment=NetworkEnrichment(
            ip=positive_handshake.candidate.ip,
            enriched_at_utc="2026-10-20T10:00:03Z",
            holder="Datenbanknetz",
        ),
        vpn=VpnClassification(status="not_known_vpn"),
        evidence_event_sha256="d" * 64,
    )
    failed_handshake = _handshake(confirmed=False)
    batch_sizes: list[int] = []

    class _RunStoreDouble:
        def iter_evidence_records(self, *, batch_size: int) -> Any:
            batch_sizes.append(batch_size)
            yield positive_record

    monkeypatch.setattr(gui, "RunStore", lambda _path: _RunStoreDouble())
    result = ScanResult(
        run_id="streaming",
        started_at_utc="2026-10-20T10:00:00Z",
        candidates=[failed_handshake.candidate],
        handshakes=[failed_handshake],
        candidate_count=307,
        handshake_count=305,
        confirmed_handshake_count=41,
        offering_observation_count=9,
        known_vpn_total=0,
        run_store_path=tmp_path / "run.sqlite3",
        target_metrics=(
            TargetScanMetrics(
                target_label="Ziel A",
                info_hash_hex="a" * 40,
                candidates_discovered=307,
                candidates_checked=305,
                verification_attempts=712,
                confirmed_handshakes=41,
                positive_findings=9,
            ),
            TargetScanMetrics(
                target_label="Ziel B",
                info_hash_hex="b" * 40,
            ),
        ),
    )

    app._show_result(result)

    assert batch_sizes == [5]
    assert len(app.result_tree.inserted) == 1
    values = app.result_tree.inserted[0][1]["values"]
    assert app.result_tree.inserted[0][1]["tags"] == ("availability",)
    assert values[2] == "[2001:4860:4860::8888]:51413"
    assert values[4] == "Datenbanknetz"
    assert "307 Kandidaten gefunden, 305 direkt geprüft" in app.status_text.value
    assert "0 bekannte VPN-Befunde" in app.status_text.value
    assert "Ziel A (aaaaaaaaaaaa…): 307 gefunden" in app.status_text.value
    assert "Ziel B (bbbbbbbbbbbb…): 0 gefunden" in app.status_text.value


def test_result_table_bounds_database_rows_and_points_to_complete_reports(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app = _runtime_app(tmp_path)
    app._finish_running_state = lambda: None
    handshake = _handshake()
    record = EvidenceRecord(
        handshake=handshake,
        enrichment=NetworkEnrichment(
            ip=handshake.candidate.ip,
            enriched_at_utc="2026-10-20T10:00:03Z",
            holder="Datenbanknetz",
        ),
        vpn=VpnClassification(status="not_known_vpn"),
        evidence_event_sha256="e" * 64,
    )
    yielded = 0

    class _RunStoreDouble:
        def iter_evidence_records(self, *, batch_size: int) -> Any:
            nonlocal yielded
            assert batch_size == 5
            for _ in range(150):
                yielded += 1
                yield record

    monkeypatch.setattr(gui, "RunStore", lambda _path: _RunStoreDouble())
    result = ScanResult(
        run_id="bounded-gui",
        started_at_utc="2026-10-20T10:00:00Z",
        candidate_count=150,
        handshake_count=150,
        confirmed_handshake_count=150,
        offering_observation_count=150,
        run_store_path=tmp_path / "run.sqlite3",
    )

    app._show_result(result)

    assert yielded == gui.MAX_GUI_RESULT_ROWS
    assert len(app.result_tree.inserted) == gui.MAX_GUI_RESULT_ROWS
    assert "100 von 150 positiven Befunden" in app.status_text.value
    assert "die Berichte enthalten alle" in app.status_text.value


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
