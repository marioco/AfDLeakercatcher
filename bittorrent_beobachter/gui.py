"""Einfache Desktop-Oberfläche für Konfiguration, Prüflauf und Ergebnisse."""

from __future__ import annotations

import logging
import queue
import sqlite3
import tempfile
import threading
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import replace
from itertools import islice
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    BooleanVar,
    Canvas,
    StringVar,
    Tk,
    Toplevel,
    X,
    messagebox,
    simpledialog,
    ttk,
)
from typing import Any, Literal

from . import APP_NAME, VERSION
from .config import (
    AppConfig,
    ConfigError,
    ReportingSettings,
    default_app_config,
    load_config,
    parse_magnet,
    save_config,
    validate_reporting_settings,
    with_bundled_presets,
)
from .desktop import open_directory
from .models import EvidenceRecord, ScanResult
from .run_store import RunStore

MAX_GUI_RESULT_ROWS = 100
DESIRED_WINDOW_WIDTH = 1040
DESIRED_WINDOW_HEIGHT = 700
DESIRED_MIN_WINDOW_WIDTH = 880
DESIRED_MIN_WINDOW_HEIGHT = 600
MAX_SCREEN_MARGIN_X = 40
MAX_SCREEN_MARGIN_Y = 80
MIN_TEXT_WRAP_LENGTH = 260
DESIRED_SETTINGS_DIALOG_WIDTH = 540
DESIRED_SETTINGS_DIALOG_HEIGHT = 330
DESIRED_MIN_SETTINGS_DIALOG_WIDTH = 320
DESIRED_MIN_SETTINGS_DIALOG_HEIGHT = 240

CYBER_COLORS = {
    "background": "#07111F",
    "surface": "#0B1728",
    "surface_raised": "#10243A",
    "surface_active": "#12324A",
    "positive_surface": "#0D2A2B",
    "warning_surface": "#2D2511",
    "text": "#F3F8FF",
    "muted": "#A7B8CC",
    "accent": "#19E6FF",
    "accent_hover": "#7CF2FF",
    "magenta": "#FF4FD8",
    "success": "#45F0A1",
    "warning": "#FFC857",
    "danger": "#FF6B8A",
    "border": "#36708F",
}
GUIStatusState = Literal["ready", "running", "success", "warning", "error"]
STATUS_STYLE_BY_STATE: dict[GUIStatusState, str] = {
    "ready": "Status.Ready.TLabel",
    "running": "Status.Running.TLabel",
    "success": "Status.Success.TLabel",
    "warning": "Status.Warning.TLabel",
    "error": "Status.Error.TLabel",
}


def _fit_window_to_screen(
    screen_width: int,
    screen_height: int,
) -> tuple[int, int, int, int]:
    """Berechnet eine start- und minimierbare Fenstergröße innerhalb des Bildschirms."""

    if (
        isinstance(screen_width, bool)
        or isinstance(screen_height, bool)
        or not isinstance(screen_width, int)
        or not isinstance(screen_height, int)
        or screen_width <= 0
        or screen_height <= 0
    ):
        raise ValueError("Die Bildschirmabmessungen müssen positive Ganzzahlen sein.")
    horizontal_margin = min(MAX_SCREEN_MARGIN_X, screen_width // 20)
    vertical_margin = min(MAX_SCREEN_MARGIN_Y, screen_height // 10)
    available_width = max(1, screen_width - horizontal_margin)
    available_height = max(1, screen_height - vertical_margin)
    initial_width = min(DESIRED_WINDOW_WIDTH, available_width)
    initial_height = min(DESIRED_WINDOW_HEIGHT, available_height)
    minimum_width = min(DESIRED_MIN_WINDOW_WIDTH, initial_width)
    minimum_height = min(DESIRED_MIN_WINDOW_HEIGHT, initial_height)
    return initial_width, initial_height, minimum_width, minimum_height


def _configure_window_geometry(root: Tk) -> None:
    initial_width, initial_height, minimum_width, minimum_height = _fit_window_to_screen(
        root.winfo_screenwidth(), root.winfo_screenheight()
    )
    root.geometry(f"{initial_width}x{initial_height}")
    root.minsize(minimum_width, minimum_height)


def _configure_cyberpunk_theme(root: Tk) -> ttk.Style:
    """Konfiguriert ein kontrastreiches, plattformunabhängiges Dark-Theme."""

    colors = CYBER_COLORS
    root.configure(background=colors["background"])
    root.option_add("*selectBackground", colors["accent"])
    root.option_add("*selectForeground", colors["background"])
    root.option_add("*insertBackground", colors["accent"])

    style = ttk.Style(root)
    if "clam" in style.theme_names():
        # Clam respektiert Farbangaben auch unter Windows; native Themes tun das
        # für einzelne Widgets nicht zuverlässig.
        style.theme_use("clam")

    style.configure(".", background=colors["background"], foreground=colors["text"])
    style.configure("TFrame", background=colors["background"])
    style.configure("Panel.TFrame", background=colors["surface"])
    style.configure("Hero.TFrame", background=colors["surface_raised"])
    style.configure("StatusPanel.TFrame", background=colors["surface"])

    style.configure("TLabel", background=colors["background"], foreground=colors["text"])
    style.configure(
        "Hero.TLabel",
        background=colors["surface_raised"],
        foreground=colors["text"],
        font=("TkDefaultFont", 20, "bold"),
    )
    style.configure(
        "Kicker.TLabel",
        background=colors["surface_raised"],
        foreground=colors["magenta"],
        font=("TkDefaultFont", 9, "bold"),
    )
    style.configure(
        "HeroAccent.TLabel",
        background=colors["surface_raised"],
        foreground=colors["accent"],
    )
    style.configure("Muted.TLabel", foreground=colors["muted"])
    style.configure(
        "Panel.TLabel",
        background=colors["surface"],
        foreground=colors["text"],
    )
    style.configure(
        "Muted.Panel.TLabel",
        background=colors["surface"],
        foreground=colors["muted"],
    )
    style.configure(
        "StatusCaption.TLabel",
        background=colors["surface"],
        foreground=colors["muted"],
        font=("TkDefaultFont", 8, "bold"),
    )
    for state, foreground in (
        ("Ready", colors["accent"]),
        ("Running", colors["warning"]),
        ("Success", colors["success"]),
        ("Warning", colors["warning"]),
        ("Error", colors["danger"]),
    ):
        style.configure(
            f"Status.{state}.TLabel",
            background=colors["surface"],
            foreground=foreground,
            font=("TkDefaultFont", 10, "bold"),
        )

    style.configure(
        "TLabelframe",
        background=colors["surface"],
        bordercolor=colors["border"],
        darkcolor=colors["border"],
        lightcolor=colors["border"],
        borderwidth=1,
        relief="solid",
    )
    style.configure(
        "TLabelframe.Label",
        background=colors["surface"],
        foreground=colors["accent"],
        font=("TkDefaultFont", 10, "bold"),
    )
    style.configure("Notice.TLabelframe", bordercolor=colors["warning"])
    style.configure(
        "Notice.TLabelframe.Label",
        background=colors["surface"],
        foreground=colors["warning"],
    )

    style.configure(
        "TButton",
        background=colors["surface_raised"],
        foreground=colors["text"],
        bordercolor=colors["border"],
        focuscolor=colors["accent"],
        focusthickness=2,
        padding=(12, 8),
    )
    style.map(
        "TButton",
        background=[("pressed", colors["surface_active"]), ("active", colors["surface_active"])],
        foreground=[("disabled", colors["muted"]), ("!disabled", colors["text"])],
        bordercolor=[("focus", colors["accent"]), ("!focus", colors["border"])],
    )
    style.configure(
        "Accent.TButton",
        background=colors["accent"],
        foreground=colors["background"],
        bordercolor=colors["accent"],
    )
    style.map(
        "Accent.TButton",
        background=[
            ("disabled", colors["surface_raised"]),
            ("pressed", colors["accent"]),
            ("active", colors["accent_hover"]),
        ],
        foreground=[("disabled", colors["muted"]), ("!disabled", colors["background"])],
        bordercolor=[("disabled", colors["border"]), ("focus", colors["accent"])],
    )
    style.configure(
        "Danger.TButton",
        background=colors["magenta"],
        foreground=colors["background"],
        bordercolor=colors["magenta"],
    )
    style.map(
        "Danger.TButton",
        background=[
            ("disabled", colors["surface_raised"]),
            ("pressed", colors["danger"]),
            ("active", colors["danger"]),
        ],
        foreground=[("disabled", colors["muted"]), ("!disabled", colors["background"])],
        bordercolor=[("disabled", colors["border"]), ("focus", colors["magenta"])],
    )

    style.configure(
        "TCheckbutton",
        background=colors["surface"],
        foreground=colors["text"],
        focuscolor=colors["accent"],
        padding=(2, 3),
    )
    style.map(
        "TCheckbutton",
        background=[("active", colors["surface"]), ("!active", colors["surface"])],
        foreground=[("disabled", colors["muted"]), ("!disabled", colors["text"])],
        indicatorcolor=[
            ("selected", colors["accent"]),
            ("!selected", colors["surface_raised"]),
        ],
    )
    style.configure(
        "TEntry",
        fieldbackground=colors["surface_raised"],
        foreground=colors["text"],
        insertcolor=colors["accent"],
        bordercolor=colors["border"],
        lightcolor=colors["border"],
        darkcolor=colors["border"],
        padding=7,
    )
    style.map(
        "TEntry",
        fieldbackground=[
            ("disabled", colors["surface"]),
            ("readonly", colors["surface"]),
        ],
        foreground=[("disabled", colors["muted"]), ("readonly", colors["text"])],
        bordercolor=[("focus", colors["accent"]), ("!focus", colors["border"])],
        lightcolor=[("focus", colors["accent"]), ("!focus", colors["border"])],
        darkcolor=[("focus", colors["accent"]), ("!focus", colors["border"])],
    )

    style.configure(
        "Treeview",
        background=colors["surface"],
        fieldbackground=colors["surface"],
        foreground=colors["text"],
        bordercolor=colors["border"],
        lightcolor=colors["border"],
        darkcolor=colors["border"],
        rowheight=28,
    )
    style.map(
        "Treeview",
        background=[("selected", colors["accent"])],
        foreground=[("selected", colors["background"])],
    )
    style.configure(
        "Treeview.Heading",
        background=colors["surface_raised"],
        foreground=colors["accent"],
        bordercolor=colors["border"],
        lightcolor=colors["border"],
        darkcolor=colors["border"],
        relief="flat",
        padding=(8, 7),
        font=("TkDefaultFont", 9, "bold"),
    )
    style.map(
        "Treeview.Heading",
        background=[("active", colors["surface_active"])],
        foreground=[("active", colors["accent_hover"])],
    )
    style.configure(
        "Vertical.TScrollbar",
        background=colors["surface_raised"],
        troughcolor=colors["background"],
        bordercolor=colors["background"],
        arrowcolor=colors["accent"],
    )
    style.configure(
        "Horizontal.TScrollbar",
        background=colors["surface_raised"],
        troughcolor=colors["background"],
        bordercolor=colors["background"],
        arrowcolor=colors["accent"],
    )
    style.configure(
        "Cyber.Horizontal.TProgressbar",
        background=colors["accent"],
        troughcolor=colors["surface_raised"],
        bordercolor=colors["border"],
        lightcolor=colors["accent"],
        darkcolor=colors["accent"],
    )
    style.configure("TSeparator", background=colors["border"])
    return style


def _fit_settings_dialog_to_screen(
    screen_width: int,
    screen_height: int,
    requested_width: int,
    requested_height: int,
) -> tuple[int, int, int, int]:
    """Begrenzt den Einstellungsdialog auf die nutzbare Bildschirmfläche."""

    dimensions = (screen_width, screen_height, requested_width, requested_height)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in dimensions
    ):
        raise ValueError("Bildschirm- und Dialogabmessungen müssen positive Ganzzahlen sein.")
    horizontal_margin = min(MAX_SCREEN_MARGIN_X, screen_width // 20)
    vertical_margin = min(MAX_SCREEN_MARGIN_Y, screen_height // 10)
    available_width = max(1, screen_width - horizontal_margin)
    available_height = max(1, screen_height - vertical_margin)
    initial_width = min(
        max(DESIRED_SETTINGS_DIALOG_WIDTH, requested_width),
        available_width,
    )
    initial_height = min(
        max(DESIRED_SETTINGS_DIALOG_HEIGHT, requested_height),
        available_height,
    )
    minimum_width = min(DESIRED_MIN_SETTINGS_DIALOG_WIDTH, initial_width)
    minimum_height = min(DESIRED_MIN_SETTINGS_DIALOG_HEIGHT, initial_height)
    return initial_width, initial_height, minimum_width, minimum_height


def _configure_settings_dialog_geometry(dialog: Toplevel) -> None:
    dialog.update_idletasks()
    initial_width, initial_height, minimum_width, minimum_height = _fit_settings_dialog_to_screen(
        dialog.winfo_screenwidth(),
        dialog.winfo_screenheight(),
        dialog.winfo_reqwidth(),
        dialog.winfo_reqheight(),
    )
    dialog.geometry(f"{initial_width}x{initial_height}")
    dialog.minsize(minimum_width, minimum_height)


class SettingsDialog(Toplevel):
    """Kleiner Dialog für optionale Absender- und Empfängerangaben."""

    def __init__(self, parent: Tk, settings: ReportingSettings) -> None:
        super().__init__(parent)
        self.title("Angaben für die Entwürfe")
        self.configure(background=CYBER_COLORS["background"])
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()
        self.result: ReportingSettings | None = None
        self.settings = settings

        self.name = StringVar(value=settings.reporter_name)
        self.email = StringVar(value=settings.reporter_email)
        self.recipient = StringVar(value=settings.police_recipient)

        viewport = ttk.Frame(self)
        viewport.pack(fill=BOTH, expand=True)
        canvas = Canvas(
            viewport,
            background=CYBER_COLORS["background"],
            highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill="y")
        canvas.pack(side=LEFT, fill=BOTH, expand=True)

        frame = ttk.Frame(canvas, padding=16, style="Panel.TFrame")
        content_window = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.columnconfigure(0, weight=1)
        fields = (
            ("Name der meldenden Person/Organisation", self.name),
            ("Absender-E-Mail (optional)", self.email),
            ("Empfänger-E-Mail der Polizei (optional)", self.recipient),
        )
        field_labels: list[Any] = []
        for row, (label, variable) in enumerate(fields):
            field_label = ttk.Label(frame, text=label, style="Panel.TLabel")
            field_label.grid(row=row * 2, column=0, sticky="w", pady=(0, 3))
            field_labels.append(field_label)
            ttk.Entry(frame, textvariable=variable).grid(
                row=row * 2 + 1, column=0, sticky="ew", pady=(0, 10)
            )

        note_label = ttk.Label(
            frame,
            text=(
                "Die Anwendung versendet nichts. Leere Empfängerfelder können später "
                "im E-Mail-Programm ergänzt werden."
            ),
            style="Muted.Panel.TLabel",
            wraplength=480,
        )
        note_label.grid(row=6, column=0, sticky="w", pady=(2, 12))
        buttons = ttk.Frame(frame, style="Panel.TFrame")
        buttons.grid(row=7, column=0, sticky="e")
        ttk.Button(buttons, text="Abbrechen", command=self.destroy).pack(side=LEFT, padx=(0, 8))
        ttk.Button(
            buttons,
            text="Speichern",
            command=self._save,
            style="Accent.TButton",
        ).pack(side=RIGHT)

        def update_scroll_region(_event: object) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_content(event: Any) -> None:
            content_width = max(1, event.width)
            canvas.itemconfigure(content_window, width=content_width)
            wrap_length = max(120, content_width - 32)
            note_label.configure(wraplength=wrap_length)
            for field_label in field_labels:
                field_label.configure(wraplength=wrap_length)

        frame.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_content)
        self.bind("<Escape>", lambda _event: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        _configure_settings_dialog_geometry(self)
        self.wait_visibility()
        self.focus_set()

    def _save(self) -> None:
        try:
            self.result = validate_reporting_settings(
                replace(
                    self.settings,
                    reporter_name=self.name.get().strip(),
                    reporter_email=self.email.get().strip(),
                    police_recipient=self.recipient.get().strip(),
                )
            )
        except ConfigError as exc:
            self.result = None
            messagebox.showerror("Angaben prüfen", str(exc), parent=self)
            return
        self.destroy()


def _iter_positive_evidence(result: ScanResult) -> Iterable[EvidenceRecord]:
    """Liefert positive GUI-Zeilen aus der laufbezogenen Ablage."""

    if result.run_store_path is None:
        return (record for record in result.records if record.handshake.offering_observed)
    return (
        record
        for record in RunStore(result.run_store_path).iter_evidence_records(batch_size=5)
        if record.handshake.offering_observed
    )


def _target_status_text(result: ScanResult) -> str:
    """Fasst die Bilanz jedes Infohashes kompakt und einschließlich Nullwerten zusammen."""

    if not result.target_metrics:
        return ""
    details = "; ".join(
        (
            f"{metric.target_label} ({metric.info_hash_hex[:12]}…): "
            f"{metric.candidates_discovered} gefunden, "
            f"{metric.candidates_checked} geprüft, "
            f"{metric.verification_attempts} Versuche, "
            f"{metric.confirmed_handshakes} Handshakes, "
            f"{metric.positive_findings} positiv"
        )
        for metric in result.target_metrics
    )
    return f" Pro Infohash: {details}."


class ObserverApp:
    """Bedienoberfläche mit klarer Trennung von Beobachtung und Behauptung."""

    def __init__(
        self,
        root: Tk,
        config_path: Path,
        data_dir: Path,
        *,
        startup_warning: str | None = None,
    ) -> None:
        self.root = root
        self.config_path = config_path
        self.data_dir = data_dir
        # Abschlussereignisse bleiben in einer eigenen, unbegrenzten Queue. So kann
        # eine hohe Fortschrittsrate weder "done" noch "error" verdrängen.
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.progress_events: queue.Queue[str] = queue.Queue(maxsize=1)
        self._progress_event_lock = threading.Lock()
        self.running = False
        self.scan_thread: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.close_requested = False
        self.latest_output_dir: Path | None = None
        self._run_output_dir: Path | None = None

        root.title(f"{APP_NAME} {VERSION}")
        _configure_cyberpunk_theme(root)
        _configure_window_geometry(root)
        self.config = self._load_initial_config()
        self._build_ui()
        self._refresh_targets()
        self.root.protocol("WM_DELETE_WINDOW", self._request_close)
        self._poll_events()
        if startup_warning is not None:
            messagebox.showwarning(
                "Protokolldatei nicht verfügbar",
                (
                    f"{startup_warning}\n\n"
                    "Die Oberfläche läuft ohne Dateiprotokoll weiter. "
                    "Probleme mit dem Ergebnisordner werden beim Prüflauf "
                    "gesondert gemeldet."
                ),
                parent=self.root,
            )

    def _load_initial_config(self) -> AppConfig:
        if not self.config_path.exists():
            config = default_app_config()
            try:
                save_config(self.config_path, config)
            except (ConfigError, OSError) as exc:
                messagebox.showerror(
                    "Voreinstellungen nicht gespeichert",
                    str(exc),
                    parent=self.root,
                )
            return config
        try:
            config = load_config(self.config_path)
        except ConfigError as exc:
            messagebox.showerror(
                "Gespeicherte Einstellungen unlesbar",
                (
                    f"Die gespeicherten Einstellungen konnten nicht geladen werden:\n\n{exc}\n\n"
                    "Das Programm verwendet für dieses Fenster sichere Voreinstellungen. "
                    "Es wurde kein Prüflauf gestartet."
                ),
                parent=self.root,
            )
            return default_app_config()

        try:
            migrated = with_bundled_presets(config)
            if migrated != config:
                save_config(self.config_path, migrated)
        except (ConfigError, OSError) as exc:
            messagebox.showerror(
                "Voreinstellungen nicht aktualisiert",
                str(exc),
                parent=self.root,
            )
            return config
        return migrated

    def _build_ui(self) -> None:
        viewport = ttk.Frame(self.root)
        viewport.pack(fill=BOTH, expand=True)
        canvas = Canvas(
            viewport,
            background=CYBER_COLORS["background"],
            highlightthickness=0,
        )
        main_scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=main_scrollbar.set)
        main_scrollbar.pack(side=RIGHT, fill="y")
        canvas.pack(side=LEFT, fill=BOTH, expand=True)

        outer = ttk.Frame(canvas, padding=16)
        content_window = canvas.create_window((0, 0), window=outer, anchor="nw")
        self._content_canvas = canvas
        self._responsive_labels: list[ttk.Label] = []

        def remember_label(label: ttk.Label) -> ttk.Label:
            self._responsive_labels.append(label)
            return label

        def update_scroll_region(_event: Any) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_content(event: Any) -> None:
            canvas.itemconfigure(content_window, width=event.width)
            wrap_length = max(MIN_TEXT_WRAP_LENGTH, event.width - 64)
            for label in self._responsive_labels:
                label.configure(wraplength=wrap_length)

        outer.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_content)

        hero = ttk.Frame(outer, style="Hero.TFrame", padding=(18, 14))
        hero.pack(fill=X, pady=(0, 12))
        ttk.Label(
            hero,
            text=f"NETWORK EVIDENCE CONSOLE  //  v{VERSION}",
            style="Kicker.TLabel",
        ).pack(anchor="w")
        ttk.Label(hero, text=APP_NAME, style="Hero.TLabel").pack(anchor="w", pady=(2, 2))
        remember_label(
            ttk.Label(
                hero,
                text=(
                    "Inhaltsfreie Verfügbarkeitsprüfung // Keine Datei- oder "
                    "Metadatenblöcke werden angefordert, heruntergeladen oder hochgeladen."
                ),
                style="HeroAccent.TLabel",
                wraplength=950,
            )
        ).pack(anchor="w", fill=X)

        notice = ttk.LabelFrame(
            outer,
            text="WICHTIGE AUSSAGEGRENZE",
            padding=12,
            style="Notice.TLabelframe",
        )
        notice.pack(fill=X, pady=(0, 12))
        remember_label(
            ttk.Label(
                notice,
                text=(
                    "Ein positiver Befund bedeutet: Der Endpunkt bestätigte den Infohash, "
                    "meldete verfügbare Teile und erlaubte während der einminütigen Verbindung "
                    "das Stellen von Datenanfragen. Es werden keine Datenblöcke angefordert. "
                    "Der Befund identifiziert keine Person und beweist keinen tatsächlichen "
                    "Upload oder eine Straftat. Jede Anzeige muss vor dem Versand geprüft werden."
                ),
                style="Panel.TLabel",
                wraplength=930,
            )
        ).pack(anchor="w", fill=X)

        target_box = ttk.LabelFrame(
            outer,
            text="ZIELE FÜR MANUELLE PRÜFLÄUFE",
            padding=12,
        )
        target_box.pack(fill=X, pady=(0, 12))
        remember_label(
            ttk.Label(
                target_box,
                text=(
                    "Die beiden Voreinstellungen bestätigen keinen Inhalt. Ein Prüflauf "
                    "beginnt erst nach „Jetzt prüfen“ und Ihrer ausdrücklichen Bestätigung."
                ),
                style="Muted.Panel.TLabel",
                wraplength=930,
            )
        ).pack(anchor="w", fill=X, pady=(0, 8))
        target_table = ttk.Frame(target_box, style="Panel.TFrame")
        target_table.pack(fill=X, expand=True)
        target_table.columnconfigure(0, weight=1)
        self.target_tree = ttk.Treeview(
            target_table,
            columns=("label", "hash"),
            show="headings",
            height=4,
            selectmode="browse",
        )
        self.target_tree.heading("label", text="Bezeichnung")
        self.target_tree.heading("hash", text="Infohash")
        self.target_tree.column("label", width=300, minwidth=150, anchor="w", stretch=True)
        self.target_tree.column("hash", width=430, minwidth=280, anchor="w", stretch=True)
        target_scrollbar = ttk.Scrollbar(
            target_table,
            orient="horizontal",
            command=self.target_tree.xview,
        )
        self.target_tree.configure(xscrollcommand=target_scrollbar.set)
        self.target_tree.grid(row=0, column=0, sticky="nsew")
        target_scrollbar.grid(row=1, column=0, sticky="ew")
        target_buttons = ttk.Frame(target_box, style="Panel.TFrame")
        target_buttons.pack(fill=X, pady=(10, 0))
        self.add_target_button = ttk.Button(
            target_buttons,
            text="Magnet-Link hinzufügen",
            command=self._add_target,
        )
        self.add_target_button.pack(side=LEFT, padx=(0, 8))
        self.remove_target_button = ttk.Button(
            target_buttons,
            text="Auswahl entfernen",
            command=self._remove_target,
        )
        self.remove_target_button.pack(side=LEFT, padx=(0, 8))
        self.settings_button = ttk.Button(
            target_buttons,
            text="Entwurfsangaben",
            command=self._edit_settings,
        )
        self.settings_button.pack(side=LEFT)
        privacy_box = ttk.LabelFrame(
            outer,
            text="OPTIONALE ÖFFENTLICHE NETZAUSKUNFT",
            padding=12,
        )
        privacy_box.pack(fill=X, pady=(0, 12))
        self.enrichment_enabled = BooleanVar(value=self.config.enrichment.enabled)
        self.enrichment_checkbox = ttk.Checkbutton(
            privacy_box,
            text="Öffentliche Netzauskunft für bestätigte IP-Adressen aktivieren",
            variable=self.enrichment_enabled,
            command=self._toggle_network_enrichment,
        )
        self.enrichment_checkbox.pack(anchor="w")
        remember_label(
            ttk.Label(
                privacy_box,
                text=(
                    "Bestätigte IP-Adressen werden an stat.ripe.net, rdap.org und das von "
                    "rdap.org bestimmte Regionalregister gesendet. Standardmäßig ist dies "
                    "aus. Bekannte VPN-IP-Bereiche werden zuerst offline erkannt und nicht "
                    "extern abgefragt. Regionalregister wie RIPE, ARIN, APNIC, LACNIC oder "
                    "AFRINIC können Anfragen protokollieren."
                ),
                style="Muted.Panel.TLabel",
                wraplength=930,
            )
        ).pack(anchor="w", fill=X, pady=(4, 0))

        action_bar = ttk.Frame(outer)
        action_bar.pack(fill=X, pady=(0, 10))
        action_buttons = ttk.Frame(action_bar)
        action_buttons.pack(fill=X)
        self.scan_button = ttk.Button(
            action_buttons,
            text="Jetzt prüfen",
            command=self._start_scan,
            style="Accent.TButton",
        )
        self.scan_button.pack(side=LEFT)
        self.cancel_button = ttk.Button(
            action_buttons,
            text="Prüflauf abbrechen",
            command=self._cancel_scan,
            state="disabled",
            style="Danger.TButton",
        )
        self.cancel_button.pack(side=LEFT, padx=(8, 0))
        self.open_button = ttk.Button(
            action_buttons,
            text="Letzten Ergebnisordner öffnen",
            command=self._open_output,
            state="disabled",
        )
        self.open_button.pack(side=LEFT, padx=(8, 0))
        self.progress = ttk.Progressbar(
            action_bar,
            mode="indeterminate",
            length=210,
            style="Cyber.Horizontal.TProgressbar",
        )
        self.progress.pack(anchor="w", pady=(8, 0))
        self.config_controls = (
            self.add_target_button,
            self.remove_target_button,
            self.settings_button,
            self.enrichment_checkbox,
        )

        status_panel = ttk.Frame(
            outer,
            style="StatusPanel.TFrame",
            padding=(12, 9),
        )
        status_panel.pack(fill=X, pady=(0, 12))
        ttk.Label(
            status_panel,
            text="SYSTEMSTATUS",
            style="StatusCaption.TLabel",
        ).pack(anchor="w")
        self.status_text = StringVar(value="Bereit. Fügen Sie einen Magnet-Link hinzu.")
        self.status_label = remember_label(
            ttk.Label(
                status_panel,
                textvariable=self.status_text,
                style=STATUS_STYLE_BY_STATE["ready"],
                wraplength=930,
            )
        )
        self.status_label.pack(anchor="w", fill=X, pady=(2, 0))

        result_box = ttk.LabelFrame(outer, text="LETZTER PRÜFLAUF", padding=12)
        result_box.pack(fill=BOTH, expand=True)
        result_box.columnconfigure(0, weight=1)
        result_box.rowconfigure(0, weight=1)
        self.result_tree = ttk.Treeview(
            result_box,
            columns=("time", "target", "endpoint", "status", "network", "class"),
            show="headings",
        )
        headings = {
            "time": "Zeit (UTC)",
            "target": "Ziel",
            "endpoint": "Endpunkt",
            "status": "Verfügbarkeitsprüfung",
            "network": "Netzbetreiber",
            "class": "Einordnung",
        }
        widths = {
            "time": 145,
            "target": 150,
            "endpoint": 180,
            "status": 205,
            "network": 190,
            "class": 120,
        }
        for name, title in headings.items():
            self.result_tree.heading(name, text=title)
            self.result_tree.column(name, width=widths[name], anchor="w")
        vertical_scrollbar = ttk.Scrollbar(
            result_box,
            orient="vertical",
            command=self.result_tree.yview,
        )
        horizontal_scrollbar = ttk.Scrollbar(
            result_box,
            orient="horizontal",
            command=self.result_tree.xview,
        )
        self.result_tree.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )
        self.result_tree.tag_configure(
            "availability",
            background=CYBER_COLORS["positive_surface"],
            foreground=CYBER_COLORS["accent"],
        )
        self.result_tree.tag_configure(
            "known_vpn",
            background=CYBER_COLORS["warning_surface"],
            foreground=CYBER_COLORS["warning"],
        )
        self.result_tree.grid(row=0, column=0, sticky="nsew")
        vertical_scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew")

        remember_label(
            ttk.Label(
                outer,
                text=(
                    "Keine automatische Anzeige · Kein automatischer E-Mail-Versand · "
                    "Bekannte VPN-Endpunkte werden gekennzeichnet und gesondert berichtet"
                ),
                style="Muted.TLabel",
            )
        ).pack(anchor="w", fill=X, pady=(10, 0))
        self.root.bind("<MouseWheel>", self._scroll_main_view, add="+")
        self.root.bind("<Button-4>", self._scroll_main_view, add="+")
        self.root.bind("<Button-5>", self._scroll_main_view, add="+")

    def _scroll_main_view(self, event: Any) -> str | None:
        if event.widget is self.result_tree:
            return None
        try:
            delta = int(getattr(event, "delta", 0))
            button = int(getattr(event, "num", 0))
        except (TypeError, ValueError):
            return None
        if button == 4 or delta > 0:
            direction = -1
        elif button == 5 or delta < 0:
            direction = 1
        else:
            return None
        self._content_canvas.yview_scroll(direction, "units")
        return "break"

    def _set_status(self, message: str, *, state: GUIStatusState) -> None:
        """Aktualisiert Statusinhalt und die dazugehörige, nicht allein farbliche Anzeige."""

        self.status_text.set(message)
        status_label = getattr(self, "status_label", None)
        if status_label is not None:
            status_label.configure(style=STATUS_STYLE_BY_STATE[state])

    def _refresh_targets(self) -> None:
        self.target_tree.delete(*self.target_tree.get_children())
        for index, target in enumerate(self.config.targets):
            self.target_tree.insert(
                "", END, iid=str(index), values=(target.label, target.info_hash_hex)
            )
        if self.config.targets:
            self._set_status(
                f"Bereit. {len(self.config.targets)} Ziel(e) konfiguriert; es läuft kein Prüflauf.",
                state="ready",
            )
        else:
            self._set_status(
                "Bereit. Keine Ziele eingetragen; es läuft kein Prüflauf.",
                state="ready",
            )

    def _add_target(self) -> None:
        magnet = simpledialog.askstring(
            "Magnet-Link hinzufügen",
            (
                "Magnet-Link einfügen. Gespeichert werden der BitTorrent-v1-Infohash "
                "und gültige UDP-Tracker für die Endpunktsuche; ein Titel ist nicht nötig:"
            ),
            parent=self.root,
        )
        if not magnet:
            return
        try:
            parsed_target = parse_magnet(magnet)
            target = replace(
                parsed_target,
                label=f"Infohash {parsed_target.info_hash_hex[:12]}",
                source_note="",
            )
            if any(existing.info_hash == target.info_hash for existing in self.config.targets):
                raise ConfigError("Dieser Infohash ist bereits eingetragen.")
            updated_config = replace(
                self.config,
                targets=(*self.config.targets, target),
            )
            save_config(self.config_path, updated_config)
        except (ConfigError, OSError) as exc:
            messagebox.showerror("Ziel nicht gespeichert", str(exc), parent=self.root)
            return
        self.config = updated_config
        self._refresh_targets()

    def _remove_target(self) -> None:
        selection = self.target_tree.selection()
        if not selection:
            messagebox.showinfo(
                "Keine Auswahl", "Bitte zuerst ein Ziel auswählen.", parent=self.root
            )
            return
        index = int(selection[0])
        target = self.config.targets[index]
        if not messagebox.askyesno(
            "Ziel entfernen",
            f"„{target.label}“ wirklich aus der Liste entfernen?",
            parent=self.root,
        ):
            return
        targets = tuple(
            item for position, item in enumerate(self.config.targets) if position != index
        )
        try:
            updated_config = replace(self.config, targets=targets)
            save_config(self.config_path, updated_config)
        except (ConfigError, OSError) as exc:
            messagebox.showerror("Ziel nicht entfernt", str(exc), parent=self.root)
            return
        self.config = updated_config
        self._refresh_targets()

    def _edit_settings(self) -> None:
        dialog = SettingsDialog(self.root, self.config.reporting)
        self.root.wait_window(dialog)
        if dialog.result is None:
            return
        try:
            updated_config = replace(self.config, reporting=dialog.result)
            save_config(self.config_path, updated_config)
        except (ConfigError, OSError) as exc:
            messagebox.showerror("Angaben nicht gespeichert", str(exc), parent=self.root)
            return
        self.config = updated_config

    def _toggle_network_enrichment(self) -> None:
        requested = self.enrichment_enabled.get()
        previous = self.config.enrichment.enabled
        if requested and not previous:
            confirmed = messagebox.askyesno(
                "Externe Netzauskunft aktivieren?",
                (
                    "Wenn Sie diese Funktion aktivieren, werden bestätigte IP-Adressen "
                    "an stat.ripe.net, rdap.org und das von rdap.org bestimmte "
                    "autoritative Regionalregister (z. B. RIPE, ARIN, APNIC, LACNIC "
                    "oder AFRINIC) gesendet. Diese Stellen können die Anfragen "
                    "protokollieren. Möchten Sie das ausdrücklich erlauben?"
                ),
                parent=self.root,
            )
            if not confirmed:
                self.enrichment_enabled.set(False)
                return

        updated_enrichment = replace(self.config.enrichment, enabled=requested)
        updated_config = replace(self.config, enrichment=updated_enrichment)
        try:
            save_config(self.config_path, updated_config)
        except (ConfigError, OSError) as exc:
            self.enrichment_enabled.set(previous)
            messagebox.showerror("Einstellung nicht gespeichert", str(exc), parent=self.root)
            return
        self.config = updated_config

    def _start_scan(self) -> None:
        if self.running:
            return
        if not self.config.targets:
            messagebox.showinfo(
                "Kein Ziel",
                "Fügen Sie zuerst mindestens einen Magnet-Link hinzu.",
                parent=self.root,
            )
            return
        if not messagebox.askyesno(
            "Öffentlich sichtbaren Netzwerktest starten?",
            (
                "Dieser Prüflauf ist nicht anonym: DHT-Knoten, konfigurierte Tracker "
                "und geprüfte Peer-Endpunkte sehen Ihre öffentliche Quell-IP und den "
                "abgefragten Infohash und können dies protokollieren. Zur Endpunktsuche "
                "erhalten Tracker kurz eine STARTED-Meldung mit unbekannter Restmenge und "
                "einem nicht geöffneten Port; unmittelbar danach sendet das Programm "
                "STOPPED. Tracker können die Messinstanz in dieser kurzen Zeit als Peer "
                "führen. Das Programm meldet keinen Upload. Nach einem passenden Handshake "
                "bleibt die direkte Verbindung bis zu einer "
                "Minute offen und das Programm meldet Interesse, fordert aber keine Datei- "
                "oder Metadatenblöcke an und lädt nichts hoch. Möchten Sie den Prüflauf "
                "trotzdem starten?"
            ),
            parent=self.root,
        ):
            return
        try:
            save_config(self.config_path, self.config)
        except (ConfigError, OSError) as exc:
            messagebox.showerror("Konfiguration nicht gespeichert", str(exc), parent=self.root)
            return

        self._run_output_dir = None
        self.running = True
        self.cancel_event.clear()
        config_snapshot = self.config
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        for control in self.config_controls:
            control.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self.progress.start(10)
        self.result_tree.delete(*self.result_tree.get_children())
        self._discard_pending_progress()
        self._set_status("Prüflauf wird vorbereitet …", state="running")
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(config_snapshot,),
            name="observer-scan",
            daemon=False,
        )
        self.scan_thread.start()

    def _scan_worker(self, config_snapshot: AppConfig) -> None:
        try:
            from .monitor import run_scan

            result = run_scan(
                config_snapshot,
                self.data_dir,
                progress=self._publish_progress,
                cancel_event=self.cancel_event,
                reports_ready=self._publish_reports_ready,
            )
        except Exception as exc:
            logging.getLogger("bittorrent_beobachter").exception("GUI-Prüflauf fehlgeschlagen")
            self.events.put_nowait(("error", f"{type(exc).__name__}: {exc}"))
        else:
            self.events.put_nowait(("done", result))

    def _publish_progress(self, message: str) -> None:
        """Ersetzt einen alten Fortschritt atomar durch den neuesten Text."""

        with self._progress_event_lock:
            with suppress(queue.Empty):
                self.progress_events.get_nowait()
            self.progress_events.put_nowait(str(message))

    def _publish_reports_ready(self, output_dir: Path, result_count: int) -> None:
        self.events.put_nowait(("reports_ready", (Path(output_dir), int(result_count))))

    def _discard_pending_progress(self) -> None:
        """Entfernt den aktuell vorgemerkten Fortschritt, sofern vorhanden."""

        with suppress(queue.Empty):
            self.progress_events.get_nowait()

    def _poll_events(self) -> None:
        terminal_event_seen = False
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "error":
                terminal_event_seen = True
                run_output_dir = self._run_output_dir
                self._finish_running_state(current_run_only=True)
                if not self.close_requested:
                    messagebox.showerror("Prüflauf fehlgeschlagen", str(payload), parent=self.root)
                    if run_output_dir is not None and run_output_dir.is_dir():
                        self._set_status(
                            "Der Prüflauf endete mit einem Fehler. Bereits gespeicherte "
                            "Teilergebnisse sind im Ergebnisordner verwendbar.",
                            state="error",
                        )
                    else:
                        self._set_status(
                            "Der Prüflauf ist fehlgeschlagen. Details stehen im Protokoll.",
                            state="error",
                        )
            elif event == "done":
                terminal_event_seen = True
                if self.close_requested:
                    self._finish_running_state()
                else:
                    self._show_result(payload)
            elif event == "reports_ready":
                output_dir, result_count = payload
                self.latest_output_dir = Path(output_dir)
                self._run_output_dir = self.latest_output_dir
                self.open_button.configure(state="normal")
                if not self.close_requested:
                    self._set_status(
                        f"{result_count} positive Befund(e) sind bereits fertig gespeichert. "
                        "Der Prüflauf sucht weiter.",
                        state="running",
                    )

        try:
            latest_progress = self.progress_events.get_nowait()
        except queue.Empty:
            latest_progress = None
        if (
            latest_progress is not None
            and not terminal_event_seen
            and self.running
            and not self.close_requested
        ):
            self._set_status(latest_progress, state="running")
        if self.close_requested and not self.running:
            self.root.destroy()
            return
        self.root.after(150, self._poll_events)

    def _finish_running_state(self, *, current_run_only: bool = False) -> None:
        self.running = False
        self.scan_thread = None
        self.progress.stop()
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        for control in self.config_controls:
            control.configure(state="normal")
        output_dir = self._run_output_dir if current_run_only else self.latest_output_dir
        output_available = output_dir is not None and output_dir.is_dir()
        self.open_button.configure(state="normal" if output_available else "disabled")

    def _cancel_scan(self) -> None:
        if not self.running or self.cancel_event.is_set():
            return
        self.cancel_event.set()
        self.cancel_button.configure(state="disabled")
        self._set_status(
            "Prüflauf wird kontrolliert abgebrochen; gefundene Ergebnisse "
            "werden fertig gespeichert.",
            state="warning",
        )

    def _request_close(self) -> None:
        if not self.running:
            self.root.destroy()
            return
        if messagebox.askyesno(
            "Prüflauf noch aktiv",
            (
                "Der laufende Prüflauf wird kontrolliert abgebrochen. Bereits gefundene "
                "Ergebnisse werden fertig gespeichert. Soll das Fenster danach schließen?"
            ),
            parent=self.root,
        ):
            self.close_requested = True
            self._cancel_scan()

    def _show_result(self, result: ScanResult) -> None:
        self._finish_running_state()
        displayed_records = 0
        records = iter(_iter_positive_evidence(result))
        try:
            for record in islice(records, MAX_GUI_RESULT_ROWS):
                displayed_records += 1
                handshake = record.handshake
                candidate = handshake.candidate
                network = record.enrichment.holder or record.enrichment.rdap_name or "unbekannt"
                if record.vpn.status == "known_vpn":
                    classification = f"VPN: {record.vpn.provider or 'bekannt'}"
                    row_tag = "known_vpn"
                else:
                    classification = "VPN unbekannt"
                    row_tag = "availability"
                endpoint = (
                    f"[{candidate.ip}]:{candidate.port}"
                    if ":" in candidate.ip
                    else f"{candidate.ip}:{candidate.port}"
                )
                self.result_tree.insert(
                    "",
                    END,
                    tags=(row_tag,),
                    values=(
                        handshake.completed_at_utc or handshake.attempted_at_utc,
                        candidate.target_label,
                        endpoint,
                        "Teile gemeldet; Anfragen erlaubt",
                        network,
                        classification,
                    ),
                )
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            result.errors.append(f"Laufdaten konnten nicht angezeigt werden: {exc}")
        finally:
            close_records = getattr(records, "close", None)
            if callable(close_records):
                close_records()

        if result.report_paths:
            self.latest_output_dir = result.report_paths[0].parent
            self._run_output_dir = self.latest_output_dir
            self.open_button.configure(state="normal")
        notice_count = len(result.notices)
        if notice_count == 1:
            notice_suffix = " 1 technischer Laufhinweis steht im Bericht."
        elif notice_count > 1:
            notice_suffix = f" {notice_count} technische Laufhinweise stehen im Bericht."
        else:
            notice_suffix = ""
        positive_total = max(result.offering_count, displayed_records)
        if positive_total > displayed_records:
            display_suffix = (
                f" Die Tabelle zeigt {displayed_records} von {positive_total} positiven "
                "Befunden; die Berichte enthalten alle."
            )
        elif displayed_records:
            display_suffix = f" Die Tabelle zeigt alle {displayed_records} positiven Befunde."
        else:
            display_suffix = " Die Ergebnistabelle enthält keine positiven Befunde."
        target_suffix = _target_status_text(result)
        if result.cancelled:
            self._set_status(
                f"Kontrolliert abgebrochen: {result.total_candidate_count} Kandidaten gefunden, "
                f"{result.total_handshake_count} direkt geprüft und {result.offering_count} "
                "positive Befunde fertig gespeichert."
                f"{display_suffix}{target_suffix}{notice_suffix}",
                state="warning",
            )
        elif result.total_candidate_count == 0 and not result.errors:
            self._set_status(
                "Fertig. Zurzeit wurden keine antwortenden Endpunkte gefunden. "
                f"Das ist kein Programmfehler.{display_suffix}{target_suffix}{notice_suffix}",
                state="ready",
            )
        else:
            self._set_status(
                f"Fertig: {result.total_candidate_count} Kandidaten gefunden, "
                f"{result.total_handshake_count} direkt geprüft, "
                f"{result.confirmed_count} bestätigte Handshakes, "
                f"{result.offering_count} positive Verfügbarkeitsprüfungen, "
                f"{result.known_vpn_count} bekannte VPN-Befunde. "
                f"{len(result.errors)} Hinweis(e)/Fehler."
                f"{display_suffix}{target_suffix}{notice_suffix}",
                state="warning" if result.errors else "success",
            )
        if result.errors:
            messagebox.showwarning(
                "Prüflauf mit Hinweisen",
                "Der Prüflauf wurde beendet, dabei gab es Teilprobleme oder "
                "Warnungen:\n\n" + "\n".join(result.errors[:8]),
                parent=self.root,
            )

    def _open_output(self) -> None:
        if self.latest_output_dir is None or not self.latest_output_dir.exists():
            messagebox.showinfo(
                "Kein Ergebnisordner", "Es liegt noch kein Ergebnis vor.", parent=self.root
            )
            return
        try:
            open_directory(self.latest_output_dir)
        except OSError as exc:
            messagebox.showerror("Ergebnisordner nicht geöffnet", str(exc), parent=self.root)


def launch_gui(
    config_path: Path,
    data_dir: Path,
    *,
    startup_warning: str | None = None,
) -> int:
    """Startet das Hauptfenster und gibt nach dessen Schließen Erfolg zurück."""
    root = Tk()
    ObserverApp(
        root,
        config_path,
        data_dir,
        startup_warning=startup_warning,
    )
    root.mainloop()
    return 0


def verify_gui_runtime() -> int:
    """Baut die echte Oberfläche unsichtbar auf und beendet sie wieder."""

    with tempfile.TemporaryDirectory(prefix="afdleakercatcher-gui-smoke-") as temp_name:
        smoke_root = Path(temp_name)
        root = Tk()
        try:
            root.withdraw()
            ObserverApp(
                root,
                smoke_root / "config.json",
                smoke_root / "data",
            )
            root.update_idletasks()
            if not root.tk.call("info", "patchlevel"):
                raise RuntimeError("Tcl/Tk meldet keine gueltige Laufzeitversion.")
        finally:
            root.destroy()
    return 0
