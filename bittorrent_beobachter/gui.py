"""Einfache Desktop-Oberfläche für Konfiguration, Prüflauf und Ergebnisse."""

from __future__ import annotations

import logging
import queue
import sqlite3
import tempfile
import threading
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    BooleanVar,
    Canvas,
    PhotoImage,
    StringVar,
    TclError,
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
MAX_GUI_ACTIVITY_ROWS = 120
MAX_PENDING_ACTIVITY_EVENTS = 240
ACTIVITY_DRAIN_BATCH_SIZE = 40
MAX_ACTIVITY_DETAIL_LENGTH = 320
TARGET_TABLE_ROWS = 2
ACTIVITY_TABLE_ROWS = 4
RESULT_TABLE_ROWS = 4
RESULT_ILLUSTRATION_MIN_VIEWPORT_WIDTH = 940
RESULT_ILLUSTRATION_SUBSAMPLE = 7
RESULT_ILLUSTRATION_PATH = Path(__file__).resolve().parent / "assets" / "leaker_chase.png"
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
    "background": "#11161D",
    "surface": "#181F27",
    "surface_raised": "#202A34",
    "surface_active": "#293641",
    "accent_surface": "#203840",
    "positive_surface": "#1B2C28",
    "warning_surface": "#2C2921",
    "text": "#E7EDF3",
    "muted": "#AAB5BF",
    "accent": "#78AFC1",
    "success": "#91C7AF",
    "warning": "#D7BD7B",
    "danger": "#D99A9A",
    "border": "#465461",
}
GUIStatusState = Literal["ready", "running", "success", "warning", "error"]
STATUS_STYLE_BY_STATE: dict[GUIStatusState, str] = {
    "ready": "Status.Ready.TLabel",
    "running": "Status.Running.TLabel",
    "success": "Status.Success.TLabel",
    "warning": "Status.Warning.TLabel",
    "error": "Status.Error.TLabel",
}


@dataclass(frozen=True, slots=True)
class ActivityEvent:
    """Eine echte Fortschrittsmeldung in kompakter, anzeigbarer Form."""

    recorded_at_utc: str
    context: str
    operation: str
    status: str
    detail: str


def _progress_semantics_without_target(message: str) -> tuple[str | None, str]:
    """Trennt nur bekannte Zielplatzhalter von ihrer festen Meldungsschablone."""

    candidate_tail = " neue eindeutige kandidat(en) dauerhaft gespeichert."
    lowered = message.casefold()
    if lowered.endswith(candidate_tail):
        stem = message[: -len(candidate_tail)]
        boundary = stem.rfind(": ")
        if boundary >= 0:
            target = stem[:boundary].strip()
            candidate_count = stem[boundary + 2 :]
            if target and candidate_count.isdecimal():
                return target, f"<Ziel>: {candidate_count}{message[len(stem) :]}"

    patterns = (
        ("DHT-Runde fuer ", " hatte "),
        ("DHT-Suche fuer ", ": "),
        ("Tracker-Runde fuer ", " hatte "),
        ("Tracker-Suche fuer ", ": "),
        ("Peer-Suche fuer ", " nach "),
        ("Peer-Suche ", ": Runde "),
    )
    for prefix, separator in patterns:
        if not message.startswith(prefix):
            continue
        remainder = message[len(prefix) :]
        boundary = remainder.rfind(separator)
        if boundary < 0:
            break
        target = remainder[:boundary].strip()
        if not target:
            break
        semantics = f"{prefix}<Ziel>{remainder[boundary:]}"
        return target, semantics

    return None, message


def _activity_event_from_progress(
    message: object,
    *,
    recorded_at: datetime | None = None,
) -> ActivityEvent:
    """Ordnet eine echte Monitor-Meldung ohne erfundene Netzwerkdaten ein."""

    normalized_message = " ".join(str(message).split())
    if not normalized_message:
        normalized_message = "Leere Fortschrittsmeldung"
    target, semantics = _progress_semantics_without_target(normalized_message)
    detail = normalized_message
    if len(detail) > MAX_ACTIVITY_DETAIL_LENGTH:
        detail = f"{detail[: MAX_ACTIVITY_DETAIL_LENGTH - 1]}…"

    moment = recorded_at or datetime.now(UTC)
    if moment.tzinfo is None:
        raise ValueError("Der Aktivitaetszeitpunkt muss eine Zeitzone enthalten.")
    recorded_at_utc = moment.astimezone(UTC).strftime("%H:%M:%S")

    lowered = semantics.casefold()
    if lowered.startswith(("dht-", "bootstrap-")):
        source = "DHT"
        operation = "Bootstrap" if lowered.startswith("bootstrap-") else "Endpunktsuche"
    elif lowered.startswith("tracker-"):
        source = "Tracker"
        operation = "Endpunktsuche"
    elif lowered.startswith("peer-suche"):
        source = "Peer-Suche"
        operation = "Endpunktsuche"
    elif "neue eindeutige kandidat" in lowered:
        source = "Discovery"
        operation = "Kandidaten speichern"
    elif "peer-pruefung" in lowered or "kandidatenpruefung" in lowered:
        source = "Peer"
        operation = "Direktprüfung"
    elif "netzregistrierungsabfrage" in lowered or "netzauskunft" in lowered:
        source = "Öffentliche Netzauskunft"
        operation = "Netzauskunft"
    elif any(
        term in lowered
        for term in ("journalisierte", "laufdatenbank", "wiederhergestellt", "legacy-lauf")
    ):
        source = "Laufdaten"
        operation = "Wiederherstellung"
    elif any(term in lowered for term in ("evidenz", "ergebnisordner", "berichte")):
        source = "Evidenz"
        operation = "Speichern"
    elif "prueflauf" in lowered:
        source = "Lauf"
        operation = "Steuerung"
    else:
        source = "System"
        operation = "Status"

    if any(
        term in lowered
        for term in ("fehlerabschluss", "fehlgeschlagen", "netzwerkfehler", "scheiterte")
    ) or ("schlug" in lowered and "fehl" in lowered):
        status = "Fehler"
    elif any(
        term in lowered
        for term in (
            "teilmeldung",
            "teilproblem",
            "unvollstaendig",
            "nicht erreichbar",
            "nicht automatisch fertiggestellt",
            "nicht mehr verfuegbar",
            "nicht migriert",
            "warnung",
        )
    ):
        status = "Hinweis"
    elif any(term in lowered for term in ("abgebrochen", "abbruch", "kontrolliert beendet")):
        status = "Abbruch"
    elif any(
        term in lowered
        for term in (
            "abgeschlossen",
            "dauerhaft geprueft",
            "dauerhaft geprüft",
            "gespeichert",
            "bereitgestellt",
            "beendet",
            "uebernommen",
        )
    ):
        status = "OK"
    elif any(term in lowered for term in ("gestartet", "laeuft", "läuft", "abfrage", "eingeplant")):
        status = "Aktiv"
    else:
        status = "Info"

    context = source if target is None else f"{source} · {target}"
    return ActivityEvent(
        recorded_at_utc=recorded_at_utc,
        context=context,
        operation=operation,
        status=status,
        detail=detail,
    )


def _activity_view_is_near_bottom(view: object, *, has_rows: bool) -> bool:
    """Entscheidet defensiv, ob neue Zeilen sichtbar nachgefuehrt werden duerfen."""

    if not has_rows:
        return True
    try:
        _first, last = view  # type: ignore[misc]
        return float(last) >= 0.98
    except (TypeError, ValueError):
        return False


def _should_show_result_illustration(viewport_width: int) -> bool:
    """Zeigt die Dekoration nur, wenn sie der Ergebnistabelle keinen Platz nimmt."""

    if (
        isinstance(viewport_width, bool)
        or not isinstance(viewport_width, int)
        or viewport_width <= 0
    ):
        raise ValueError("Die Fensterbreite muss eine positive Ganzzahl sein.")
    return viewport_width >= RESULT_ILLUSTRATION_MIN_VIEWPORT_WIDTH


def _load_result_illustration(root: Tk) -> PhotoImage | None:
    """Laedt die optionale Dekoration; ein Fehler darf die GUI nicht blockieren."""

    try:
        source = PhotoImage(master=root, file=str(RESULT_ILLUSTRATION_PATH))
        return source.subsample(
            RESULT_ILLUSTRATION_SUBSAMPLE,
            RESULT_ILLUSTRATION_SUBSAMPLE,
        )
    except (OSError, TclError) as exc:
        logging.getLogger("bittorrent_beobachter").warning(
            "Dekoratives Ergebnisbild konnte nicht geladen werden: %s",
            exc,
        )
        return None


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
    """Konfiguriert ein dezentes, plattformunabhaengiges Dark-Theme."""

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
        font=("TkDefaultFont", 18, "bold"),
    )
    style.configure(
        "Kicker.TLabel",
        background=colors["surface_raised"],
        foreground=colors["muted"],
        font=("TkDefaultFont", 9, "bold"),
    )
    style.configure(
        "HeroAccent.TLabel",
        background=colors["surface_raised"],
        foreground=colors["muted"],
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
        ("Ready", colors["muted"]),
        ("Running", colors["accent"]),
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
        foreground=colors["text"],
        font=("TkDefaultFont", 10, "bold"),
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
        background=colors["accent_surface"],
        foreground=colors["text"],
        bordercolor=colors["accent"],
    )
    style.map(
        "Accent.TButton",
        background=[
            ("disabled", colors["surface_raised"]),
            ("pressed", colors["surface_active"]),
            ("active", colors["surface_active"]),
        ],
        foreground=[("disabled", colors["muted"]), ("!disabled", colors["text"])],
        bordercolor=[("disabled", colors["border"]), ("focus", colors["accent"])],
    )
    style.configure(
        "Danger.TButton",
        background=colors["surface_raised"],
        foreground=colors["danger"],
        bordercolor=colors["danger"],
    )
    style.map(
        "Danger.TButton",
        background=[
            ("disabled", colors["surface_raised"]),
            ("pressed", colors["surface_active"]),
            ("active", colors["surface_active"]),
        ],
        foreground=[("disabled", colors["muted"]), ("!disabled", colors["danger"])],
        bordercolor=[("disabled", colors["border"]), ("focus", colors["danger"])],
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
        background=[("selected", colors["accent_surface"])],
        foreground=[("selected", colors["text"])],
    )
    style.configure(
        "Treeview.Heading",
        background=colors["surface_raised"],
        foreground=colors["text"],
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
        foreground=[("active", colors["text"])],
    )
    style.configure(
        "Activity.Treeview",
        background=colors["surface"],
        fieldbackground=colors["surface"],
        foreground=colors["text"],
        bordercolor=colors["border"],
        lightcolor=colors["border"],
        darkcolor=colors["border"],
        rowheight=23,
        font=("TkFixedFont", 9),
    )
    style.map(
        "Activity.Treeview",
        background=[("selected", colors["accent_surface"])],
        foreground=[("selected", colors["text"])],
    )
    style.configure(
        "Activity.Treeview.Heading",
        background=colors["surface_raised"],
        foreground=colors["text"],
        bordercolor=colors["border"],
        lightcolor=colors["border"],
        darkcolor=colors["border"],
        relief="flat",
        padding=(7, 5),
        font=("TkDefaultFont", 9, "bold"),
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
        # Nur die einmaligen Abschlussereignisse bleiben in der unbegrenzten Queue.
        # Fortschritt und Zwischenberichte werden getrennt begrenzt zusammengefuehrt.
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.progress_events: queue.Queue[str] = queue.Queue(maxsize=1)
        self.report_events: queue.Queue[tuple[Path, int]] = queue.Queue(maxsize=1)
        self.activity_events: queue.Queue[ActivityEvent] = queue.Queue(
            maxsize=MAX_PENDING_ACTIVITY_EVENTS
        )
        self._progress_event_lock = threading.Lock()
        self._report_event_lock = threading.Lock()
        self._activity_event_lock = threading.Lock()
        self.running = False
        self.scan_thread: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.close_requested = False
        self.latest_output_dir: Path | None = None
        self._run_output_dir: Path | None = None
        self._result_illustration_image: PhotoImage | None = None
        self._result_illustration_panel: ttk.Frame | None = None

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

        outer = ttk.Frame(canvas, padding=10)
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
            self._update_result_illustration_visibility(event.width)

        outer.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_content)

        hero = ttk.Frame(outer, style="Hero.TFrame", padding=(12, 8))
        hero.pack(fill=X, pady=(0, 6))
        ttk.Label(
            hero,
            text=f"Netzwerkprüfung  ·  Version {VERSION}",
            style="Kicker.TLabel",
        ).pack(anchor="w")
        ttk.Label(hero, text=APP_NAME, style="Hero.TLabel").pack(anchor="w", pady=(2, 2))
        remember_label(
            ttk.Label(
                hero,
                text=(
                    "Inhaltsfreie Verfügbarkeitsprüfung. Keine Datei- oder "
                    "Metadatenblöcke werden angefordert, heruntergeladen oder hochgeladen."
                ),
                style="HeroAccent.TLabel",
                wraplength=950,
            )
        ).pack(anchor="w", fill=X)

        target_box = ttk.LabelFrame(
            outer,
            text="Ziele für manuelle Prüfläufe",
            padding=8,
        )
        target_box.pack(fill=X, pady=(0, 6))
        target_table = ttk.Frame(target_box, style="Panel.TFrame")
        target_table.pack(fill=X, expand=True)
        target_table.columnconfigure(0, weight=1)
        target_table.rowconfigure(0, weight=1)
        self.target_tree = ttk.Treeview(
            target_table,
            columns=("label", "hash"),
            show="headings",
            height=TARGET_TABLE_ROWS,
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
        target_vertical_scrollbar = ttk.Scrollbar(
            target_table,
            orient="vertical",
            command=self.target_tree.yview,
        )
        self.target_tree.configure(
            xscrollcommand=target_scrollbar.set,
            yscrollcommand=target_vertical_scrollbar.set,
        )
        self.target_tree.grid(row=0, column=0, sticky="nsew")
        target_vertical_scrollbar.grid(row=0, column=1, sticky="ns")
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
        self.enrichment_enabled = BooleanVar(value=self.config.enrichment.enabled)
        self.enrichment_checkbox = ttk.Checkbutton(
            target_box,
            text="Optionale Netzauskunft für bestätigte IP-Adressen (RDAP / RIPEstat)",
            variable=self.enrichment_enabled,
            command=self._toggle_network_enrichment,
        )
        self.enrichment_checkbox.pack(anchor="w", pady=(6, 0))

        action_bar = ttk.Frame(outer)
        action_bar.pack(fill=X, pady=(0, 6))
        action_buttons = ttk.Frame(action_bar)
        action_buttons.pack(side=LEFT)
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
        self.progress.pack(side=RIGHT, padx=(12, 0))
        self.config_controls = (
            self.add_target_button,
            self.remove_target_button,
            self.settings_button,
            self.enrichment_checkbox,
        )

        status_panel = ttk.Frame(
            outer,
            style="StatusPanel.TFrame",
            padding=(8, 6),
        )
        status_panel.pack(fill=X, pady=(0, 6))
        ttk.Label(
            status_panel,
            text="Status",
            style="StatusCaption.TLabel",
        ).pack(side=LEFT)
        self.status_text = StringVar(value="Bereit. Fügen Sie einen Magnet-Link hinzu.")
        self.status_label = remember_label(
            ttk.Label(
                status_panel,
                textvariable=self.status_text,
                style=STATUS_STYLE_BY_STATE["ready"],
                wraplength=930,
            )
        )
        self.status_label.pack(side=LEFT, fill=X, expand=True, padx=(8, 0))

        activity_box = ttk.LabelFrame(
            outer,
            text="Technische Laufaktivität · echte Meldungen",
            padding=8,
        )
        activity_box.pack(fill=X, pady=(0, 6))
        activity_table = ttk.Frame(activity_box, style="Panel.TFrame")
        activity_table.pack(fill=X, expand=True)
        activity_table.columnconfigure(0, weight=1)
        activity_table.rowconfigure(0, weight=1)
        self.activity_tree = ttk.Treeview(
            activity_table,
            columns=("time", "context", "operation", "status", "detail"),
            show="headings",
            height=ACTIVITY_TABLE_ROWS,
            selectmode="browse",
            style="Activity.Treeview",
        )
        activity_headings = {
            "time": "UTC",
            "context": "Quelle / Ziel",
            "operation": "Vorgang",
            "status": "Status",
            "detail": "Details",
        }
        activity_widths = {
            "time": (80, 74, False),
            "context": (245, 150, True),
            "operation": (145, 115, False),
            "status": (82, 72, False),
            "detail": (560, 260, True),
        }
        for name, title in activity_headings.items():
            width, minimum, stretch = activity_widths[name]
            self.activity_tree.heading(name, text=title)
            self.activity_tree.column(
                name,
                width=width,
                minwidth=minimum,
                anchor="w",
                stretch=stretch,
            )
        activity_vertical_scrollbar = ttk.Scrollbar(
            activity_table,
            orient="vertical",
            command=self.activity_tree.yview,
        )
        activity_horizontal_scrollbar = ttk.Scrollbar(
            activity_table,
            orient="horizontal",
            command=self.activity_tree.xview,
        )
        self.activity_tree.configure(
            yscrollcommand=activity_vertical_scrollbar.set,
            xscrollcommand=activity_horizontal_scrollbar.set,
        )
        self.activity_tree.grid(row=0, column=0, sticky="nsew")
        activity_vertical_scrollbar.grid(row=0, column=1, sticky="ns")
        activity_horizontal_scrollbar.grid(row=1, column=0, sticky="ew")

        result_box = ttk.LabelFrame(outer, text="Letzter Prüflauf", padding=8)
        result_box.pack(fill=BOTH, expand=True)
        result_box.columnconfigure(0, weight=1)
        result_box.rowconfigure(0, weight=1)
        self.result_tree = ttk.Treeview(
            result_box,
            columns=("time", "target", "endpoint", "status", "network", "class"),
            show="headings",
            height=RESULT_TABLE_ROWS,
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
            foreground=CYBER_COLORS["text"],
        )
        self.result_tree.tag_configure(
            "known_vpn",
            background=CYBER_COLORS["warning_surface"],
            foreground=CYBER_COLORS["warning"],
        )
        self.result_tree.grid(row=0, column=0, sticky="nsew")
        vertical_scrollbar.grid(row=0, column=1, sticky="ns")
        horizontal_scrollbar.grid(row=1, column=0, sticky="ew")

        self._result_illustration_image = _load_result_illustration(self.root)
        if self._result_illustration_image is not None:
            illustration_panel = ttk.Frame(result_box, style="Panel.TFrame", padding=(8, 4))
            ttk.Label(
                illustration_panel,
                image=self._result_illustration_image,
                style="Panel.TLabel",
            ).pack()
            illustration_panel.grid(
                row=0,
                column=2,
                rowspan=2,
                sticky="se",
                padx=(10, 0),
            )
            self._result_illustration_panel = illustration_panel

        result_footer = remember_label(
            ttk.Label(
                result_box,
                text=(
                    "Keine automatische Anzeige · Kein automatischer E-Mail-Versand · "
                    "Bekannte VPN-Endpunkte werden gekennzeichnet und gesondert berichtet"
                ),
                style="Muted.Panel.TLabel",
            )
        )
        result_footer.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self.root.bind("<MouseWheel>", self._scroll_main_view, add="+")
        self.root.bind("<Button-4>", self._scroll_main_view, add="+")
        self.root.bind("<Button-5>", self._scroll_main_view, add="+")

    def _scroll_main_view(self, event: Any) -> str | None:
        if event.widget in (self.target_tree, self.result_tree, self.activity_tree):
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

    def _update_result_illustration_visibility(self, viewport_width: int) -> None:
        """Blendet die Dekoration aus, bevor sie Nutzflaeche verdraengt."""

        panel = getattr(self, "_result_illustration_panel", None)
        if panel is None:
            return
        if _should_show_result_illustration(viewport_width):
            panel.grid()
        else:
            panel.grid_remove()

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
        self.activity_tree.delete(*self.activity_tree.get_children())
        self._discard_pending_progress()
        self._discard_pending_report()
        self._discard_pending_activity()
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
        """Haelt den neuesten Status sowie eine begrenzte echte Aktivitaetshistorie."""

        activity_event = _activity_event_from_progress(message)
        with self._activity_event_lock:
            while True:
                try:
                    self.activity_events.put_nowait(activity_event)
                    break
                except queue.Full:
                    with suppress(queue.Empty):
                        self.activity_events.get_nowait()
        with self._progress_event_lock:
            with suppress(queue.Empty):
                self.progress_events.get_nowait()
            self.progress_events.put_nowait(str(message))

    def _publish_reports_ready(self, output_dir: Path, result_count: int) -> None:
        """Haelt atomar nur den neuesten Stand der inkrementellen Berichte."""

        report_event = (Path(output_dir), int(result_count))
        with self._report_event_lock:
            with suppress(queue.Empty):
                self.report_events.get_nowait()
            self.report_events.put_nowait(report_event)

    def _discard_pending_progress(self) -> None:
        """Entfernt den aktuell vorgemerkten Fortschritt, sofern vorhanden."""

        with suppress(queue.Empty):
            self.progress_events.get_nowait()

    def _discard_pending_report(self) -> None:
        """Entfernt einen noch nicht angezeigten Zwischenstand des vorigen Laufs."""

        with self._report_event_lock, suppress(queue.Empty):
            self.report_events.get_nowait()

    def _discard_pending_activity(self) -> None:
        """Leert noch nicht angezeigte Aktivitaetsmeldungen eines vorigen Laufs."""

        with self._activity_event_lock:
            while True:
                try:
                    self.activity_events.get_nowait()
                except queue.Empty:
                    break

    def _append_activity_event(self, event: ActivityEvent) -> None:
        """Fuegt eine echte Meldung ein und respektiert die Leseposition."""

        children_before = self.activity_tree.get_children()
        keep_at_bottom = _activity_view_is_near_bottom(
            self.activity_tree.yview(),
            has_rows=bool(children_before),
        )
        self.activity_tree.insert(
            "",
            END,
            values=(
                event.recorded_at_utc,
                event.context,
                event.operation,
                event.status,
                event.detail,
            ),
        )
        children_after = self.activity_tree.get_children()
        overflow = len(children_after) - MAX_GUI_ACTIVITY_ROWS
        if overflow > 0:
            self.activity_tree.delete(*children_after[:overflow])
        if keep_at_bottom:
            self.activity_tree.yview_moveto(1.0)

    def _drain_activity_events(self) -> None:
        """Uebernimmt begrenzt viele Meldungen pro UI-Takt, damit Tk responsiv bleibt."""

        for _index in range(ACTIVITY_DRAIN_BATCH_SIZE):
            try:
                event = self.activity_events.get_nowait()
            except queue.Empty:
                break
            self._append_activity_event(event)

    def _poll_events(self) -> None:
        terminal_event_seen = False
        try:
            latest_report = self.report_events.get_nowait()
        except queue.Empty:
            latest_report = None
        if latest_report is not None:
            output_dir, _result_count = latest_report
            self.latest_output_dir = Path(output_dir)
            self._run_output_dir = self.latest_output_dir
            self.open_button.configure(state="normal")

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

        if (
            latest_report is not None
            and not terminal_event_seen
            and self.running
            and not self.close_requested
        ):
            _output_dir, result_count = latest_report
            self._set_status(
                f"{result_count} positive Befund(e) sind bereits fertig gespeichert. "
                "Der Prüflauf sucht weiter.",
                state="running",
            )

        self._drain_activity_events()

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
