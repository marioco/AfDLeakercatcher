"""Einfache Desktop-Oberfläche für Konfiguration, Prüflauf und Ergebnisse."""

from __future__ import annotations

import logging
import queue
import sqlite3
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
    StringVar,
    Tk,
    Toplevel,
    X,
    messagebox,
    simpledialog,
    ttk,
)
from typing import Any

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


class SettingsDialog(Toplevel):
    """Kleiner Dialog für optionale Absender- und Empfängerangaben."""

    def __init__(self, parent: Tk, settings: ReportingSettings) -> None:
        super().__init__(parent)
        self.title("Angaben für die Entwürfe")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: ReportingSettings | None = None
        self.settings = settings

        self.name = StringVar(value=settings.reporter_name)
        self.email = StringVar(value=settings.reporter_email)
        self.recipient = StringVar(value=settings.police_recipient)

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=BOTH, expand=True)
        fields = (
            ("Name der meldenden Person/Organisation", self.name),
            ("Absender-E-Mail (optional)", self.email),
            ("Empfänger-E-Mail der Polizei (optional)", self.recipient),
        )
        for row, (label, variable) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row * 2, column=0, sticky="w", pady=(0, 3))
            ttk.Entry(frame, textvariable=variable, width=60).grid(
                row=row * 2 + 1, column=0, sticky="ew", pady=(0, 10)
            )

        ttk.Label(
            frame,
            text=(
                "Die Anwendung versendet nichts. Leere Empfängerfelder können später "
                "im E-Mail-Programm ergänzt werden."
            ),
            wraplength=480,
        ).grid(row=6, column=0, sticky="w", pady=(2, 12))
        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, sticky="e")
        ttk.Button(buttons, text="Abbrechen", command=self.destroy).pack(side=LEFT, padx=(0, 8))
        ttk.Button(buttons, text="Speichern", command=self._save).pack(side=RIGHT)
        self.bind("<Escape>", lambda _event: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)
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

    def __init__(self, root: Tk, config_path: Path, data_dir: Path) -> None:
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
        self.close_requested = False
        self.latest_output_dir: Path | None = None
        self.config = self._load_initial_config()

        root.title(f"{APP_NAME} {VERSION}")
        root.geometry("1040x700")
        root.minsize(880, 600)
        self._build_ui()
        self._refresh_targets()
        self.root.protocol("WM_DELETE_WINDOW", self._request_close)
        self._poll_events()

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
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill=BOTH, expand=True)

        ttk.Label(outer, text=APP_NAME, font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text=(
                "Inhaltsfreie Verfügbarkeitsprüfung: Es werden keine Datei- oder "
                "Metadatenblöcke angefordert, heruntergeladen oder hochgeladen."
            ),
            foreground="#205493",
            wraplength=950,
        ).pack(anchor="w", pady=(4, 12))

        notice = ttk.LabelFrame(outer, text="Wichtige Aussagegrenze", padding=10)
        notice.pack(fill=X, pady=(0, 12))
        ttk.Label(
            notice,
            text=(
                "Ein positiver Befund bedeutet: Der Endpunkt bestätigte den Infohash, "
                "meldete verfügbare Teile und erlaubte während der einminütigen Verbindung "
                "das Stellen von Datenanfragen. Es werden keine Datenblöcke angefordert. "
                "Der Befund identifiziert keine Person und beweist keinen tatsächlichen "
                "Upload oder eine Straftat. Jede Anzeige muss vor dem Versand geprüft werden."
            ),
            wraplength=930,
        ).pack(anchor="w")

        target_box = ttk.LabelFrame(outer, text="Ziele für manuelle Prüfläufe", padding=10)
        target_box.pack(fill=X, pady=(0, 12))
        ttk.Label(
            target_box,
            text=(
                "Die beiden Voreinstellungen bestätigen keinen Inhalt. Ein Prüflauf "
                "beginnt erst nach „Jetzt prüfen“ und Ihrer ausdrücklichen Bestätigung."
            ),
            foreground="#555555",
            wraplength=930,
        ).pack(anchor="w", fill=X, pady=(0, 8))
        self.target_tree = ttk.Treeview(
            target_box,
            columns=("label", "hash"),
            show="headings",
            height=4,
            selectmode="browse",
        )
        self.target_tree.heading("label", text="Bezeichnung")
        self.target_tree.heading("hash", text="Infohash")
        self.target_tree.column("label", width=340, anchor="w")
        self.target_tree.column("hash", width=430, anchor="w")
        self.target_tree.pack(side=LEFT, fill=X, expand=True)
        target_buttons = ttk.Frame(target_box)
        target_buttons.pack(side=RIGHT, padx=(10, 0), anchor="n")
        self.add_target_button = ttk.Button(
            target_buttons,
            text="Magnet-Link hinzufügen",
            command=self._add_target,
        )
        self.add_target_button.pack(fill=X, pady=(0, 6))
        self.remove_target_button = ttk.Button(
            target_buttons,
            text="Auswahl entfernen",
            command=self._remove_target,
        )
        self.remove_target_button.pack(fill=X, pady=(0, 6))
        self.settings_button = ttk.Button(
            target_buttons,
            text="Entwurfsangaben",
            command=self._edit_settings,
        )
        self.settings_button.pack(fill=X)
        privacy_box = ttk.LabelFrame(outer, text="Optionale öffentliche Netzauskunft", padding=10)
        privacy_box.pack(fill=X, pady=(0, 12))
        self.enrichment_enabled = BooleanVar(value=self.config.enrichment.enabled)
        self.enrichment_checkbox = ttk.Checkbutton(
            privacy_box,
            text=(
                "Bestätigte IP-Adressen an stat.ripe.net, rdap.org und das von "
                "rdap.org bestimmte autoritative Regionalregister senden"
            ),
            variable=self.enrichment_enabled,
            command=self._toggle_network_enrichment,
        )
        self.enrichment_checkbox.pack(anchor="w")
        ttk.Label(
            privacy_box,
            text=(
                "Standardmäßig aus. Bekannte VPN-IP-Bereiche werden zuerst offline "
                "erkannt und nicht extern abgefragt. Regionalregister können z. B. "
                "RIPE, ARIN, APNIC, LACNIC oder AFRINIC sein und Anfragen protokollieren."
            ),
            foreground="#555555",
            wraplength=930,
        ).pack(anchor="w", pady=(4, 0))

        action_bar = ttk.Frame(outer)
        action_bar.pack(fill=X, pady=(0, 10))
        self.scan_button = ttk.Button(
            action_bar,
            text="Jetzt prüfen",
            command=self._start_scan,
        )
        self.scan_button.pack(side=LEFT)
        self.open_button = ttk.Button(
            action_bar,
            text="Letzten Ergebnisordner öffnen",
            command=self._open_output,
            state="disabled",
        )
        self.open_button.pack(side=LEFT, padx=(8, 0))
        self.progress = ttk.Progressbar(action_bar, mode="indeterminate", length=170)
        self.progress.pack(side=RIGHT)
        self.config_controls = (
            self.add_target_button,
            self.remove_target_button,
            self.settings_button,
            self.enrichment_checkbox,
        )

        self.status_text = StringVar(value="Bereit. Fügen Sie einen Magnet-Link hinzu.")
        ttk.Label(outer, textvariable=self.status_text, wraplength=930).pack(
            anchor="w", pady=(0, 8)
        )

        result_box = ttk.LabelFrame(outer, text="Letzter Prüflauf", padding=10)
        result_box.pack(fill=BOTH, expand=True)
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
        scrollbar = ttk.Scrollbar(result_box, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        self.result_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill="y")

        ttk.Label(
            outer,
            text=(
                "Keine automatische Anzeige · Kein automatischer E-Mail-Versand · "
                "Bekannte VPN-Endpunkte erscheinen nur in der gesonderten Liste"
            ),
            foreground="#555555",
        ).pack(anchor="w", pady=(10, 0))

    def _refresh_targets(self) -> None:
        self.target_tree.delete(*self.target_tree.get_children())
        for index, target in enumerate(self.config.targets):
            self.target_tree.insert(
                "", END, iid=str(index), values=(target.label, target.info_hash_hex)
            )
        if self.config.targets:
            self.status_text.set(
                f"Bereit. {len(self.config.targets)} Ziel(e) konfiguriert; es läuft kein Prüflauf."
            )
        else:
            self.status_text.set("Bereit. Keine Ziele eingetragen; es läuft kein Prüflauf.")

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

        self.running = True
        config_snapshot = self.config
        self.scan_button.configure(state="disabled")
        for control in self.config_controls:
            control.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self.progress.start(10)
        self.result_tree.delete(*self.result_tree.get_children())
        self._discard_pending_progress()
        self.status_text.set("Prüflauf wird vorbereitet …")
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
                self._finish_running_state()
                if not self.close_requested:
                    messagebox.showerror("Prüflauf fehlgeschlagen", str(payload), parent=self.root)
                    self.status_text.set(
                        "Der Prüflauf ist fehlgeschlagen. Details stehen im Protokoll."
                    )
            elif event == "done":
                terminal_event_seen = True
                if self.close_requested:
                    self._finish_running_state()
                else:
                    self._show_result(payload)

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
            self.status_text.set(latest_progress)
        if self.close_requested and not self.running:
            self.root.destroy()
            return
        self.root.after(150, self._poll_events)

    def _finish_running_state(self) -> None:
        self.running = False
        self.scan_thread = None
        self.progress.stop()
        self.scan_button.configure(state="normal")
        for control in self.config_controls:
            control.configure(state="normal")
        output_available = self.latest_output_dir is not None and self.latest_output_dir.is_dir()
        self.open_button.configure(state="normal" if output_available else "disabled")

    def _request_close(self) -> None:
        if not self.running:
            self.root.destroy()
            return
        if messagebox.askyesno(
            "Prüflauf noch aktiv",
            (
                "Der laufende Prüflauf wird kontrolliert zu Ende geführt, damit "
                "Journal und Berichte nicht beschädigt werden. Soll das Fenster "
                "danach geschlossen werden?"
            ),
            parent=self.root,
        ):
            self.close_requested = True
            self.status_text.set("Prüflauf läuft weiter; das Fenster schließt nach dem Abschluss.")

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
                else:
                    classification = "VPN unbekannt"
                endpoint = (
                    f"[{candidate.ip}]:{candidate.port}"
                    if ":" in candidate.ip
                    else f"{candidate.ip}:{candidate.port}"
                )
                self.result_tree.insert(
                    "",
                    END,
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
        if result.total_candidate_count == 0 and not result.errors:
            self.status_text.set(
                "Fertig. Zurzeit wurden keine antwortenden Endpunkte gefunden. "
                f"Das ist kein Programmfehler.{display_suffix}{target_suffix}{notice_suffix}"
            )
        else:
            self.status_text.set(
                f"Fertig: {result.total_candidate_count} Kandidaten gefunden, "
                f"{result.total_handshake_count} direkt geprüft, "
                f"{result.confirmed_count} bestätigte Handshakes, "
                f"{result.offering_count} positive Verfügbarkeitsprüfungen, "
                f"{result.known_vpn_count} bekannte VPN-Befunde. "
                f"{len(result.errors)} Hinweis(e)/Fehler."
                f"{display_suffix}{target_suffix}{notice_suffix}"
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


def launch_gui(config_path: Path, data_dir: Path) -> int:
    """Startet das Hauptfenster und gibt nach dessen Schließen Erfolg zurück."""
    root = Tk()
    ObserverApp(root, config_path, data_dir)
    root.mainloop()
    return 0
