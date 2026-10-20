"""Einfache Desktop-Oberfläche für Konfiguration, Prüflauf und Ergebnisse."""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import replace
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
    with_bundled_presets,
)
from .desktop import open_directory
from .models import ScanResult


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
        self.result = replace(
            self.settings,
            reporter_name=self.name.get().strip(),
            reporter_email=self.email.get().strip(),
            police_recipient=self.recipient.get().strip(),
        )
        self.destroy()


class ObserverApp:
    """Bedienoberfläche mit klarer Trennung von Beobachtung und Behauptung."""

    def __init__(self, root: Tk, config_path: Path, data_dir: Path) -> None:
        self.root = root
        self.config_path = config_path
        self.data_dir = data_dir
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
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
            messagebox.showerror("Konfiguration fehlerhaft", str(exc))
            return AppConfig(targets=())

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
                "Inhaltsfreie Beobachtung: Es werden weder Dateien noch Torrent-Metadaten "
                "heruntergeladen, angefordert oder hochgeladen."
            ),
            foreground="#205493",
            wraplength=950,
        ).pack(anchor="w", pady=(4, 12))

        notice = ttk.LabelFrame(outer, text="Wichtige Aussagegrenze", padding=10)
        notice.pack(fill=X, pady=(0, 12))
        ttk.Label(
            notice,
            text=(
                "Ein bestätigter Handshake belegt nur, dass ein Netzwerkendpunkt zu diesem "
                "Zeitpunkt für den Infohash antwortete. Er identifiziert keine Person und "
                "beweist weder Dateibesitz noch Upload oder Strafbarkeit. Jeder Entwurf muss "
                "vor Verwendung von einem Menschen geprüft werden."
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
            text="Ergebnisordner öffnen",
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
            "status": "Handshake",
            "network": "Netzbetreiber",
            "class": "Einordnung",
        }
        widths = {
            "time": 145,
            "target": 150,
            "endpoint": 180,
            "status": 100,
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
                "Magnet-Link einfügen. Gespeichert wird ausschließlich der "
                "BitTorrent-v1-Infohash; Name, Tracker und sonstige Angaben werden verworfen:"
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
            f"„{target.label}“ wirklich aus der Überwachung entfernen?",
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
                "Dieser Prüflauf ist nicht anonym: DHT-Knoten und geprüfte "
                "Peer-Endpunkte sehen Ihre öffentliche Quell-IP und den abgefragten "
                "Infohash und können dies protokollieren. Das Programm führt kein "
                "announce durch und lädt weder Inhalte noch Metadaten herunter oder "
                "hoch. Möchten Sie den Prüflauf trotzdem starten?"
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
                progress=lambda message: self.events.put(("progress", message)),
            )
        except Exception as exc:
            logging.getLogger("bittorrent_beobachter").exception("GUI-Prüflauf fehlgeschlagen")
            self.events.put(("error", f"{type(exc).__name__}: {exc}"))
        else:
            self.events.put(("done", result))

    def _poll_events(self) -> None:
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "progress":
                self.status_text.set(str(payload))
            elif event == "error":
                self._finish_running_state()
                if not self.close_requested:
                    messagebox.showerror("Prüflauf fehlgeschlagen", str(payload), parent=self.root)
                    self.status_text.set(
                        "Der Prüflauf ist fehlgeschlagen. Details stehen im Protokoll."
                    )
            elif event == "done":
                if self.close_requested:
                    self._finish_running_state()
                else:
                    self._show_result(payload)
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
        records_by_key = {
            (
                record.handshake.candidate.info_hash_hex,
                record.handshake.candidate.ip,
                record.handshake.candidate.port,
            ): record
            for record in result.records
        }
        for handshake in result.handshakes:
            candidate = handshake.candidate
            record = records_by_key.get((candidate.info_hash_hex, candidate.ip, candidate.port))
            network = ""
            classification = "nicht eingestuft"
            if record is not None:
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
                    "bestätigt" if handshake.confirmed else "nicht bestätigt",
                    network,
                    classification,
                ),
            )
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
        if not result.candidates and not result.errors:
            self.status_text.set(
                "Fertig. Zurzeit wurden keine antwortenden Endpunkte gefunden. "
                f"Das ist kein Programmfehler.{notice_suffix}"
            )
        else:
            self.status_text.set(
                f"Fertig: {len(result.candidates)} DHT-Treffer, "
                f"{result.confirmed_count} bestätigte Handshakes, "
                f"{result.known_vpn_count} bekannte VPN-Endpunkte. "
                f"{len(result.errors)} Hinweis(e)/Fehler.{notice_suffix}"
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
