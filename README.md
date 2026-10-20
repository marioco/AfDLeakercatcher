# BitTorrent-Beobachter

Eine leicht bedienbare, quelloffene Python-Anwendung zur **inhaltsfreien** Beobachtung
ausdrücklich konfigurierter BitTorrent-v1-Infohashes. Die Anwendung lädt keine Dateien
oder Torrent-Metadaten herunter, stellt nichts bereit und verschickt keine Meldung
automatisch.

## Was die Anwendung belastbar sagen kann

Die Anwendung fragt das öffentliche BitTorrent-DHT ausschließlich mit `get_peers` ab.
Für gefundene Endpunkte führt sie eine eng begrenzte Prüfung durch:

1. Ein DHT-Knoten nennt `IP:Port` für den konfigurierten Infohash.
2. Die Anwendung sendet genau den standardisierten 68-Byte-BitTorrent-Handshake.
3. Nur wenn der Endpunkt mit einem gültigen Handshake für denselben Infohash antwortet,
   wird ein prüfbarer Entwurf erzeugt.
4. Danach wird die Verbindung sofort geschlossen. Es folgen keine Protokollnachrichten.

Das belegt ausschließlich, dass der angesprochene Netzwerkendpunkt zum protokollierten
Zeitpunkt für diesen Infohash antwortete. Es belegt **nicht**:

- Besitz, Download oder Upload eines Dateiteils,
- Inhalt oder Echtheit des bezeichneten Archivs,
- Identität oder Handlung des Anschlussinhabers,
- Vorsatz, Rechtswidrigkeit oder eine Straftat.

NAT/CGNAT, dynamische Adressen, VPN/Proxy, gemeinsam genutzte Anschlüsse, offene Netze
und kompromittierte Geräte bleiben mögliche Erklärungen. Eine zeitbezogene Zuordnung zu
einem Anschluss kann nur der Provider im rechtlich vorgesehenen Verfahren leisten.

## Einfacher Start unter Windows

Veröffentlichte Versionen stehen in GitHub unter **Releases** bereit. Erfolgreiche
Teststände sind zusätzlich beim jeweiligen Lauf unter **Actions → Artifacts** verfügbar;
sie sind keine veröffentlichte Version und können von GitHub nach einiger Zeit gelöscht
werden.

1. Für den normalen Einsatz unter **Releases** das ZIP
   `BitTorrent-Beobachter-Windows-x64.zip` herunterladen.
2. Die daneben veröffentlichte SHA-256-Prüfsumme vergleichen.
3. Das ZIP vollständig entpacken und `BitTorrent-Beobachter.exe` doppelklicken.
4. Über **Magnet-Link hinzufügen** ein Ziel eintragen.
5. **Jetzt prüfen** wählen und den Hinweis zur öffentlichen Sichtbarkeit bestätigen.
6. Nach Abschluss **Ergebnisordner öffnen** wählen.

Ein Installer und Administratorrechte sind nicht nötig. Das bewusst verwendete
`onedir`-Paket ist transparenter als eine selbstentpackende Ein-Datei-EXE und wird ohne
UPX-Kompression gebaut. Ein öffentlich protokollierter GitHub-Actions-Lauf, SHA-256 und
eine GitHub-Herkunftsbestätigung machen den Build nachprüfbar. Eine vollständig
zuverlässige Vermeidung von Antivirus-Fehlalarmen ist technisch nicht versprechbar; den
stärksten Vertrauenshinweis liefert zusätzlich eine digitale Herausgebersignatur. Der
Build-Workflow signiert automatisch, sobald die Repository-Secrets
`WINDOWS_CERTIFICATE_BASE64` und `WINDOWS_CERTIFICATE_PASSWORD` hinterlegt sind.

## Verständliche Ausgabe

Jeder Lauf erhält einen eigenen Zeitstempel-Ordner. Alle Dateinamen beginnen mit der
jeweiligen Lauf-ID und erzeugen:

- `<Lauf-ID>_laufbericht.pdf`: Umfang, Ergebnisse, Fehler und Aussagegrenzen;
- `<Lauf-ID>_beobachtungen.csv`: tabellarische technische Beobachtungen;
- pro bestätigter, nicht als bekannter VPN-Endpunkt eingestufter IP einen neutralen
  `<Lauf-ID>_hinweis_<IP>.pdf` und `<Lauf-ID>_entwurf_<IP>.eml`;
- `<Lauf-ID>_vpn_liste.pdf` und `<Lauf-ID>_vpn_liste.csv`: bekannte
  VPN-Endpunkte ausschließlich als Liste;
- `<Lauf-ID>_SHA256SUMS.txt`: Prüfsummen aller Ausgabedateien;
- ein append-only JSONL-Journal mit SHA-256-Hash-Kette im Evidenzordner.

Für Berichte und Evidenzjournal gelten feste lokale Kapazitätsgrenzen. Bei Annäherung
bricht ein neuer Lauf vor dem Netzwerkzugriff mit einem Archivhinweis ab. Die Anwendung
löscht Evidenz oder Berichte niemals automatisch.

Die Anwendung sendet nie E-Mails. `.eml`-Dateien sind Entwürfe für die menschliche
Prüfung. Wenn keine Empfängeradresse konfiguriert wurde, bleibt das Empfängerfeld leer.

„Nicht als VPN erkannt“ bedeutet immer nur **unbekannt**, niemals „sicher kein VPN“.
Eine positive VPN-Einordnung erfolgt nur durch ein ausdrücklich konfiguriertes
IP-Präfix oder einen eindeutigen VPN-Markennamen in öffentlichen Netzbetreiberdaten.

## Datenschutz und verantwortlicher Betrieb

IP-Adressen und Zeitstempel können personenbezogene Daten sein. Vor einem echten Betrieb
sind insbesondere Rechtsgrundlage, Erforderlichkeit, Zugriffsschutz, Speicherfrist und
Löschkonzept zu klären. Die Anwendung versucht keine Person zu deanonymisieren. Sie
verarbeitet nur:

- öffentlich im DHT genannte Endpunkte,
- den minimalen BitTorrent-Handshake,
- öffentliche RDAP- und RIPEstat-Netzbetreiberangaben.

Ein Prüflauf ist **nicht anonym**. Die kontaktierten DHT-Knoten und geprüften
Peer-Endpunkte sehen die öffentliche Quell-IP der Messinstanz und den abgefragten
Infohash und können diese Anfrage protokollieren. Die Anwendung führt trotzdem kein
`announce` durch und lädt weder Inhalte noch Torrent-Metadaten herunter oder hoch.

Die optionale öffentliche Netzauskunft ist standardmäßig ausgeschaltet. Nach einer
ausdrücklichen Aktivierung werden bestätigte IP-Adressen an `stat.ripe.net`, `rdap.org`
und das von `rdap.org` bestimmte autoritative Regionalregister übermittelt, zum Beispiel
RIPE, ARIN, APNIC, LACNIC oder AFRINIC. Alle beteiligten Stellen können die Abfragen
protokollieren. Bekannte, lokal konfigurierte VPN-Präfixe werden vorher offline erkannt
und nicht extern abgefragt.

Sie führt keine Portscans, Geolokalisierung, Social-Media-Suche, Datenbroker-Abfrage oder
sonstige Personenrecherche aus. Netzbetreiber, Registry-Land und Abuse-Kontakt sind keine
Angaben zum Anschlussinhaber.

Die Zuordnung eines Infohashes zu einem behaupteten Inhalt stammt aus der jeweiligen
Konfiguration und wird wegen des absichtlich unterlassenen Inhaltsdownloads nicht
verifiziert. Rechtliche Hinweise in einem Entwurf sind ausdrücklich nur eine Bitte um
behördliche Prüfung. Vor einer Verwendung sollte eine sachkundige rechtliche und
datenschutzrechtliche Prüfung erfolgen.

## Aus dem Quellcode starten

Voraussetzungen: Python 3.11 oder neuer und Tkinter.

```bash
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python 164_bittorrent_beobachter.py
```

Unter Windows lauten die letzten beiden Befehle:

```powershell
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\python.exe 164_bittorrent_beobachter.py
```

Ohne Argumente öffnet sich die Oberfläche. Ein einzelner Hintergrundlauf ist möglich
mit:

```bash
.venv/bin/python 164_bittorrent_beobachter.py --config /pfad/config.json \
  scan --acknowledge-public-network
```

Der Pflichtschalter bestätigt ausdrücklich, dass DHT-Knoten und geprüfte
Peer-Endpunkte die öffentliche Quell-IP und den Infohash sehen und protokollieren
können. Er ist auch für `watch` erforderlich.

Die Hash-Kette des Journals wird geprüft mit:

```bash
.venv/bin/python 164_bittorrent_beobachter.py --data-dir /pfad/daten verify-journal
```

## Konfiguration

Die Oberfläche speichert aus einem Magnet-Link ausschließlich Bezeichnung und v1-btih.
Tracker-URLs werden verworfen und nicht kontaktiert. Eine Konfiguration kann auch über
`init --magnet ...` angelegt werden. Live-Ziele sind absichtlich nicht im öffentlichen
Quellcode enthalten.

Wichtige Schutzgrenzen sind fest im Programm angelegt:

- höchstens 20 Ziele;
- höchstens 600 Sekunden für die gesamte DHT- und Handshake-Netzphase sowie weitere
  harte Zeitlimits und Grenzen für DHT-Knoten, Anfragen, Treffer und parallele
  Handshakes;
- höchstens 20 externe Netzauskünfte pro Lauf; weitere bestätigte Adressen bleiben in
  diesem Lauf ohne externe Anreicherung;
- nur global routbare öffentliche Adressen;
- zufällige Knoten- und Peer-ID pro Lauf;
- niemals `announce_peer`, Tracker-Announce, `interested`, `request`, `piece`,
  `ut_metadata` oder Peer Exchange;
- Single-Instance-Sperre gegen überlappende Läufe.

## Windows-Build selbst prüfen

In PowerShell:

```powershell
./build_windows.ps1
```

Der GitHub-Workflow führt Tests und Ruff aus, baut mit PyInstaller ohne UPX, signiert
optional, erstellt das ZIP samt SHA-256 und versieht öffentliche Nicht-PR-Builds mit
einer GitHub-Artefaktbestätigung. Eine Bestätigung lässt sich mit der GitHub CLI prüfen:

```bash
gh attestation verify BitTorrent-Beobachter-Windows-x64.zip -R marioco/AfDLeakercatcher
```

Ein Push eines passenden Versionstags wie `bittorrent-beobachter-v0.1.0` erzeugt nach
erfolgreichem Build automatisch ein GitHub-Release mit ZIP, SHA-256-Datei und generierten
Versionshinweisen. Andere erfolgreiche Workflow-Läufe stellen den Build nur als
Actions-Artefakt bereit.

## Technische Grundlagen

- [BEP 3 – BitTorrent Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
- [BEP 5 – DHT Protocol](https://www.bittorrent.org/beps/bep_0005.html)
- [BEP 32 – IPv6 extension for DHT](https://www.bittorrent.org/beps/bep_0032.html)
- [GitHub-Artefaktbestätigungen](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## Lizenz

MIT, siehe `LICENSE`.
