# AfDLeakerCatcher

## Windows-Download – Version 0.3.8

### [⬇ AfDLeakerCatcher für Windows herunterladen](https://github.com/marioco/AfDLeakercatcher/releases/download/afdleakercatcher-v0.3.8/AfDLeakerCatcher-Windows-x64.zip)

[SHA-256-Prüfsumme zum Download](https://github.com/marioco/AfDLeakercatcher/releases/download/afdleakercatcher-v0.3.8/AfDLeakerCatcher-Windows-x64.zip.sha256)

[Einseitige Kurzbeschreibung: So funktioniert AfDLeakerCatcher (PDF)](AfDLeakerCatcher-Kurzuebersicht.pdf)

Keine GitHub-Kenntnisse nötig: Auf den Link klicken, die ZIP-Datei **einmal**
entpacken und anschließend `AfDLeakerCatcher.exe` doppelklicken. Es gibt keinen
Installer und es werden keine Administratorrechte benötigt.

Eine leicht bedienbare, quelloffene Python-Anwendung zur **inhaltsfreien** Prüfung
ausdrücklich konfigurierter BitTorrent-v1-Infohashes. Die Anwendung fordert keine Datei-
oder Torrent-Metadatenblöcke an, lädt keine davon hoch und verschickt keine Meldung
automatisch.
Die kompakte Desktop-Oberfläche verwendet ein zurückhaltendes dunkles Design mit
Klartext-Statusmeldungen, sichtbaren Tastaturfokussen und responsiven Tabellen. Eine
kleine, begrenzte Live-Tabelle zeigt ausschließlich echte technische Laufmeldungen aus
Peer-Suche, Direktprüfung, Evidenzspeicherung und Berichtserzeugung.

## Was die Anwendung belastbar sagen kann

Die Anwendung sucht Endpunkte parallel im öffentlichen BitTorrent-DHT mit `get_peers`
und über die für ein Ziel gespeicherten, validierten UDP-Tracker. Beides geschieht erst
nach der ausdrücklichen Bestätigung vor dem Prüflauf. Für gefundene Endpunkte führt sie
eine gezielte, inhaltsfreie Prüfung durch:

1. Ein DHT-Knoten oder UDP-Tracker nennt `IP:Port` für den konfigurierten Infohash.
2. Die Anwendung sendet den standardisierten 68-Byte-BitTorrent-Handshake.
3. Nach einem gültigen Handshake für denselben Infohash meldet sie auf derselben
   Verbindung Interesse und beobachtet bis zu 60 Sekunden ausschließlich
   BitTorrent-Kontrollnachrichten.
4. Ein positiver Verfügbarkeitsbefund erfordert mindestens ein nicht leeres `bitfield`-
   oder gültiges `have`-Signal und ein zeitgleich geltendes `unchoke`. Das bedeutet:
   Der Endpunkt meldete verfügbare Teile und teilte dem Prüfprogramm mit, dass es
   Datenblöcke anfordern dürfe.
5. Die Anwendung sendet niemals `request`-Nachrichten und fordert weder Dateiinhalte
   noch Torrent-Metadaten an. Positive Befunde werden nach IP-Adresse gebündelt. Für jede
   positive, nicht als bekannter VPN-Endpunkt eingestufte IP werden eine technische
   Anlage und eine versandfertige Strafanzeige als `.eml` erzeugt.

Es gibt keine Mengenbegrenzung für gefundene oder direkt geprüfte Kandidaten. Die
DHT-Suche läuft in wiederholten konvergierenden Runden weiter, bis während des
konfigurierten Ruhefensters – standardmäßig 30 Sekunden – kein neuer eindeutiger
Kandidat mehr gefunden wurde. Gleichzeitige Doppelnennungen desselben Infohashes mit
derselben IP und demselben Port werden zusammengeführt. Ein bestätigter, technisch fehlerfreier
Vollzeitbefund ist nach einem Versuch abschließend; nur technische oder vorzeitige
Teilbeobachtungen werden unmittelbar wiederholt, standardmäßig bis zu drei Versuche.
Eine zeitlich spätere echte Wiederentdeckung kann einen negativen Endpunkt erneut
einplanen, ohne erstmals gefundene Kandidaten zu verdrängen.

Ein positiver Angebotsbefund wird nur erzeugt, wenn der bestätigte Client während der
vollständig abgelaufenen konfigurierten Beobachtungszeit – standardmäßig 60 Sekunden –
ohne technischen Fehler erreichbar blieb, dabei Stückverfügbarkeit meldete und das
Anfordern per `UNCHOKE` freigab. Vorzeitig beendete oder fehlerhafte Teilbeobachtungen
bleiben ausschließlich als Diagnose gespeichert und erzeugen weder eine Strafanzeige
noch eine technische Anlage.

Kandidaten und Ergebnisse werden fortlaufend in Fünferpaketen in einer privaten lokalen
SQLite-Laufdatenbank gespeichert; die vollständige Treffermenge wird dadurch nicht im
Arbeitsspeicher gehalten. Nach jeweils fünf positiven Befunden wird sofort ein
nummerierter Unterordner `zwischenstand-000001`, `zwischenstand-000002` usw. mit fertigen
PDF-, E-Mail- und CSV-Ergebnissen angelegt. Frühere Zwischenstände werden nicht erneut
berechnet und können bereits während der weiteren Suche geöffnet und verwendet werden.
Über **Prüflauf abbrechen** lässt sich die Suche kontrolliert beenden; der letzte
Restblock und alle bisherigen Ergebnisse werden anschließend im Hauptordner fertig
gespeichert. Das letzte Paket darf weniger als fünf Einträge enthalten.
Nach einem Programmneustart prüft die Anwendung vor jedem neuen Netzwerkzugriff das
Evidenzjournal und die privaten SQLite-Laufdatenbanken. Bereits positiv geprüfte, aber
noch nicht vollständig ausgegebene Befunde werden in Fünferpaketen abgeglichen und als
eigene Wiederherstellungsberichte fertiggestellt. Die eigentliche Netzwerksuche eines
unterbrochenen Laufs wird nicht an derselben Stelle fortgesetzt; danach beginnt ein
neuer Prüflauf.
Bei großen oder aktiven Schwärmen kann ein vollständiger Lauf deshalb viele Minuten
oder Stunden dauern.
Netzwerk-Zeitlimits begrenzen einzelne Anfragen und Verbindungsversuche, nicht die Anzahl
der insgesamt gefundenen oder geprüften Endpunkte.

Das ist ein stärkeres Protokollindiz als ein bloßer Eintrag in einer Teilnehmerliste oder
ein Handshake. Die Kontrollsignale werden jedoch vom Gegenüber selbst erzeugt und ohne
Inhaltsabruf nicht gegen echte Dateistücke geprüft. Der Befund belegt daher **nicht**:

- tatsächlichen Besitz, Download oder Upload eines Dateiteils,
- Inhalt oder Echtheit des bezeichneten Archivs,
- Identität oder Handlung des Anschlussinhabers,
- Vorsatz, Rechtswidrigkeit oder eine Straftat.

NAT/CGNAT, dynamische Adressen, VPN/Proxy, gemeinsam genutzte Anschlüsse, offene Netze
und kompromittierte Geräte bleiben mögliche Erklärungen. Eine zeitbezogene Zuordnung zu
einem Anschluss kann nur der Provider im rechtlich vorgesehenen Verfahren leisten.

## Einfacher Start unter Windows

Die aktuelle Windows-Version kann direkt über den großen Downloadlink ganz oben auf
dieser Seite geladen werden. Erfolgreiche Teststände sind zusätzlich beim jeweiligen
Lauf unter **Actions → Artifacts** verfügbar; sie sind keine veröffentlichte Version und
können von GitHub nach einiger Zeit gelöscht werden.

1. Ganz oben auf **AfDLeakerCatcher für Windows herunterladen** klicken.
2. Die direkt darunter verlinkte SHA-256-Prüfsummendatei in denselben Ordner laden.
3. In diesem Ordner PowerShell öffnen und die beiden Werte automatisch vergleichen:

   ```powershell
   $Soll = (Get-Content .\AfDLeakerCatcher-Windows-x64.zip.sha256).Split()[0]
   $Ist = (Get-FileHash .\AfDLeakerCatcher-Windows-x64.zip -Algorithm SHA256).Hash
   $Ist -eq $Soll
   ```

4. Nur wenn PowerShell `True` ausgibt, das ZIP genau einmal vollständig entpacken
   und `AfDLeakerCatcher.exe` doppelklicken.
5. Die beiden vorgesehenen Infohashes sind bereits sichtbar eingetragen.
6. **Jetzt prüfen** wählen und den Hinweis zur öffentlichen Sichtbarkeit bestätigen.
7. Nach Abschluss **Ergebnisordner öffnen** wählen.

Es gibt kein ZIP im ZIP. Für einen Teststand unter **Actions → Artifacts** ist das
Artefakt `AfDLeakerCatcher-Windows-x64` ohne den Zusatz `-release` vorgesehen: Es
enthält direkt die Programmdateien und muss nur einmal entpackt werden. Für die
voreingestellten Ziele sind weder Titel noch Beschreibung einzugeben. Ein zusätzlicher
Magnet-Link lässt sich bei Bedarf in genau einem Eingabefenster ergänzen.

Im selben entpackten Ordner wie die EXE liegt die Datei
`Cybercrime-E-Mail-Kontakte_BKA-und-LKA_Deutschland_Stand-2026-10-20.pdf` mit einer
Kontaktübersicht. Sie ist eine separate Arbeitshilfe: Das Programm wählt daraus keine
Empfänger automatisch aus, versendet keine E-Mail und macht aus einer Beobachtung keinen
Beweis für Inhalt, Person oder Straftat.

Ein Installer und Administratorrechte sind nicht nötig. Das bewusst verwendete
`onedir`-Paket ist transparenter als eine selbstentpackende Ein-Datei-EXE und wird ohne
UPX-Kompression gebaut. Ein öffentlich protokollierter GitHub-Actions-Lauf, SHA-256 und
eine GitHub-Herkunftsbestätigung machen den Build nachprüfbar. Eine vollständig
zuverlässige Vermeidung von Antivirus-Fehlalarmen ist technisch nicht versprechbar; den
stärksten Vertrauenshinweis liefert zusätzlich eine digitale Herausgebersignatur. Der
Build-Workflow signiert automatisch, sobald die Repository-Secrets
`WINDOWS_CERTIFICATE_BASE64` und `WINDOWS_CERTIFICATE_PASSWORD` hinterlegt sind. Fehlen
diese Secrets, kann der Workflow den Build trotzdem **unsigniert** veröffentlichen.
Windows kann dann „Unbekannter Herausgeber“ oder eine SmartScreen-Warnung anzeigen.
SHA-256 und GitHub-Herkunftsbestätigung sichern Integrität und Build-Herkunft, ersetzen
aber keine Windows-Herausgebersignatur.

## Verständliche Ausgabe

Jeder Lauf erhält einen eigenen Zeitstempel-Ordner. Alle Dateinamen beginnen mit der
jeweiligen Lauf-ID und erzeugen:

- `<Lauf-ID>_laufbericht.pdf`: Umfang, Ergebnisse und technische Laufkennzahlen;
- `<Lauf-ID>_beobachtungen.csv`: tabellarische technische Beobachtungen;
- pro positiver, nicht als bekannter VPN-Endpunkt eingestufter IP eine
  `<Lauf-ID>_anlage_<IP>.pdf` und
  `<Lauf-ID>_strafanzeige_<IP>.eml`;
- `<Lauf-ID>_vpn_liste.pdf` und `<Lauf-ID>_vpn_liste.csv`: bekannte
  VPN-Endpunkte ausschließlich als Liste;
- `<Lauf-ID>_SHA256SUMS.txt`: Prüfsummen aller Ausgabedateien;
- ein append-only JSONL-Journal mit SHA-256-Hash-Kette im Evidenzordner.

Für Kandidaten, Prüfungen und Berichte gelten keine festen Mengenlimits. Die tatsächlich
verfügbare lokale Speicherkapazität bleibt die physische Grenze; Schreib- und
Speicherfehler werden sichtbar gemeldet. Die Anwendung löscht Laufdaten, Evidenz oder
Berichte niemals automatisch.

Die Anwendung sendet nie E-Mails. `.eml`-Dateien sind versandfertig formuliert, müssen
aber von einem Menschen geprüft, geöffnet und bewusst versandt werden. Wenn keine
Empfängeradresse konfiguriert wurde, bleibt das Empfängerfeld leer.

Der CSV-Status `nicht als bekannter VPN klassifiziert` ist eine neutrale
Klassifikationsangabe. Eine positive VPN-Einordnung erfolgt nur durch ein ausdrücklich
konfiguriertes IP-Präfix oder einen eindeutigen VPN-Markennamen in öffentlichen
Netzbetreiberdaten.

## Datenschutz und verantwortlicher Betrieb

IP-Adressen und Zeitstempel können personenbezogene Daten sein. Vor einem echten Betrieb
sind insbesondere Rechtsgrundlage, Erforderlichkeit, Zugriffsschutz, Speicherfrist und
Löschkonzept zu klären. Die Anwendung versucht keine Person zu deanonymisieren. Sie
verarbeitet nur:

- öffentlich im DHT genannte Endpunkte,
- von validierten UDP-Trackern gemeldete Endpunkte,
- den BitTorrent-Handshake sowie streng begrenzte `interested`-, `bitfield`-,
  `have`-, `have_all`-, `choke`- und `unchoke`-Kontrollnachrichten,
- öffentliche RDAP- und RIPEstat-Netzbetreiberangaben.

Ein Prüflauf ist **nicht anonym**. Die kontaktierten DHT-Knoten, UDP-Tracker und geprüften
Peer-Endpunkte sehen die öffentliche Quell-IP der Messinstanz und den abgefragten
Infohash und können diese Anfrage protokollieren. Zur Endpunktsuche sendet die Anwendung
nach der ausdrücklichen Bestätigung einen kurzlebigen UDP-Tracker-Announce mit `STARTED`,
unbekannter Restmenge und einem nicht geöffneten Port; unmittelbar danach meldet sie
`STOPPED`. Der Tracker kann die Messinstanz in dieser kurzen Zeit als Peer führen. Die
Anwendung öffnet keinen Listener, meldet keinen Upload, fordert weder Dateistücke noch
Torrent-Metadaten an und lädt beides auch nicht hoch.

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
verifiziert. Die in der Strafanzeige genannten Vorschriften sind ausdrücklich als Bitte
um behördliche Prüfung formuliert. Vor einer Verwendung sollte eine sachkundige
rechtliche und datenschutzrechtliche Prüfung erfolgen.

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

Der Pflichtschalter bestätigt ausdrücklich, dass DHT-Knoten, konfigurierte UDP-Tracker
und geprüfte Peer-Endpunkte die öffentliche Quell-IP und den Infohash sehen und
protokollieren können. Er ist auch für `watch` erforderlich.

Die Hash-Kette des Journals wird geprüft mit:

```bash
.venv/bin/python 164_bittorrent_beobachter.py --data-dir /pfad/daten verify-journal
```

## Konfiguration

Beim ersten Start legt die Oberfläche die beiden für dieses Projekt vorgesehenen
Infohashes einschließlich ihrer ursprünglichen validierten UDP-Tracker als sichtbare
Voreinstellungen an. Die Konfigurationsmigration von Version 0.3.0 ergänzt diese Tracker
auch bei bereits vorhandenen voreingestellten Zielen, verändert aber keine eigenen
Bezeichnungen und stellt bewusst gelöschte Ziele nicht wieder her. Eigene Einträge und
eigene Tracker bleiben unverändert.

Das bestätigt weder einen behaupteten Inhalt noch Echtheit, Rechtmäßigkeit, Besitz oder
Übertragung und startet keinen Netzlauf. Bei einem zusätzlich eingefügten Magnet-Link
speichert die Oberfläche den v1-btih-Infohash und ausschließlich vollständig validierte
UDP-Tracker. Der Magnetname und sonstige Angaben werden verworfen. Andere Protokolle,
unsichere Zieladressen und ungültige Tracker-Angaben werden abgelehnt. Eine Konfiguration
kann auch über `init --magnet ...` angelegt werden.

Wichtige Schutzgrenzen betreffen einzelne Operationen, nicht die Kandidatenmenge:

- höchstens 20 ausdrücklich konfigurierte Ziele;
- Zeitlimits und Größenprüfungen pro DNS-, DHT-, Tracker- und Peer-Operation;
- begrenzte Parallelität und fortlaufende Verarbeitung in Fünferpaketen, damit große
  Treffermengen weder Arbeitsspeicher noch Netzwerk unkontrolliert belasten;
- eine begrenzte Zahl von Wiederholungsversuchen pro Kandidat;
- keine Gesamtfrist und keine Anzahlgrenze für DHT-Anfragen, gefundene Kandidaten oder
  direkte Prüfungen; die DHT-Runden enden erst nach dem konfigurierten Ruhefenster;
- nur global routbare öffentliche Adressen;
- zufällige Knoten- und Peer-ID pro Lauf;
- niemals DHT-`announce_peer`, `request`, `piece`, `ut_metadata`-Anforderung oder Peer
  Exchange; der kurzlebige UDP-Tracker-Announce (`STARTED`, anschließend `STOPPED`) dient
  nur der Endpunktsuche und
  `interested` wird ausschließlich innerhalb der beschriebenen
  Kontrollnachrichtenprüfung gesendet;
- keine Anforderung und kein Hochladen von Dateistücken oder Torrent-Metadaten;
- Single-Instance-Sperre gegen überlappende Läufe.

## Windows-Build selbst prüfen

In PowerShell:

```powershell
./build_windows.ps1
```

Der GitHub-Workflow führt Tests und Ruff aus, baut mit PyInstaller ohne UPX und
signiert optional. Bereits der Windows-Job erzeugt aus dem geprüften App-Ordner das
finale, direkt einmal entpackbare ZIP samt SHA-256-Datei. In öffentlichen
Nicht-PR-Builds erhält genau dieses ZIP eine Attestierung. Bei einem Release werden
dieselben ZIP-Bytes anschließend unverändert veröffentlicht.
Vor dem Entpacken lässt sich seine Herkunft mit der GitHub CLI prüfen:

```bash
gh attestation verify AfDLeakerCatcher-Windows-x64.zip -R marioco/AfDLeakercatcher
```

Ein Push auf `main` erzeugt nach erfolgreichem Build ein GitHub-Release, sofern für die
eingetragene Version noch keines existiert. Dasselbe gilt für einen exakt zur
Paket- und App-Version passenden Tag wie `afdleakercatcher-v0.3.8`. Ein bereits
vorhandenes Release wird nicht überschrieben, sondern auf Ziel-Commit, Entwurfsstatus,
exakt erwartete Assets und ZIP-Prüfsumme kontrolliert. Pull Requests und manuell
gestartete Läufe stellen nur Actions-Artefakte bereit.

## Technische Grundlagen

- [BEP 3 – BitTorrent Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
- [BEP 5 – DHT Protocol](https://www.bittorrent.org/beps/bep_0005.html)
- [BEP 32 – IPv6 extension for DHT](https://www.bittorrent.org/beps/bep_0032.html)
- [GitHub-Artefaktbestätigungen](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## Lizenz

MIT, siehe `LICENSE`.
