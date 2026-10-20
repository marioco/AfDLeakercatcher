# Hinweise zu Drittkomponenten

Das Windows-Paket enthält neben dem unter der MIT-Lizenz veröffentlichten
BitTorrent-Beobachter die folgenden Laufzeit- und Build-Komponenten. Ihre
vollständigen, unveränderten Lizenz- und Hinweisdateien liegen direkt
im Paket unter `THIRD_PARTY_LICENSES`:

| Komponente | Gebündelte Version | Vollständiger Lizenztext |
| --- | --- | --- |
| Python-Laufzeit und Standardbibliothek | 3.12.10 | `THIRD_PARTY_LICENSES/Python-3.12.10.txt` |
| Tcl-Laufzeit | 8.6.15 | `THIRD_PARTY_LICENSES/Tcl-8.6.15.txt` |
| Tk-Laufzeit | 8.6.15 | `THIRD_PARTY_LICENSES/Tk-8.6.15.txt` |
| OpenSSL-Laufzeitbibliotheken | 3.0.16 (11. Februar 2025) | `THIRD_PARTY_LICENSES/OpenSSL-3.0.16-LICENSE.txt`; `THIRD_PARTY_LICENSES/OpenSSL-3.0.16-ACKNOWLEDGEMENTS.md` |
| ReportLab | 4.5.1 | `THIRD_PARTY_LICENSES/ReportLab-4.5.1.txt` |
| Pillow einschließlich der im Wheel dokumentierten Drittkomponenten | 13.0.0 | `THIRD_PARTY_LICENSES/Pillow-13.0.0.txt` |
| charset-normalizer | 3.5.2 | `THIRD_PARTY_LICENSES/charset-normalizer-3.5.2.txt` |
| PyInstaller-Bootloader und eingebettete Laufzeitmodule | 6.22.3 | `THIRD_PARTY_LICENSES/PyInstaller-6.22.3.txt` |

Der PyInstaller-Text enthält neben der GPL die Bootloader-Ausnahme und die
Lizenzbedingungen für eingebettete Laufzeitmodule. Der Pillow-Text enthält
auch die Lizenzhinweise der im Windows-Wheel mitgelieferten Bildbibliotheken.
OpenSSL 3.0.16 steht unter der Apache License 2.0. Copyright © 1998–2025
The OpenSSL Project sowie © 1995–1998 Eric A. Young und Tim J. Hudson.
Der offizielle Release-Tag enthält keine gesonderte `NOTICE`-Datei; die dort
veröffentlichte `ACKNOWLEDGEMENTS.md` ist deshalb zusätzlich unverändert
beigefügt. Offizieller Quellstand:
<https://github.com/openssl/openssl/tree/openssl-3.0.16>.

Die für Test und Windows-Build verwendeten direkten und transitiven Versionen
sowie ihre erlaubten SHA-256-Paketwerte stehen in `requirements-build.lock`.
Reine Test- und Build-Werkzeuge, die nicht Bestandteil des ausführbaren
Windows-Pakets sind, sind in der Tabelle nicht als gebündelte Komponenten
aufgeführt.
