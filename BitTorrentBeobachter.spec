# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller-Konfiguration für ein transparentes Windows-Onedir-Paket."""

import ssl
import sys
import tkinter
from pathlib import Path


EXPECTED_PYTHON_VERSION = (3, 14, 8)
EXPECTED_OPENSSL_VERSION = "OpenSSL 3.5.9 29 Sep 2026"
EXPECTED_TCL_VERSION = "9.0.4"
EXPECTED_TK_VERSION = "9.0.4"
if sys.version_info[:3] != EXPECTED_PYTHON_VERSION:
    raise RuntimeError(
        f"Build benötigt Python {EXPECTED_PYTHON_VERSION}, gefunden: "
        f"{sys.version_info[:3]}"
    )
if ssl.OPENSSL_VERSION != EXPECTED_OPENSSL_VERSION:
    raise RuntimeError(
        f"Build benötigt {EXPECTED_OPENSSL_VERSION}, gefunden: {ssl.OPENSSL_VERSION}"
    )
root = tkinter.Tk()
try:
    root.withdraw()
    actual_tcl_version = str(root.tk.call("info", "patchlevel"))
    actual_tk_version = str(root.tk.call("package", "provide", "Tk"))
finally:
    root.destroy()
if (
    actual_tcl_version != EXPECTED_TCL_VERSION
    or actual_tk_version != EXPECTED_TK_VERSION
):
    raise RuntimeError(
        f"Build benötigt Tcl/Tk {EXPECTED_TCL_VERSION}/{EXPECTED_TK_VERSION}, "
        f"gefunden: {actual_tcl_version}/{actual_tk_version}"
    )

PROJECT_ROOT = Path(SPECPATH)
THIRD_PARTY_LICENSES_DIR = PROJECT_ROOT / "THIRD_PARTY_LICENSES"
RESULT_ILLUSTRATION_PATH = (
    PROJECT_ROOT / "bittorrent_beobachter" / "assets" / "leaker_chase.png"
)

analysis = Analysis(
    [str(PROJECT_ROOT / "164_bittorrent_beobachter.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "README.md"), "."),
        (str(PROJECT_ROOT / "LICENSE"), "."),
        (str(PROJECT_ROOT / "THIRD_PARTY_NOTICES.md"), "."),
        (str(PROJECT_ROOT / "requirements-build.lock"), "."),
        (str(THIRD_PARTY_LICENSES_DIR), "THIRD_PARTY_LICENSES"),
        (
            str(RESULT_ILLUSTRATION_PATH),
            "bittorrent_beobachter/assets",
        ),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)
python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="AfDLeakerCatcher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

bundle = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    name="AfDLeakerCatcher",
)
