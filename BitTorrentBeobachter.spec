# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller-Konfiguration für ein transparentes Windows-Onedir-Paket."""

from pathlib import Path


PROJECT_ROOT = Path(SPECPATH)
THIRD_PARTY_LICENSES_DIR = PROJECT_ROOT / "THIRD_PARTY_LICENSES"

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
