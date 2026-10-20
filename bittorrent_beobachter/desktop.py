"""Kleine, tkinter-unabhängige Desktop-Helfer."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


def open_directory(
    path: Path,
    *,
    platform: str | None = None,
    startfile: Callable[[str], object] | None = None,
    runner: Callable[..., object] = subprocess.run,
) -> None:
    """Öffnet einen vorhandenen Ordner im Dateimanager des Betriebssystems."""

    directory = Path(path).expanduser().resolve()
    if not directory.is_dir():
        raise FileNotFoundError(f"Ergebnisordner nicht gefunden: {directory}")

    active_platform = platform or sys.platform
    if active_platform == "win32":
        opener = startfile or getattr(os, "startfile", None)
        if opener is None:
            raise OSError("Windows stellt keine Ordneröffnungsfunktion bereit.")
        opener(str(directory))
        return

    command = (
        ["open", str(directory)] if active_platform == "darwin" else ["xdg-open", str(directory)]
    )
    try:
        runner(
            command,
            check=True,
            shell=False,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise OSError("Der Dateimanager hat nicht innerhalb von 10 Sekunden reagiert.") from exc
    except subprocess.CalledProcessError as exc:
        detail = " ".join((exc.stderr or "").split())[:300]
        message = "Der Ergebnisordner konnte nicht geöffnet werden."
        if detail:
            message = f"{message} {detail}"
        raise OSError(message) from exc
