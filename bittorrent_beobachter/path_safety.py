"""Gemeinsame Pfadpruefungen gegen symbolische Links und Windows-Junctions."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def is_link_like(path: Path) -> bool:
    """Erkennt Symlinks sowie NTFS-Junctions ohne dem Ziel zu folgen."""

    candidate = Path(path)
    if candidate.is_symlink():
        return True
    is_junction = getattr(candidate, "is_junction", None)
    if is_junction is not None and is_junction():
        return True
    try:
        attributes = int(getattr(os.lstat(candidate), "st_file_attributes", 0))
    except (FileNotFoundError, NotADirectoryError):
        return False
    reparse_point = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_point)


def path_has_link_like_component(path: Path) -> bool:
    """Prueft den absoluten Pfad und alle Vorfahren auf Link-Umleitungen."""

    absolute = Path(path).absolute()
    return any(is_link_like(component) for component in (absolute, *absolute.parents))
