"""Plattformneutrale Tests fuer Link- und Junction-Erkennung."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import bittorrent_beobachter.path_safety as path_safety
from bittorrent_beobachter.path_safety import (
    is_link_like,
    path_has_link_like_component,
)


def test_junction_is_treated_like_a_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    junction = (tmp_path / "junction").absolute()

    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda self: self.absolute() == junction,
        raising=False,
    )

    assert is_link_like(junction)
    assert path_has_link_like_component(junction / "private" / "data.sqlite3")
    assert not path_has_link_like_component(tmp_path / "ordinary" / "data.sqlite3")


def test_existing_symlink_remains_link_like(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"Symlinks sind nicht verfuegbar: {exc}")

    assert is_link_like(link)
    assert path_has_link_like_component(link / "child")


def test_python311_windows_reparse_fallback_is_link_like(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "junction"
    monkeypatch.setattr(Path, "is_symlink", lambda _self: False)
    monkeypatch.setattr(Path, "is_junction", lambda _self: False, raising=False)
    monkeypatch.setattr(
        path_safety.os,
        "lstat",
        lambda _path: SimpleNamespace(st_file_attributes=0x400),
    )

    assert is_link_like(candidate)
