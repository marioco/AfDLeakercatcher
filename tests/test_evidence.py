"""Tests fuer das kanonische, manipulationssichtbare Beweisjournal."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

import bittorrent_beobachter.evidence as evidence_module
from bittorrent_beobachter.evidence import (
    INTEGRITY_LIMITATION,
    EvidenceJournal,
    EvidenceJournalError,
    _windows_region_lock,
    atomic_write_json,
    canonical_json_bytes,
)
from bittorrent_beobachter.models import (
    HandshakeResult,
    NetworkEnrichment,
    PeerCandidate,
    VpnClassification,
)


def _confirmed_handshake(ip: str = "8.8.8.8") -> HandshakeResult:
    candidate = PeerCandidate(
        target_label="Testziel",
        info_hash_hex="11" * 20,
        ip=ip,
        port=51413,
        discovered_at_utc="2026-10-20T10:00:00Z",
        dht_node_ip="1.1.1.1",
        dht_node_port=6881,
        transaction_id_hex="a1b2",
        response_sha256="22" * 32,
    )
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc="2026-10-20T10:00:01Z",
        completed_at_utc="2026-10-20T10:00:02Z",
        confirmed=True,
        remote_peer_id_hex="33" * 20,
        reserved_bits_hex="0000000000000000",
        local_ip="192.0.2.10",
        local_port=40000,
        bytes_sent=68,
        bytes_received=68,
        error=None,
    )


def test_append_creates_canonical_chained_jsonl(tmp_path: Path) -> None:
    assert "sachlichen Richtigkeit" in INTEGRITY_LIMITATION
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)

    first = journal.append(
        {"kind": "first", "nested": {"z": 2, "a": 1}},
        recorded_at_utc="2026-10-20T10:00:00Z",
    )
    second = journal.append(
        {"kind": "second"},
        recorded_at_utc="2026-10-20T10:01:00Z",
    )

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_event_sha256 == first.event_sha256
    verification = journal.verify()
    assert verification.valid is True
    assert verification.entries_count == 2
    assert verification.last_event_sha256 == second.event_sha256

    lines = path.read_bytes().splitlines()
    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert line == canonical_json_bytes(parsed)


def test_append_many_verifies_once_and_builds_one_hash_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    original_read_entries = evidence_module._read_entries
    verification_calls = 0

    def counting_read_entries(file_handle: object, *, end_offset: int | None = None) -> object:
        nonlocal verification_calls
        verification_calls += 1
        return original_read_entries(file_handle, end_offset=end_offset)

    monkeypatch.setattr(evidence_module, "_read_entries", counting_read_entries)
    entries = journal.append_many(
        ({"kind": "first"}, {"kind": "second"}, {"kind": "third"}),
        recorded_at_utc="2026-10-20T10:00:00Z",
    )

    assert verification_calls == 1
    assert [entry.sequence for entry in entries] == [1, 2, 3]
    assert entries[1].previous_event_sha256 == entries[0].event_sha256
    assert entries[2].previous_event_sha256 == entries[1].event_sha256
    assert journal.verify().valid is True


def test_append_many_prevalidation_is_atomic_for_oversized_event(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    journal.append(
        {"kind": "existing"},
        recorded_at_utc="2026-10-20T09:00:00Z",
    )
    original = path.read_bytes()

    with pytest.raises(EvidenceJournalError, match="Groessenlimit"):
        journal.append_many(
            (
                {"kind": "would-have-fit"},
                {"value": "x" * evidence_module.MAX_JOURNAL_LINE_BYTES},
            ),
            recorded_at_utc="2026-10-20T10:00:00Z",
        )

    assert path.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Dateimodi sind unter Windows anders")
def test_journal_and_atomic_files_use_private_permissions(tmp_path: Path) -> None:
    private_dir = tmp_path / "private"
    private_dir.mkdir(mode=0o775)
    private_dir.chmod(0o775)
    journal_path = private_dir / "evidence.jsonl"
    EvidenceJournal(journal_path).append(
        {"kind": "private"},
        recorded_at_utc="2026-10-20T10:00:00Z",
    )
    lock_path = private_dir / ".evidence.jsonl.lock"
    journal_path.chmod(0o664)
    assert EvidenceJournal(journal_path).verify().valid

    assert stat.S_IMODE(private_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(mode=0o775)
    cache_dir.chmod(0o775)
    cache_path = cache_dir / "entry.json"
    atomic_write_json(cache_path, {"private": True})
    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(cache_path.stat().st_mode) == 0o600


def test_append_has_no_total_event_count_or_journal_size_cap(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    assert not hasattr(evidence_module, "MAX_JOURNAL_BYTES")

    for batch_index in range(13):
        entries = journal.append_many(
            ({"batch": batch_index, "item": item} for item in range(5)),
            recorded_at_utc="2026-10-20T10:01:00Z",
        )
        assert len(entries) == 5

    verification = journal.verify()
    assert verification.valid is True
    assert verification.entries_count == 65


def test_repeated_five_event_batches_scan_existing_chain_only_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    original_read_entries = evidence_module._read_entries
    verification_calls = 0

    def counting_read_entries(file_handle: object, *, end_offset: int | None = None) -> object:
        nonlocal verification_calls
        verification_calls += 1
        return original_read_entries(file_handle, end_offset=end_offset)

    monkeypatch.setattr(evidence_module, "_read_entries", counting_read_entries)
    for batch_index in range(13):
        entries = journal.append_many(
            ({"batch": batch_index, "item": item} for item in range(5)),
            recorded_at_utc="2026-10-20T10:01:00Z",
        )
        assert len(entries) == 5

    assert verification_calls == 1
    assert len(path.read_bytes().splitlines()) == 65


def test_verify_completes_exact_prepared_partial_batch_after_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    journal.append(
        {"kind": "existing"},
        recorded_at_utc="2026-10-20T09:00:00Z",
    )
    original_size = path.stat().st_size
    original_write_all = evidence_module._write_all
    write_calls = 0

    def interrupt_journal_write(file_descriptor: int, data: bytes) -> None:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 3:
            original_write_all(file_descriptor, data[: max(1, len(data) // 2)])
            raise OSError("simulierter Absturz beim Journal-Append")
        original_write_all(file_descriptor, data)

    monkeypatch.setattr(evidence_module, "_write_all", interrupt_journal_write)
    with pytest.raises(EvidenceJournalError, match="konnte nicht erweitert"):
        journal.append_many(
            ({"batch": 1, "item": item} for item in range(5)),
            recorded_at_utc="2026-10-20T10:00:00Z",
        )

    pending_path = path.with_name(f".{path.name}.pending")
    assert pending_path.is_file()
    assert path.stat().st_size > original_size
    monkeypatch.setattr(evidence_module, "_write_all", original_write_all)

    recovered_journal = EvidenceJournal(path)
    verification = recovered_journal.verify()

    assert verification.valid is True
    assert verification.entries_count == 6
    assert not pending_path.exists()
    stored_events = [json.loads(line)["event"] for line in path.read_bytes().splitlines()]
    assert stored_events[0] == {"kind": "existing"}
    assert stored_events[1:] == [{"batch": 1, "item": item} for item in range(5)]
    assert recovered_journal.append({"kind": "after-recovery"}).sequence == 7


def test_verify_does_not_repair_tail_that_differs_from_prepared_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    journal.append(
        {"kind": "existing"},
        recorded_at_utc="2026-10-20T09:00:00Z",
    )
    original_size = path.stat().st_size
    original_write_all = evidence_module._write_all
    write_calls = 0

    def interrupt_journal_write(file_descriptor: int, data: bytes) -> None:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 3:
            original_write_all(file_descriptor, data[: max(1, len(data) // 2)])
            raise OSError("simulierter Absturz beim Journal-Append")
        original_write_all(file_descriptor, data)

    monkeypatch.setattr(evidence_module, "_write_all", interrupt_journal_write)
    with pytest.raises(EvidenceJournalError):
        journal.append_many(
            ({"batch": 1, "item": item} for item in range(5)),
            recorded_at_utc="2026-10-20T10:00:00Z",
        )
    monkeypatch.setattr(evidence_module, "_write_all", original_write_all)

    tampered = bytearray(path.read_bytes())
    tampered[original_size] ^= 1
    path.write_bytes(tampered)
    pending_path = path.with_name(f".{path.name}.pending")
    before_verification = path.read_bytes()

    verification = EvidenceJournal(path).verify()

    assert verification.valid is False
    assert "Journalende passt nicht" in (verification.error or "")
    assert path.read_bytes() == before_verification
    assert pending_path.is_file()


def test_verification_detects_modified_event(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    journal = EvidenceJournal(path)
    journal.append(
        {"confirmed": True},
        recorded_at_utc="2026-10-20T10:00:00Z",
    )
    path.write_bytes(path.read_bytes().replace(b"true", b"false"))

    verification = journal.verify()

    assert verification.valid is False
    assert "Hash" in (verification.error or "")


def test_append_refuses_incomplete_existing_journal(tmp_path: Path) -> None:
    path = tmp_path / "evidence.jsonl"
    path.write_bytes(b'{"unvollstaendig":true}')

    with pytest.raises(EvidenceJournalError, match="unvollstaendigen Zeile"):
        EvidenceJournal(path).append({"new": "event"})

    assert path.read_bytes() == b'{"unvollstaendig":true}'


def test_append_refuses_event_larger_than_journal_line_limit(tmp_path: Path) -> None:
    from bittorrent_beobachter.evidence import MAX_JOURNAL_LINE_BYTES

    path = tmp_path / "evidence.jsonl"
    oversized_event = {"value": "x" * MAX_JOURNAL_LINE_BYTES}

    with pytest.raises(EvidenceJournalError, match="Groessenlimit"):
        EvidenceJournal(path).append(oversized_event)

    assert path.read_bytes() == b""


def test_append_evidence_returns_model_with_journal_hash(tmp_path: Path) -> None:
    handshake = _confirmed_handshake()
    enrichment = NetworkEnrichment(
        ip="8.8.8.8",
        enriched_at_utc="2026-10-20T10:02:00Z",
        prefix="8.8.8.0/24",
        asns=(15169,),
        holder="Example Network",
    )
    vpn = VpnClassification(status="unknown")
    path = tmp_path / "evidence.jsonl"

    record = EvidenceJournal(path).append_evidence(handshake, enrichment, vpn)

    assert len(record.evidence_event_sha256) == 64
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["event_sha256"] == record.evidence_event_sha256
    assert stored["event"]["handshake"]["candidate"]["ip"] == "8.8.8.8"


def test_append_evidence_rejects_unconfirmed_handshake(tmp_path: Path) -> None:
    handshake = _confirmed_handshake()
    unconfirmed = HandshakeResult(
        candidate=handshake.candidate,
        attempted_at_utc=handshake.attempted_at_utc,
        completed_at_utc=None,
        confirmed=False,
        remote_peer_id_hex=None,
        reserved_bits_hex=None,
        local_ip=None,
        local_port=None,
        bytes_sent=68,
        bytes_received=0,
        error="timeout",
    )
    enrichment = NetworkEnrichment(
        ip=handshake.candidate.ip,
        enriched_at_utc="2026-10-20T10:02:00Z",
    )

    with pytest.raises(ValueError, match="bestaetigte Handshakes"):
        EvidenceJournal(tmp_path / "evidence.jsonl").append_evidence(
            unconfirmed,
            enrichment,
            VpnClassification(status="unknown"),
        )


def test_append_evidence_compares_ipv6_addresses_semantically(tmp_path: Path) -> None:
    handshake = _confirmed_handshake("2606:4700:4700:0:0:0:0:1111")
    enrichment = NetworkEnrichment(
        ip="2606:4700:4700::1111",
        enriched_at_utc="2026-10-20T10:02:00Z",
    )

    record = EvidenceJournal(tmp_path / "evidence.jsonl").append_evidence(
        handshake,
        enrichment,
        VpnClassification(status="unknown"),
    )

    assert record.handshake.candidate.ip == "2606:4700:4700:0:0:0:0:1111"


def test_atomic_write_json_replaces_complete_document(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    atomic_write_json(path, {"version": 1, "state": "old"})
    atomic_write_json(path, {"version": 2, "state": "new"})

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "state": "new",
        "version": 2,
    }
    assert not list(tmp_path.glob("*.tmp"))


def test_windows_lock_uses_one_stable_byte_for_lock_and_unlock() -> None:
    calls: list[tuple[int, int]] = []

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        @staticmethod
        def locking(_descriptor: int, mode: int, length: int) -> None:
            calls.append((mode, length))

    with tempfile.TemporaryFile("w+b") as lock_file:
        with _windows_region_lock(lock_file, FakeMsvcrt):
            assert lock_file.read(1) == b"\0"
        lock_file.seek(0, 2)
        assert lock_file.tell() == 1

    assert calls == [(FakeMsvcrt.LK_LOCK, 1), (FakeMsvcrt.LK_UNLCK, 1)]
