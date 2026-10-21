"""Orchestriert konvergierende Peer-Suche, Direktpruefung und lokale Berichte.

Das Modul ruft weder Torrent-Metadaten noch Inhaltsbloecke ab und teilt keine
Inhalte. Externe Netzregistrierungsabfragen erfolgen ausschliesslich nach
ausdruecklicher Aktivierung in der Konfiguration.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import secrets
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Awaitable, Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import BinaryIO

from . import APP_NAME, VERSION
from .config import AppConfig, ConfigError, config_from_dict, config_to_dict, load_config
from .dht import (
    BOOTSTRAP_ISSUE_DNS,
    BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS,
    BOOTSTRAP_ISSUE_RESOLVER,
    BOOTSTRAP_ISSUE_TIMEOUT,
    MAX_RESPONSE_BYTES,
    DHTConfig,
    DHTCrawler,
    resolve_bootstrap_nodes,
)
from .enrichment import (
    ENRICHMENT_CANCELLED_REASON,
    EnrichmentError,
    NetworkEnricher,
    VpnClassifier,
)
from .evidence import (
    EvidenceJournal,
    EvidenceJournalError,
    atomic_write_json,
    canonical_json_bytes,
)
from .models import (
    MAX_PEER_OBSERVATION_BYTES,
    MAX_PEER_OBSERVATION_MESSAGES,
    MAX_RETAINED_PEER_CONTROL_EVENTS,
    OBSERVATION_ROUNDING_TOLERANCE_SECONDS,
    REQUIRED_PEER_OBSERVATION_SECONDS,
    TERMINAL_PEER_DIAGNOSTIC_KINDS,
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerCandidate,
    ScanResult,
    Target,
    TargetScanMetrics,
    VpnClassification,
)
from .path_safety import is_link_like, path_has_link_like_component
from .peer import PeerVerifier
from .recovery import (
    EvidenceRecoveryError,
    LegacyRecoveryNotice,
    RecoveredEvidenceBatch,
    RecoveredRunContext,
    recover_evidence_journal,
)
from .reports import ReportConfig, generate_reports
from .run_store import RunStore
from .tracker import TrackerDiscoveryStats, discover_tracker_peers

ProgressCallback = Callable[[str], None]
ReportsReadyCallback = Callable[[Path, int], None]
EvidenceReadyCallback = Callable[[], Awaitable[None]]
EvidenceBatchCallback = Callable[[tuple[EvidenceRecord, ...]], None]
PERSIST_BATCH_SIZE = 5
PARALLEL_VERIFY_BATCHES = 8
VERIFY_IDLE_POLL_SECONDS = 0.1
EVIDENCE_SEMANTICS_VERSION = 2
MIN_FREE_SPACE_BYTES = 100_000_000


class MonitorError(RuntimeError):
    """Ein Prueflauf kann nicht verlaesslich fortgesetzt werden."""


class MonitorAlreadyRunningError(MonitorError):
    """Eine andere Instanz besitzt bereits die betriebssystemweite Sperre."""


class ScanCancelled(MonitorError):
    """Der Benutzer hat den laufenden Prueflauf kontrolliert abgebrochen."""


@dataclass(slots=True)
class _TargetRuntimeMetrics:
    """Kleine laufende Zaehler; Kandidaten und Resultate bleiben in SQLite."""

    target: Target
    dht_queries_started: int = 0
    dht_queries_completed: int = 0
    dht_queries_failed: int = 0
    tracker_queries_completed: int = 0
    tracker_queries_failed: int = 0
    verification_attempts: int = 0


def _utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _new_run_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{secrets.token_hex(4)}"


def _safe_error(error: BaseException) -> str:
    text = " ".join(str(error).replace("\x00", "").split())
    label = type(error).__name__
    return (f"{label}: {text}" if text else label)[:500]


def _path_has_symlink_component(path: Path) -> bool:
    return path_has_link_like_component(path)


def _ensure_private_directory(path: Path, *, app_owned: bool = False) -> Path:
    path = Path(path)
    if _path_has_symlink_component(path):
        raise MonitorError(f"Anwendungspfad darf keine Symlink-Komponente enthalten: {path}")
    existed = path.exists()
    if existed and not path.is_dir():
        raise MonitorError(f"Anwendungspfad ist kein Verzeichnis: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MonitorError(f"Anwendungsverzeichnis kann nicht angelegt werden: {path}") from exc
    if _path_has_symlink_component(path) or not path.is_dir():
        raise MonitorError(f"Anwendungspfad ist kein sicheres Verzeichnis: {path}")
    if existed and not app_owned:
        return path
    if os.name == "nt":  # pragma: no cover - Windows ACLs do not use POSIX modes
        with suppress(OSError):
            path.chmod(0o700)
    else:
        path.chmod(0o700)
    return path


def _ensure_private_file(path: Path) -> None:
    if os.name == "nt":  # pragma: no cover - Windows ACLs do not use POSIX modes
        with suppress(OSError):
            path.chmod(0o600)
    else:
        path.chmod(0o600)


def _enforce_storage_capacity(data_dir: Path) -> None:
    """Stoppt nur bei physisch knappem Datentraeger, nie nach einer Trefferzahl."""

    try:
        free_bytes = shutil.disk_usage(data_dir).free
    except OSError as exc:
        raise MonitorError("Freier Speicherplatz konnte nicht bestimmt werden.") from exc
    if free_bytes < MIN_FREE_SPACE_BYTES:
        raise MonitorError(
            "Weniger als 100 MB freier Speicherplatz. Bisherige Laufdaten bleiben "
            "lokal erhalten und werden beim naechsten Start vor einem neuen Lauf "
            "automatisch geprueft. Bitte Speicherplatz freigeben."
        )


def _lock_windows(file_handle: BinaryIO) -> None:  # pragma: no cover - Windows only
    import msvcrt

    file_handle.seek(0, os.SEEK_END)
    if file_handle.tell() == 0:
        file_handle.write(b"\0")
        file_handle.flush()
        os.fsync(file_handle.fileno())
    file_handle.seek(0)
    try:
        msvcrt.locking(file_handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        raise MonitorAlreadyRunningError("Ein anderer Prueflauf ist bereits aktiv.") from exc


def _unlock_windows(file_handle: BinaryIO) -> None:  # pragma: no cover - Windows only
    import msvcrt

    file_handle.seek(0)
    msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def single_instance_lock(path: Path) -> Iterator[None]:
    """Haelt eine nicht blockierende Kernel-Sperre fuer genau einen Prueflauf."""

    lock_path = Path(path)
    _ensure_private_directory(lock_path.parent)
    if is_link_like(lock_path):
        raise MonitorError(f"Sperrdatei darf kein symbolischer Link sein: {lock_path}")

    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP or is_link_like(lock_path):
            raise MonitorError(f"Sperrdatei darf kein symbolischer Link sein: {lock_path}") from exc
        raise MonitorError(f"Sperrdatei kann nicht sicher geoeffnet werden: {lock_path}") from exc

    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise MonitorError(f"Sperrdatei ist keine regulaere Datei: {lock_path}")
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        file_handle = os.fdopen(descriptor, "a+b", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise

    with file_handle:
        if os.name == "nt":  # pragma: no cover - Windows only
            _lock_windows(file_handle)
            try:
                yield
            finally:
                _unlock_windows(file_handle)
            return

        import fcntl

        try:
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise MonitorAlreadyRunningError(
                    "Ein anderer Prueflauf ist bereits aktiv."
                ) from exc
            raise
        try:
            yield
        finally:
            fcntl.flock(file_handle.fileno(), fcntl.LOCK_UN)


def _config_sha256(config: AppConfig) -> str:
    return hashlib.sha256(canonical_json_bytes(config_to_dict(config))).hexdigest()


def _software_sha256() -> str:
    """Hasht die ausgelieferten Python-Quellen oder ersatzweise die EXE."""

    digest = hashlib.sha256()
    package_dir = Path(__file__).resolve().parent
    source_files = sorted(package_dir.glob("*.py"), key=lambda path: path.name)
    if source_files:
        for path in source_files:
            payload = path.read_bytes()
            digest.update(path.name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
        return digest.hexdigest()

    if getattr(sys, "frozen", False):  # pragma: no cover - PyInstaller runtime
        executable = Path(sys.executable)
        with executable.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1_048_576), b""):
                digest.update(chunk)
        return digest.hexdigest()

    digest.update(
        canonical_json_bytes({"application": APP_NAME, "version": VERSION, "source": "unavailable"})
    )
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    """Berechnet einen Dateifingerabdruck ohne den Dateiinhalt zu puffern."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _report_file_count(output_dir: Path) -> int:
    """Zaehlt erzeugte Berichtsdateien ohne eine wachsende Pfadliste."""

    with os.scandir(output_dir) as entries:
        return sum(entry.is_file(follow_symlinks=False) for entry in entries)


def _dht_config(config: AppConfig) -> DHTConfig:
    settings = config.dht
    return DHTConfig(
        timeout_seconds=settings.timeout_seconds,
        overall_timeout_seconds=settings.overall_timeout_seconds,
        concurrency=settings.concurrency,
        max_response_bytes=MAX_RESPONSE_BYTES,
    )


def _group_range_rules(
    rules: Iterable[tuple[str, str]],
) -> dict[str, tuple[str, ...]]:
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    for network, provider in rules:
        grouped[provider].append(network)
    return {provider: tuple(networks) for provider, networks in grouped.items()}


def _group_marker_rules(
    rules: Iterable[tuple[str, tuple[str, ...]]],
) -> dict[str, tuple[str, ...]]:
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    for provider, markers in rules:
        grouped[provider].extend(markers)
    return {provider: tuple(markers) for provider, markers in grouped.items()}


async def _resolve_bootstrap(
    config: AppConfig,
    notices: list[str],
    progress: ProgressCallback,
) -> tuple[tuple[str, int], ...]:
    issue_counts: Counter[str] = Counter()

    def record_bootstrap_issue(category: str) -> None:
        issue_counts[category] += 1

    resolved = await resolve_bootstrap_nodes(
        config.dht.bootstrap_nodes,
        timeout=min(config.dht.timeout_seconds, 5.0),
        issue_hook=record_bootstrap_issue,
    )
    if issue_counts:
        labels = (
            (BOOTSTRAP_ISSUE_DNS, "DNS-Fehler"),
            (BOOTSTRAP_ISSUE_TIMEOUT, "Zeitlimit"),
            (BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS, "keine globale Adresse"),
            (BOOTSTRAP_ISSUE_RESOLVER, "Resolver-Fehler"),
        )
        details = ", ".join(
            f"{issue_counts[category]} {label}"
            for category, label in labels
            if issue_counts[category]
        )
        notice = (
            f"Bootstrap-Aufloesung: {len(resolved)} globale Endpunkte nutzbar; "
            f"{sum(issue_counts.values())} Teilproblem(e) ({details})."
        )
        notices.append(notice)
        progress(notice)
    if not resolved:
        notice = (
            "DHT-Bootstrap war nicht erreichbar. Konfigurierte UDP-Tracker werden "
            "weiterhin abgefragt."
        )
        notices.append(notice)
        progress(notice)
    return tuple(resolved)


async def _discover_target_until_quiet(
    config: AppConfig,
    target: Target,
    bootstrap_nodes: Sequence[tuple[str, int]],
    dht_node_id: bytes,
    store: RunStore,
    runtime: _TargetRuntimeMetrics,
    data_dir: Path,
    notices: list[str],
    progress: ProgressCallback,
) -> None:
    """Wiederholt beide Quellen bis zur konfigurierten Ruhephase ohne Neufund."""

    quiet_started_at: float | None = None
    new_candidates_in_round = 0
    rounds = 0
    dht_issue_count = 0
    tracker_outer_failures = 0
    tracker_cleanup_failures = 0
    crawler = (
        DHTCrawler(
            bootstrap_nodes,
            node_id=dht_node_id,
            config=_dht_config(config),
            frontier_directory=data_dir,
        )
        if bootstrap_nodes
        else None
    )

    async def persist_candidates(batch: tuple[PeerCandidate, ...]) -> None:
        nonlocal new_candidates_in_round
        if not 1 <= len(batch) <= PERSIST_BATCH_SIZE:
            raise MonitorError("Discovery-Callback lieferte keinen gueltigen Fuenferbatch.")
        if any(candidate.info_hash_hex != target.info_hash_hex for candidate in batch):
            raise MonitorError("Discovery lieferte einen Kandidaten fuer ein falsches Ziel.")
        _enforce_storage_capacity(data_dir)
        inserted = store.add_candidates(batch)
        if inserted:
            new_candidates_in_round += inserted
            progress(
                f"{target.label}: {inserted} neue eindeutige Kandidat(en) dauerhaft gespeichert."
            )

    async def discover_dht_round() -> bool:
        """Fuehrt genau einen DHT-Zeitschnitt mit isolierter Bilanz aus."""

        nonlocal dht_issue_count
        if crawler is None:
            return False
        try:
            await crawler.discover(
                target,
                candidate_callback=persist_candidates,
                collect=False,
            )
        except (OSError, TimeoutError) as exc:
            runtime.dht_queries_failed += 1
            dht_issue_count += 1
            progress(
                f"DHT-Runde fuer {target.label} hatte ein technisches Teilproblem "
                f"({type(exc).__name__})."
            )
        finally:
            runtime.dht_queries_started += crawler.queries_started
            runtime.dht_queries_completed += crawler.queries_completed
            runtime.dht_queries_failed += crawler.queries_failed
            dht_issue_count += crawler.issue_count
        return crawler.has_pending_work

    async def discover_tracker_round() -> None:
        """Fuehrt genau eine Tracker-Runde mit isolierter Bilanz aus."""

        nonlocal tracker_cleanup_failures, tracker_outer_failures
        if not target.trackers:
            return
        tracker_stats = TrackerDiscoveryStats()
        try:
            await discover_tracker_peers(
                target,
                target.trackers,
                timeout=config.dht.timeout_seconds,
                candidate_callback=persist_candidates,
                collect=False,
                stats=tracker_stats,
            )
        except (OSError, TimeoutError) as exc:
            runtime.tracker_queries_completed += tracker_stats.queries_completed
            runtime.tracker_queries_failed += (
                tracker_stats.queries_failed + tracker_stats.stop_queries_failed + 1
            )
            tracker_cleanup_failures += tracker_stats.stop_queries_failed
            tracker_outer_failures += 1
            progress(
                f"Tracker-Runde fuer {target.label} hatte ein technisches Teilproblem "
                f"({type(exc).__name__})."
            )
        else:
            runtime.tracker_queries_completed += tracker_stats.queries_completed
            runtime.tracker_queries_failed += (
                tracker_stats.queries_failed + tracker_stats.stop_queries_failed
            )
            tracker_cleanup_failures += tracker_stats.stop_queries_failed

    try:
        while True:
            rounds += 1
            new_candidates_in_round = 0
            dht_pending_work = False
            progress(f"Peer-Suche {target.label}: Runde {rounds} gestartet.")

            dht_task = asyncio.create_task(discover_dht_round()) if crawler is not None else None
            tracker_task = (
                asyncio.create_task(discover_tracker_round()) if target.trackers else None
            )
            source_tasks = tuple(task for task in (dht_task, tracker_task) if task is not None)
            if len(source_tasks) > 2:  # pragma: no cover - strukturelle Invariante
                raise AssertionError("Pro Ziel duerfen hoechstens zwei Peer-Quellen laufen.")
            try:
                await asyncio.gather(*source_tasks)
            except BaseException:
                for task in source_tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*source_tasks, return_exceptions=True)
                raise
            if dht_task is not None:
                dht_pending_work = dht_task.result()

            round_completed_at = time.monotonic()
            if dht_pending_work:
                quiet_started_at = None
            elif new_candidates_in_round or quiet_started_at is None:
                quiet_started_at = round_completed_at
            else:
                quiet_for = round_completed_at - quiet_started_at
                if rounds >= 2 and quiet_for >= config.dht.quiet_seconds:
                    break

            quiet_for = (
                0.0 if quiet_started_at is None else max(0.0, time.monotonic() - quiet_started_at)
            )
            await asyncio.sleep(
                min(
                    config.dht.refresh_interval_seconds,
                    max(0.0, config.dht.quiet_seconds - quiet_for),
                )
            )
    finally:
        if crawler is not None:
            crawler.close()

    if dht_issue_count:
        notice = (
            f"DHT-Suche fuer {target.label}: {runtime.dht_queries_completed} verwertbare "
            f"Antwort(en), {dht_issue_count} technische Teilmeldung(en)."
        )
        notices.append(notice)
        progress(notice)
    if tracker_outer_failures:
        notice = (
            f"Tracker-Suche fuer {target.label}: {tracker_outer_failures} Runde(n) mit "
            "technischen Teilproblemen; die DHT-Suche und weitere Runden liefen weiter."
        )
        notices.append(notice)
        progress(notice)
    if tracker_cleanup_failures:
        notice = (
            f"Tracker-Suche fuer {target.label}: STOPPED-Aufraeumen schlug bei "
            f"{tracker_cleanup_failures} Anfrage(n) fehl; kurzlebige Tracker-Eintraege "
            "koennen bis zu ihrem Ablauf sichtbar bleiben."
        )
        notices.append(notice)
        progress(notice)
    if runtime.dht_queries_completed == 0 and runtime.tracker_queries_completed == 0:
        raise MonitorError(
            f"Keine Peer-Quelle fuer {target.label} lieferte eine gueltige Antwort. "
            "Bitte Netzwerkzugang, Firewall und Tracker-Erreichbarkeit pruefen."
        )
    progress(
        f"Peer-Suche fuer {target.label} nach {rounds} Runde(n) und "
        f"{config.dht.quiet_seconds:g} Sekunden ohne neuen eindeutigen Kandidaten beendet."
    )


async def _discover_candidates_to_store(
    config: AppConfig,
    store: RunStore,
    data_dir: Path,
    runtimes: dict[str, _TargetRuntimeMetrics],
    progress: ProgressCallback,
) -> list[str]:
    if not config.targets:
        raise MonitorError("Mindestens ein Ziel ist fuer die Peer-Suche erforderlich.")

    notices: list[str] = []
    dht_node_id = secrets.token_bytes(20)
    bootstrap_nodes = await _resolve_bootstrap(config, notices, progress)
    if not bootstrap_nodes and not any(target.trackers for target in config.targets):
        raise MonitorError(
            "Kein globaler DHT-Bootstrap-Knoten und kein UDP-Tracker war konfiguriert."
        )

    target_tasks = tuple(
        asyncio.create_task(
            _discover_target_until_quiet(
                config,
                target,
                bootstrap_nodes,
                dht_node_id,
                store,
                runtimes[target.info_hash_hex],
                data_dir,
                notices,
                progress,
            )
        )
        for target in config.targets
    )
    outcomes = await asyncio.gather(*target_tasks, return_exceptions=True)
    failures: list[tuple[Target, BaseException]] = []
    for target, outcome in zip(config.targets, outcomes, strict=True):
        if isinstance(outcome, asyncio.CancelledError):
            raise outcome
        if isinstance(outcome, BaseException):
            failures.append((target, outcome))
    if failures:
        summary = ", ".join(
            f"{target.label} ({type(failure).__name__})" for target, failure in failures
        )
        aggregated = MonitorError(
            f"Peer-Suche war bei {len(failures)} von {len(config.targets)} Ziel(en) "
            f"nicht erfolgreich: {summary}."
        )
        for target, failure in failures[1:]:
            aggregated.add_note(f"Weiterer Zielfehler: {target.label} ({type(failure).__name__}).")
        raise aggregated from failures[0][1]
    return notices


def _failed_handshake(candidate: PeerCandidate, error: BaseException) -> HandshakeResult:
    return HandshakeResult(
        candidate=candidate,
        attempted_at_utc=_utc_now_text(),
        completed_at_utc=None,
        confirmed=False,
        remote_peer_id_hex=None,
        reserved_bits_hex=None,
        local_ip=None,
        local_port=None,
        bytes_sent=0,
        bytes_received=0,
        error=_safe_error(error),
    )


def _handshake_quality(result: HandshakeResult) -> tuple[int, int, int, int, int]:
    observation = result.availability
    return (
        int(result.offering_observed),
        int(result.confirmed),
        int(observation is not None and observation.piece_availability_announced),
        int(observation is not None and observation.unchoked),
        result.bytes_received,
    )


def _is_conclusive_full_window(result: HandshakeResult, requested_seconds: float) -> bool:
    """Erkennt nur intern konsistente, technisch fehlerfreie Vollbeobachtungen."""

    observation = result.availability
    if observation is None:
        return False
    minimum_control_bytes = HandshakeResult._minimum_recorded_control_bytes(
        observation.control_events
    )
    if (
        type(observation.messages_received) is not int
        or not 0 <= observation.messages_received <= MAX_PEER_OBSERVATION_MESSAGES
        or len(observation.control_events)
        != min(observation.messages_received, MAX_RETAINED_PEER_CONTROL_EVENTS)
        or type(observation.bytes_received) is not int
        or not 0 <= observation.bytes_received <= MAX_PEER_OBSERVATION_BYTES
        or minimum_control_bytes is None
    ):
        return False
    minimum_control_bytes += 4 * (observation.messages_received - len(observation.control_events))
    exact_control_bytes = (
        observation.bytes_received == minimum_control_bytes
        if observation.messages_received <= MAX_RETAINED_PEER_CONTROL_EVENTS
        else observation.bytes_received >= minimum_control_bytes
    )
    return bool(
        result.confirmed
        and result.error is None
        and result.bytes_sent == 73
        and result.bytes_received == 68 + observation.bytes_received
        and observation.completed_full_window
        and observation.error is None
        and observation.interested_sent
        and observation.termination_reason == "duration_elapsed"
        and abs(requested_seconds - REQUIRED_PEER_OBSERVATION_SECONDS)
        <= OBSERVATION_ROUNDING_TOLERANCE_SECONDS
        and abs(observation.requested_duration_seconds - requested_seconds)
        <= OBSERVATION_ROUNDING_TOLERANCE_SECONDS
        and observation.duration_seconds + OBSERVATION_ROUNDING_TOLERANCE_SECONDS
        >= observation.requested_duration_seconds
        and HandshakeResult._wall_clock_duration_is_consistent(observation)
        and HandshakeResult._control_event_times_are_consistent(observation)
        and exact_control_bytes
        and not any(
            event.kind in TERMINAL_PEER_DIAGNOSTIC_KINDS for event in observation.control_events
        )
        and observation.request_messages_sent == 0
        and observation.piece_payload_bytes_received == 0
        and observation.metadata_requests_sent == 0
    )


async def _verify_candidate_with_retries(
    candidate: PeerCandidate,
    info_hash: bytes,
    verifier: PeerVerifier,
    config: AppConfig,
    runtime: _TargetRuntimeMetrics,
) -> HandshakeResult:
    best: HandshakeResult | None = None
    for attempt in range(1, config.peer.retry_attempts + 1):
        runtime.verification_attempts += 1
        try:
            current = await verifier.verify(candidate, info_hash)
        except (OSError, TimeoutError) as exc:
            current = _failed_handshake(candidate, exc)
        if current.candidate != candidate:
            raise MonitorError("Peer-Pruefung lieferte ein Ergebnis fuer einen anderen Kandidaten.")
        if best is None or _handshake_quality(current) > _handshake_quality(best):
            best = current
        conclusive_full_window = _is_conclusive_full_window(
            current,
            config.peer.observation_seconds,
        )
        if current.offering_observed or conclusive_full_window:
            break
        if attempt < config.peer.retry_attempts and config.peer.retry_backoff_seconds:
            await asyncio.sleep(config.peer.retry_backoff_seconds)
    if best is None:  # pragma: no cover - retry_attempts ist validiert mindestens eins
        raise AssertionError("Peer-Pruefung erzeugte kein Ergebnis.")
    return best


async def _verify_candidate_batch(
    batch: Sequence[PeerCandidate],
    info_hashes: dict[str, bytes],
    verifier: PeerVerifier,
    config: AppConfig,
    runtimes: dict[str, _TargetRuntimeMetrics],
    completed_results: list[HandshakeResult | None],
) -> tuple[HandshakeResult, ...]:
    if len(completed_results) != len(batch):
        raise MonitorError("Ergebnisspeicher und Kandidatenbatch haben verschiedene Laengen.")

    async def verify(index: int, candidate: PeerCandidate) -> HandshakeResult:
        info_hash = info_hashes.get(candidate.info_hash_hex)
        runtime = runtimes.get(candidate.info_hash_hex)
        if info_hash is None or runtime is None:
            raise MonitorError("Handshake-Kandidat gehoert zu keinem konfigurierten Ziel.")
        result = await _verify_candidate_with_retries(
            candidate,
            info_hash,
            verifier,
            config,
            runtime,
        )
        completed_results[index] = result
        return result

    tasks = [asyncio.create_task(verify(index, candidate)) for index, candidate in enumerate(batch)]
    try:
        return tuple(await asyncio.gather(*tasks))
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def _verify_all_candidates(
    config: AppConfig,
    store: RunStore,
    data_dir: Path,
    runtimes: dict[str, _TargetRuntimeMetrics],
    progress: ProgressCallback,
    producers_done: asyncio.Event | None = None,
    evidence_ready: EvidenceReadyCallback | None = None,
) -> None:
    """Prueft alle persistierten Kandidaten fair und schreibt jeden Fuenferbatch."""

    target_hashes = tuple(target.info_hash_hex for target in config.targets)
    info_hashes = {target.info_hash_hex: target.info_hash for target in config.targets}
    requeued = store.requeue_in_progress()
    if requeued:
        progress(f"{requeued} unterbrochene Kandidatenpruefung(en) erneut eingeplant.")

    verifier = PeerVerifier(
        timeout=config.peer.timeout_seconds,
        observation_seconds=config.peer.observation_seconds,
    )
    checked = store.handshake_result_count(target_hashes)

    active_tasks: set[asyncio.Task[tuple[HandshakeResult, ...]]] = set()
    unpersisted_tasks: set[asyncio.Task[tuple[HandshakeResult, ...]]] = set()
    task_order: dict[asyncio.Task[tuple[HandshakeResult, ...]], int] = {}
    partial_results: dict[
        asyncio.Task[tuple[HandshakeResult, ...]], list[HandshakeResult | None]
    ] = {}
    next_task_order = 0

    def fill_available_slots() -> None:
        nonlocal next_task_order
        while len(active_tasks) < PARALLEL_VERIFY_BATCHES:
            batch = store.claim_candidate_batch(target_hashes, size=PERSIST_BATCH_SIZE)
            if not batch:
                break
            completed_results: list[HandshakeResult | None] = [None] * len(batch)
            task = asyncio.create_task(
                _verify_candidate_batch(
                    batch,
                    info_hashes,
                    verifier,
                    config,
                    runtimes,
                    completed_results,
                )
            )
            active_tasks.add(task)
            unpersisted_tasks.add(task)
            task_order[task] = next_task_order
            partial_results[task] = completed_results
            next_task_order += 1

    def persist_results(
        task: asyncio.Task[tuple[HandshakeResult, ...]],
        result_batch: tuple[HandshakeResult, ...],
        *,
        failure_completion: bool,
    ) -> tuple[HandshakeResult, ...]:
        nonlocal checked
        _enforce_storage_capacity(data_dir)
        checked += store.store_handshake_batch(result_batch, count_new_only=True)
        unpersisted_tasks.remove(task)
        task_order.pop(task)
        partial_results.pop(task)
        if failure_completion:
            progress(
                f"Fehlerabschluss: {checked} eindeutige Kandidat(en) mindestens einmal "
                "dauerhaft geprüft."
            )
        else:
            progress(
                f"Direkte Peer-Pruefung: {checked} eindeutige Kandidat(en) mindestens "
                "einmal dauerhaft geprüft."
            )
        return result_batch

    def persist_completed_task(
        task: asyncio.Task[tuple[HandshakeResult, ...]],
        *,
        failure_completion: bool,
    ) -> tuple[HandshakeResult, ...]:
        return persist_results(
            task,
            task.result(),
            failure_completion=failure_completion,
        )

    try:
        while True:
            fill_available_slots()
            if not active_tasks:
                if producers_done is None or producers_done.is_set():
                    break
                await asyncio.sleep(VERIFY_IDLE_POLL_SECONDS)
                continue

            completed_tasks, _pending_tasks = await asyncio.wait(
                active_tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            active_tasks.difference_update(completed_tasks)
            for completed in sorted(completed_tasks, key=task_order.__getitem__):
                result_batch = persist_completed_task(completed, failure_completion=False)
                fill_available_slots()
                if evidence_ready is not None and any(
                    result.offering_observed for result in result_batch
                ):
                    await evidence_ready()
    except BaseException as exc:
        for task in unpersisted_tasks:
            if not task.done():
                task.cancel()
        if unpersisted_tasks:
            await asyncio.gather(*unpersisted_tasks, return_exceptions=True)
        try:
            for task in sorted(tuple(unpersisted_tasks), key=task_order.__getitem__):
                result_batch = (
                    task.result()
                    if not task.cancelled() and task.exception() is None
                    else tuple(result for result in partial_results[task] if result is not None)
                )
                if result_batch:
                    persist_results(task, result_batch, failure_completion=True)
        except BaseException as drain_error:
            exc.add_note(
                "Ein bereits fertiger Kandidatenbatch konnte beim Fehlerabschluss nicht "
                f"persistiert werden: {_safe_error(drain_error)}"
            )
        try:
            store.requeue_in_progress()
        except Exception as requeue_error:
            exc.add_note(
                "Unterbrochene Kandidaten konnten nicht zurueckgestellt werden: "
                f"{_safe_error(requeue_error)}"
            )
        raise

    final_metrics = store.metrics_by_hash(target_hashes)
    unfinished = sum(metric.pending + metric.in_progress for metric in final_metrics.values())
    if unfinished:
        raise MonitorError(
            f"Interner Fehler: {unfinished} persistierte Kandidat(en) blieben ungeprueft."
        )
    progress(
        "Direkte Peer-Pruefung abgeschlossen: "
        f"{sum(metric.done for metric in final_metrics.values())} Kandidat(en), "
        f"{sum(metric.confirmed for metric in final_metrics.values())} Handshake(s), "
        f"{sum(metric.offering_observed for metric in final_metrics.values())} "
        "positive Verfuegbarkeitsbefund(e)."
    )


async def _network_phase(
    config: AppConfig,
    store: RunStore,
    data_dir: Path,
    runtimes: dict[str, _TargetRuntimeMetrics],
    progress: ProgressCallback,
    *,
    cancel_event: Event | None = None,
    evidence_ready: EvidenceReadyCallback | None = None,
) -> list[str]:
    producers_done = asyncio.Event()

    async def discover() -> list[str]:
        try:
            return await _discover_candidates_to_store(
                config,
                store,
                data_dir,
                runtimes,
                progress,
            )
        finally:
            producers_done.set()

    discovery_task = asyncio.create_task(discover())
    verification_task = asyncio.create_task(
        _verify_all_candidates(
            config,
            store,
            data_dir,
            runtimes,
            progress,
            producers_done,
            evidence_ready,
        )
    )
    tasks = (discovery_task, verification_task)
    cancellation_task: asyncio.Task[None] | None = None
    if cancel_event is not None:

        async def cancel_network_when_requested() -> None:
            while not cancel_event.is_set():
                await asyncio.sleep(VERIFY_IDLE_POLL_SECONDS)
            for task in tasks:
                task.cancel()

        cancellation_task = asyncio.create_task(cancel_network_when_requested())
    try:
        completed, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if verification_task in completed and not discovery_task.done():
            verification_task.result()
            raise MonitorError(
                "Direkte Peer-Pruefung endete unerwartet vor Abschluss der Peer-Suche."
            )

        discovery_failure: Exception | None = None
        try:
            notices = discovery_task.result()
        except Exception as exc:
            discovery_failure = exc
            notices = []

        try:
            await verification_task
        except Exception as exc:
            if discovery_failure is not None:
                exc.add_note(
                    "Die Peer-Suche war ebenfalls nicht erfolgreich "
                    f"({type(discovery_failure).__name__})."
                )
            raise
        if discovery_failure is not None:
            raise discovery_failure
    except asyncio.CancelledError as exc:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled("Der Prueflauf wurde vom Benutzer abgebrochen.") from exc
        raise
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    finally:
        if cancellation_task is not None:
            cancellation_task.cancel()
            await asyncio.gather(cancellation_task, return_exceptions=True)
    return notices


def _empty_enrichment(ip: str, *, reason: str | None = None) -> NetworkEnrichment:
    return NetworkEnrichment(
        ip=ip,
        enriched_at_utc=_utc_now_text(),
        error=reason,
    )


def _append_evidence_batch(
    journal: EvidenceJournal,
    handshakes: Sequence[HandshakeResult],
    enrichment: Sequence[tuple[NetworkEnrichment, VpnClassification]],
    *,
    run_id: str,
    config_sha256: str,
    software_sha256: str,
) -> tuple[EvidenceRecord, ...]:
    if len(handshakes) != len(enrichment):
        raise MonitorError("Evidenzbatch und Netzauskunft haben unterschiedliche Laengen.")
    events = [
        {
            "event_type": "observed_bittorrent_piece_availability",
            "run_id": run_id,
            "config_sha256": config_sha256,
            "software_sha256": software_sha256,
            "handshake": asdict(handshake),
            "enrichment": asdict(network_data),
            "vpn": asdict(vpn),
        }
        for handshake, (network_data, vpn) in zip(handshakes, enrichment, strict=True)
    ]
    entries = journal.append_many(events, recorded_at_utc=_utc_now_text())
    return tuple(
        EvidenceRecord(
            handshake=handshake,
            enrichment=network_data,
            vpn=vpn,
            evidence_event_sha256=entry.event_sha256,
        )
        for handshake, (network_data, vpn), entry in zip(
            handshakes,
            enrichment,
            entries,
            strict=True,
        )
    )


def _iter_offering_batches(
    store: RunStore,
    *,
    full_batches_only: bool = False,
) -> Iterator[tuple[HandshakeResult, ...]]:
    batch: list[HandshakeResult] = []
    for handshake in store.iter_unpersisted_offering_handshakes(batch_size=PERSIST_BATCH_SIZE):
        batch.append(handshake)
        if len(batch) == PERSIST_BATCH_SIZE:
            yield tuple(batch)
            batch.clear()
    if batch and not full_batches_only:
        yield tuple(batch)


def _persist_all_evidence(
    config: AppConfig,
    data_dir: Path,
    store: RunStore,
    journal: EvidenceJournal,
    result: ScanResult,
    progress: ProgressCallback,
    *,
    config_sha256: str,
    software_sha256: str,
    cancel_event: Event | None = None,
    full_batches_only: bool = False,
    batch_persisted: EvidenceBatchCallback | None = None,
) -> int:
    """Reichert jeden positiven Befund an und persistiert ihn sofort in Fuenferbatches."""

    classifier = VpnClassifier(
        vpn_ranges=_group_range_rules(config.enrichment.vpn_ranges),
        vpn_provider_markers=_group_marker_rules(config.enrichment.vpn_provider_markers),
    )
    enricher: NetworkEnricher | None = None
    if config.enrichment.enabled:
        cache_root = _ensure_private_directory(data_dir / "cache", app_owned=True)
        cache_dir = _ensure_private_directory(cache_root / "network", app_owned=True)
        enricher = NetworkEnricher(
            cache_dir,
            timeout_seconds=config.enrichment.timeout_seconds,
            cache_days=config.enrichment.cache_days,
            external_lookup_enabled=True,
            max_retries=0,
        )

    stored = store.evidence_count()
    known_vpn_count = 0
    enrichment_failures: Counter[str] = Counter()
    for handshake_batch in _iter_offering_batches(store, full_batches_only=full_batches_only):
        enriched_batch: list[tuple[NetworkEnrichment, VpnClassification]] = []
        for handshake in handshake_batch:
            ip = handshake.candidate.ip
            offline_vpn = classifier.classify(ip)
            if offline_vpn.status == "known_vpn":
                enriched_batch.append((_empty_enrichment(ip), offline_vpn))
                continue
            if enricher is None:
                enriched_batch.append(
                    (
                        _empty_enrichment(
                            ip,
                            reason="Externe Netzregistrierungsabfrage ist deaktiviert.",
                        ),
                        offline_vpn,
                    )
                )
                continue

            if cancel_event is not None and cancel_event.is_set():
                enrichment_failures["abgebrochen"] += 1
                enriched_batch.append(
                    (_empty_enrichment(ip, reason=ENRICHMENT_CANCELLED_REASON), offline_vpn)
                )
                continue

            progress(f"Netzregistrierungsabfrage fuer positiven Befund {stored + 1}.")
            try:
                network_data = enricher.enrich(ip, cancel_event=cancel_event)
            except (EnrichmentError, OSError) as exc:
                enrichment_failures[type(exc).__name__] += 1
                network_data = _empty_enrichment(ip, reason=_safe_error(exc))
            else:
                if network_data.error:
                    enrichment_failures["unvollstaendig"] += 1
            enriched_batch.append((network_data, classifier.classify(network_data)))

        batch_vpn_count = sum(vpn.status == "known_vpn" for _data, vpn in enriched_batch)
        known_vpn_count += batch_vpn_count
        _enforce_storage_capacity(data_dir)
        records = _append_evidence_batch(
            journal,
            handshake_batch,
            enriched_batch,
            run_id=result.run_id,
            config_sha256=config_sha256,
            software_sha256=software_sha256,
        )
        store.store_evidence_batch(records)
        stored += len(records)
        progress(f"{stored} positive Befund(e) dauerhaft als Evidenz gespeichert.")
        if batch_persisted is not None:
            batch_persisted(records)

    if enrichment_failures:
        total = sum(enrichment_failures.values())
        result.enrichment_failure_count += total
        prefix = "Netzauskunft war bei "
        result.notices[:] = [notice for notice in result.notices if not notice.startswith(prefix)]
        result.notices.append(
            f"{prefix}{result.enrichment_failure_count} positivem Befund(en) "
            "unvollstaendig oder nicht erreichbar; die technischen Beobachtungen "
            "wurden dennoch gespeichert."
        )
    return known_vpn_count


def _refresh_result_metrics(
    result: ScanResult,
    config: AppConfig,
    store: RunStore,
    runtimes: dict[str, _TargetRuntimeMetrics],
) -> None:
    result.target_metrics = _build_target_metrics(config, store, runtimes)
    result.candidate_count = sum(item.candidates_discovered for item in result.target_metrics)
    result.handshake_count = sum(item.candidates_checked for item in result.target_metrics)
    result.confirmed_handshake_count = sum(
        item.confirmed_handshakes for item in result.target_metrics
    )
    result.offering_observation_count = sum(
        item.positive_findings for item in result.target_metrics
    )


def _build_target_metrics(
    config: AppConfig,
    store: RunStore,
    runtimes: dict[str, _TargetRuntimeMetrics],
) -> tuple[TargetScanMetrics, ...]:
    target_hashes = tuple(target.info_hash_hex for target in config.targets)
    stored = store.metrics_by_hash(target_hashes)
    reasons = store.failure_reasons_by_hash(target_hashes)
    metrics: list[TargetScanMetrics] = []
    for target in config.targets:
        runtime = runtimes[target.info_hash_hex]
        aggregate = stored[target.info_hash_hex]
        metrics.append(
            TargetScanMetrics(
                target_label=target.label,
                info_hash_hex=target.info_hash_hex,
                dht_queries_started=runtime.dht_queries_started,
                dht_queries_completed=runtime.dht_queries_completed,
                dht_queries_failed=runtime.dht_queries_failed,
                tracker_queries_completed=runtime.tracker_queries_completed,
                tracker_queries_failed=runtime.tracker_queries_failed,
                candidates_discovered=aggregate.candidates,
                candidates_checked=aggregate.handshake_results,
                verification_attempts=runtime.verification_attempts,
                confirmed_handshakes=aggregate.confirmed,
                piece_availability_observed=aggregate.piece_availability,
                unchoke_observed=aggregate.unchoked,
                positive_findings=aggregate.offering_observed,
                terminal_failures=aggregate.terminal_failures,
                failure_reasons=tuple(sorted(reasons[target.info_hash_hex].items())),
            )
        )
    return tuple(metrics)


def _report_config(config: AppConfig) -> ReportConfig:
    settings = config.reporting
    return ReportConfig(
        reporter_name=settings.reporter_name,
        reporter_contact=settings.reporter_email,
        reporter_email=settings.reporter_email or None,
        recipient_name="Polizeidienststelle",
        recipient_email=settings.police_recipient or None,
        legal_notes=settings.legal_notes,
    )


def _load_recovery_config(
    current_config: AppConfig,
    evidence_dir: Path,
    *,
    run_id: str,
    config_sha256: str,
    config_snapshot: str | None,
    config_snapshot_file_sha256: str | None,
) -> AppConfig | None:
    """Laedt den unveraenderlichen Lauf-Snapshot oder einen passenden Legacy-Stand."""

    if (config_snapshot is None) != (config_snapshot_file_sha256 is None):
        raise MonitorError(f"Lauf {run_id!r} hat eine unvollstaendige Snapshot-Bindung.")
    if config_snapshot is None:
        return current_config if _config_sha256(current_config) == config_sha256 else None

    snapshot_path = evidence_dir / "runs" / config_snapshot
    if is_link_like(snapshot_path) or not snapshot_path.is_file():
        raise MonitorError(f"Konfigurationssnapshot fuer Lauf {run_id!r} fehlt.")
    try:
        snapshot_file_hash = _file_sha256(snapshot_path)
    except OSError as exc:
        raise MonitorError(
            f"Konfigurationssnapshot fuer Lauf {run_id!r} kann nicht gelesen werden."
        ) from exc
    if not secrets.compare_digest(snapshot_file_hash, config_snapshot_file_sha256):
        raise MonitorError(f"Konfigurationssnapshot fuer Lauf {run_id!r} ist veraendert.")
    try:
        recovered_config = load_config(snapshot_path)
    except ConfigError as exc:
        raise MonitorError(
            f"Konfigurationssnapshot fuer Lauf {run_id!r} ist ungueltig: {_safe_error(exc)}"
        ) from exc
    if not secrets.compare_digest(_config_sha256(recovered_config), config_sha256):
        raise MonitorError(f"Konfigurationssnapshot fuer Lauf {run_id!r} passt nicht zum Journal.")
    return recovered_config


def _recovery_report_is_complete(output_dir: Path, report_run_id: str) -> bool:
    """Prueft ein bereits publiziertes Recovery-Paket gegen sein Manifest."""

    manifest_path = output_dir / f"{report_run_id}_SHA256SUMS.txt"
    try:
        if (
            is_link_like(output_dir)
            or not output_dir.is_dir()
            or is_link_like(output_dir.parent)
            or output_dir.resolve(strict=True).parent != output_dir.parent.resolve(strict=True)
        ):
            return False
        if is_link_like(manifest_path) or not manifest_path.is_file():
            return False
        if manifest_path.stat().st_size > 4_000_000:
            return False
        seen_names: set[str] = set()
        run_id_header_count = 0
        with manifest_path.open("r", encoding="utf-8", newline=None) as handle:
            while raw_line := handle.readline(4_097):
                if len(raw_line) > 4_096:
                    return False
                line = raw_line.rstrip("\r\n")
                if not line:
                    continue
                if line.startswith("#"):
                    if line.startswith("# Lauf-ID: "):
                        run_id_header_count += 1
                        if not secrets.compare_digest(
                            line.removeprefix("# Lauf-ID: "),
                            report_run_id,
                        ):
                            return False
                    continue
                digest, separator, file_name = line.partition(" *")
                if (
                    not separator
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                    or not file_name
                    or file_name.strip() != file_name
                    or file_name in {".", ".."}
                    or "/" in file_name
                    or "\\" in file_name
                    or "\x00" in file_name
                    or file_name in seen_names
                ):
                    return False
                report_path = output_dir / file_name
                if is_link_like(report_path) or not report_path.is_file():
                    return False
                if not secrets.compare_digest(_file_sha256(report_path), digest):
                    return False
                seen_names.add(file_name)

        if run_id_header_count != 1:
            return False
        actual_names: set[str] = set()
        with os.scandir(output_dir) as entries:
            for entry in entries:
                if is_link_like(Path(entry.path)):
                    return False
                if entry.is_dir(follow_symlinks=False):
                    return False
                if not entry.is_file(follow_symlinks=False):
                    return False
                actual_names.add(entry.name)
    except (OSError, UnicodeError):
        return False

    required_suffixes = (
        "_laufbericht.pdf",
        "_beobachtungen.csv",
        "_vpn_liste.csv",
        "_vpn_liste.pdf",
    )
    return actual_names == seen_names | {manifest_path.name} and all(
        f"{report_run_id}{suffix}" in seen_names for suffix in required_suffixes
    )


def _quarantine_invalid_recovery_report_directory(output_dir: Path) -> None:
    """Verschiebt ein defektes app-eigenes Batchverzeichnis verlustfrei beiseite."""

    try:
        if not is_link_like(output_dir):
            with os.scandir(output_dir) as entries:
                if next(entries, None) is None:
                    return
    except OSError as exc:
        raise MonitorError(
            f"Recovery-Berichtsverzeichnis kann nicht geprueft werden: {output_dir}"
        ) from exc

    parent = output_dir.parent
    for _attempt in range(100):
        quarantine_dir = parent / f".{output_dir.name}.defekt-{secrets.token_hex(4)}"
        if quarantine_dir.exists() or is_link_like(quarantine_dir):
            continue
        try:
            os.replace(output_dir, quarantine_dir)
            _ensure_private_directory(output_dir, app_owned=True)
        except OSError as exc:
            raise MonitorError(
                "Beschaedigtes Recovery-Berichtsverzeichnis kann nicht verlustfrei "
                f"beiseite verschoben werden: {output_dir}"
            ) from exc
        return
    raise MonitorError(
        f"Kein sicherer Quarantaenename fuer Recovery-Berichte verfuegbar: {output_dir}"
    )


def _publish_recovered_batch(
    batch: RecoveredEvidenceBatch,
    config: AppConfig,
    data_dir: Path,
    progress: ProgressCallback,
    reports_ready: ReportsReadyCallback | None,
) -> None:
    """Erzeugt ein idempotentes, sofort nutzbares Berichtspaket fuer hoechstens 5 Befunde."""

    digest = hashlib.sha256(
        "\n".join(record.evidence_event_sha256 for record in batch.records).encode("ascii")
    ).hexdigest()[:16]
    report_run_id = f"recovery-{batch.run_id[-32:]}-{digest}"
    reports_root = data_dir / "reports"
    if is_link_like(reports_root):
        raise MonitorError(f"Recovery-Berichtswurzel darf kein Symlink sein: {reports_root}")
    reports_root = _ensure_private_directory(reports_root, app_owned=True)
    run_output_path = reports_root / batch.run_id
    if is_link_like(run_output_path):
        raise MonitorError(f"Recovery-Laufverzeichnis darf kein Symlink sein: {run_output_path}")
    run_output_dir = _ensure_private_directory(run_output_path, app_owned=True)
    batch_output_path = run_output_dir / f"wiederhergestellt-{digest}"
    batch_output_dir = (
        batch_output_path
        if is_link_like(batch_output_path)
        else _ensure_private_directory(batch_output_path, app_owned=True)
    )
    if not _recovery_report_is_complete(batch_output_dir, report_run_id):
        _quarantine_invalid_recovery_report_directory(batch_output_dir)
        generated_at = _utc_now_text()
        result = ScanResult(
            run_id=report_run_id,
            started_at_utc=min(record.handshake.attempted_at_utc for record in batch.records),
            completed_at_utc=generated_at,
            records=list(batch.records),
            candidate_count=len(batch.records),
            handshake_count=len(batch.records),
            confirmed_handshake_count=sum(record.handshake.confirmed for record in batch.records),
            offering_observation_count=len(batch.records),
            known_vpn_total=sum(record.vpn.status == "known_vpn" for record in batch.records),
            notices=[
                "Diese Befunde wurden nach einem unterbrochenen Lauf aus dem "
                "verifizierten Evidenzjournal wiederhergestellt."
            ],
        )
        generated_paths = generate_reports(
            result,
            batch_output_dir,
            _report_config(config),
            generated_at_utc=generated_at,
        )
        for path in generated_paths:
            _ensure_private_file(path)
    progress(
        f"{len(batch.records)} Befund(e) aus Lauf {batch.run_id} wurden "
        "wiederhergestellt und als Berichte bereitgestellt."
    )
    if reports_ready is not None:
        reports_ready(run_output_dir, len(batch.records))


def _recover_previous_runs(
    current_config: AppConfig,
    data_dir: Path,
    evidence_dir: Path,
    journal: EvidenceJournal,
    progress: ProgressCallback,
    reports_ready: ReportsReadyCallback | None,
) -> None:
    """Reconciliert Journal und Laufdatenbanken vor jedem neuen Netzwerkzugriff."""

    def recovery_config(
        *,
        run_id: str,
        config_sha256: str,
        config_snapshot: str | None,
        config_snapshot_file_sha256: str | None,
    ) -> AppConfig | None:
        return _load_recovery_config(
            current_config,
            evidence_dir,
            run_id=run_id,
            config_sha256=config_sha256,
            config_snapshot=config_snapshot,
            config_snapshot_file_sha256=config_snapshot_file_sha256,
        )

    def publish_reconciled(batch: RecoveredEvidenceBatch) -> None:
        config = recovery_config(
            run_id=batch.run_id,
            config_sha256=batch.config_sha256,
            config_snapshot=batch.config_snapshot,
            config_snapshot_file_sha256=batch.config_snapshot_file_sha256,
        )
        if config is None:
            progress(
                f"Legacy-Lauf {batch.run_id} wurde in der Laufdatenbank abgeglichen; "
                "sein damaliger Konfigurationsstand ist nicht mehr verfuegbar, daher "
                "wurde kein neuer Bericht erzeugt."
            )
            return
        _publish_recovered_batch(batch, config, data_dir, progress, reports_ready)

    def persist_incomplete(context: RecoveredRunContext) -> None:
        config = recovery_config(
            run_id=context.run_id,
            config_sha256=context.config_sha256,
            config_snapshot=context.config_snapshot,
            config_snapshot_file_sha256=context.config_snapshot_file_sha256,
        )
        if config is None:
            progress(
                f"Legacy-Lauf {context.run_id} hat unverarbeitete Befunde, kann aber "
                "ohne seinen damaligen Konfigurationsstand nicht automatisch "
                "fertiggestellt werden."
            )
            return
        store = RunStore(context.store_path)
        result = ScanResult(
            run_id=context.run_id,
            started_at_utc=_utc_now_text(),
            run_store_path=context.store_path,
        )

        def publish_new_records(records: tuple[EvidenceRecord, ...]) -> None:
            publish_reconciled(
                RecoveredEvidenceBatch(
                    run_id=context.run_id,
                    config_sha256=context.config_sha256,
                    software_sha256=context.software_sha256,
                    config_snapshot=context.config_snapshot,
                    config_snapshot_file_sha256=context.config_snapshot_file_sha256,
                    records=records,
                    evidence_semantics_version=context.evidence_semantics_version,
                )
            )

        _persist_all_evidence(
            config,
            data_dir,
            store,
            journal,
            result,
            progress,
            config_sha256=context.config_sha256,
            software_sha256=context.software_sha256,
            batch_persisted=publish_new_records,
        )

    def report_legacy_skip(notice: LegacyRecoveryNotice) -> None:
        progress(f"Legacy-Lauf {notice.run_id} wurde nicht migriert: {notice.reason}")

    try:
        summary = recover_evidence_journal(
            evidence_dir,
            on_reconciled=publish_reconciled,
            on_incomplete_run=persist_incomplete,
            on_legacy_skipped=report_legacy_skip,
        )
    except EvidenceJournalError as exc:
        raise MonitorError(
            "Das Evidenzjournal ist beschaedigt; die Wiederherstellung wurde vor "
            f"allen Netzwerkzugriffen abgebrochen: {_safe_error(exc)}"
        ) from exc
    except (EvidenceRecoveryError, OSError, ValueError, TypeError) as exc:
        raise MonitorError(
            "Fruehere Laufdaten konnten vor dem neuen Lauf nicht sicher "
            f"wiederhergestellt werden: {_safe_error(exc)}"
        ) from exc
    if summary.inserted_records:
        progress(
            f"{summary.inserted_records} journalisierte Befund(e) wurden vor dem "
            "neuen Lauf in ihre Laufdatenbank uebernommen."
        )


def _run_scan_locked_impl(
    config: AppConfig,
    data_dir: Path,
    progress: ProgressCallback,
    failure_state: list[tuple[EvidenceJournal, str, str, str, Path]],
    *,
    cancel_event: Event | None = None,
    reports_ready: ReportsReadyCallback | None = None,
) -> ScanResult:
    _enforce_storage_capacity(data_dir)
    evidence_dir = _ensure_private_directory(data_dir / "evidence", app_owned=True)
    run_store_dir = _ensure_private_directory(evidence_dir / "runs", app_owned=True)
    reports_dir = _ensure_private_directory(data_dir / "reports", app_owned=True)
    journal_path = evidence_dir / "events.jsonl"
    journal = EvidenceJournal(journal_path)
    _recover_previous_runs(
        config,
        data_dir,
        evidence_dir,
        journal,
        progress,
        reports_ready,
    )
    verification = journal.verify()
    if not verification.valid:
        raise MonitorError(
            "Das Evidenzjournal ist beschaedigt; der Lauf wurde vor allen "
            f"Netzwerkzugriffen abgebrochen: {verification.error or 'unbekannter Fehler'}"
        )

    run_id = _new_run_id()
    started_at = _utc_now_text()
    run_store_path = run_store_dir / f"{run_id}.sqlite3"
    store = RunStore(run_store_path)
    _ensure_private_file(run_store_path)
    result = ScanResult(
        run_id=run_id,
        started_at_utc=started_at,
        run_store_path=run_store_path,
    )
    runtimes = {
        target.info_hash_hex: _TargetRuntimeMetrics(target=target) for target in config.targets
    }
    output_dir = _ensure_private_directory(reports_dir / run_id, app_owned=True)

    config_hash = _config_sha256(config)
    software_hash = _software_sha256()
    config_snapshot_path = run_store_dir / f"{run_id}.config.json"
    atomic_write_json(config_snapshot_path, config_to_dict(config))
    _ensure_private_file(config_snapshot_path)
    config_snapshot_file_hash = _file_sha256(config_snapshot_path)
    journal.append(
        {
            "event_type": "scan_started",
            "run_id": run_id,
            "config_sha256": config_hash,
            "config_snapshot": config_snapshot_path.name,
            "config_snapshot_file_sha256": config_snapshot_file_hash,
            "evidence_semantics_version": EVIDENCE_SEMANTICS_VERSION,
            "software_sha256": software_hash,
            "targets": [
                {"label": target.label, "info_hash": target.info_hash_hex}
                for target in config.targets
            ],
            "network_enrichment_enabled": config.enrichment.enabled,
        },
        recorded_at_utc=started_at,
    )
    _ensure_private_file(journal_path)
    failure_state.append((journal, run_id, config_hash, software_hash, journal_path))
    intermediate_batch_number = 0

    def publish_report_snapshot(records: tuple[EvidenceRecord, ...]) -> None:
        nonlocal intermediate_batch_number
        batch_count = len(records)
        if not 1 <= batch_count <= PERSIST_BATCH_SIZE:
            raise MonitorError("Zwischenbericht erhielt keinen gueltigen Fuenferbatch.")
        intermediate_batch_number += 1
        result.known_vpn_total += sum(record.vpn.status == "known_vpn" for record in records)
        generated_at = _utc_now_text()
        batch_run_id = f"{run_id}-zwischenstand-{intermediate_batch_number:06d}"
        batch_result = ScanResult(
            run_id=batch_run_id,
            started_at_utc=result.started_at_utc,
            completed_at_utc=generated_at,
            records=list(records),
            candidate_count=batch_count,
            handshake_count=batch_count,
            confirmed_handshake_count=sum(record.handshake.confirmed for record in records),
            offering_observation_count=batch_count,
            known_vpn_total=sum(record.vpn.status == "known_vpn" for record in records),
        )
        batch_output_dir = _ensure_private_directory(
            output_dir / f"zwischenstand-{intermediate_batch_number:06d}",
            app_owned=True,
        )
        generated_paths = generate_reports(
            batch_result,
            batch_output_dir,
            _report_config(config),
            generated_at_utc=generated_at,
        )
        for path in generated_paths:
            _ensure_private_file(path)
        evidence_count = store.evidence_count()
        progress(
            f"{evidence_count} positive Befund(e) sind fertig im Ergebnisordner "
            f"gespeichert (+{batch_count}, Zwischenstand {intermediate_batch_number})."
        )
        if reports_ready is not None:
            reports_ready(output_dir, evidence_count)

    async def persist_ready_batches() -> None:
        worker = asyncio.create_task(
            asyncio.to_thread(
                _persist_all_evidence,
                config,
                data_dir,
                store,
                journal,
                result,
                progress,
                config_sha256=config_hash,
                software_sha256=software_hash,
                cancel_event=cancel_event,
                full_batches_only=True,
                batch_persisted=publish_report_snapshot,
            )
        )
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            # Ein Thread lässt sich nach dem Start nicht sicher abbrechen. Vor der
            # kontrollierten Beendigung muss deshalb genau dieser Writer fertig sein,
            # damit Journal, SQLite und Bericht nicht parallel erneut beschrieben werden.
            await asyncio.shield(worker)
            raise

    network_notices: list[str] = []
    network_failure: MonitorError | None = None

    def mark_cancelled() -> None:
        if result.cancelled:
            return
        result.cancelled = True
        result.notices.append(
            "Der Prueflauf wurde kontrolliert abgebrochen; alle bis dahin "
            "gefundenen positiven Befunde wurden fertig ausgegeben."
        )
        progress("Prueflauf wird kontrolliert beendet; Restbefunde werden gespeichert.")

    def mark_cancelled_if_requested() -> None:
        if cancel_event is not None and cancel_event.is_set():
            mark_cancelled()

    try:
        network_notices = asyncio.run(
            _network_phase(
                config,
                store,
                data_dir,
                runtimes,
                progress,
                cancel_event=cancel_event,
                evidence_ready=persist_ready_batches,
            )
        )
    except ScanCancelled:
        mark_cancelled()
    except TimeoutError as exc:
        network_failure = MonitorError(
            "Eine einzelne Netzwerkoperation ueberschritt ihr Zeitlimit."
        )
        network_failure.__cause__ = exc
    except OSError as exc:
        network_failure = MonitorError(
            "Die Peer-Suche oder Direktpruefung scheiterte wegen eines Netzwerkfehlers."
        )
        network_failure.__cause__ = exc
    except MonitorError as exc:
        network_failure = exc
    if network_failure is not None:
        result.errors.append(str(network_failure))
    result.notices.extend(network_notices)
    mark_cancelled_if_requested()
    _persist_all_evidence(
        config,
        data_dir,
        store,
        journal,
        result,
        progress,
        config_sha256=config_hash,
        software_sha256=software_hash,
        cancel_event=cancel_event,
        batch_persisted=lambda records: setattr(
            result,
            "known_vpn_total",
            result.known_vpn_total + sum(record.vpn.status == "known_vpn" for record in records),
        ),
    )
    mark_cancelled_if_requested()
    _refresh_result_metrics(result, config, store, runtimes)

    result.completed_at_utc = _utc_now_text()
    _enforce_storage_capacity(data_dir)
    generated_paths = generate_reports(
        result,
        output_dir,
        _report_config(config),
        generated_at_utc=result.completed_at_utc,
    )
    for path in generated_paths:
        if path not in result.report_paths:
            result.report_paths.append(path)
        _ensure_private_file(path)
    if reports_ready is not None:
        reports_ready(output_dir, store.evidence_count())

    manifest_path = generated_paths[-1]
    terminal_event = (
        "scan_failed"
        if network_failure is not None
        else "scan_cancelled"
        if result.cancelled
        else "scan_completed"
    )

    journal.append(
        {
            "event_type": terminal_event,
            "run_id": run_id,
            "config_sha256": config_hash,
            "config_snapshot": config_snapshot_path.name,
            "config_snapshot_file_sha256": config_snapshot_file_hash,
            "software_sha256": software_hash,
            "completed_at_utc": result.completed_at_utc,
            "candidate_count": result.total_candidate_count,
            "handshake_count": result.total_handshake_count,
            "confirmed_count": result.confirmed_count,
            "evidence_count": store.evidence_count(),
            "target_metrics": [asdict(item) for item in result.target_metrics],
            "report_file_count": _report_file_count(output_dir),
            "report_manifest": manifest_path.name,
            "report_manifest_sha256": _file_sha256(manifest_path),
            "warning_count": len(result.errors),
            "notice_count": len(result.notices),
            "operational_notices": list(result.notices),
            **(
                {
                    "error_type": type(network_failure).__name__,
                    "error": _safe_error(network_failure),
                }
                if network_failure is not None
                else {}
            ),
        },
        recorded_at_utc=result.completed_at_utc,
    )
    # Ab hier existiert bereits ein terminales Ereignis. Ein nachfolgender
    # Dateirechtefehler darf nicht durch den Wrapper als zweites scan_failed
    # journalisiert werden.
    failure_state.clear()
    _ensure_private_file(journal_path)
    if network_failure is not None:
        progress(
            f"Prueflauf {run_id} mit Netzwerkfehler beendet; vorhandene Ergebnisse sind fertig."
        )
        raise network_failure
    if result.cancelled:
        progress(f"Prueflauf {run_id} kontrolliert abgebrochen; vorhandene Ergebnisse sind fertig.")
    else:
        progress(f"Prueflauf {run_id} abgeschlossen.")
    return result


def _run_scan_locked(
    config: AppConfig,
    data_dir: Path,
    progress: ProgressCallback,
    *,
    cancel_event: Event | None = None,
    reports_ready: ReportsReadyCallback | None = None,
) -> ScanResult:
    failure_state: list[tuple[EvidenceJournal, str, str, str, Path]] = []
    try:
        return _run_scan_locked_impl(
            config,
            data_dir,
            progress,
            failure_state,
            cancel_event=cancel_event,
            reports_ready=reports_ready,
        )
    except BaseException as exc:
        if failure_state:
            journal, run_id, config_hash, software_hash, journal_path = failure_state[0]
            failed_at = _utc_now_text()
            try:
                journal.append(
                    {
                        "event_type": "scan_failed",
                        "run_id": run_id,
                        "config_sha256": config_hash,
                        "software_sha256": software_hash,
                        "failed_at_utc": failed_at,
                        "error_type": type(exc).__name__,
                        "error": _safe_error(exc),
                    },
                    recorded_at_utc=failed_at,
                )
                _ensure_private_file(journal_path)
            except BaseException as journal_error:
                exc.add_note(
                    "scan_failed konnte nicht ins Evidenzjournal geschrieben werden: "
                    f"{_safe_error(journal_error)}"
                )
        raise


def run_scan(
    config: AppConfig,
    data_dir: Path,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: Event | None = None,
    reports_ready: ReportsReadyCallback | None = None,
) -> ScanResult:
    """Fuehrt einen gesperrten, konvergierenden und speicherschonenden Prueflauf aus."""

    if not isinstance(config, AppConfig):
        raise TypeError("config muss eine AppConfig sein.")
    validated_config = config_from_dict(config_to_dict(config))
    if not validated_config.targets:
        raise MonitorError("Mindestens ein Ziel ist fuer einen Prueflauf erforderlich.")
    requested_runtime_dir = Path(data_dir).expanduser().absolute()
    if _path_has_symlink_component(requested_runtime_dir):
        raise MonitorError(
            f"Der Datenpfad darf keine Symlink-Komponente enthalten: {requested_runtime_dir}"
        )
    runtime_dir = requested_runtime_dir.resolve()
    forbidden_data_dirs = {
        Path(runtime_dir.anchor),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    }
    if runtime_dir in forbidden_data_dirs:
        raise MonitorError(
            "Der Datenpfad muss ein eigener Anwendungsordner sein; ein "
            "Wurzel-, Home- oder gemeinsamer Temp-Ordner ist nicht zulaessig."
        )
    # Ein ausdrücklich gewählter, bereits vorhandener Stammordner kann auch
    # anderweitig genutzt werden. Seine Zugriffsrechte werden deshalb niemals
    # still verändert; nur neu angelegte Stammordner und unsere eigenen
    # Unterordner werden auf private Rechte gesetzt.
    _ensure_private_directory(runtime_dir, app_owned=False)
    callback = progress or (lambda _message: None)
    with single_instance_lock(runtime_dir / "monitor.lock"):
        return _run_scan_locked(
            validated_config,
            runtime_dir,
            callback,
            cancel_event=cancel_event,
            reports_ready=reports_ready,
        )
