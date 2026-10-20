"""Orchestriert begrenzte DHT-Suche, Handshake-Pruefung und lokale Berichte.

Das Modul nutzt weder Tracker noch Funktionen zum Abruf oder Teilen von
Torrent-Inhalten. Externe Netzregistrierungsabfragen erfolgen ausschliesslich
nach ausdruecklicher Aktivierung in der Konfiguration.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import math
import os
import secrets
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from . import APP_NAME, VERSION
from .config import AppConfig, config_from_dict, config_to_dict
from .dht import (
    BOOTSTRAP_ISSUE_DNS,
    BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS,
    BOOTSTRAP_ISSUE_RESOLVER,
    BOOTSTRAP_ISSUE_TIMEOUT,
    MAX_BOOTSTRAP_RESULTS,
    MAX_OVERALL_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    DHTConfig,
    DHTCrawler,
    resolve_bootstrap_nodes,
)
from .enrichment import EnrichmentError, NetworkEnricher, VpnClassifier
from .evidence import EvidenceJournal, canonical_json_bytes
from .models import (
    EvidenceRecord,
    HandshakeResult,
    NetworkEnrichment,
    PeerCandidate,
    ScanResult,
    Target,
    VpnClassification,
)
from .peer import PeerVerifier
from .reports import ReportConfig, generate_reports

ProgressCallback = Callable[[str], None]
NETWORK_PHASE_TIMEOUT_SECONDS = 600.0
MAX_EXTERNAL_ENRICHMENTS_PER_RUN = 20
MAX_CANDIDATES_PER_RUN = 10_000
MAX_REPORT_STORAGE_BYTES = 1_000_000_000
REPORT_RUN_RESERVE_BYTES = 100_000_000
MAX_EVIDENCE_STORAGE_BYTES = 32 * 1024 * 1024
EVIDENCE_RUN_RESERVE_BYTES = 8 * 1024 * 1024


class MonitorError(RuntimeError):
    """Ein Prueflauf kann nicht verlaesslich fortgesetzt werden."""


class MonitorAlreadyRunningError(MonitorError):
    """Eine andere Instanz besitzt bereits die betriebssystemweite Sperre."""


def _utc_now_text() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _new_run_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{secrets.token_hex(4)}"


def _safe_error(error: BaseException) -> str:
    text = " ".join(str(error).replace("\x00", "").split())
    label = type(error).__name__
    return (f"{label}: {text}" if text else label)[:500]


def _ensure_private_directory(path: Path, *, app_owned: bool = False) -> Path:
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
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


def _directory_size(path: Path, *, stop_after: int) -> int:
    """Summiert reguläre Dateien ohne Symlink-Folgen und bricht begrenzt ab."""

    if not path.exists():
        return 0
    total = 0
    pending = [path]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    continue
                if entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                    if total > stop_after:
                        return total
    return total


def _enforce_storage_capacity(data_dir: Path) -> None:
    checks = (
        (
            data_dir / "reports",
            MAX_REPORT_STORAGE_BYTES,
            REPORT_RUN_RESERVE_BYTES,
            "Berichtsablage",
        ),
        (
            data_dir / "evidence",
            MAX_EVIDENCE_STORAGE_BYTES,
            EVIDENCE_RUN_RESERVE_BYTES,
            "Evidenzjournal-Ablage",
        ),
    )
    for path, hard_limit, reserve, label in checks:
        threshold = hard_limit - reserve
        used = _directory_size(path, stop_after=threshold)
        if used > threshold:
            raise MonitorError(
                f"{label} hat die sichere Kapazitätsgrenze von "
                f"{hard_limit // 1_000_000} MB fast erreicht. Es wird nichts "
                "automatisch gelöscht. Bitte vorhandene Daten nachvollziehbar "
                "archivieren oder die Ablage wechseln und den Prüflauf erneut starten."
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
    with lock_path.open("a+b", buffering=0) as file_handle:
        # Manche Windows-Dateisysteme bilden POSIX-Modi nicht ab.
        with suppress(OSError):
            lock_path.chmod(0o600)

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


def _dht_config(config: AppConfig) -> DHTConfig:
    settings = config.dht
    query_waves = math.ceil(settings.max_queries / settings.alpha)
    overall_timeout = min(
        MAX_OVERALL_TIMEOUT_SECONDS,
        max(settings.timeout_seconds, settings.timeout_seconds * query_waves),
    )
    return DHTConfig(
        timeout_seconds=settings.timeout_seconds,
        overall_timeout_seconds=overall_timeout,
        max_queries=settings.max_queries,
        concurrency=settings.alpha,
        max_nodes=settings.max_nodes,
        max_candidates=settings.max_candidates,
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


def _fair_handshake_candidates(
    targets: Iterable[Target],
    candidates: Iterable[PeerCandidate],
    limit: int,
) -> list[PeerCandidate]:
    """Waehlt reihum pro Ziel, damit ein grosser Schwarm andere nicht verdraengt."""

    grouped: defaultdict[str, list[PeerCandidate]] = defaultdict(list)
    seen: set[tuple[str, str, int]] = set()
    for candidate in candidates:
        key = (candidate.info_hash_hex, candidate.ip, candidate.port)
        if key in seen:
            continue
        seen.add(key)
        grouped[candidate.info_hash_hex].append(candidate)

    target_hashes = [target.info_hash_hex for target in targets]
    offsets = {info_hash: 0 for info_hash in target_hashes}
    selected: list[PeerCandidate] = []
    while len(selected) < limit:
        added = False
        for info_hash in target_hashes:
            items = grouped.get(info_hash, [])
            offset = offsets[info_hash]
            if offset >= len(items):
                continue
            selected.append(items[offset])
            offsets[info_hash] = offset + 1
            added = True
            if len(selected) >= limit:
                break
        if not added:
            break
    return selected


async def _discover_candidates(
    config: AppConfig,
    progress: ProgressCallback,
) -> tuple[list[PeerCandidate], list[str]]:
    if not config.targets:
        raise MonitorError("Mindestens ein Ziel ist für die DHT-Suche erforderlich.")

    dht_config = _dht_config(config)
    per_target_candidate_limit = min(
        dht_config.max_candidates,
        max(1, MAX_CANDIDATES_PER_RUN // len(config.targets)),
    )
    target_dht_config = (
        dht_config
        if per_target_candidate_limit == dht_config.max_candidates
        else replace(dht_config, max_candidates=per_target_candidate_limit)
    )
    notices: list[str] = []
    if per_target_candidate_limit < dht_config.max_candidates:
        notice = (
            "Das laufweite Sicherheitslimit begrenzt die DHT-Kandidaten auf "
            f"{per_target_candidate_limit} pro Ziel."
        )
        notices.append(notice)
        progress(notice)

    bootstrap_issues: Counter[str] = Counter()

    def record_bootstrap_issue(category: str) -> None:
        bootstrap_issues[category] += 1

    resolved = await resolve_bootstrap_nodes(
        config.dht.bootstrap_nodes,
        timeout=min(config.dht.timeout_seconds, 5.0),
        max_results=min(config.dht.max_nodes, MAX_BOOTSTRAP_RESULTS),
        issue_hook=record_bootstrap_issue,
    )
    if not resolved:
        raise MonitorError("Kein globaler DHT-Bootstrap-Knoten konnte aufgeloest werden.")

    if bootstrap_issues:
        issue_labels = (
            (BOOTSTRAP_ISSUE_DNS, "DNS-Fehler"),
            (BOOTSTRAP_ISSUE_TIMEOUT, "Zeitlimit"),
            (BOOTSTRAP_ISSUE_NO_GLOBAL_ADDRESS, "keine globale Adresse"),
            (BOOTSTRAP_ISSUE_RESOLVER, "Resolver-Fehler"),
        )
        details = ", ".join(
            f"{bootstrap_issues[category]} {label}"
            for category, label in issue_labels
            if bootstrap_issues[category]
        )
        notice = (
            f"Bootstrap-Auflösung: {len(resolved)} globale Endpunkte nutzbar; "
            f"{sum(bootstrap_issues.values())} Teilproblem(e) ({details})."
        )
        notices.append(notice)
        progress(notice)

    candidates: list[PeerCandidate] = []
    responsive_targets = 0
    for index, target in enumerate(config.targets, start=1):
        progress(f"DHT-Suche {index}/{len(config.targets)}: {target.label}")
        crawler = DHTCrawler(resolved, config=target_dht_config)
        discovered = await crawler.discover(target)
        if crawler.queries_completed == 0:
            notice = (
                f"DHT-Suche fuer {target.label}: In diesem Lauf antwortete kein "
                "DHT-Knoten; dieses Ziel wurde uebersprungen."
            )
            notices.append(notice)
            progress(notice)
            continue

        responsive_targets += 1
        crawler_errors = tuple(getattr(crawler, "errors", ()))
        crawler_issue_count = getattr(crawler, "issue_count", len(crawler_errors))
        if type(crawler_issue_count) is not int or crawler_issue_count < 0:
            crawler_issue_count = len(crawler_errors)
        if crawler_issue_count:
            notice = (
                f"DHT-Suche fuer {target.label}: {crawler.queries_completed} "
                f"verwertbare Antwort(en); {crawler_issue_count} technische "
                "Teilmeldung(en) wurden protokolliert."
            )
            notices.append(notice)
            progress(notice)
        if any(candidate.info_hash_hex != target.info_hash_hex for candidate in discovered):
            raise MonitorError("Die DHT-Suche lieferte einen Kandidaten fuer ein falsches Ziel.")
        if len(discovered) > target_dht_config.max_candidates:
            raise MonitorError("Die DHT-Suche überschritt das feste Kandidatenlimit eines Ziels.")
        candidates.extend(discovered)
        progress(
            f"DHT-Suche {index}/{len(config.targets)} abgeschlossen: {len(discovered)} Kandidat(en)"
        )

    if responsive_targets == 0:
        raise MonitorError("Keines der konfigurierten DHT-Ziele erhielt eine verwertbare Antwort.")
    return candidates, notices


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


async def _verify_candidates(
    config: AppConfig,
    candidates: list[PeerCandidate],
    progress: ProgressCallback,
) -> list[HandshakeResult]:
    selected = _fair_handshake_candidates(
        config.targets,
        candidates,
        config.peer.max_checks,
    )
    if not selected:
        return []

    info_hashes = {target.info_hash_hex: target.info_hash for target in config.targets}
    verifier = PeerVerifier(timeout=config.peer.timeout_seconds)
    work_queue: asyncio.Queue[tuple[int, PeerCandidate]] = asyncio.Queue()
    for index, candidate in enumerate(selected):
        work_queue.put_nowait((index, candidate))
    ordered: list[HandshakeResult | None] = [None] * len(selected)

    async def worker() -> None:
        while True:
            try:
                index, candidate = work_queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                info_hash = info_hashes.get(candidate.info_hash_hex)
                if info_hash is None:
                    raise MonitorError("Handshake-Kandidat gehoert zu keinem konfigurierten Ziel.")
                try:
                    ordered[index] = await verifier.verify(candidate, info_hash)
                except (OSError, TimeoutError) as exc:
                    ordered[index] = _failed_handshake(candidate, exc)
            finally:
                work_queue.task_done()

    worker_count = min(config.peer.workers, len(selected))
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    if any(item is None for item in ordered):
        raise MonitorError("Interner Fehler: Nicht alle Handshake-Aufgaben wurden abgeschlossen.")
    results = [item for item in ordered if item is not None]
    progress(
        f"Handshake-Pruefung abgeschlossen: {sum(item.confirmed for item in results)} "
        f"von {len(results)} bestaetigt"
    )
    return results


async def _network_phase(
    config: AppConfig,
    progress: ProgressCallback,
) -> tuple[list[PeerCandidate], list[HandshakeResult], list[str]]:
    candidates, notices = await _discover_candidates(config, progress)
    handshakes = await _verify_candidates(config, candidates, progress)
    return candidates, handshakes, notices


async def _bounded_network_phase(
    config: AppConfig,
    progress: ProgressCallback,
) -> tuple[list[PeerCandidate], list[HandshakeResult], list[str]]:
    network_task = asyncio.create_task(_network_phase(config, progress))
    try:
        done, _pending = await asyncio.wait(
            (network_task,),
            timeout=NETWORK_PHASE_TIMEOUT_SECONDS,
        )
    except BaseException:
        network_task.cancel()
        await asyncio.gather(network_task, return_exceptions=True)
        raise

    if network_task not in done:
        network_task.cancel()
        await asyncio.gather(network_task, return_exceptions=True)
        raise MonitorError(
            "Die gesamte DHT- und Handshake-Netzwerkphase hat die harte "
            f"Zeitgrenze von {int(NETWORK_PHASE_TIMEOUT_SECONDS)} Sekunden erreicht."
        )
    if network_task.cancelled():
        raise MonitorError("Die DHT- und Handshake-Netzwerkphase wurde unerwartet abgebrochen.")

    try:
        return network_task.result()
    except TimeoutError as exc:
        raise MonitorError(
            "Eine einzelne Operation der DHT- oder Handshake-Phase überschritt ihr Zeitlimit."
        ) from exc
    except OSError as exc:
        raise MonitorError(
            "Die DHT- oder Handshake-Phase scheiterte wegen eines Netzwerkfehlers."
        ) from exc


def _empty_enrichment(ip: str, *, reason: str | None = None) -> NetworkEnrichment:
    return NetworkEnrichment(
        ip=ip,
        enriched_at_utc=_utc_now_text(),
        error=reason,
    )


def _rotated_external_ips(ips: tuple[str, ...], run_id: str) -> frozenset[str]:
    """Begrenzt Abfragen und variiert den Startpunkt deterministisch je Lauf."""

    if len(ips) <= MAX_EXTERNAL_ENRICHMENTS_PER_RUN:
        return frozenset(ips)
    offset = int.from_bytes(
        hashlib.sha256(run_id.encode("utf-8")).digest()[:8],
        "big",
    ) % len(ips)
    rotated = ips[offset:] + ips[:offset]
    return frozenset(rotated[:MAX_EXTERNAL_ENRICHMENTS_PER_RUN])


def _enrich_confirmed_handshakes(
    config: AppConfig,
    data_dir: Path,
    handshakes: Iterable[HandshakeResult],
    result: ScanResult,
    progress: ProgressCallback,
) -> dict[str, tuple[NetworkEnrichment, VpnClassification]]:
    classifier = VpnClassifier(
        vpn_ranges=_group_range_rules(config.enrichment.vpn_ranges),
        vpn_provider_markers=_group_marker_rules(config.enrichment.vpn_provider_markers),
    )
    confirmed_ips = tuple(
        dict.fromkeys(handshake.candidate.ip for handshake in handshakes if handshake.confirmed)
    )
    enriched: dict[str, tuple[NetworkEnrichment, VpnClassification]] = {}
    enricher: NetworkEnricher | None = None
    offline_classifications = {ip: classifier.classify(ip) for ip in confirmed_ips}
    external_candidates = tuple(
        ip for ip in confirmed_ips if offline_classifications[ip].status != "known_vpn"
    )
    selected_external_ips = _rotated_external_ips(external_candidates, result.run_id)
    if config.enrichment.enabled and len(external_candidates) > MAX_EXTERNAL_ENRICHMENTS_PER_RUN:
        result.notices.append(
            "Externe Netzauskunft wurde aus Datenschutz- und Laufzeitgründen auf "
            f"{MAX_EXTERNAL_ENRICHMENTS_PER_RUN} bestätigte IP-Adressen begrenzt; "
            f"{len(external_candidates) - MAX_EXTERNAL_ENRICHMENTS_PER_RUN} weitere "
            "IP-Adresse(n) wurden in diesem Lauf nicht extern angereichert."
        )

    for index, ip in enumerate(confirmed_ips, start=1):
        offline_vpn = offline_classifications[ip]
        if offline_vpn.status == "known_vpn":
            network_data = _empty_enrichment(ip)
            enriched[ip] = network_data, offline_vpn
            continue

        if not config.enrichment.enabled:
            network_data = _empty_enrichment(
                ip,
                reason="Externe Netzregistrierungsabfrage ist deaktiviert.",
            )
            enriched[ip] = network_data, offline_vpn
            continue

        if ip not in selected_external_ips:
            network_data = _empty_enrichment(
                ip,
                reason=(
                    "In diesem Lauf nicht extern angereichert: Mengenlimit von "
                    f"{MAX_EXTERNAL_ENRICHMENTS_PER_RUN} IP-Adressen erreicht."
                ),
            )
            enriched[ip] = network_data, offline_vpn
            continue

        if enricher is None:
            cache_root = _ensure_private_directory(
                data_dir / "cache",
                app_owned=True,
            )
            cache_dir = _ensure_private_directory(
                cache_root / "network",
                app_owned=True,
            )
            enricher = NetworkEnricher(
                cache_dir,
                timeout_seconds=config.enrichment.timeout_seconds,
                cache_days=config.enrichment.cache_days,
                external_lookup_enabled=config.enrichment.enabled,
                max_retries=0,
            )
        progress(
            f"Netzregistrierungsabfrage {index}/{len(confirmed_ips)} fuer eine "
            "bestaetigte IP-Adresse"
        )
        try:
            network_data = enricher.enrich(ip)
        except (EnrichmentError, OSError) as exc:
            error_text = _safe_error(exc)
            network_data = _empty_enrichment(ip, reason=error_text)
            result.notices.append(
                f"Netzauskunft für eine bestätigte IP fehlgeschlagen ({type(exc).__name__})."
            )
        else:
            if network_data.error:
                result.notices.append(
                    "Netzauskunft für eine bestätigte IP war unvollständig; "
                    "Details stehen im privaten Bericht."
                )
        enriched[ip] = network_data, classifier.classify(network_data)
    return enriched


def _append_evidence_records(
    journal: EvidenceJournal,
    handshakes: Iterable[HandshakeResult],
    enrichment_by_ip: dict[str, tuple[NetworkEnrichment, VpnClassification]],
    *,
    run_id: str,
    config_sha256: str,
    software_sha256: str,
) -> list[EvidenceRecord]:
    confirmed = [handshake for handshake in handshakes if handshake.confirmed]
    events = []
    for handshake in confirmed:
        enrichment, vpn = enrichment_by_ip[handshake.candidate.ip]
        events.append(
            {
                "event_type": "confirmed_bittorrent_handshake",
                "run_id": run_id,
                "config_sha256": config_sha256,
                "software_sha256": software_sha256,
                "handshake": asdict(handshake),
                "enrichment": asdict(enrichment),
                "vpn": asdict(vpn),
            }
        )
    entries = journal.append_many(events, recorded_at_utc=_utc_now_text())
    records: list[EvidenceRecord] = []
    for handshake, entry in zip(confirmed, entries, strict=True):
        enrichment, vpn = enrichment_by_ip[handshake.candidate.ip]
        records.append(
            EvidenceRecord(
                handshake=handshake,
                enrichment=enrichment,
                vpn=vpn,
                evidence_event_sha256=entry.event_sha256,
            )
        )
    return records


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


def _run_scan_locked_impl(
    config: AppConfig,
    data_dir: Path,
    progress: ProgressCallback,
    failure_state: list[tuple[EvidenceJournal, str, str, str, Path]],
) -> ScanResult:
    _enforce_storage_capacity(data_dir)
    run_id = _new_run_id()
    started_at = _utc_now_text()
    result = ScanResult(run_id=run_id, started_at_utc=started_at)
    evidence_dir = _ensure_private_directory(
        data_dir / "evidence",
        app_owned=True,
    )
    journal_path = evidence_dir / "events.jsonl"
    journal = EvidenceJournal(journal_path)
    verification = journal.verify()
    if not verification.valid:
        raise MonitorError(
            "Das Evidenzjournal ist beschaedigt; der Lauf wurde vor allen "
            f"Netzwerkzugriffen abgebrochen: {verification.error or 'unbekannter Fehler'}"
        )

    config_hash = _config_sha256(config)
    software_hash = _software_sha256()
    journal.append(
        {
            "event_type": "scan_started",
            "run_id": run_id,
            "config_sha256": config_hash,
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

    candidates, handshakes, dht_notices = asyncio.run(_bounded_network_phase(config, progress))
    result.candidates.extend(candidates)
    result.handshakes.extend(handshakes)
    result.notices.extend(dht_notices)

    enrichment_by_ip = _enrich_confirmed_handshakes(
        config,
        data_dir,
        handshakes,
        result,
        progress,
    )
    result.records.extend(
        _append_evidence_records(
            journal,
            handshakes,
            enrichment_by_ip,
            run_id=run_id,
            config_sha256=config_hash,
            software_sha256=software_hash,
        )
    )

    result.completed_at_utc = _utc_now_text()
    reports_dir = _ensure_private_directory(
        data_dir / "reports",
        app_owned=True,
    )
    output_dir = _ensure_private_directory(
        reports_dir / run_id,
        app_owned=True,
    )
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

    journal.append(
        {
            "event_type": "scan_completed",
            "run_id": run_id,
            "config_sha256": config_hash,
            "software_sha256": software_hash,
            "completed_at_utc": result.completed_at_utc,
            "candidate_count": len(result.candidates),
            "handshake_count": len(result.handshakes),
            "confirmed_count": result.confirmed_count,
            "evidence_count": len(result.records),
            "report_files": [path.name for path in result.report_paths],
            "warning_count": len(result.errors),
            "notice_count": len(result.notices),
            "operational_notices": list(result.notices),
        },
        recorded_at_utc=result.completed_at_utc,
    )
    _ensure_private_file(journal_path)
    failure_state.clear()
    progress(f"Prueflauf {run_id} abgeschlossen.")
    return result


def _run_scan_locked(
    config: AppConfig,
    data_dir: Path,
    progress: ProgressCallback,
) -> ScanResult:
    failure_state: list[tuple[EvidenceJournal, str, str, str, Path]] = []
    try:
        return _run_scan_locked_impl(
            config,
            data_dir,
            progress,
            failure_state,
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
) -> ScanResult:
    """Fuehrt genau einen gesperrten, mengenbegrenzten Prueflauf aus."""

    if not isinstance(config, AppConfig):
        raise TypeError("config muss eine AppConfig sein.")
    validated_config = config_from_dict(config_to_dict(config))
    if not validated_config.targets:
        raise MonitorError("Mindestens ein Ziel ist fuer einen Prueflauf erforderlich.")
    runtime_dir = Path(data_dir).expanduser().resolve()
    forbidden_data_dirs = {
        Path(runtime_dir.anchor),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    }
    if runtime_dir in forbidden_data_dirs:
        raise MonitorError(
            "Der Datenpfad muss ein eigener Anwendungsordner sein; ein "
            "Wurzel-, Home- oder gemeinsamer Temp-Ordner ist nicht zulässig."
        )
    _ensure_private_directory(runtime_dir, app_owned=True)
    callback = progress or (lambda _message: None)
    with single_instance_lock(runtime_dir / "monitor.lock"):
        return _run_scan_locked(validated_config, runtime_dir, callback)
