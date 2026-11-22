"""Database-polling worker for Subfinder, httpx, Nuclei, Semgrep, and ZAP.

Start it as its own process: python -m app.workers.scan_worker
It does not use Redis or Celery. Each process claims pending rows itself.
Each scanner is its own job. Any other module list is failed.
"""
import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.scope_guard import ScopeGuardian, _is_ip_address
from app.database.session import SessionLocal
from app.models import (
    Asset,
    AssetStatus,
    AssetType,
    AuthorizedScope,
    ConfidenceLevel,
    ScanJob,
    ScanStatus,
    SecurityFinding,
    Severity,
    ValidationStatus,
)
from app.scanners.httpx import HttpxOutcome, HttpxProbe, run_httpx
from app.scanners.nuclei import NucleiMatch, NucleiOutcome, normalize_target_url, run_nuclei
from app.scanners.semgrep import (
    SOURCE_PREREQUISITE,
    SemgrepMatch,
    SemgrepOutcome,
    allocate_source_directory,
    extract_source_archive,
    load_source_bundle,
    release_source_directory,
    run_semgrep,
)
from app.scanners.subfinder import SubfinderOutcome, is_safe_domain, run_subfinder
from app.scanners.zap import ZapAlert, ZapOutcome, run_zap

logger = get_logger("scan_worker")
Runner = Callable[[str], SubfinderOutcome]
HttpxRunner = Callable[[list[str]], HttpxOutcome]
NucleiRunner = Callable[[list[str]], NucleiOutcome]
SemgrepRunner = Callable[[object], SemgrepOutcome]
ZapRunner = Callable[[list[str]], ZapOutcome]
_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.UNKNOWN,
}


def is_subfinder_job(modules: Optional[list]) -> bool:
    names = [str(item).strip().lower() for item in (modules or [])]
    return names == ["subfinder"]


def is_httpx_job(modules: Optional[list]) -> bool:
    names = [str(item).strip().lower() for item in (modules or [])]
    return names == ["httpx"]


def is_nuclei_job(modules: Optional[list]) -> bool:
    names = [str(item).strip().lower() for item in (modules or [])]
    return names == ["nuclei"]


def is_semgrep_job(modules: Optional[list]) -> bool:
    names = [str(item).strip().lower() for item in (modules or [])]
    return names == ["semgrep"]


def is_zap_job(modules: Optional[list]) -> bool:
    names = [str(item).strip().lower() for item in (modules or [])]
    return names == ["zap"]


def load_scope_values(db: Session, project_id: str) -> list[str]:
    rows = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project_id,
        AuthorizedScope.is_active.is_(True),
    ).all()
    return [row.scope_value for row in rows]


def existing_asset(db: Session, project_id: str, hostname: str) -> Optional[Asset]:
    return db.query(Asset).filter(
        Asset.project_id == project_id,
        Asset.hostname == hostname,
    ).first()


def load_project_assets(db: Session, project_id: str) -> list[Asset]:
    return db.query(Asset).filter(Asset.project_id == project_id).all()


def load_httpx_results(db: Session, project_id: str) -> list[dict]:
    """Return HTTPX result objects stored on completed jobs for this project."""
    rows = db.query(ScanJob).filter(
        ScanJob.project_id == project_id,
        ScanJob.status == ScanStatus.COMPLETED,
    ).all()
    found: list[dict] = []
    for row in rows:
        raw = row.raw_output if isinstance(row.raw_output, dict) else {}
        if raw.get("module") != "httpx":
            continue
        for item in raw.get("results") or []:
            if isinstance(item, dict):
                found.append(item)
    return found


def existing_nuclei_finding(db: Session, project_id: str, scan_id: str, template_id: str, endpoint: str):
    return db.query(SecurityFinding).filter(
        SecurityFinding.project_id == project_id,
        SecurityFinding.scan_job_id == scan_id,
        SecurityFinding.source_template == template_id,
        SecurityFinding.endpoint == endpoint,
    ).first()


def _belongs_to_target(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def fail_scan(scan: ScanJob, message: str, now: Optional[datetime] = None) -> None:
    scan.status = ScanStatus.FAILED
    scan.completed_at = now or datetime.now(timezone.utc)
    scan.error_message = message[:500]
    if is_httpx_job(scan.modules):
        scan.raw_output = {
            "module": "httpx",
            "service_discovery": True,
            "ports": [80, 443],
            "probed": 0,
            "updated": 0,
            "results": [],
        }
        return
    if is_nuclei_job(scan.modules):
        scan.raw_output = {
            "module": "nuclei",
            "vulnerability_detection": True,
            "template_set": "reviewed-header-checks",
            "targets": 0,
            "findings": 0,
            "informational": 0,
            "potential": 0,
            "results": [],
        }
        return
    if is_semgrep_job(scan.modules):
        scan.raw_output = {
            "module": "semgrep",
            "source_analysis": True,
            "findings": 0,
            "results": [],
        }
        scan.findings_count = 0
        return
    if is_zap_job(scan.modules):
        scan.raw_output = {
            "module": "zap",
            "passive_baseline": True,
            "targets": 0,
            "findings": 0,
            "results": [],
        }
        scan.findings_count = 0
        return
    if is_subfinder_job(scan.modules):
        scan.raw_output = {"module": "subfinder", "passive": True, "stored": 0, "hostnames": []}
        return
    scan.raw_output = {"module": "unsupported", "findings": 0}
    scan.findings_count = 0


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


def fail_stale_running(db: Session, now: Optional[datetime] = None) -> int:
    """Mark a running Subfinder or httpx job failed when its worker did not finish."""
    moment = now or datetime.now(timezone.utc)
    changed = 0
    rows = db.query(ScanJob).filter(ScanJob.status == ScanStatus.RUNNING).all()
    for scan in rows:
        if is_subfinder_job(scan.modules):
            max_age = timedelta(seconds=settings.subfinder_timeout_seconds + 30)
            message = "The scan worker stopped before Subfinder finished."
        elif is_httpx_job(scan.modules):
            max_age = timedelta(seconds=settings.httpx_job_timeout_seconds + 30)
            message = "The scan worker stopped before httpx finished."
        elif is_nuclei_job(scan.modules):
            max_age = timedelta(seconds=settings.nuclei_job_timeout_seconds + 30)
            message = "The scan worker stopped before Nuclei finished."
        elif is_semgrep_job(scan.modules):
            max_age = timedelta(seconds=settings.semgrep_job_timeout_seconds + 30)
            message = "The scan worker stopped before Semgrep finished."
        elif is_zap_job(scan.modules):
            max_age = timedelta(seconds=settings.zap_job_timeout_seconds + 30)
            message = "The scan worker stopped before ZAP finished."
        else:
            max_age = timedelta(seconds=60)
            message = "The scan worker stopped before this job finished."
        started = None if scan.started_at is None else _aware(scan.started_at)
        if started is None or _aware(moment) - started > max_age:
            fail_scan(scan, message, moment)
            changed += 1
    if changed:
        db.commit()
    return changed


def mark_running(db: Session, scan: ScanJob) -> bool:
    now = datetime.now(timezone.utc)
    updated = db.query(ScanJob).filter(
        ScanJob.id == scan.id,
        ScanJob.status == ScanStatus.PENDING,
    ).update(
        {"status": ScanStatus.RUNNING, "started_at": now},
        synchronize_session=False,
    )
    db.commit()
    if not updated:
        return False
    scan.status = ScanStatus.RUNNING
    scan.started_at = now
    return True


def _claim_pending(db: Session, accepted) -> Optional[ScanJob]:
    fail_stale_running(db)
    pending = db.query(ScanJob).filter(
        ScanJob.status == ScanStatus.PENDING,
    ).order_by(ScanJob.created_at).limit(25).all()
    for scan in pending:
        if not accepted(scan.modules):
            continue
        if mark_running(db, scan):
            return scan
    return None


def claim_subfinder_job(db: Session) -> Optional[ScanJob]:
    """Claim one pending Subfinder-only job. Other modules stay pending."""
    return _claim_pending(db, is_subfinder_job)


def claim_supported_job(db: Session) -> Optional[ScanJob]:
    """Claim the oldest pending job. The caller fails a module list it cannot run."""
    return _claim_pending(db, lambda modules: True)


def execute_subfinder_scan(db: Session, scan: ScanJob, runner: Optional[Runner] = None) -> ScanJob:
    """Re-check scope, run Subfinder, and store only in-scope names for this target."""
    run = runner or run_subfinder
    now = datetime.now(timezone.utc)
    guardian = ScopeGuardian.from_scope_values(load_scope_values(db, scan.project_id))
    decision = guardian.validate(scan.target)
    domain = decision.normalized_host
    if (
        not decision.is_allowed
        or _is_ip_address(domain)
        or not is_safe_domain(domain)
    ):
        fail_scan(scan, "Target is not an authorized domain for Subfinder.", now)
        db.commit()
        return scan

    outcome = run(domain)
    if outcome.timed_out or outcome.too_large or outcome.failed or outcome.exit_code != 0:
        fail_scan(scan, outcome.message or "Subfinder did not complete.", now)
        db.commit()
        return scan

    stored: list[str] = []
    duplicates = 0
    rejected = 0
    for host in outcome.hosts:
        if not _belongs_to_target(host, domain) or not guardian.validate(host).is_allowed:
            rejected += 1
            continue
        current = existing_asset(db, scan.project_id, host)
        if current is not None:
            current.last_seen = now
            duplicates += 1
            continue
        db.add(Asset(
            project_id=scan.project_id,
            hostname=host,
            asset_type=AssetType.SUBDOMAIN,
            status=AssetStatus.UNKNOWN,
            discovery_source="subfinder",
            is_in_scope=True,
            is_demo=False,
            last_seen=now,
        ))
        stored.append(host)

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = now
    scan.error_message = None
    scan.findings_count = 0
    scan.raw_output = {
        "module": "subfinder",
        "passive": True,
        "exit_code": 0,
        "discovered": len(outcome.hosts),
        "stored": len(stored),
        "duplicates": duplicates,
        "rejected_out_of_scope": rejected,
        "hostnames": stored[:200],
    }
    db.commit()
    return scan


def select_httpx_hosts(assets: list, domain: str, guardian: ScopeGuardian) -> tuple[list[str], int]:
    """Hostnames already stored for this project that still match the job domain and scope."""
    hosts: list[str] = []
    seen: set[str] = set()
    rejected = 0
    for asset in assets:
        host = (getattr(asset, "hostname", "") or "").strip().lower().rstrip(".")
        if host in seen:
            continue
        allowed = (
            bool(host)
            and _belongs_to_target(host, domain)
            and is_safe_domain(host)
            and not _is_ip_address(host)
            and guardian.validate(host).is_allowed
        )
        if not allowed:
            rejected += 1
            continue
        seen.add(host)
        hosts.append(host)
    return hosts, rejected


def _probe_record(probe) -> dict:
    record = {"hostname": probe.hostname, "url": probe.url}
    if probe.status_code is not None:
        record["status_code"] = probe.status_code
    if probe.title:
        record["title"] = probe.title
    if probe.webserver:
        record["webserver"] = probe.webserver
    if probe.technologies:
        record["technologies"] = list(probe.technologies)
    return record


def _apply_httpx_probe(asset: Asset, probe, now: datetime, fallback=None) -> bool:
    """Copy fields httpx returned. A second scheme fills only fields the first one omitted."""
    status_code = probe.status_code if probe.status_code is not None else getattr(fallback, "status_code", None)
    title = probe.title or getattr(fallback, "title", None)
    technologies = list(probe.technologies or []) or list(getattr(fallback, "technologies", None) or [])
    changed = False
    if status_code is not None:
        asset.http_status_code = status_code
        asset.status = AssetStatus.LIVE
        changed = True
    if title:
        asset.title = title
        changed = True
    if technologies:
        asset.technologies = technologies
        changed = True
    if changed:
        asset.last_seen = now
    return changed


def execute_httpx_scan(db: Session, scan: ScanJob, runner: Optional[HttpxRunner] = None) -> ScanJob:
    """Probe stored assets for this project. The typed target selects the domain, not a URL."""
    run = runner or run_httpx
    now = datetime.now(timezone.utc)
    guardian = ScopeGuardian.from_scope_values(load_scope_values(db, scan.project_id))
    decision = guardian.validate(scan.target)
    domain = decision.normalized_host
    if (
        not decision.is_allowed
        or _is_ip_address(domain)
        or not is_safe_domain(domain)
        or "://" in (scan.target or "")
    ):
        fail_scan(scan, "Target is not an authorized domain for httpx.", now)
        db.commit()
        return scan

    hosts, rejected = select_httpx_hosts(load_project_assets(db, scan.project_id), domain, guardian)
    limit = max(1, int(settings.httpx_max_assets))
    skipped = max(0, len(hosts) - limit)
    hosts = hosts[:limit]
    if not hosts:
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = now
        scan.error_message = None
        scan.findings_count = 0
        scan.raw_output = {
            "module": "httpx",
            "service_discovery": True,
            "ports": [80, 443],
            "probed": 0,
            "updated": 0,
            "rejected_out_of_scope": rejected,
            "skipped_over_limit": skipped,
            "results": [],
        }
        db.commit()
        return scan

    outcome = run(hosts)
    if outcome.timed_out or outcome.too_large or outcome.failed or outcome.exit_code != 0:
        fail_scan(scan, outcome.message or "httpx did not complete.", now)
        db.commit()
        return scan

    chosen: dict[str, HttpxProbe] = {}
    for probe in outcome.probes:
        if probe.hostname not in hosts or not guardian.validate(probe.hostname).is_allowed:
            rejected += 1
            continue
        current = chosen.get(probe.hostname)
        if current is None or (probe.url.startswith("https://") and not current.url.startswith("https://")):
            chosen[probe.hostname] = probe

    updated = 0
    results = []
    for host in hosts:
        probe = chosen.get(host)
        if probe is None:
            continue
        asset = existing_asset(db, scan.project_id, host)
        if asset is None:
            rejected += 1
            continue
        fallback = next(
            (extra for extra in outcome.probes if extra.hostname == host and extra.url != probe.url),
            None,
        )
        if _apply_httpx_probe(asset, probe, now, fallback):
            updated += 1
        results.append(_probe_record(probe))
        for extra in outcome.probes:
            if extra.hostname == host and extra.url != probe.url:
                results.append(_probe_record(extra))

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = now
    scan.error_message = None
    scan.findings_count = 0
    scan.raw_output = {
        "module": "httpx",
        "service_discovery": True,
        "ports": [80, 443],
        "probed": len(hosts),
        "updated": updated,
        "rejected_out_of_scope": rejected,
        "invalid_lines": outcome.invalid_lines,
        "skipped_over_limit": skipped,
        "results": results[:100],
    }
    db.commit()
    return scan


def select_nuclei_targets(results: list, assets: list, domain: str, guardian: ScopeGuardian):
    """Origins that HTTPX verified for this project and that are still in scope."""
    assets_by_host = {}
    for asset in assets:
        host = (getattr(asset, "hostname", "") or "").strip().lower().rstrip(".")
        if host and host not in assets_by_host:
            assets_by_host[host] = asset
    urls: list[str] = []
    seen: set[str] = set()
    rejected = 0
    unverified = 0
    for item in results:
        if not isinstance(item, dict):
            unverified += 1
            continue
        host = str(item.get("hostname") or "").strip().lower().rstrip(".")
        status_code = item.get("status_code")
        asset = assets_by_host.get(host)
        located = normalize_target_url(item.get("url") or "")
        verified = (
            isinstance(status_code, int)
            and asset is not None
            and asset.http_status_code is not None
            and located is not None
        )
        if not verified:
            unverified += 1
            continue
        canonical, url_host = located
        allowed = (
            url_host == host
            and _belongs_to_target(host, domain)
            and guardian.validate(host).is_allowed
        )
        if not allowed:
            rejected += 1
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        urls.append(canonical)
    return urls, rejected, unverified


def _nuclei_evidence(match: NucleiMatch, classification: str) -> dict:
    evidence = {
        "template_id": match.template_id,
        "matched_url": match.url,
        "severity": match.severity,
        "classification": classification,
        "confirmed": False,
    }
    if match.detected_at:
        evidence["detected_at"] = match.detected_at
    if match.matcher_name:
        evidence["matcher_name"] = match.matcher_name
    return evidence


def execute_nuclei_scan(db: Session, scan: ScanJob, runner: Optional[NucleiRunner] = None) -> ScanJob:
    """Scan HTTPX-verified origins with the reviewed templates. The API does not run this."""
    run = runner or run_nuclei
    now = datetime.now(timezone.utc)
    guardian = ScopeGuardian.from_scope_values(load_scope_values(db, scan.project_id))
    decision = guardian.validate(scan.target)
    domain = decision.normalized_host
    if (
        not decision.is_allowed
        or _is_ip_address(domain)
        or not is_safe_domain(domain)
        or "://" in (scan.target or "")
    ):
        fail_scan(scan, "Target is not an authorized domain for Nuclei.", now)
        db.commit()
        return scan

    urls, rejected, unverified = select_nuclei_targets(
        load_httpx_results(db, scan.project_id),
        load_project_assets(db, scan.project_id),
        domain,
        guardian,
    )
    limit = max(1, int(settings.nuclei_max_targets))
    skipped = max(0, len(urls) - limit)
    urls = urls[:limit]
    if not urls:
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = now
        scan.error_message = None
        scan.findings_count = 0
        scan.raw_output = {
            "module": "nuclei",
            "vulnerability_detection": True,
            "template_set": "reviewed-header-checks",
            "coverage": "Reviewed header checks only.",
            "targets": 0,
            "findings": 0,
            "informational": 0,
            "potential": 0,
            "duplicates": 0,
            "rejected_out_of_scope": rejected,
            "unverified": unverified,
            "skipped_over_limit": skipped,
            "results": [],
        }
        db.commit()
        return scan

    outcome = run(urls)
    if outcome.timed_out or outcome.too_large or outcome.failed or outcome.exit_code != 0:
        fail_scan(scan, outcome.message or "Nuclei did not complete.", now)
        db.commit()
        return scan

    stored = 0
    duplicates = 0
    informational = 0
    potential = 0
    public = []
    seen_keys: set[tuple[str, str]] = set()
    allowed_hosts: set[str] = set()
    for url in urls:
        located = normalize_target_url(url)
        if located is not None:
            allowed_hosts.add(located[1])
    for match in outcome.matches:
        if match.hostname not in allowed_hosts or not _belongs_to_target(match.hostname, domain):
            rejected += 1
            continue
        if not guardian.validate(match.hostname).is_allowed:
            rejected += 1
            continue
        severity = _SEVERITY.get(match.severity)
        if severity is None:
            rejected += 1
            continue
        identity = (match.template_id, match.url)
        if identity in seen_keys or existing_nuclei_finding(
            db, scan.project_id, scan.id, match.template_id, match.url
        ) is not None:
            duplicates += 1
            continue
        seen_keys.add(identity)
        asset = existing_asset(db, scan.project_id, match.hostname)
        if asset is None or asset.project_id != scan.project_id or asset.http_status_code is None:
            rejected += 1
            continue
        classification = "informational" if severity == Severity.INFO else "potential"
        if classification == "informational":
            description = (
                f"{match.name} This is an informational observation from a reviewed Nuclei template. "
                "It is not a confirmed vulnerability."
            )
        else:
            description = (
                f"{match.name} This is a potential issue from a reviewed Nuclei template. It is not confirmed."
            )
        digest = hashlib.sha256(f"{scan.id}|{match.template_id}|{match.url}".encode()).hexdigest()
        db.add(SecurityFinding(
            project_id=scan.project_id,
            asset_id=asset.id,
            scan_job_id=scan.id,
            title=match.name[:512],
            vulnerability_type="header-check",
            endpoint=match.url[:1024],
            scanner_severity=severity,
            effective_severity=severity,
            description=description[:2000],
            evidence=_nuclei_evidence(match, classification),
            confidence=ConfidenceLevel.UNVERIFIED,
            validation_status=ValidationStatus.PENDING,
            source_tool="nuclei",
            source_template=match.template_id[:255],
            finding_hash=digest,
            is_demo=False,
            needs_human_review=classification == "potential",
        ))
        stored += 1
        if classification == "informational":
            informational += 1
        else:
            potential += 1
        public.append({
            "template_id": match.template_id,
            "url": match.url,
            "severity": match.severity,
            "classification": classification,
        })

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = now
    scan.error_message = None
    scan.findings_count = stored
    scan.raw_output = {
        "module": "nuclei",
        "vulnerability_detection": True,
        "template_set": "reviewed-header-checks",
        "coverage": "Reviewed header checks only. Exploit, fuzz, brute force, DoS, and out-of-band templates are not included.",
        "targets": len(urls),
        "findings": stored,
        "informational": informational,
        "potential": potential,
        "duplicates": duplicates,
        "rejected_out_of_scope": rejected,
        "unverified": unverified,
        "invalid_lines": outcome.invalid_lines,
        "skipped_over_limit": skipped,
        "results": public[:100],
    }
    db.commit()
    return scan


def _authorized_domain(scan: ScanJob, guardian: ScopeGuardian) -> Optional[str]:
    decision = guardian.validate(scan.target)
    domain = decision.normalized_host
    if (
        not decision.is_allowed
        or _is_ip_address(domain)
        or not is_safe_domain(domain)
        or "://" in (scan.target or "")
    ):
        return None
    return domain


def execute_semgrep_scan(db: Session, scan: ScanJob, runner: Optional[SemgrepRunner] = None) -> ScanJob:
    """Scan a stored source archive. With no archive, record the missing prerequisite."""
    run = runner or run_semgrep
    now = datetime.now(timezone.utc)
    guardian = ScopeGuardian.from_scope_values(load_scope_values(db, scan.project_id))
    if _authorized_domain(scan, guardian) is None:
        fail_scan(scan, "Target is not an authorized domain for Semgrep.", now)
        db.commit()
        return scan
    bundle = load_source_bundle(db, scan.project_id)
    if not bundle:
        fail_scan(scan, SOURCE_PREREQUISITE, now)
        db.commit()
        return scan
    directory = allocate_source_directory()
    try:
        extracted = extract_source_archive(bundle, directory)
        if extracted == 0:
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = now
            scan.error_message = None
            scan.findings_count = 0
            scan.raw_output = {
                "module": "semgrep",
                "source_analysis": True,
                "files": 0,
                "findings": 0,
                "results": [],
            }
            db.commit()
            return scan
        outcome = run(directory)
        if outcome.timed_out or outcome.too_large or outcome.failed or outcome.exit_code not in (0, 1):
            fail_scan(scan, outcome.message or "Semgrep did not complete.", now)
            db.commit()
            return scan
        stored, duplicates, public = _store_static_findings(db, scan, outcome.matches, now)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = now
        scan.error_message = None
        scan.findings_count = stored
        scan.raw_output = {
            "module": "semgrep",
            "source_analysis": True,
            "ruleset": "reviewed-static-checks",
            "files": extracted,
            "findings": stored,
            "duplicates": duplicates,
            "invalid_lines": outcome.invalid_lines,
            "results": public,
        }
        db.commit()
        return scan
    finally:
        release_source_directory(directory)


def _store_static_findings(db: Session, scan: ScanJob, matches: list[SemgrepMatch], now: datetime):
    stored = 0
    duplicates = 0
    public = []
    seen = set()
    for match in matches:
        identity = (match.rule_id, match.path, match.line)
        endpoint = f"{match.path}:{match.line}"
        if identity in seen or existing_nuclei_finding(db, scan.project_id, scan.id, match.rule_id, endpoint) is not None:
            duplicates += 1
            continue
        severity = _SEVERITY.get(match.severity)
        if severity is None:
            continue
        seen.add(identity)
        digest = hashlib.sha256(f"{scan.id}|{match.rule_id}|{endpoint}".encode()).hexdigest()
        db.add(SecurityFinding(
            project_id=scan.project_id,
            scan_job_id=scan.id,
            title=match.rule_id[:512],
            vulnerability_type="static-analysis",
            endpoint=endpoint[:1024],
            scanner_severity=severity,
            effective_severity=severity,
            description="Static source finding from a reviewed Semgrep rule. It is not a confirmed vulnerability.",
            evidence={
                "rule_id": match.rule_id,
                "path": match.path,
                "line": match.line,
                "severity": match.severity,
                "evidence": match.evidence,
                "classification": "static-source",
                "source_kind": "static",
                "confirmed": False,
            },
            confidence=ConfidenceLevel.UNVERIFIED,
            validation_status=ValidationStatus.PENDING,
            source_tool="semgrep",
            source_template=match.rule_id[:255],
            finding_hash=digest,
            is_demo=False,
            needs_human_review=True,
        ))
        stored += 1
        public.append({
            "rule_id": match.rule_id,
            "path": match.path,
            "line": match.line,
            "severity": match.severity,
            "classification": "static-source",
        })
    del now
    return stored, duplicates, public[:100]


def execute_zap_scan(db: Session, scan: ScanJob, runner: Optional[ZapRunner] = None) -> ScanJob:
    """Passive ZAP baseline of HTTPX-verified origins. Active scan is not requested."""
    run = runner or run_zap
    now = datetime.now(timezone.utc)
    guardian = ScopeGuardian.from_scope_values(load_scope_values(db, scan.project_id))
    domain = _authorized_domain(scan, guardian)
    if domain is None:
        fail_scan(scan, "Target is not an authorized domain for ZAP.", now)
        db.commit()
        return scan
    urls, rejected, unverified = select_nuclei_targets(
        load_httpx_results(db, scan.project_id),
        load_project_assets(db, scan.project_id),
        domain,
        guardian,
    )
    cap = 10
    skipped = max(0, len(urls) - cap)
    urls = urls[:cap]
    if not urls:
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = now
        scan.error_message = None
        scan.findings_count = 0
        scan.raw_output = {
            "module": "zap",
            "passive_baseline": True,
            "targets": 0,
            "findings": 0,
            "rejected_out_of_scope": rejected,
            "unverified": unverified,
            "results": [],
        }
        db.commit()
        return scan
    outcome = run(urls)
    if outcome.timed_out or outcome.too_large or outcome.failed or outcome.exit_code not in (0, None):
        fail_scan(scan, outcome.message or "ZAP did not complete.", now)
        db.commit()
        return scan
    stored = 0
    duplicates = 0
    public = []
    seen = set()
    allowed = set()
    for url in urls:
        located = normalize_target_url(url)
        if located is not None:
            allowed.add(located[1])
    for alert in outcome.alerts:
        if alert.hostname not in allowed or not guardian.validate(alert.hostname).is_allowed:
            rejected += 1
            continue
        severity = _SEVERITY.get(alert.risk)
        if severity is None:
            rejected += 1
            continue
        identity = (alert.plugin_id, alert.url)
        if identity in seen or existing_nuclei_finding(db, scan.project_id, scan.id, alert.plugin_id, alert.url) is not None:
            duplicates += 1
            continue
        asset = existing_asset(db, scan.project_id, alert.hostname)
        if asset is None or asset.project_id != scan.project_id or asset.http_status_code is None:
            rejected += 1
            continue
        seen.add(identity)
        classification = "informational" if severity == Severity.INFO else "potential"
        digest = hashlib.sha256(f"{scan.id}|{alert.plugin_id}|{alert.url}".encode()).hexdigest()
        db.add(SecurityFinding(
            project_id=scan.project_id,
            asset_id=asset.id,
            scan_job_id=scan.id,
            title=alert.name[:512],
            vulnerability_type="web-baseline",
            endpoint=alert.url[:1024],
            scanner_severity=severity,
            effective_severity=severity,
            description="Passive ZAP baseline result. This is a potential issue, not a confirmed vulnerability.",
            evidence={
                "plugin_id": alert.plugin_id,
                "url": alert.url,
                "risk": alert.risk,
                "zap_confidence": alert.confidence,
                "evidence": alert.evidence,
                "classification": classification,
                "source_kind": "web-baseline",
                "confirmed": False,
            },
            confidence=ConfidenceLevel.UNVERIFIED,
            validation_status=ValidationStatus.PENDING,
            source_tool="zap",
            source_template=alert.plugin_id[:255],
            finding_hash=digest,
            is_demo=False,
            needs_human_review=True,
        ))
        stored += 1
        public.append({
            "plugin_id": alert.plugin_id,
            "url": alert.url,
            "risk": alert.risk,
            "classification": classification,
        })
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = now
    scan.error_message = None
    scan.findings_count = stored
    scan.raw_output = {
        "module": "zap",
        "passive_baseline": True,
        "targets": len(urls),
        "findings": stored,
        "duplicates": duplicates,
        "rejected_out_of_scope": rejected,
        "unverified": unverified,
        "skipped_over_limit": skipped,
        "invalid_records": outcome.invalid_records,
        "results": public[:100],
    }
    db.commit()
    return scan


def run_once(db: Session) -> bool:
    scan = claim_supported_job(db)
    if scan is None:
        return False
    try:
        if is_nuclei_job(scan.modules):
            execute_nuclei_scan(db, scan)
        elif is_httpx_job(scan.modules):
            execute_httpx_scan(db, scan)
        elif is_subfinder_job(scan.modules):
            execute_subfinder_scan(db, scan)
        elif is_semgrep_job(scan.modules):
            execute_semgrep_scan(db, scan)
        elif is_zap_job(scan.modules):
            execute_zap_scan(db, scan)
        else:
            message = "The import module does not run a scanner." if scan.modules == ["import"] else (
                "This module list is not a supported scanner."
            )
            fail_scan(scan, message)
            db.commit()
    except Exception:
        db.rollback()
        logger.error("scan job failed before results were saved", scan_id=scan.id)
        fail_scan(scan, "The scan worker could not save results.")
        db.commit()
    return True


def main() -> None:
    configure_logging()
    logger.info("scan worker started", poll_seconds=settings.scan_worker_poll_seconds)
    while True:
        db = SessionLocal()
        worked = False
        try:
            worked = run_once(db)
        except Exception:
            db.rollback()
            logger.error("scan worker loop failed")
        finally:
            db.close()
        if not worked:
            time.sleep(settings.scan_worker_poll_seconds)


if __name__ == "__main__":
    main()
