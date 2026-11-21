"""
BugHawk AI 2.0 — Findings API
"""
import hashlib
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.api.deps import get_current_user, require_owned_finding, require_owned_project
from app.database.session import get_db
from app.models import SecurityFinding, Asset, Severity, ValidationStatus, ConfidenceLevel, User
from app.schemas import FindingImportRequest, FindingResponse, MessageResponse, DashboardStats

router = APIRouter()


def _compute_finding_hash(title: str, endpoint: Optional[str], asset_id: Optional[str]) -> str:
    """Compute a deduplication hash for a finding."""
    key = f"{title.lower().strip()}|{(endpoint or '').lower().strip()}|{asset_id or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:64]


def _map_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }
    return mapping.get(raw.lower().strip(), Severity.UNKNOWN)


@router.post("/import", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def import_findings(
    payload: FindingImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Import scanner findings. Deduplication is applied automatically."""
    require_owned_project(payload.project_id, db, current_user)
    imported = 0
    duplicates = 0

    for item in payload.findings:
        severity = _map_severity(item.severity)
        finding_hash = _compute_finding_hash(item.title, item.endpoint, None)

        # Check for duplicate by hash in this project
        existing = db.query(SecurityFinding).filter(
            SecurityFinding.project_id == payload.project_id,
            SecurityFinding.finding_hash == finding_hash,
        ).first()

        if existing:
            duplicates += 1
            continue

        finding = SecurityFinding(
            project_id=payload.project_id,
            scan_job_id=payload.scan_job_id,
            title=item.title,
            vulnerability_type=item.vulnerability_type,
            cve_id=item.cve_id,
            cwe_id=item.cwe_id,
            endpoint=item.endpoint,
            description=item.description,
            evidence=item.evidence,
            scanner_severity=severity,
            effective_severity=severity,
            source_tool=item.source_tool,
            raw_finding=item.raw_finding,
            finding_hash=finding_hash,
            validation_status=ValidationStatus.PENDING,
            confidence=ConfidenceLevel.UNVERIFIED,
        )
        db.add(finding)
        imported += 1

    db.commit()
    return MessageResponse(
        message=f"Import complete. New: {imported}, Duplicates skipped: {duplicates}",
        success=True,
    )


@router.get("", response_model=List[FindingResponse])
def list_findings(
    project_id: str = Query(...),
    severity: Optional[str] = Query(None),
    validation_status: Optional[str] = Query(None),
    source_tool: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings for a project owned by the authenticated user."""
    require_owned_project(project_id, db, current_user)
    q = db.query(SecurityFinding).filter(SecurityFinding.project_id == project_id)

    if severity:
        q = q.filter(SecurityFinding.effective_severity == severity)
    if validation_status:
        q = q.filter(SecurityFinding.validation_status == validation_status)
    if source_tool:
        q = q.filter(SecurityFinding.source_tool == source_tool)
    if search:
        q = q.filter(SecurityFinding.title.ilike(f"%{search}%"))

    return q.order_by(SecurityFinding.effective_severity.desc(), SecurityFinding.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/stats/{project_id}", response_model=DashboardStats)
def get_dashboard_stats(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get aggregated dashboard statistics for an owned project."""
    require_owned_project(project_id, db, current_user)
    from app.models import Asset, ScanJob, AssetStatus

    total_assets = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id).scalar() or 0
    live_assets = db.query(func.count(Asset.id)).filter(
        Asset.project_id == project_id, Asset.status == AssetStatus.LIVE
    ).scalar() or 0

    total_findings = db.query(func.count(SecurityFinding.id)).filter(SecurityFinding.project_id == project_id).scalar() or 0

    def count_sev(sev):
        return db.query(func.count(SecurityFinding.id)).filter(
            SecurityFinding.project_id == project_id,
            SecurityFinding.effective_severity == sev
        ).scalar() or 0

    critical = count_sev(Severity.CRITICAL)
    high = count_sev(Severity.HIGH)
    medium = count_sev(Severity.MEDIUM)
    low = count_sev(Severity.LOW)
    info = count_sev(Severity.INFO)

    duplicates = db.query(func.count(SecurityFinding.id)).filter(
        SecurityFinding.project_id == project_id,
        SecurityFinding.validation_status == ValidationStatus.DUPLICATE,
    ).scalar() or 0

    pending_review = db.query(func.count(SecurityFinding.id)).filter(
        SecurityFinding.project_id == project_id,
        SecurityFinding.needs_human_review == True,
    ).scalar() or 0

    total_scans = db.query(func.count(ScanJob.id)).filter(ScanJob.project_id == project_id).scalar() or 0
    from app.models import ScanStatus
    active_scans = db.query(func.count(ScanJob.id)).filter(
        ScanJob.project_id == project_id,
        ScanJob.status == ScanStatus.RUNNING,
    ).scalar() or 0

    return DashboardStats(
        total_assets=total_assets,
        live_assets=live_assets,
        total_findings=total_findings,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        info_findings=info,
        potential_duplicates=duplicates,
        findings_pending_review=pending_review,
        total_scans=total_scans,
        active_scans=active_scans,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a finding from a project owned by the authenticated user."""
    return require_owned_finding(finding_id, db, current_user)
