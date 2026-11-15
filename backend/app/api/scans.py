"""
BugHawk AI 2.0 — Scans API
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database.session import get_db
from app.models import ScanJob, AuthorizedScope, ScanStatus
from app.schemas import ScanCreate, ScanResponse, MessageResponse
from app.core.scope_guard import ScopeGuardian

router = APIRouter()

ALLOWED_MODULES = {"subfinder", "httpx", "nuclei", "semgrep", "zap", "import"}


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)):
    """
    Create a scan job.
    Target is validated against project scopes before the job is accepted.
    Only approved modules are allowed.
    """
    # Validate modules
    invalid_modules = set(payload.modules) - ALLOWED_MODULES
    if invalid_modules:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan modules: {invalid_modules}. Allowed: {ALLOWED_MODULES}"
        )

    # Scope validation — mandatory
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == payload.project_id,
        AuthorizedScope.is_active == True,
    ).all()
    scope_strings = [s.scope_value for s in scopes]
    guardian = ScopeGuardian(scope_strings)
    scope_result = guardian.validate(payload.target)

    if not scope_result.is_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Target '{payload.target}' is not in authorized scope: {scope_result.reason}"
        )

    scan = ScanJob(
        project_id=payload.project_id,
        name=payload.name,
        target=payload.target,
        modules=payload.modules,
        status=ScanStatus.PENDING,
        scope_validated=True,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=List[ScanResponse])
def list_scans(
    project_id: str = Query(...),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List scan jobs for a project."""
    return db.query(ScanJob).filter(
        ScanJob.project_id == project_id
    ).order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Get a single scan job."""
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return scan
