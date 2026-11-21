"""
BugHawk AI 2.0 — Remediation API
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_owned_finding, require_owned_project
from app.database.session import get_db
from app.models import RemediationSuggestion, SecurityFinding, RemediationStatus, User
from app.schemas import RemediationResponse, RemediationStatusUpdate

router = APIRouter()


@router.get("/{finding_id}", response_model=List[RemediationResponse])
def get_remediation(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get remediation suggestions for a finding in an owned project."""
    require_owned_finding(finding_id, db, current_user)

    suggestions = db.query(RemediationSuggestion).filter(
        RemediationSuggestion.finding_id == finding_id
    ).all()
    return suggestions


@router.patch("/{remediation_id}/status", response_model=RemediationResponse)
def update_remediation_status(
    remediation_id: str,
    payload: RemediationStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update the status of a remediation suggestion in an owned project."""
    suggestion = db.query(RemediationSuggestion).filter(
        RemediationSuggestion.id == remediation_id
    ).first()
    if not suggestion:
        raise HTTPException(status_code=404, detail="Remediation suggestion not found")
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == suggestion.finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    require_owned_project(finding.project_id, db, current_user)

    valid_statuses = {s.value for s in RemediationStatus}
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    suggestion.status = payload.status
    db.commit()
    db.refresh(suggestion)
    return suggestion
