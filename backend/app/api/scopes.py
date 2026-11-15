"""
BugHawk AI 2.0 — Scopes API
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import AuthorizedScope, Project
from app.schemas import ScopeCreate, ScopeResponse, ScopeValidateRequest, ScopeValidateResponse
from app.core.scope_guard import ScopeGuardian

router = APIRouter()


def _get_project_scopes(project_id: str, db: Session) -> List[str]:
    scopes = db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project_id,
        AuthorizedScope.is_active == True
    ).all()
    return [s.scope_value for s in scopes]


@router.post("", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
def add_scope(project_id: str, payload: ScopeCreate, db: Session = Depends(get_db)):
    """Add an authorized scope to a project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Determine if wildcard
    is_wildcard = payload.scope_value.startswith("*.")

    scope = AuthorizedScope(
        project_id=project_id,
        scope_value=payload.scope_value,
        is_wildcard=is_wildcard,
        notes=payload.notes,
        authorized_by=payload.authorized_by,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    return scope


@router.get("", response_model=List[ScopeResponse])
def list_scopes(
    project_id: str = Query(...),
    db: Session = Depends(get_db),
):
    """List all authorized scopes for a project."""
    return db.query(AuthorizedScope).filter(
        AuthorizedScope.project_id == project_id,
        AuthorizedScope.is_active == True,
    ).all()


@router.post("/validate", response_model=ScopeValidateResponse)
def validate_target(payload: ScopeValidateRequest, db: Session = Depends(get_db)):
    """
    Validate whether a target is within authorized scope.
    Uses the deterministic Scope Guardian — no LLM involved.
    """
    scope_strings = _get_project_scopes(payload.project_id, db)
    guardian = ScopeGuardian(scope_strings)
    result = guardian.validate(payload.target)

    return ScopeValidateResponse(
        target=payload.target,
        normalized_host=result.normalized_host,
        decision=result.decision.value,
        matched_rule=result.matched_rule,
        reason=result.reason,
        is_allowed=result.is_allowed,
    )


@router.delete("/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(scope_id: str, db: Session = Depends(get_db)):
    """Deactivate a scope rule."""
    scope = db.query(AuthorizedScope).filter(AuthorizedScope.id == scope_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    scope.is_active = False
    db.commit()
